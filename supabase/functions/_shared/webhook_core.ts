import { Bot } from "npm:grammy";

export type CommandType = "remember" | "search" | "radar" | "status" | "help" | "note";

export interface ParsedCommand {
  command: CommandType;
  argument: string;
}

export interface BotHandlers {
  onRemember?: (ctx: { chatId: number; userId: string; text: string }) => Promise<string> | string;
  onSearch?: (ctx: { chatId: number; userId: string; query: string }) => Promise<string> | string;
  onRadar?: (ctx: { chatId: number; userId: string }) => Promise<string> | string;
  onStatus?: (ctx: { chatId: number; userId: string }) => Promise<string> | string;
  onNote?: (ctx: { chatId: number; userId: string; text: string }) => Promise<string | void> | string | void;
  replyFn?: (chatId: number, text: string) => Promise<void>;
}

type EdgeRuntimeLike = { waitUntil: (promise: Promise<unknown>) => void };

export const HELP_TEXT = [
  "Personal OS Webhook Commands:",
  "/remember <note> - Save a technical note or decision in the background",
  "/search <query>  - Query hybrid pgvector + full-text memory",
  "/radar           - Return the latest macro and supply-chain status",
  "/status          - Show current workload and budget limits",
  "/help            - Show this command list",
].join("\n");

export function runInBackground(
  promise: Promise<unknown>,
  label = "background_task",
): "edge_runtime" | "detached" {
  const guarded = promise.catch((err) => {
    console.error(`${label} failed`, err instanceof Error ? err.message : String(err));
  });
  const runtime = (globalThis as unknown as { EdgeRuntime?: EdgeRuntimeLike }).EdgeRuntime;
  if (runtime && typeof runtime.waitUntil === "function") {
    try {
      runtime.waitUntil(guarded);
      return "edge_runtime";
    } catch (err) {
      console.error("EdgeRuntime.waitUntil failed, falling back to detached promise", err);
    }
  }
  return "detached";
}

export function findHardSecret(text: string): string | null {
  const patterns: Array<[string, RegExp]> = [
    ["telegram_bot_token", /\b\d{6,12}:[A-Za-z0-9_-]{30,}\b/],
    ["openai_like_key", /\bsk-[A-Za-z0-9_-]{20,}\b/],
    ["github_token", /\bgh[pousr]_[A-Za-z0-9]{20,}\b/],
    ["supabase_token", /\bsbp_[A-Za-z0-9_-]{20,}\b/],
    ["aws_access_key", /\bAKIA[0-9A-Z]{16}\b/],
    ["secret_assignment", /\b(api[_ -]?key|secret|password|passwd|token)\s*[:=]\s*["']?[A-Za-z0-9_.-]{16,}/i],
  ];
  for (const [label, pattern] of patterns) {
    if (pattern.test(text)) return label;
  }
  return null;
}

export function parseTelegramCommand(rawText: string): ParsedCommand {
  const text = String(rawText ?? "").trim();
  const match = /^\/(remember|search|radar|status|help)(?:@[A-Za-z0-9_]+)?(?:\s+([\s\S]*))?$/i.exec(text);
  if (!match) {
    return { command: "note", argument: text };
  }
  return {
    command: match[1].toLowerCase() as CommandType,
    argument: (match[2] ?? "").trim(),
  };
}

export function isAuthorizedUser(senderId: string | number | undefined, allowedUserId: string): boolean {
  if (!allowedUserId) return true;
  return String(senderId ?? "") === String(allowedUserId).trim();
}

export function createPersonalOsBot(args: {
  token: string;
  allowedUserId: string;
  handlers?: BotHandlers;
}): Bot {
  // Pre-cache botInfo so serverless cold starts do not wait on a Telegram getMe HTTP roundtrip.
  const bot = new Bot(args.token || "000:dummy_token_for_ci", {
    botInfo: {
      id: 123456,
      is_bot: true,
      first_name: "Personal OS Bot",
      username: "personal_os_bot",
      can_join_groups: false,
      can_read_all_group_messages: false,
      supports_inline_queries: false,
    },
  });

  const reply = args.handlers?.replyFn ?? (async () => {});

  // User allowlist middleware: ignore updates from any Telegram user ID except the owner.
  bot.use(async (ctx, next) => {
    if (!isAuthorizedUser(ctx.from?.id, args.allowedUserId)) {
      return;
    }
    await next();
  });

  bot.on("message:text", async (ctx) => {
    const chatId = Number(ctx.chat.id);
    const userId = String(ctx.from?.id ?? "");
    const rawText = String(ctx.message.text ?? "").trim();
    if (!rawText) return;

    const secretKind = findHardSecret(rawText);
    if (secretKind) {
      await reply(chatId, `Blocked: detected ${secretKind}. Remove secrets before sending.`);
      return;
    }

    const parsed = parseTelegramCommand(rawText);
    if (parsed.command === "help") {
      await reply(chatId, HELP_TEXT);
      return;
    }
    if (parsed.command === "remember") {
      if (!parsed.argument) {
        await reply(chatId, "Usage: /remember <note>");
        return;
      }
      if (args.handlers?.onRemember) {
        const msg = await args.handlers.onRemember({ chatId, userId, text: parsed.argument });
        await reply(chatId, msg);
      }
      return;
    }
    if (parsed.command === "search") {
      if (!parsed.argument) {
        await reply(chatId, "Usage: /search <query>");
        return;
      }
      if (args.handlers?.onSearch) {
        const msg = await args.handlers.onSearch({ chatId, userId, query: parsed.argument });
        await reply(chatId, msg);
      }
      return;
    }
    if (parsed.command === "radar") {
      if (args.handlers?.onRadar) {
        const msg = await args.handlers.onRadar({ chatId, userId });
        await reply(chatId, msg);
      }
      return;
    }
    if (parsed.command === "status") {
      if (args.handlers?.onStatus) {
        const msg = await args.handlers.onStatus({ chatId, userId });
        await reply(chatId, msg);
      }
      return;
    }
    if (args.handlers?.onNote) {
      const msg = await args.handlers.onNote({ chatId, userId, text: parsed.argument });
      if (msg) await reply(chatId, msg);
    }
  });

  return bot;
}
