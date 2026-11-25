import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { webhookCallback } from "npm:grammy";
import {
  createPersonalOsBot,
  runInBackground,
} from "../_shared/webhook_core.ts";

function envOrEmpty(name: string): string {
  return (Deno.env.get(name) ?? "").trim();
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sendTelegramReply(botToken: string, chatId: number, text: string): Promise<void> {
  if (!botToken) return;
  const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text: text.slice(0, 3900),
      disable_web_page_preview: true,
    }),
  });
  if (!resp.ok) {
    console.error("Telegram sendMessage failed", resp.status);
  }
}

const supabaseUrl = envOrEmpty("SUPABASE_URL");
const serviceRoleKey = envOrEmpty("SUPABASE_SERVICE_ROLE_KEY");
const telegramBotToken = envOrEmpty("TELEGRAM_BOT_TOKEN");
const webhookSecret = envOrEmpty("TELEGRAM_WEBHOOK_SECRET");
const allowedUserId = envOrEmpty("TELEGRAM_ALLOWED_USER_ID");

const supabase = supabaseUrl && serviceRoleKey
  ? createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

async function persistQuickCard(text: string, sourceFile: string): Promise<void> {
  if (!supabase) return;
  const trimmed = text.trim();
  if (trimmed.length < 40) return;

  const threadHash = await sha256Hex(trimmed);
  const nowIso = new Date().toISOString();
  const { error } = await supabase.from("knowledge_cards").upsert(
    {
      thread_hash: threadHash,
      source_file: sourceFile,
      started_at: nowIso,
      ended_at: nowIso,
      turn_count: 1,
      title: trimmed.split("\n")[0].slice(0, 100),
      distilled_summary: trimmed.slice(0, 800),
      domain: "general_tech",
      intent_type: "reference_knowledge",
      value_score: 7,
      entities: [],
      actionable_takeaways: [trimmed.slice(0, 120)],
      raw_turns: [{ prompt: trimmed, response: "", timestamp: nowIso }],
      embedding: new Array(768).fill(0),
    },
    { onConflict: "thread_hash" },
  );
  if (error) {
    console.error("knowledge_cards background upsert failed", error.message);
  }
}

const bot = createPersonalOsBot({
  token: telegramBotToken,
  allowedUserId,
  handlers: {
    replyFn: (chatId, text) => sendTelegramReply(telegramBotToken, chatId, text),
    onRemember: ({ text }) => {
      if (text.trim().length < 40) {
        return "Skipped: note is under 40 characters (Gate 1 minimum).";
      }
      runInBackground(persistQuickCard(text, "telegram:remember"), "telegram_remember_ingest");
      return "Queued note for background indexing into knowledge_cards.";
    },
    onSearch: async ({ query }) => {
      if (!supabase) return "Database client is not configured.";
      const { data, error } = await supabase.rpc("match_knowledge_hybrid", {
        query_text: query.slice(0, 500),
        query_embedding: null,
        match_count: 5,
      });
      if (error) return `Search failed: ${error.message}`;
      const rows = (data ?? []) as Array<{ title?: string; domain?: string; rrf_score?: number }>;
      if (!rows.length) return "No matching records found.";
      return rows
        .map((r, idx) => `${idx + 1}. [${r.domain ?? "general"}] ${r.title ?? "Untitled"}`)
        .join("\n");
    },
    onRadar: () => {
      return "Macro radar runs on schedule via systemd (pos-auto-radar). Run `python3 -m src.intel_radar --briefing` locally for live feeds.";
    },
    onStatus: async () => {
      if (!supabase) return "Status unavailable: database client is not configured.";
      const { data, error } = await supabase
        .from("executive_state")
        .select("state_key,version,updated_at")
        .in("state_key", ["current_priorities", "pillar_metrics"]);
      if (error) return `Status lookup failed: ${error.message}`;
      const summary = ((data ?? []) as Array<{ state_key: string; version: number }>)
        .map((r) => `${r.state_key}=v${r.version}`)
        .join(", ");
      return summary ? `State versions: ${summary}` : "No synced state rows found.";
    },
    onNote: ({ text }) => {
      if (text.trim().length >= 40) {
        runInBackground(persistQuickCard(text, "telegram:note"), "telegram_note_ingest");
        return "Captured note in background queue.";
      }
      return "Received. Use /remember <40+ chars> or /help for commands.";
    },
  },
});

const handleUpdate = webhookCallback(bot, "std/http", {
  secretToken: webhookSecret || undefined,
});

Deno.serve(async (req) => {
  if (req.method === "GET") {
    return Response.json({
      ok: true,
      service: "personal-os-telegram",
      framework: "grammY",
      commands: ["/remember", "/search", "/radar", "/status", "/help"],
    });
  }

  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  try {
    return await handleUpdate(req);
  } catch (err) {
    console.error("Webhook handler error", err);
    return Response.json({ ok: false }, { status: 200 });
  }
});
