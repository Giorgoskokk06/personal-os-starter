import { assertEquals, assertStringIncludes } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { webhookCallback } from "npm:grammy";
import {
  createPersonalOsBot,
  findHardSecret,
  parseTelegramCommand,
  runInBackground,
} from "../_shared/webhook_core.ts";

Deno.test("grammY webhook verifies secretToken, user allowlist, commands, and pre-cached botInfo", async () => {
  const replies: Array<{ chatId: number; text: string }> = [];
  let remembered = "";

  const bot = createPersonalOsBot({
    token: "000:dummy_token_for_ci",
    allowedUserId: "999",
    handlers: {
      replyFn: async (chatId, text) => {
        replies.push({ chatId, text });
      },
      onRemember: ({ text }) => {
        remembered = text;
        return `Stored: ${text.slice(0, 20)}`;
      },
      onSearch: ({ query }) => `Results for ${query}`,
      onRadar: () => "Radar nominal",
      onStatus: () => "Workload 12h/15h",
    },
  });

  const handleUpdate = webhookCallback(bot, "std/http", {
    secretToken: "test_secret_token",
  });

  // 1. Reject invalid webhook secret token
  const badReq = new Request("https://example.com/telegram", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-telegram-bot-api-secret-token": "wrong_secret",
    },
    body: JSON.stringify({ update_id: 1, message: { text: "/status" } }),
  });
  const badRes = await handleUpdate(badReq);
  assertEquals(badRes.status, 401);

  // 2. Ignore unauthorized Telegram user ID
  const unauthReq = new Request("https://example.com/telegram", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-telegram-bot-api-secret-token": "test_secret_token",
    },
    body: JSON.stringify({
      update_id: 2,
      message: {
        message_id: 100,
        date: Math.floor(Date.now() / 1000),
        chat: { id: 888, type: "private" },
        from: { id: 888, is_bot: false, first_name: "Other" },
        text: "/status",
      },
    }),
  });
  const unauthRes = await handleUpdate(unauthReq);
  assertEquals(unauthRes.status, 200);
  assertEquals(replies.length, 0);

  // 3. Accept authorized /remember command without network getMe call
  const goodReq = new Request("https://example.com/telegram", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-telegram-bot-api-secret-token": "test_secret_token",
    },
    body: JSON.stringify({
      update_id: 3,
      message: {
        message_id: 101,
        date: Math.floor(Date.now() / 1000),
        chat: { id: 999, type: "private" },
        from: { id: 999, is_bot: false, first_name: "User" },
        text: "/remember Always keep pgvector halfvec index memory under container limits.",
      },
    }),
  });
  const goodRes = await handleUpdate(goodReq);
  assertEquals(goodRes.status, 200);
  assertEquals(
    remembered,
    "Always keep pgvector halfvec index memory under container limits.",
  );
  assertEquals(replies.length, 1);
  assertStringIncludes(replies[0].text, "Stored:");
});

Deno.test("command parser, secret scanner, and EdgeRuntime.waitUntil wrapper", async () => {
  assertEquals(parseTelegramCommand("/search pgvector index"), {
    command: "search",
    argument: "pgvector index",
  });
  assertEquals(parseTelegramCommand("/radar@my_bot"), {
    command: "radar",
    argument: "",
  });

  const syntheticToken = "ghp_" + "0".repeat(24);
  assertEquals(findHardSecret(syntheticToken), "github_token");
  assertEquals(findHardSecret("normal architecture note"), null);

  let waitUntilCalls = 0;
  (globalThis as unknown as { EdgeRuntime?: { waitUntil: (p: Promise<unknown>) => void } }).EdgeRuntime = {
    waitUntil: (_p: Promise<unknown>) => {
      waitUntilCalls++;
    },
  };
  const mode = runInBackground(Promise.resolve("ok"), "unit_test");
  assertEquals(mode, "edge_runtime");
  assertEquals(waitUntilCalls, 1);
  delete (globalThis as unknown as { EdgeRuntime?: unknown }).EdgeRuntime;
});
