import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createNotifier, dispatchEvent } from "../../src/integrations/notify/notifyDispatch.js";
import type { SmtpConnect, SmtpReply, SmtpSocketLike } from "../../src/integrations/notify/smtpClient.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import {
  parseChannelInput,
  type NotificationChannel,
  type NotificationEvent,
} from "../../src/analysis/notifications.js";
import { redactSecrets } from "../../src/integrations/notify/secretRedact.js";

// A failed send must never put the channel's own secret into the error text the dashboard shows and
// the server log keeps — even when the remote reply repeats it back.

const NOW = "2026-06-12T10:00:00.000Z";
const TOKEN = "123456:AAQAsecretTOKENvalue99";
const SLACK_URL = "https://hooks.example.test/services/T0FAKE01/B0FAKE02/abcdefFAKEkey0123456789";
const SLACK_KEY = "abcdefFAKEkey0123456789";
const PASSWORD = "Fake-Pass-4242!";

function event(over: Partial<NotificationEvent> = {}): NotificationEvent {
  return {
    kind: "milestone",
    caseId: "case-1",
    title: "Report generated",
    severity: "Critical",
    lines: ["Case: case-1"],
    at: NOW,
    ...over,
  };
}

function channel(over: Partial<NotificationChannel>): NotificationChannel {
  return {
    id: "c1",
    type: "slack",
    name: "SOC",
    enabled: true,
    minSeverity: "Info",
    events: { critical_finding: true, playbook_update: true, milestone: true, mention: true, import: false },
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

// A fake remote that answers 500 and repeats the request path back (as some proxy 404 pages do).
function echoingFetch(prefix = ""): typeof fetch {
  return (async (u: string | URL) => {
    const url = new URL(String(u));
    const body = `${prefix}upstream error for path ${url.pathname} encoded=${encodeURIComponent(url.pathname)} full=${String(u)}`;
    return new Response(body, { status: 500 });
  }) as typeof fetch;
}

function expectNoSecret(text: string | undefined, secrets: string[]): void {
  expect(text).toBeTruthy();
  for (const s of secrets) {
    expect(text).not.toContain(s);
    expect(text).not.toContain(encodeURIComponent(s));
  }
}

describe("notification error text never carries the channel secret", () => {
  it("telegram: a remote that echoes the bot path does not leak the token", async () => {
    const ch = channel({ type: "telegram", telegram: { botToken: TOKEN, chatId: "-100" } });
    const [r] = await dispatchEvent([ch], event(), {
      fetchFn: echoingFetch(),
      telegramApiBase: "http://fake-telegram.test",
    });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("HTTP 500");
    expectNoSecret(r.error, [TOKEN, "AAQAsecretTOKENvalue99"]);
  });

  it("telegram: a token straddling the 200-char cut is not left half-visible", async () => {
    const ch = channel({ type: "telegram", telegram: { botToken: TOKEN, chatId: "-100" } });
    // "upstream error for path /bot" is 28 chars; pad so the token starts just before char 200.
    const pad = "x".repeat(200 - 28 - 10);
    const [r] = await dispatchEvent([ch], event(), {
      fetchFn: echoingFetch(pad),
      telegramApiBase: "http://fake-telegram.test",
    });
    // Unmasked, the cut would leave the first 10 token characters ("123456:AAQ") visible.
    expectNoSecret(r.error, [TOKEN, "123456:AA"]);
  });

  it("slack: a remote that echoes the webhook path does not leak the key", async () => {
    const ch = channel({ type: "slack", webhookUrl: SLACK_URL });
    const [r] = await dispatchEvent([ch], event(), { fetchFn: echoingFetch() });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("HTTP 500");
    expectNoSecret(r.error, [SLACK_URL, SLACK_KEY, "/services/T0FAKE01/B0FAKE02"]);
  });

  it("email: an SMTP reply echoing the password (plain or base64) does not leak it", async () => {
    const b64 = Buffer.from(PASSWORD, "utf8").toString("base64");
    const replies: SmtpReply[] = [
      { code: 220, lines: ["mx ready"] },
      { code: 250, lines: ["mx", "AUTH LOGIN"] },
      { code: 334, lines: ["VXNlcm5hbWU6"] },
      { code: 334, lines: ["UGFzc3dvcmQ6"] },
      { code: 535, lines: [`bad credentials ${b64} (${PASSWORD})`] },
    ];
    let i = 0;
    const sock: SmtpSocketLike = {
      secure: true,
      write() {},
      async readReply() {
        return replies[i++];
      },
      async startTls() {},
      close() {},
    };
    const smtpConnect: SmtpConnect = async () => sock;
    const ch = channel({
      type: "email",
      smtp: {
        host: "mx.example.test",
        port: 465,
        secure: true,
        from: "soc@example.test",
        to: ["ir@example.test"],
        username: "u",
        password: PASSWORD,
      },
    });
    const [r] = await dispatchEvent([ch], event(), { fetchFn: echoingFetch(), smtpConnect });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("535");
    expectNoSecret(r.error, [PASSWORD, b64]);
  });

  it("the server log line and the test-route result carry no token", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-notify-redact-"));
    const store = new NotificationConfigStore(join(dir, "n", "config.json"));
    const parsed = parseChannelInput(
      {
        type: "telegram",
        name: "TG",
        minSeverity: "Info",
        events: { milestone: true },
        telegram: { chatId: "-100" },
      },
      undefined,
      { envTelegramBotToken: TOKEN },
    );
    expect(parsed.error).toBeUndefined();
    const added = await store.add(parsed.draft!, NOW);
    const logs: string[] = [];
    const notifier = createNotifier({
      store,
      fetchFn: echoingFetch(),
      telegramBotToken: () => TOKEN, // the env-borrowed token path
      telegramApiBase: () => "http://fake-telegram.test",
      log: (m) => logs.push(m),
    });
    const dispatched = await notifier.dispatch(event());
    const tested = await notifier.test(added.id, NOW);
    expect(dispatched[0].ok).toBe(false);
    expect(tested[0].ok).toBe(false);
    expectNoSecret(dispatched[0].error, [TOKEN]);
    expectNoSecret(tested[0].error, [TOKEN]);
    expectNoSecret(logs.join("\n"), [TOKEN, "AAQAsecretTOKENvalue99"]);
  });
});

describe("redactSecrets", () => {
  it("replaces plain, URL-encoded and base64 forms, and ignores short or empty secrets", () => {
    const s = "abc:DEF/ghi+jkl";
    const text = `a ${s} b ${encodeURIComponent(s)} c ${Buffer.from(s).toString("base64")} d`;
    const out = redactSecrets(text, [s, "", "ab"]);
    expect(out).not.toContain(s);
    expect(out).not.toContain(encodeURIComponent(s));
    expect(out).not.toContain(Buffer.from(s).toString("base64"));
    expect(out).toContain("[redacted]");
    expect(out.startsWith("a ")).toBe(true);
  });
});
