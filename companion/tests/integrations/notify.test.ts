import { describe, it, expect } from "vitest";
import { formatSlack } from "../../src/integrations/notify/slackFormat.js";
import { formatTeams } from "../../src/integrations/notify/teamsFormat.js";
import { formatMattermost } from "../../src/integrations/notify/mattermostFormat.js";
import { formatDiscord } from "../../src/integrations/notify/discordFormat.js";
import { formatTelegram } from "../../src/integrations/notify/telegramFormat.js";
import { formatEmail, buildRfc822Message } from "../../src/integrations/notify/emailFormat.js";
import { postWebhook } from "../../src/integrations/notify/webhookSender.js";
import {
  sendSmtp,
  dotStuff,
  parseReplies,
  type SmtpConnect,
  type SmtpReply,
  type SmtpSocketLike,
} from "../../src/integrations/notify/smtpClient.js";
import { dispatchEvent, createNotifier } from "../../src/integrations/notify/notifyDispatch.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import { parseChannelInput, type NotificationChannel, type NotificationEvent } from "../../src/analysis/notifications.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const NOW = "2026-06-12T10:00:00.000Z";

function event(over: Partial<NotificationEvent> = {}): NotificationEvent {
  return {
    kind: "critical_finding",
    caseId: "case-1",
    title: "New finding: Cobalt Strike beacon",
    severity: "Critical",
    lines: ["Severity: Critical", "Case: case-1", "C2 on DC01"],
    at: NOW,
    ...over,
  };
}

function channel(over: Partial<NotificationChannel> = {}): NotificationChannel {
  return {
    id: "c1", type: "slack", name: "SOC", enabled: true, minSeverity: "High",
    events: { critical_finding: true, playbook_update: true, milestone: false, mention: true },
    webhookUrl: "https://hooks.slack.com/services/x", createdAt: NOW, updatedAt: NOW, ...over,
  };
}

describe("slack/teams/email/telegram formatters", () => {
  it("Slack payload has a header, a section, and a text fallback", () => {
    const p = formatSlack(event());
    expect(p.text).toContain("Cobalt Strike beacon");
    const blocks = p.blocks as Array<{ type: string }>;
    expect(blocks[0].type).toBe("header");
    expect(blocks.some((b) => b.type === "section")).toBe(true);
  });

  it("Teams MessageCard colours by severity and renders Key: value lines as facts", () => {
    const c = formatTeams(event());
    expect(c["@type"]).toBe("MessageCard");
    expect(c.themeColor).toBe("D00000"); // Critical = red
    const facts = c.sections[0].facts ?? [];
    expect(facts.find((f) => f.name === "Case")?.value).toBe("case-1");
    expect(facts.find((f) => f.name === "Severity")?.value).toBe("Critical");
  });

  it("Telegram payload has HTML parse_mode, severity emoji, and escaped content", () => {
    const p = formatTelegram(event());
    expect(p.parse_mode).toBe("HTML");
    expect(p.text).toContain("🔴");
    expect(p.text).toContain("Cobalt Strike beacon");
    expect(p.text).toContain("C2 on DC01");
    expect(p.text).toContain("<b>");
    expect(p.text).toContain("critical finding");
  });

  it("Telegram formatter escapes HTML entities in content", () => {
    const p = formatTelegram(event({ title: "Finding: <script>alert(1)</script>", lines: ["a & b"] }));
    expect(p.text).not.toContain("<script>");
    expect(p.text).toContain("&lt;script&gt;");
    expect(p.text).toContain("a &amp; b");
  });

  it("Telegram formatter includes a link when url is set", () => {
    const p = formatTelegram(event({ url: "http://127.0.0.1:4773/dashboard" }));
    expect(p.text).toContain("Open case");
    expect(p.text).toContain("http://127.0.0.1:4773/dashboard");
  });

  it("Mattermost payload colours by severity, renders Key: value lines as fields, has a markdown headline", () => {
    const p = formatMattermost(event());
    expect(p.text).toContain("Cobalt Strike beacon");
    expect(p.text).toContain("**"); // bold markdown headline
    const att = p.attachments[0];
    expect(att.color).toBe("#D00000"); // Critical = red
    expect(att.fields.find((f) => f.title === "Case")?.value).toBe("case-1");
    expect(att.fields.find((f) => f.title === "Severity")?.value).toBe("Critical");
    expect(att.text).toContain("C2 on DC01"); // non Key:value line → body
  });

  it("Mattermost adds an Open case markdown link when url is set", () => {
    const p = formatMattermost(event({ url: "http://127.0.0.1:4773/dashboard" }));
    expect(p.attachments[0].text).toContain("[Open case](http://127.0.0.1:4773/dashboard)");
  });

  it("Discord payload uses an integer colour, an embed, fields, and a timestamp", () => {
    const p = formatDiscord(event());
    const embed = p.embeds[0];
    expect(embed.color).toBe(0xd00000); // Critical = red, as an integer
    expect(embed.title).toContain("Cobalt Strike beacon");
    expect(embed.title).toContain("🔴");
    expect(embed.fields.find((f) => f.name === "Case")?.value).toBe("case-1");
    expect(embed.fields.find((f) => f.name === "Severity")?.value).toBe("Critical");
    expect(embed.description).toContain("C2 on DC01"); // non Key:value line → description
    expect(embed.timestamp).toBe(NOW);
    expect(embed.url).toBeUndefined();
  });

  it("Discord embed links its title to the case when url is set", () => {
    const p = formatDiscord(event({ url: "http://127.0.0.1:4773/dashboard" }));
    expect(p.embeds[0].url).toBe("http://127.0.0.1:4773/dashboard");
  });

  it("email content has subject/text/html; the RFC822 message is deterministic multipart base64", () => {
    const content = formatEmail(event());
    expect(content.subject).toBe("[DFIR Critical] New finding: Cobalt Strike beacon");
    expect(content.html).toContain("Cobalt Strike");
    const raw = buildRfc822Message({ from: "a@b.c", to: ["x@y.z"], subject: content.subject, text: content.text, html: content.html, date: NOW });
    expect(raw).toContain("MIME-Version: 1.0");
    expect(raw).toContain("multipart/alternative");
    expect(raw.split("\r\n").length).toBeGreaterThan(5);
    // Deterministic: same inputs → identical bytes.
    const raw2 = buildRfc822Message({ from: "a@b.c", to: ["x@y.z"], subject: content.subject, text: content.text, html: content.html, date: NOW });
    expect(raw2).toBe(raw);
    expect(raw).toContain("Date: Fri, 12 Jun 2026 10:00:00 +0000");
  });
});

describe("postWebhook", () => {
  it("succeeds on 2xx and surfaces the body on failure", async () => {
    const ok = await postWebhook((async () => new Response("ok", { status: 200 })) as typeof fetch, "https://x", { a: 1 });
    expect(ok.ok).toBe(true);
    const bad = await postWebhook((async () => new Response("invalid_payload", { status: 400 })) as typeof fetch, "https://x", {});
    expect(bad.ok).toBe(false);
    expect(bad.error).toContain("invalid_payload");
    const net = await postWebhook((async () => { throw new Error("boom"); }) as typeof fetch, "https://x", {});
    expect(net.ok).toBe(false);
    expect(net.error).toContain("network error");
  });
});

describe("SMTP dialog (sendSmtp) with a scripted fake socket", () => {
  // A fake socket that records written commands and dispenses scripted replies in order.
  function fakeSocket(replies: SmtpReply[], opts: { secure?: boolean } = {}): { sock: SmtpSocketLike; written: string[] } {
    const written: string[] = [];
    let i = 0;
    let secure = opts.secure ?? false;
    const sock: SmtpSocketLike = {
      get secure() { return secure; },
      write(d: string) { written.push(d); },
      async readReply() {
        if (i >= replies.length) throw new Error("no more scripted replies");
        return replies[i++];
      },
      async startTls() { secure = true; },
      close() { /* no-op */ },
    };
    return { sock, written };
  }

  const smtp = { host: "mx.example.com", port: 587, secure: false, from: "soc@corp", to: ["ir@corp"], username: "u", password: "p" };

  it("walks greeting → EHLO → STARTTLS → AUTH → MAIL/RCPT/DATA → QUIT", async () => {
    const replies: SmtpReply[] = [
      { code: 220, lines: ["mx ready"] },
      { code: 250, lines: ["mx", "STARTTLS", "AUTH LOGIN"] }, // EHLO
      { code: 220, lines: ["go ahead"] },                      // STARTTLS
      { code: 250, lines: ["mx", "AUTH LOGIN"] },              // EHLO after TLS
      { code: 334, lines: ["VXNlcm5hbWU6"] },                  // AUTH LOGIN
      { code: 334, lines: ["UGFzc3dvcmQ6"] },                  // username accepted
      { code: 235, lines: ["auth ok"] },                       // password accepted
      { code: 250, lines: ["sender ok"] },                     // MAIL FROM
      { code: 250, lines: ["rcpt ok"] },                       // RCPT TO
      { code: 354, lines: ["start mail input"] },              // DATA
      { code: 250, lines: ["queued"] },                        // body
      { code: 221, lines: ["bye"] },                           // QUIT
    ];
    const { sock, written } = fakeSocket(replies);
    const connect: SmtpConnect = async () => sock;
    await sendSmtp(connect, smtp, "Subject: hi\r\n\r\nbody");
    const joined = written.join("");
    expect(joined).toContain("EHLO ");
    expect(joined).toContain("STARTTLS\r\n");
    expect(joined).toContain("AUTH LOGIN\r\n");
    expect(joined).toContain("MAIL FROM:<soc@corp>\r\n");
    expect(joined).toContain("RCPT TO:<ir@corp>\r\n");
    expect(joined).toContain("DATA\r\n");
    expect(joined).toContain("\r\n.\r\n"); // end-of-data
    expect(joined).toContain("QUIT\r\n");
  });

  it("refuses to send credentials when STARTTLS isn't offered on a plain link", async () => {
    const replies: SmtpReply[] = [
      { code: 220, lines: ["mx ready"] },
      { code: 250, lines: ["mx", "AUTH LOGIN"] }, // no STARTTLS
    ];
    const { sock } = fakeSocket(replies);
    await expect(sendSmtp(async () => sock, smtp, "x")).rejects.toThrow(/plaintext/i);
  });

  it("throws SmtpError on a rejected recipient", async () => {
    const replies: SmtpReply[] = [
      { code: 220, lines: ["ready"] },
      { code: 250, lines: ["mx"] },              // EHLO, no STARTTLS/AUTH
      { code: 250, lines: ["sender ok"] },        // MAIL FROM
      { code: 550, lines: ["no such user"] },     // RCPT TO
    ];
    const { sock } = fakeSocket(replies);
    const noAuth = { ...smtp, username: undefined, password: undefined, secure: true };
    await expect(sendSmtp(async () => sock, noAuth, "x")).rejects.toThrow(/RCPT/);
  });
});

describe("SMTP helpers", () => {
  it("dot-stuffs lines beginning with a dot", () => {
    expect(dotStuff(".leading\r\nnormal\r\n..two")).toBe("..leading\r\nnormal\r\n...two");
  });

  it("parses single + multiline replies and keeps an incomplete tail", () => {
    const a = parseReplies("220 ready\r\n");
    expect(a.replies).toEqual([{ code: 220, lines: ["ready"] }]);
    const b = parseReplies("250-mx\r\n250-STARTTLS\r\n250 AUTH LOGIN\r\n");
    expect(b.replies[0]).toEqual({ code: 250, lines: ["mx", "STARTTLS", "AUTH LOGIN"] });
    const c = parseReplies("250-mx\r\n250 done\r\n354 go");
    expect(c.replies).toHaveLength(1);
    expect(c.rest).toBe("354 go");
  });
});

describe("dispatchEvent + createNotifier", () => {
  it("routes to matching channels only and records per-channel results", async () => {
    const sent: string[] = [];
    const fetchFn = (async (url: string) => { sent.push(String(url)); return new Response("ok", { status: 200 }); }) as typeof fetch;
    const channels = [
      channel({ id: "slack1", type: "slack", webhookUrl: "https://slack" }),
      channel({ id: "teams1", type: "teams", webhookUrl: "https://teams" }),
      channel({ id: "lowsev", type: "slack", minSeverity: "Critical", webhookUrl: "https://x" }),
      channel({ id: "off", enabled: false, webhookUrl: "https://y" }),
    ];
    const results = await dispatchEvent(channels, event({ severity: "High" }), { fetchFn });
    // slack1 + teams1 fire (High >= High); lowsev filtered (needs Critical); off disabled.
    expect(results.map((r) => r.channelId).sort()).toEqual(["slack1", "teams1"]);
    expect(results.every((r) => r.ok)).toBe(true);
    expect(sent).toContain("https://slack");
    expect(sent).toContain("https://teams");
  });

  it("routes mattermost + discord events to their webhook URLs with the right payload shape", async () => {
    const sent: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      sent.push({ url: String(url), body: JSON.parse((init?.body as string) ?? "{}") });
      return new Response(null, { status: 204 }); // Discord replies 204 No Content
    }) as typeof fetch;
    const channels = [
      channel({ id: "mm1", type: "mattermost", webhookUrl: "https://mm.example.com/hooks/abc" }),
      channel({ id: "dc1", type: "discord", webhookUrl: "https://discord.com/api/webhooks/1/xyz" }),
    ];
    const results = await dispatchEvent(channels, event(), { fetchFn });
    expect(results.map((r) => r.channelId).sort()).toEqual(["dc1", "mm1"]);
    expect(results.every((r) => r.ok)).toBe(true);
    const mm = sent.find((s) => s.url.includes("/hooks/"))!;
    expect(Array.isArray(mm.body.attachments)).toBe(true);
    const dc = sent.find((s) => s.url.includes("/api/webhooks/"))!;
    expect(Array.isArray(dc.body.embeds)).toBe(true);
  });

  it("routes telegram events to the Bot API sendMessage endpoint", async () => {
    const sent: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchFn = (async (url: string, init?: RequestInit) => {
      sent.push({ url: String(url), body: JSON.parse((init?.body as string) ?? "{}") });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    const ch = channel({ id: "tg1", type: "telegram", webhookUrl: undefined,
      telegram: { botToken: "123:TOKEN", chatId: "-1001234567890" } });
    const results = await dispatchEvent([ch], event(), { fetchFn });
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(true);
    expect(sent[0].url).toBe("https://api.telegram.org/bot123:TOKEN/sendMessage");
    expect(sent[0].body.chat_id).toBe("-1001234567890");
    expect(sent[0].body.parse_mode).toBe("HTML");
    expect(String(sent[0].body.text)).toContain("Cobalt Strike");
  });

  it("reports telegram channels as failed when no bot token is configured", async () => {
    const fetchFn = (async () => new Response("ok")) as typeof fetch;
    const ch = channel({ id: "tg2", type: "telegram", webhookUrl: undefined,
      telegram: { botToken: "", chatId: "-100" } });
    const [r] = await dispatchEvent([ch], event(), { fetchFn });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("no bot token");
  });

  it("reports email channels as failed when no SMTP transport is available", async () => {
    const fetchFn = (async () => new Response("ok")) as typeof fetch;
    const ch = channel({ id: "mail", type: "email", webhookUrl: undefined, smtp: { host: "mx", port: 587, secure: false, from: "a@b", to: ["c@d"] } });
    const [r] = await dispatchEvent([ch], event(), { fetchFn });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("SMTP transport not available");
  });

  it("createNotifier loads channels from the store and a no-store notifier is a no-op", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-notify-d-"));
    const store = new NotificationConfigStore(join(dir, "n", "config.json"));
    await store.add(parseChannelInput({ type: "slack", webhookUrl: "https://hooks/x", minSeverity: "Info" }).draft!, NOW);

    const calls: string[] = [];
    const fetchFn = (async (u: string) => { calls.push(String(u)); return new Response("ok", { status: 200 }); }) as typeof fetch;
    const notifier = createNotifier({ store, fetchFn });
    const results = await notifier.dispatch(event({ severity: "Critical" }));
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(true);
    expect(calls).toEqual(["https://hooks/x"]);

    const noop = createNotifier({ fetchFn });
    expect(await noop.dispatch(event())).toEqual([]);
  });

  it("test() bypasses enable/threshold filters", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-notify-t-"));
    const store = new NotificationConfigStore(join(dir, "n", "config.json"));
    const added = await store.add(parseChannelInput({ type: "slack", enabled: false, minSeverity: "Critical", webhookUrl: "https://hooks/test" }).draft!, NOW);
    const calls: string[] = [];
    const fetchFn = (async (u: string) => { calls.push(String(u)); return new Response("ok", { status: 200 }); }) as typeof fetch;
    const notifier = createNotifier({ store, fetchFn });
    const results = await notifier.test(added.id, NOW);
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(true);
    expect(calls).toEqual(["https://hooks/test"]);
  });
});
