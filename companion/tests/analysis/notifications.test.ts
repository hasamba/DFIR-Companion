import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  shouldNotify,
  findingEventsFromDiff,
  playbookTaskEvent,
  milestoneEvent,
  mentionEvent,
  parseChannelInput,
  applyChannelPatch,
  redactChannel,
  severityForPriority,
  SEVERITY_RANK,
  type NotificationChannel,
  type NotificationEvent,
} from "../../src/analysis/notifications.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import type { Finding } from "../../src/analysis/stateTypes.js";
import type { FindingsDiff } from "../../src/analysis/findingsDiff.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";

const NOW = "2026-06-12T10:00:00.000Z";

function channel(over: Partial<NotificationChannel> = {}): NotificationChannel {
  return {
    id: "c1",
    type: "slack",
    name: "Slack",
    enabled: true,
    minSeverity: "High",
    events: { critical_finding: true, playbook_update: true, milestone: false, mention: true },
    webhookUrl: "https://hooks.slack.com/services/x",
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

function event(over: Partial<NotificationEvent> = {}): NotificationEvent {
  return { kind: "critical_finding", caseId: "case-1", title: "t", severity: "High", lines: [], at: NOW, ...over };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1", severity: "Critical", title: "Cobalt Strike beacon", description: "C2 on DC01",
    relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: NOW, lastUpdated: NOW, status: "open", ...over,
  };
}

describe("shouldNotify", () => {
  it("requires enabled + the event-kind toggle", () => {
    expect(shouldNotify(channel({ enabled: false }), event())).toBe(false);
    expect(shouldNotify(channel({ events: { critical_finding: false, playbook_update: true, milestone: false, mention: true } }), event())).toBe(false);
    expect(shouldNotify(channel(), event())).toBe(true);
  });

  it("applies the severity threshold to findings/playbook", () => {
    expect(shouldNotify(channel({ minSeverity: "Critical" }), event({ severity: "High" }))).toBe(false);
    expect(shouldNotify(channel({ minSeverity: "Critical" }), event({ severity: "Critical" }))).toBe(true);
    expect(shouldNotify(channel({ minSeverity: "Low" }), event({ severity: "Medium" }))).toBe(true);
  });

  it("milestones bypass the threshold (gated only by the toggle)", () => {
    const ch = channel({ minSeverity: "Critical", events: { critical_finding: true, playbook_update: true, milestone: true, mention: true } });
    expect(shouldNotify(ch, event({ kind: "milestone", severity: "Info" }))).toBe(true);
    const off = channel({ minSeverity: "Info", events: { critical_finding: true, playbook_update: true, milestone: false, mention: true } });
    expect(shouldNotify(off, event({ kind: "milestone", severity: "Info" }))).toBe(false);
  });

  it("mentions bypass the threshold (gated only by the toggle)", () => {
    const ch = channel({ minSeverity: "Critical", events: { critical_finding: true, playbook_update: true, milestone: false, mention: true } });
    expect(shouldNotify(ch, event({ kind: "mention", severity: "Info" }))).toBe(true);
    const off = channel({ minSeverity: "Info", events: { critical_finding: true, playbook_update: true, milestone: false, mention: false } });
    expect(shouldNotify(off, event({ kind: "mention", severity: "Info" }))).toBe(false);
  });
});

describe("findingEventsFromDiff", () => {
  it("emits a critical_finding per added finding at its own severity", () => {
    const diff: FindingsDiff = { added: ["Cobalt Strike beacon"], removed: [], severityChanged: [] };
    const evs = findingEventsFromDiff("case-1", diff, [finding()], NOW);
    expect(evs).toHaveLength(1);
    expect(evs[0].kind).toBe("critical_finding");
    expect(evs[0].severity).toBe("Critical");
    expect(evs[0].title).toBe("New finding: Cobalt Strike beacon");
    expect(evs[0].lines.join(" ")).toContain("C2 on DC01");
  });

  it("falls back to Info severity when the added title has no matching finding", () => {
    const diff: FindingsDiff = { added: ["Mystery"], removed: [], severityChanged: [] };
    const evs = findingEventsFromDiff("case-1", diff, [], NOW);
    expect(evs[0].severity).toBe("Info");
  });

  it("emits only ESCALATIONS, not de-escalations", () => {
    const diff: FindingsDiff = {
      added: [],
      removed: [],
      severityChanged: [
        { title: "Up", from: "Medium", to: "Critical" },
        { title: "Down", from: "Critical", to: "Low" },
      ],
    };
    const evs = findingEventsFromDiff("case-1", diff, [], NOW);
    expect(evs).toHaveLength(1);
    expect(evs[0].title).toBe("Finding escalated: Up");
    expect(evs[0].severity).toBe("Critical");
  });
});

describe("playbookTaskEvent / milestoneEvent", () => {
  const task: PlaybookTask = {
    id: "t1", title: "Isolate DC01", description: "", status: "done", priority: "critical",
    source: "finding", order: 0, createdAt: NOW, updatedAt: NOW,
  };

  it("maps task priority → severity for threshold filtering", () => {
    expect(severityForPriority("critical")).toBe("Critical");
    expect(severityForPriority("low")).toBe("Low");
    const ev = playbookTaskEvent("case-1", task, "completed", NOW);
    expect(ev.kind).toBe("playbook_update");
    expect(ev.severity).toBe("Critical");
    expect(ev.title).toContain("completed");
  });

  it("milestone is Info severity and carries the case", () => {
    const ev = milestoneEvent("case-1", "Investigation opened", ["Investigator: ana"], NOW);
    expect(ev.kind).toBe("milestone");
    expect(ev.severity).toBe("Info");
    expect(ev.lines).toContain("Case: case-1");
  });

  it("mentionEvent is Info severity and names the mentioned investigators", () => {
    const ev = mentionEvent("case-1", "finding", "f1", "Alice", ["bob", "carol"], "cc @bob @carol please check", NOW);
    expect(ev.kind).toBe("mention");
    expect(ev.severity).toBe("Info");
    expect(ev.title).toBe("Alice mentioned @bob, @carol in a comment");
    expect(ev.lines).toContain("On finding f1");
    expect(ev.lines).toContain("Case: case-1");
  });
});

describe("parseChannelInput", () => {
  it("requires an http(s) webhook URL for slack/teams", () => {
    expect(parseChannelInput({ type: "slack", webhookUrl: "not-a-url" }).ok).toBe(false);
    const ok = parseChannelInput({ type: "teams", webhookUrl: "https://outlook.office.com/webhook/x" });
    expect(ok.ok).toBe(true);
    expect(ok.draft?.webhookUrl).toBe("https://outlook.office.com/webhook/x");
    expect(ok.draft?.minSeverity).toBe("High"); // default
  });

  it("treats mattermost + discord as webhook channels with default names", () => {
    expect(parseChannelInput({ type: "mattermost", webhookUrl: "not-a-url" }).ok).toBe(false);
    const mm = parseChannelInput({ type: "mattermost", webhookUrl: "https://mm.example.com/hooks/abc" });
    expect(mm.ok).toBe(true);
    expect(mm.draft?.webhookUrl).toBe("https://mm.example.com/hooks/abc");
    expect(mm.draft?.name).toBe("Mattermost"); // default name

    const dc = parseChannelInput({ type: "discord", webhookUrl: "https://discord.com/api/webhooks/1/xyz" });
    expect(dc.ok).toBe(true);
    expect(dc.draft?.name).toBe("Discord");
  });

  it("preserves a saved mattermost/discord webhook URL when the edit leaves it blank", () => {
    const existing = channel({ type: "discord", webhookUrl: "https://discord.com/api/webhooks/1/saved" });
    const r = parseChannelInput({ type: "discord", webhookUrl: "" }, existing);
    expect(r.ok).toBe(true);
    expect(r.draft?.webhookUrl).toBe("https://discord.com/api/webhooks/1/saved");
  });

  it("requires smtp host/from/to for email and splits a recipient string", () => {
    expect(parseChannelInput({ type: "email", smtp: { host: "mx", port: 587, from: "a@b.c", to: "" } }).ok).toBe(false);
    const ok = parseChannelInput({ type: "email", smtp: { host: "mx", port: "587", from: "a@b.c", to: "x@y.z, p@q.r" } });
    expect(ok.ok).toBe(true);
    expect(ok.draft?.smtp?.to).toEqual(["x@y.z", "p@q.r"]);
    expect(ok.draft?.smtp?.port).toBe(587);
  });

  it("requires botToken + chatId for telegram", () => {
    expect(parseChannelInput({ type: "telegram" }).ok).toBe(false);
    expect(parseChannelInput({ type: "telegram", telegram: { botToken: "tok", chatId: "" } }).ok).toBe(false);
    expect(parseChannelInput({ type: "telegram", telegram: { chatId: "-100" } }).ok).toBe(false); // no token, no existing
    const ok = parseChannelInput({ type: "telegram", telegram: { botToken: "123:TOKEN", chatId: "-1001234567890" } });
    expect(ok.ok).toBe(true);
    expect(ok.draft?.telegram?.chatId).toBe("-1001234567890");
    expect(ok.draft?.name).toBe("Telegram"); // default name
  });

  it("preserves saved telegram token when the update leaves botToken blank", () => {
    const existing = channel({ type: "telegram", webhookUrl: undefined,
      telegram: { botToken: "saved-token", chatId: "-100" } });
    const r = parseChannelInput({ type: "telegram", telegram: { botToken: "", chatId: "-100" } }, existing);
    expect(r.ok).toBe(true);
    expect(r.draft?.telegram?.botToken).toBe("saved-token");
  });

  it("rejects an unknown type", () => {
    expect(parseChannelInput({ type: "sms" }).ok).toBe(false);
  });
});

describe("applyChannelPatch (secret preservation) + redactChannel", () => {
  it("keeps the saved webhook URL when the edit leaves it blank", () => {
    const existing = channel({ webhookUrl: "https://old" });
    const draft = parseChannelInput({ type: "slack", webhookUrl: "https://old" }).draft!; // UI resends; but simulate blank:
    const blankDraft = { ...draft, webhookUrl: "" };
    const next = applyChannelPatch(existing, blankDraft, "2026-06-12T11:00:00.000Z");
    expect(next.webhookUrl).toBe("https://old");
    expect(next.updatedAt).toBe("2026-06-12T11:00:00.000Z");
  });

  it("keeps the saved SMTP password when blank, replaces transport otherwise", () => {
    const existing = channel({
      type: "email", webhookUrl: undefined,
      smtp: { host: "mx", port: 587, secure: false, from: "a@b.c", to: ["x@y.z"], password: "secret" },
    });
    const draft = parseChannelInput({ type: "email", smtp: { host: "mx2", port: 465, secure: true, from: "a@b.c", to: "x@y.z" } }).draft!;
    const next = applyChannelPatch(existing, draft, NOW);
    expect(next.smtp?.host).toBe("mx2");
    expect(next.smtp?.secure).toBe(true);
    expect(next.smtp?.password).toBe("secret"); // preserved
    expect(next.webhookUrl).toBeUndefined();
  });

  it("keeps the saved telegram token when the edit leaves it blank", () => {
    const existing = channel({ type: "telegram", webhookUrl: undefined,
      telegram: { botToken: "saved-token", chatId: "-100" } });
    const draft = parseChannelInput({ type: "telegram", telegram: { botToken: "", chatId: "-100" } }, existing).draft!;
    const next = applyChannelPatch(existing, draft, NOW);
    expect(next.telegram?.botToken).toBe("saved-token");
    expect(next.telegram?.chatId).toBe("-100");
    expect(next.webhookUrl).toBeUndefined();
    expect(next.smtp).toBeUndefined();
  });

  it("redacts webhook URL + SMTP password for the client view", () => {
    const r = redactChannel(channel({ webhookUrl: "https://hooks.slack.com/x" }));
    expect((r as Record<string, unknown>).webhookUrl).toBeUndefined();
    expect(r.hasWebhookUrl).toBe(true);
    const e = redactChannel(channel({ type: "email", webhookUrl: undefined, smtp: { host: "mx", port: 587, secure: false, from: "a", to: ["b"], password: "p" } }));
    expect(e.smtp?.hasPassword).toBe(true);
    expect((e.smtp as Record<string, unknown>).password).toBeUndefined();
  });

  it("redacts telegram bot token for the client view", () => {
    const ch = channel({ type: "telegram", webhookUrl: undefined,
      telegram: { botToken: "secret-token", chatId: "@mychannel" } });
    const r = redactChannel(ch);
    expect((r as Record<string, unknown>).telegram).toBeDefined();
    expect(r.telegram?.hasBotToken).toBe(true);
    expect(r.telegram?.chatId).toBe("@mychannel");
    expect((r.telegram as Record<string, unknown>).botToken).toBeUndefined();
  });
});

describe("SEVERITY_RANK", () => {
  it("orders Critical highest, Info lowest", () => {
    expect(SEVERITY_RANK.Critical).toBeGreaterThan(SEVERITY_RANK.High);
    expect(SEVERITY_RANK.Info).toBeLessThan(SEVERITY_RANK.Low);
  });
});

describe("NotificationConfigStore", () => {
  let store: NotificationConfigStore;
  beforeEach(async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-notify-"));
    store = new NotificationConfigStore(join(dir, "notify", "config.json"));
  });

  it("starts empty (opt-in)", async () => {
    expect(await store.load()).toEqual([]);
  });

  it("adds, updates (secret-preserving), gets and removes channels", async () => {
    const draft = parseChannelInput({ type: "slack", name: "SOC", webhookUrl: "https://hooks/x" }).draft!;
    const added = await store.add(draft, NOW);
    expect(added.id).toBeTruthy();
    expect(added.webhookUrl).toBe("https://hooks/x");

    const blank = parseChannelInput({ type: "slack", name: "SOC renamed", webhookUrl: "https://hooks/x" }).draft!;
    const updated = await store.update(added.id, { ...blank, webhookUrl: "" }, "2026-06-12T12:00:00.000Z");
    expect(updated?.name).toBe("SOC renamed");
    expect(updated?.webhookUrl).toBe("https://hooks/x"); // preserved through the store

    expect((await store.get(added.id))?.name).toBe("SOC renamed");
    expect(await store.update("nope", blank)).toBeNull();
    expect(await store.remove(added.id)).toBe(true);
    expect(await store.load()).toEqual([]);
  });

  it("does not auto-opt a pre-#88 channel into mention notifications", async () => {
    // A config written before @mentions existed has no `mention` key. Its owner never opted in,
    // so upgrading must NOT silently start pushing comment text to their existing destination.
    const path = join(await mkdtemp(join(tmpdir(), "dfir-notify-legacy-")), "config.json");
    const legacy = new NotificationConfigStore(path);
    await writeFile(path, JSON.stringify([{
      id: "legacy-1", type: "slack", name: "SOC", enabled: true, minSeverity: "High",
      events: { critical_finding: true, playbook_update: true, milestone: false },
      webhookUrl: "https://hooks/legacy", createdAt: NOW, updatedAt: NOW,
    }]), "utf8");
    const [ch] = await legacy.load();
    expect(ch.events.mention).toBe(false);
    expect(ch.events.critical_finding).toBe(true); // the settings they DID choose are untouched
    // A channel created now still defaults mentions on — that's a deliberate, visible opt-in.
    expect(parseChannelInput({ type: "slack", webhookUrl: "https://hooks/new" }).draft!.events.mention).toBe(true);
  });

  it("drops malformed channels on read", async () => {
    const draft = parseChannelInput({ type: "teams", webhookUrl: "https://o/x" }).draft!;
    await store.add(draft, NOW);
    // A second add with a valid shape, then ensure load returns 2 well-formed entries.
    await store.add(parseChannelInput({ type: "slack", webhookUrl: "https://s/x" }).draft!, NOW);
    expect(await store.load()).toHaveLength(2);
  });

  it("persists and loads Telegram channels with bot token intact", async () => {
    const draft = parseChannelInput({ type: "telegram", telegram: { botToken: "123:SECRET", chatId: "-1001234567890" } }).draft!;
    const added = await store.add(draft, NOW);
    expect(added.telegram?.botToken).toBe("123:SECRET");
    expect(added.telegram?.chatId).toBe("-1001234567890");

    // Re-load from disk: the telegram field must survive the Zod schema validation pass.
    const [loaded] = await store.load();
    expect(loaded.telegram?.botToken).toBe("123:SECRET");
    expect(loaded.telegram?.chatId).toBe("-1001234567890");
    expect(loaded.type).toBe("telegram");
  });
});
