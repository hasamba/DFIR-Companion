import { describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addCounts,
  countsFromSettled,
  importEvent,
  notifyImport,
  type ImportOutcome,
} from "../../src/analysis/importNotification.js";
import {
  parseChannelInput,
  shouldNotify,
  type NotificationChannel,
} from "../../src/analysis/notifications.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";

// #2978 — an "import finished" notification on the analyst's channels.

const AT = "2026-11-27T10:00:00.000Z";
const ev = (severity: string) => ({
  timestamp: AT,
  description: `row ${severity} ${Math.random()}`,
  severity,
});

describe("countsFromSettled", () => {
  it("counts every added row and the High/Critical ones, from the full diff", () => {
    const added = [ev("Critical"), ev("High"), ev("Medium"), ev("Info"), ev("High")];
    expect(countsFromSettled({ timelineDiff: { added } as never, superTimelineAddedCount: 40 })).toEqual({
      added: 5,
      highCritical: 3,
      superAdded: 40,
    });
  });

  it("leaves the super-timeline count out when the settle did not report one", () => {
    expect(countsFromSettled({ timelineDiff: { added: [] } })).toEqual({ added: 0, highCritical: 0 });
  });
});

describe("addCounts", () => {
  it("sums known counts and keeps unknown only when both sides are unknown", () => {
    expect(addCounts(undefined, undefined)).toBeUndefined();
    expect(addCounts({ added: 2, highCritical: 1 }, undefined)).toEqual({ added: 2, highCritical: 1 });
    expect(addCounts({ added: 2, highCritical: 1, superAdded: 5 }, { added: 3, highCritical: 0 })).toEqual({
      added: 5,
      highCritical: 1,
      superAdded: 5,
    });
  });
});

describe("importEvent", () => {
  const base: ImportOutcome = { caseId: "CASE-EXAMPLE", source: "example-triage.zip", ok: true };

  it("summarises a finished import with its counts", () => {
    const e = importEvent(
      { ...base, files: 3, counts: { added: 12480, highCritical: 7, superAdded: 90000 } },
      AT,
    );
    expect(e.kind).toBe("import");
    expect(e.title).toBe("Import finished: example-triage.zip");
    expect(e.lines).toEqual([
      "Files: 3",
      "Forensic timeline: +12,480 events (7 High/Critical)",
      "Super-timeline: +90,000 rows",
      "Case: CASE-EXAMPLE",
    ]);
    expect(e.severity).toBe("High"); // High/Critical arrived
  });

  it("is Info when nothing High/Critical arrived and nothing failed", () => {
    expect(importEvent({ ...base, counts: { added: 1, highCritical: 0 } }, AT).severity).toBe("Info");
  });

  // Unknown is not zero: a path that cannot count must not claim nothing arrived.
  it("says the counts are not available instead of reporting zero", () => {
    const e = importEvent(base, AT);
    expect(e.lines).toContain("Event counts are not available for this import");
    expect(e.lines.join(" ")).not.toContain("+0");
  });

  it("names a partial import's failed items, capped at ten", () => {
    const failed = Array.from({ length: 12 }, (_, i) => ({ name: `artifact-${i}`, reason: "read failed" }));
    const e = importEvent({ ...base, counts: { added: 1, highCritical: 0 }, failed }, AT);
    expect(e.title).toBe("Import finished, 12 failed: example-triage.zip");
    expect(e.lines).toContain("Failed: artifact-0 — read failed");
    expect(e.lines).not.toContain("Failed: artifact-10 — read failed");
    expect(e.lines).toContain("…and 2 more failed");
    expect(e.severity).toBe("High");
  });

  it("reports a failed import with its reason and whether it can be retried", () => {
    const e = importEvent({ ...base, ok: false, reason: "parse error", retryable: true }, AT);
    expect(e.title).toBe("Import failed: example-triage.zip");
    expect(e.lines).toEqual([
      "Reason: parse error",
      "It can be retried from the Jobs list.",
      "Case: CASE-EXAMPLE",
    ]);
    expect(e.severity).toBe("High");
  });
});

describe("notifyImport", () => {
  it("dispatches the event and never throws when the dispatcher does", () => {
    const sent: string[] = [];
    notifyImport((e) => sent.push(e.title), { caseId: "c", source: "s", ok: true });
    expect(sent).toEqual(["Import finished: s"]);
    const logs: string[] = [];
    expect(() =>
      notifyImport(
        () => {
          throw new Error("boom");
        },
        { caseId: "c", source: "s", ok: true },
        (l) => logs.push(l),
      ),
    ).not.toThrow();
    expect(logs[0]).toContain("boom");
  });

  it("is a no-op with no dispatcher wired", () => {
    expect(() => notifyImport(undefined, { caseId: "c", source: "s", ok: true })).not.toThrow();
  });
});

describe("the imports toggle on a channel", () => {
  const channel = (events: Partial<NotificationChannel["events"]>): NotificationChannel => ({
    id: "x",
    type: "slack",
    name: "x",
    enabled: true,
    minSeverity: "Critical",
    events: {
      critical_finding: true,
      playbook_update: true,
      milestone: true,
      mention: true,
      import: true,
      ...events,
    },
    createdAt: AT,
    updatedAt: AT,
  });
  const event = importEvent(
    { caseId: "c", source: "s", ok: true, counts: { added: 1, highCritical: 0 } },
    AT,
  );

  it("bypasses the severity threshold, like milestones", () => {
    expect(shouldNotify(channel({}), event)).toBe(true);
  });

  it("is gated by its own toggle", () => {
    expect(shouldNotify(channel({ import: false }), event)).toBe(false);
  });

  it("is on for a new channel and can be switched off", () => {
    const on = parseChannelInput({ type: "slack", webhookUrl: "https://hooks.slack.com/services/T/B/x" });
    expect(on.draft?.events.import).toBe(true);
    const off = parseChannelInput({
      type: "slack",
      webhookUrl: "https://hooks.slack.com/services/T/B/x",
      events: { import: false },
    });
    expect(off.draft?.events.import).toBe(false);
  });

  it("is on for a channel saved before the toggle existed, and an explicit off survives a load", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-import-notify-"));
    await mkdir(join(root, "n"), { recursive: true });
    const file = join(root, "n", "config.json");
    const legacy = { critical_finding: true, playbook_update: true, milestone: false, mention: false };
    await writeFile(
      file,
      JSON.stringify([
        {
          id: "a",
          type: "slack",
          name: "old",
          enabled: true,
          minSeverity: "High",
          events: legacy,
          webhookUrl: "https://hooks.slack.com/services/T/B/a",
        },
        {
          id: "b",
          type: "slack",
          name: "off",
          enabled: true,
          minSeverity: "High",
          events: { ...legacy, import: false },
          webhookUrl: "https://hooks.slack.com/services/T/B/b",
        },
      ]),
    );
    const loaded = await new NotificationConfigStore(file).load();
    expect(loaded.find((c) => c.id === "a")?.events.import).toBe(true);
    expect(loaded.find((c) => c.id === "b")?.events.import).toBe(false);
  });
});
