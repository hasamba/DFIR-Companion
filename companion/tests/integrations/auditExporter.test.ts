import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuditExporter } from "../../src/integrations/audit/auditExporter.js";
import { AuditExportStore } from "../../src/analysis/auditExportStore.js";
import { AuditCursorStore } from "../../src/analysis/auditExportCursor.js";
import { parseDestinationInput } from "../../src/analysis/auditExport.js";
import type { ActivityLogEntry } from "../../src/analysis/activityLog.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-audit-exporter-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const entry = (id: string): ActivityLogEntry => ({
  id,
  timestamp: "2026-09-12T10:00:00.000Z",
  actor: "alice",
  category: "triage",
  action: "mark_false_positive",
  detail: `entry ${id}`,
  outcome: "success",
});

// A fake activity log: a per-case array of entries, read forward exactly like the real store.
function fakeActivity(byCase: Record<string, ActivityLogEntry[]>) {
  return {
    readFrom: async (caseId: string, afterLines: number, limit = 500) => {
      const all = byCase[caseId] ?? [];
      const slice = all.slice(afterLines, afterLines + limit);
      return { entries: slice, lines: afterLines + slice.length };
    },
  };
}

const okResponse = () => new Response(JSON.stringify({ text: "Success", code: 0 }), { status: 200 });

async function setup(opts: { entries?: Record<string, ActivityLogEntry[]>; enabled?: boolean } = {}) {
  const store = new AuditExportStore(join(root, "audit-export", "config.json"));
  const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
  const parsed = parseDestinationInput({
    type: "splunk",
    name: "SOC",
    enabled: opts.enabled ?? true,
    splunk: { url: "https://splunk:8088", token: "t" },
  });
  const destination = await store.add(parsed.draft!);
  const fetchFn = vi.fn(async () => okResponse());
  const exporter = createAuditExporter({
    store,
    cursors,
    activity: fakeActivity(opts.entries ?? {}),
    listCaseIds: async () => Object.keys(opts.entries ?? {}),
    transport: { fetchFn: fetchFn, syslogSend: async () => {}, hostname: "h" },
    now: () => "2026-09-12T12:00:00.000Z",
  });
  return { store, cursors, destination, fetchFn, exporter };
}

describe("createAuditExporter — forwarding", () => {
  it("forwards a case's new entries and remembers how far it got", async () => {
    const { cursors, destination, fetchFn, exporter } = await setup({
      entries: { "case-1": [entry("e1"), entry("e2")] },
    });
    const results = await exporter.exportCase("case-1");
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ ok: true, sent: 2, caseId: "case-1" });
    expect(await cursors.get(destination.id, "case-1")).toBe(2);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("sends nothing, and makes no request, when there is nothing new", async () => {
    const { fetchFn, exporter } = await setup({ entries: { "case-1": [entry("e1")] } });
    await exporter.exportCase("case-1");
    fetchFn.mockClear();
    const results = await exporter.exportCase("case-1");
    expect(results[0]).toMatchObject({ ok: true, sent: 0 });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("forwards only what was appended since the last run", async () => {
    const entries: Record<string, ActivityLogEntry[]> = { "case-1": [entry("e1")] };
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    const parsed = parseDestinationInput({
      type: "splunk",
      splunk: { url: "https://splunk:8088", token: "t" },
    });
    await store.add(parsed.draft!);
    const bodies: string[] = [];
    const fetchFn = vi.fn(async (_url: string, init: { body: string }) => {
      bodies.push(init.body);
      return okResponse();
    });
    const exporter = createAuditExporter({
      store,
      cursors,
      activity: fakeActivity(entries),
      listCaseIds: async () => ["case-1"],
      transport: { fetchFn: fetchFn as never, syslogSend: async () => {}, hostname: "h" },
    });
    await exporter.exportCase("case-1");
    entries["case-1"].push(entry("e2"));
    await exporter.exportCase("case-1");
    expect(bodies).toHaveLength(2);
    expect(bodies[0]).toContain('"id":"e1"');
    expect(bodies[1]).toContain('"id":"e2"');
    expect(bodies[1]).not.toContain('"id":"e1"');
  });

  it("walks a long history in batches rather than loading it whole", async () => {
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    const parsed = parseDestinationInput({
      type: "splunk",
      splunk: { url: "https://splunk:8088", token: "t" },
    });
    const destination = await store.add(parsed.draft!);
    const fetchFn = vi.fn(async () => okResponse());
    const exporter = createAuditExporter({
      store,
      cursors,
      activity: fakeActivity({ "case-1": Array.from({ length: 25 }, (_, i) => entry(`e${i}`)) }),
      listCaseIds: async () => ["case-1"],
      transport: { fetchFn: fetchFn, syslogSend: async () => {}, hostname: "h" },
      batchSize: 10,
    });
    const results = await exporter.exportCase("case-1");
    expect(fetchFn).toHaveBeenCalledTimes(3);
    expect(results[0].sent).toBe(25);
    expect(await cursors.get(destination.id, "case-1")).toBe(25);
  });
});

describe("createAuditExporter — failure", () => {
  it("does not advance the position when the send fails, so nothing is lost", async () => {
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    const parsed = parseDestinationInput({
      type: "splunk",
      splunk: { url: "https://splunk:8088", token: "t" },
    });
    const destination = await store.add(parsed.draft!);
    let failing = true;
    const fetchFn = vi.fn(async () =>
      failing ? new Response("collector down", { status: 503 }) : okResponse(),
    );
    const exporter = createAuditExporter({
      store,
      cursors,
      activity: fakeActivity({ "case-1": [entry("e1"), entry("e2")] }),
      listCaseIds: async () => ["case-1"],
      transport: { fetchFn: fetchFn, syslogSend: async () => {}, hostname: "h" },
    });
    const failed = await exporter.exportCase("case-1");
    expect(failed[0].ok).toBe(false);
    expect(failed[0].error).toContain("503");
    expect(await cursors.get(destination.id, "case-1")).toBe(0);

    // The same two entries go on the next attempt — the feed resumes rather than skipping.
    failing = false;
    const retried = await exporter.exportCase("case-1");
    expect(retried[0]).toMatchObject({ ok: true, sent: 2 });
    expect(await cursors.get(destination.id, "case-1")).toBe(2);
  });

  it("stops that destination at the first failed batch instead of sending later ones out of order", async () => {
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    const parsed = parseDestinationInput({
      type: "splunk",
      splunk: { url: "https://splunk:8088", token: "t" },
    });
    const destination = await store.add(parsed.draft!);
    let call = 0;
    const fetchFn = vi.fn(async () => {
      call += 1;
      return call === 2 ? new Response("nope", { status: 500 }) : okResponse();
    });
    const exporter = createAuditExporter({
      store,
      cursors,
      activity: fakeActivity({ "case-1": Array.from({ length: 25 }, (_, i) => entry(`e${i}`)) }),
      listCaseIds: async () => ["case-1"],
      transport: { fetchFn: fetchFn, syslogSend: async () => {}, hostname: "h" },
      batchSize: 10,
    });
    const results = await exporter.exportCase("case-1");
    expect(results[0].ok).toBe(false);
    expect(results[0].sent).toBe(10);
    // The first batch is durably recorded; the rest is retried next time.
    expect(await cursors.get(destination.id, "case-1")).toBe(10);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("keeps one broken destination from blocking a healthy one", async () => {
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    const bad = await store.add(
      parseDestinationInput({
        type: "splunk",
        name: "broken",
        splunk: { url: "https://broken:8088", token: "t" },
      }).draft!,
    );
    const good = await store.add(
      parseDestinationInput({
        type: "splunk",
        name: "healthy",
        splunk: { url: "https://healthy:8088", token: "t" },
      }).draft!,
    );
    const fetchFn = vi.fn(async (url: string) =>
      url.startsWith("https://broken") ? new Response("down", { status: 502 }) : okResponse(),
    );
    const exporter = createAuditExporter({
      store,
      cursors,
      activity: fakeActivity({ "case-1": [entry("e1")] }),
      listCaseIds: async () => ["case-1"],
      transport: { fetchFn: fetchFn as never, syslogSend: async () => {}, hostname: "h" },
    });
    const results = await exporter.exportCase("case-1");
    expect(results).toHaveLength(2);
    expect(results.find((r) => r.destinationId === bad.id)?.ok).toBe(false);
    expect(results.find((r) => r.destinationId === good.id)?.ok).toBe(true);
    expect(await cursors.get(bad.id, "case-1")).toBe(0);
    expect(await cursors.get(good.id, "case-1")).toBe(1);
  });
});

describe("createAuditExporter — enablement and concurrency", () => {
  it("sends nothing while the destination is disabled", async () => {
    const { fetchFn, exporter } = await setup({
      entries: { "case-1": [entry("e1")] },
      enabled: false,
    });
    const results = await exporter.exportCase("case-1");
    expect(results).toEqual([]);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("two overlapping runs of the same case never send an entry twice", async () => {
    const { fetchFn, exporter } = await setup({ entries: { "case-1": [entry("e1"), entry("e2")] } });
    await Promise.all([exporter.exportCase("case-1"), exporter.exportCase("case-1")]);
    // The second run waits for the first, then finds nothing new.
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});

describe("createAuditExporter — backfill, test and status", () => {
  it("backfill re-sends a case's whole history from the start", async () => {
    const { destination, fetchFn, exporter, cursors } = await setup({
      entries: { "case-1": [entry("e1"), entry("e2")] },
    });
    await exporter.exportCase("case-1");
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const results = await exporter.backfill(destination.id);
    expect(results.find((r) => r.caseId === "case-1")).toMatchObject({ ok: true, sent: 2 });
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(await cursors.get(destination.id, "case-1")).toBe(2);
  });

  it("backfill reports an unknown destination rather than silently doing nothing", async () => {
    const { exporter } = await setup();
    await expect(exporter.backfill("no-such-id")).rejects.toThrow(/not found/i);
  });

  it("test sends one clearly-marked record and leaves every position untouched", async () => {
    const { destination, fetchFn, exporter, cursors } = await setup({
      entries: { "case-1": [entry("e1")] },
    });
    const bodies: string[] = [];
    fetchFn.mockImplementation((async (_url: string, init: { body: string }) => {
      bodies.push(init.body);
      return okResponse();
    }) as never);
    const results = await exporter.test(destination.id, "2026-09-12T12:00:00.000Z");
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(true);
    expect(bodies[0]).toContain("audit_export_test");
    expect(await cursors.get(destination.id, "case-1")).toBe(0);
  });

  it("status reports the last attempt, the last success and the last error per destination", async () => {
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    const destination = await store.add(
      parseDestinationInput({
        type: "splunk",
        splunk: { url: "https://splunk:8088", token: "t" },
      }).draft!,
    );
    let failing = true;
    const fetchFn = vi.fn(async () => (failing ? new Response("x", { status: 500 }) : okResponse()));
    let clock = "2026-09-12T12:00:00.000Z";
    const exporter = createAuditExporter({
      store,
      cursors,
      activity: fakeActivity({ "case-1": [entry("e1")] }),
      listCaseIds: async () => ["case-1"],
      transport: { fetchFn: fetchFn, syslogSend: async () => {}, hostname: "h" },
      now: () => clock,
    });

    await exporter.exportCase("case-1");
    let s = exporter.status().find((x) => x.destinationId === destination.id)!;
    expect(s.lastAttemptAt).toBe("2026-09-12T12:00:00.000Z");
    expect(s.lastError).toContain("500");
    expect(s.lastSuccessAt).toBeUndefined();
    expect(s.sentTotal).toBe(0);

    failing = false;
    clock = "2026-09-12T12:05:00.000Z";
    await exporter.exportCase("case-1");
    s = exporter.status().find((x) => x.destinationId === destination.id)!;
    expect(s.lastSuccessAt).toBe("2026-09-12T12:05:00.000Z");
    expect(s.sentTotal).toBe(1);
    // A success clears the stale error so the dashboard does not show a fixed fault forever.
    expect(s.lastError).toBeUndefined();
  });
});
