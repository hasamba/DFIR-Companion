// #1128/#1132: the collection-generation-diff panel — persistence + mobile halves, independent
// loading/ready/unconfigured/error state, and the minimal mobile recording flow.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderCollectionGenerationDiff(): string;
  loadCollectionGenerationDiff(caseId: string): Promise<void>;
}

type Responder = (url: string) => { ok: boolean; status?: number; json?: () => Promise<unknown> };

function panelWith(respond: Responder) {
  return loadDashboardModule<Api>("dashboard-collection-generation-diff.js", ["dashboard-escape.js"], {
    fetch: async (url: string) => {
      const r = respond(url);
      return { ok: r.ok, status: r.status ?? (r.ok ? 200 : 500), json: r.json ?? (async () => ({})) };
    },
    document: { getElementById: () => null }, // paint() no-ops without the panel element
  });
}

async function panel(persistenceBody: unknown, mobileBody: unknown): Promise<Api> {
  const p = panelWith((url) => ({
    ok: true,
    json: async () => (url.includes("mobile-backup-generations") ? mobileBody : persistenceBody),
  }));
  await p.loadCollectionGenerationDiff("c1");
  return p;
}

const PERSISTENCE_PAIR = {
  resolvedHost: "ws-01",
  eligibleCount: 2,
  excluded: [],
  ambiguousOrder: [],
  truncatedPairs: false,
  pairs: [
    {
      earlier: { order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } },
      later: { order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" } },
      interveningExcludedCount: 0,
      truncated: false,
      inventoryTruncated: false,
      changes: [
        {
          direction: "changed",
          key: JSON.stringify(["Run Key", "HKCU\\Run\\A"]),
          earlierValue: "old.exe",
          laterValue: "new.exe",
        },
      ],
    },
  ],
};

const MOBILE_PAIR = {
  resolvedDevice: { kind: "serial-number", value: "F2LN12ABCDEF" },
  eligibleCount: 2,
  excluded: [],
  ambiguousOrder: [],
  truncatedPairs: false,
  pairs: [
    {
      earlier: { order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } },
      later: { order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" } },
      interveningExcludedCount: 0,
      truncated: false,
      inventoryTruncated: false,
      changes: [
        {
          direction: "changed",
          key: "com.example.app",
          earlierValue: { itemName: "Example", version: "1.0" },
          laterValue: { itemName: "Example", version: "2.0" },
        },
      ],
    },
  ],
};

describe("collection generation diff panel — persistence + mobile", () => {
  it("renders both a Persistence and a Mobile backups sub-heading", async () => {
    const html = (await panel({ cohorts: [] }, { cohorts: [] })).renderCollectionGenerationDiff();
    expect(html).toContain("Persistence");
    expect(html).toContain("Mobile backups");
  });

  it("renders a persistence pair's technique/path/value change", async () => {
    const html = (
      await panel({ cohorts: [PERSISTENCE_PAIR] }, { cohorts: [] })
    ).renderCollectionGenerationDiff();
    expect(html).toContain("ws-01");
    expect(html).toContain("Run Key");
    expect(html).toContain("HKCU\\Run\\A");
    expect(html).toContain("old.exe");
    expect(html).toContain("new.exe");
  });

  it("renders a mobile pair's bundle id/item/version change, never as [object Object]", async () => {
    const html = (await panel({ cohorts: [] }, { cohorts: [MOBILE_PAIR] })).renderCollectionGenerationDiff();
    expect(html).toContain("com.example.app");
    expect(html).toContain("Example");
    expect(html).toContain("1.0");
    expect(html).toContain("2.0");
    expect(html).not.toContain("[object Object]");
  });

  it("a mobile fetch failure never hides a valid persistence result", async () => {
    const p = panelWith((url) =>
      url.includes("mobile-backup-generations")
        ? { ok: false, status: 500 }
        : { ok: true, json: async () => ({ cohorts: [PERSISTENCE_PAIR] }) },
    );
    await p.loadCollectionGenerationDiff("c1");
    const html = p.renderCollectionGenerationDiff();
    expect(html).toContain("ws-01"); // persistence result still rendered
    expect(html).toContain("Could not load the mobile backup comparison");
  });

  it("a persistence fetch failure never hides a valid mobile result", async () => {
    const p = panelWith((url) =>
      url.includes("mobile-backup-generations")
        ? { ok: true, json: async () => ({ cohorts: [MOBILE_PAIR] }) }
        : { ok: false, status: 500 },
    );
    await p.loadCollectionGenerationDiff("c1");
    const html = p.renderCollectionGenerationDiff();
    expect(html).toContain("com.example.app"); // mobile result still rendered
    expect(html).toContain("Could not load the persistence comparison");
  });

  it("501 on either route renders an honest 'not configured' state, not an error", async () => {
    const p = panelWith(() => ({ ok: false, status: 501 }));
    await p.loadCollectionGenerationDiff("c1");
    const html = p.renderCollectionGenerationDiff();
    expect(html).not.toContain("Could not load");
    expect(html).toContain("No host has two or more");
    expect(html).toContain("No device has two or more");
  });

  it("shows the record-pairing button in the mobile section", async () => {
    const html = (await panel({ cohorts: [] }, { cohorts: [] })).renderCollectionGenerationDiff();
    expect(html).toContain("Record a backup pairing");
  });

  it("never uses added/removed/deleted labels for either domain", async () => {
    const html = (
      await panel({ cohorts: [PERSISTENCE_PAIR] }, { cohorts: [MOBILE_PAIR] })
    ).renderCollectionGenerationDiff();
    expect(html).not.toMatch(/\badded\b|\bremoved\b|\bdeleted\b/i);
  });
});
