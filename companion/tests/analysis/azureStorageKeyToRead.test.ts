import { describe, it, expect } from "vitest";
import {
  correlateStorageKeyToRead,
  STORAGE_KEY_JOINS_MAX,
} from "../../src/analysis/azureStorageKeyToRead.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const at = (hOffset: number) =>
  new Date(Date.parse("2024-05-14T12:00:00Z") + hOffset * 3_600_000).toISOString();

function listing(over: { time?: number; account?: string; outcome?: string } = {}): ForensicEvent {
  return {
    id: `l${++seq}`,
    timestamp: at(over.time ?? 0),
    description: "Azure storageAccounts/listKeys/action",
    severity: "High",
    mitreTechniques: ["T1552.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      event: { category: "cloud", type: "storage-key-list", outcome: over.outcome ?? "success" },
      cloud: {
        resource: `/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/${over.account ?? "acct1"}`,
      },
    },
  } as unknown as ForensicEvent;
}

function read(
  over: { time?: number; account?: string; mechanism?: string; outcome?: string; count?: number } = {},
): ForensicEvent {
  return {
    id: `r${++seq}`,
    timestamp: at(over.time ?? 0),
    description: "Azure Storage GetBlob (StorageRead)",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(over.count !== undefined ? { count: over.count } : {}),
    canonical: {
      event: { category: "cloud", type: "storage-object-op", outcome: over.outcome ?? "success" },
      cloud: { resource: `${over.account ?? "acct1"}/cont1/obj1` },
      authentication: { mechanism: over.mechanism ?? "account-key" },
    },
  } as unknown as ForensicEvent;
}

describe("correlateStorageKeyToRead", () => {
  it("joins a listing to a later account-key read on the same account", () => {
    const events = [listing({ time: 0 }), read({ time: 2 })];
    const out = correlateStorageKeyToRead(events);
    const join = out.find((e) => e.description.includes("Storage key listed"));
    expect(join).toBeDefined();
    expect(join!.description).toContain("acct1");
    expect(join!.description).toContain("temporal coexistence only");
    expect(join!.description).toContain("never proof the same actor used the listed key");
  });

  // Codex review (P2): a matched read row can itself be a cloudBulkRead-aggregated group (count
  // > 1). The join must report the real read count, not the number of distinct rows.
  it("sums each matched read's own count, not just the number of matched rows", () => {
    const events = [listing({ time: 0 }), read({ time: 2, count: 100 })];
    const out = correlateStorageKeyToRead(events);
    const join = out.find((e) => e.description.includes("Storage key listed"))!;
    expect(join.description).toContain("100 account-key-authenticated");
    expect(join.count).toBe(100);
  });

  it("does not fire when there is no matching read", () => {
    const events = [listing({ time: 0 })];
    const out = correlateStorageKeyToRead(events);
    expect(out.some((e) => e.description.includes("Storage key listed"))).toBe(false);
    expect(out).toEqual(events); // untouched — the existing High listKeys row stands alone
  });

  it("does not join a read to a DIFFERENT account's listing", () => {
    const events = [listing({ time: 0, account: "acct1" }), read({ time: 2, account: "acct2" })];
    const out = correlateStorageKeyToRead(events);
    expect(out.some((e) => e.description.includes("Storage key listed"))).toBe(false);
  });

  it("does not join a failed listing attempt", () => {
    const events = [listing({ time: 0, outcome: "failure" }), read({ time: 2 })];
    const out = correlateStorageKeyToRead(events);
    expect(out.some((e) => e.description.includes("Storage key listed"))).toBe(false);
  });

  it("does not join a non-account-key read (OAuth reads say nothing about a listed key)", () => {
    const events = [listing({ time: 0 }), read({ time: 2, mechanism: "oauth" })];
    const out = correlateStorageKeyToRead(events);
    expect(out.some((e) => e.description.includes("Storage key listed"))).toBe(false);
  });

  it("does not join a read outside the default 24h window", () => {
    const events = [listing({ time: 0 }), read({ time: 30 })];
    const out = correlateStorageKeyToRead(events);
    expect(out.some((e) => e.description.includes("Storage key listed"))).toBe(false);
  });

  it("a read joins only the NEAREST preceding listing when two overlap", () => {
    const events = [listing({ time: 0 }), listing({ time: 5 }), read({ time: 6 })];
    const out = correlateStorageKeyToRead(events);
    const joins = out.filter((e) => e.description.includes("Storage key listed"));
    expect(joins).toHaveLength(1);
    expect(joins[0].timestamp).toBe(at(5)); // the nearer listing, not the one at t=0
  });

  it("caps total joins and discloses the overflow", () => {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < STORAGE_KEY_JOINS_MAX + 3; i++) {
      events.push(listing({ time: i * 48, account: `acct-${i}` }));
      events.push(read({ time: i * 48 + 1, account: `acct-${i}` }));
    }
    const out = correlateStorageKeyToRead(events);
    const joins = out.filter((e) => e.description.includes("Storage key listed"));
    expect(joins.length).toBe(STORAGE_KEY_JOINS_MAX);
    expect(out.some((e) => e.description.includes("further storage key"))).toBe(true);
  });
});
