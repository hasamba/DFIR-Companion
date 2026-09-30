import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { loadHostEvidence, MAX_CACHED_HOST_EVIDENCE_ENTRIES } from "../../src/analysis/hostScopeLoad.js";
import { aggregateHostEvidence, type HostEvidenceMap } from "../../src/analysis/hostScopeAggregate.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1881: the scope ledger's per-host evidence is scanned once per content version, and alias
// changes are applied without a rescan.

function ev(id: string, asset: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: `2026-06-0${(Number(id.slice(1)) % 9) + 1}T00:00:00Z`,
    description: `event ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: [`src-${id}`],
    ...extra,
  };
}

function plain(map: HostEvidenceMap): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [host, e] of [...map].sort(([a], [b]) => a.localeCompare(b))) {
    out[host] = {
      ...e,
      sources: [...e.sources].sort(),
      findingIds: [...e.findingIds].sort(),
      referencedBy: [...e.referencedBy].sort(),
    };
  }
  return out;
}

describe("loadHostEvidence (#1881)", () => {
  let store: SuperTimelineStore;
  let scans: number;
  let source: SuperTimelineStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-host-evidence-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
    scans = 0;
    // Count full scans without changing what the store returns.
    source = Object.create(store) as SuperTimelineStore;
    source.eventBatches = (caseId: string) => {
      scans += 1;
      return store.eventBatches(caseId);
    };
    await store.append("c1", [
      ev("e1", "WS-1", { severity: "High" }),
      ev("e2", "ws-1.example.com"),
      ev("e3", "WS-2", { canonical: { target: { kind: "host", name: "WS-3" } } as never }),
    ]);
  });

  it("matches the uncached aggregate and scans once while the rows are unchanged", async () => {
    const index = buildHostAliasIndex([], {});
    const first = await loadHostEvidence(source, "c1", index);
    const second = await loadHostEvidence(source, "c1", index);
    expect(plain(first)).toEqual(plain(await aggregateHostEvidence(store, "c1", index)));
    expect(plain(second)).toEqual(plain(first));
    expect(scans).toBe(1);
  });

  it("applies a new alias merge without a rescan", async () => {
    await loadHostEvidence(source, "c1", buildHostAliasIndex([], {}));
    const merged = buildHostAliasIndex([{ hostname: "WS-1", fqdn: "ws-1.example.com" }], {});
    const result = await loadHostEvidence(source, "c1", merged);
    expect(plain(result)).toEqual(plain(await aggregateHostEvidence(store, "c1", merged)));
    expect(scans).toBe(1);
  });

  it("rescans after an import adds rows", async () => {
    const index = buildHostAliasIndex([], {});
    await loadHostEvidence(source, "c1", index);
    await store.append("c1", [ev("e4", "WS-4")]);
    const result = await loadHostEvidence(source, "c1", index);
    expect(result.get("ws-4")?.eventCount).toBe(1); // canonical names are lower-case
    expect(scans).toBe(2);
  });

  it("does not keep a collection with more spellings than a real case has", async () => {
    const many = Array.from({ length: MAX_CACHED_HOST_EVIDENCE_ENTRIES + 1 }, (_, i) =>
      ev(`x${i}`, `H-${i}`),
    );
    for (let i = 0; i < many.length; i += 5000) await store.append("c1", many.slice(i, i + 5000));
    const index = buildHostAliasIndex([], {});
    await loadHostEvidence(source, "c1", index);
    await loadHostEvidence(source, "c1", index);
    expect(scans).toBe(2);
  });

  it("a caller's changes to the result never reach the next load", async () => {
    const index = buildHostAliasIndex([], {});
    const first = await loadHostEvidence(source, "c1", index);
    const host = [...first.values()][0];
    host.eventCount += 100;
    host.sources.add("tampered");
    const second = await loadHostEvidence(source, "c1", index);
    expect(plain(second)).toEqual(plain(await aggregateHostEvidence(store, "c1", index)));
  });
});
