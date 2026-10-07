import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import { loadHostScopeLedger, loadPendingHostDuplicates } from "../../src/analysis/hostScopeLoad.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// The Scope & Clearance banner listed `host-a` and `host-a.corp.example.com` as one possible host, yet
// synthesis ran straight through. The gate read only the forensic timeline's host names, where every
// row carries the full name. The short name is spelled inside a super-timeline row
// (`WorkstationName=HOST-A`), and the banner reads that too. Gate, panel and banner now share one list.

function ev(id: string, asset: string, description = "Sysmon Process create (EID 1)"): ForensicEvent {
  return {
    id,
    timestamp: "2017-03-20T11:41:00Z",
    description,
    severity: "High",
    mitreTechniques: ["T1078"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

const FQDN_ROW = ev("e0", "host-a.corp.example.com");
// The short spelling lives in the row's structured fields (the logon's source workstation), as in a
// real Windows import. `WorkstationName=HOST-A` in the text is the same fact, rendered.
const SHORT_NAME_ROW: ForensicEvent = {
  ...ev(
    "s0",
    "host-a.corp.example.com",
    "Windows Security Successful logon (EID 4624) - LogonType=3 - WorkstationName=HOST-A @ host-a.corp.example.com",
  ),
  canonical: { session: { terminal: "HOST-A" } },
} as ForensicEvent;

let cases: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let assetOverridesStore: AssetOverridesStore;
let dismissals: HostDuplicateDismissalStore;
let analyze: ReturnType<typeof vi.fn>;

function pipeline(withSuperTimeline: boolean): AnalysisPipeline {
  return new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore: dismissals,
    ...(withSuperTimeline ? { superTimelineStore: superStore } : {}),
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

const sources = () => ({
  state: stateStore,
  superTimeline: superStore,
  assetOverrides: assetOverridesStore,
  dismissals,
});

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdupbanner-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  dismissals = new HostDuplicateDismissalStore(cases);
  analyze = vi.fn(async () => ({ text: "{}" }));
  const state = emptyState("c1");
  state.forensicTimeline.push(FQDN_ROW);
  await stateStore.save(state);
  await superStore.append("c1", [FQDN_ROW, SHORT_NAME_ROW]);
});

describe("duplicate-host gate reads the banner's host list", () => {
  it("stops synthesis before the provider when the super-timeline names the short spelling", async () => {
    const err = await pipeline(true)
      .synthesize("c1")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(HostMergeDecisionRequired);
    const pair = (err as HostMergeDecisionRequired).pairs[0];
    expect([pair.canonical, pair.other]).toEqual(["host-a.corp.example.com", "host-a"]);
    expect(analyze).not.toHaveBeenCalled();
  });

  it("lists the same pair for the merge panel and for the banner", async () => {
    const pending = await loadPendingHostDuplicates(sources(), "c1");
    const ledger = await loadHostScopeLedger({ ...sources(), decisions: { load: async () => [] } }, "c1");
    expect(pending.map((p) => [p.canonical, p.other])).toEqual([["host-a.corp.example.com", "host-a"]]);
    expect(ledger.nearDuplicates.map((p) => [p.canonical, p.other])).toEqual([
      ["host-a.corp.example.com", "host-a"],
    ]);
  });

  it("releases the gate and clears the banner once the pair is dismissed", async () => {
    await dismissals.append("c1", {
      canonical: "host-a.corp.example.com",
      other: "host-a",
      dismissedAt: "t",
      dismissedBy: "a",
    });
    expect(await loadPendingHostDuplicates(sources(), "c1")).toEqual([]);
    const ledger = await loadHostScopeLedger({ ...sources(), decisions: { load: async () => [] } }, "c1");
    expect(ledger.nearDuplicates).toEqual([]);
    await pipeline(true)
      .synthesize("c1")
      .catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });

  it("releases the gate once the pair is merged", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:host-a", "host:host-a.corp.example.com");
    expect(await loadPendingHostDuplicates(sources(), "c1")).toEqual([]);
  });

  it("keeps the forensic-only list when no super-timeline store is wired", async () => {
    await pipeline(false)
      .synthesize("c1")
      .catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });
});
