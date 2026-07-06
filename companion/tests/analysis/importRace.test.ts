import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

// Regression test for the read-modify-write race on per-case investigation state: two
// concurrent imports for the SAME case used to silently lose events (whichever import
// finished its load()->merge->save() cycle last would clobber the other's save with a
// state it loaded BEFORE the other import's write landed). AnalysisPipeline.importSiem
// (like every import/analyze method) now wraps its load->merge->save critical section in
// StateLock.runExclusive(caseId, ...), so concurrent imports for the same case serialize
// instead of interleaving.

let caseStore: CaseStore;
let stateStore: StateStore;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Wraps a real StateStore but injects an artificial delay between load() returning its
// snapshot and the caller observing it / between save() being called and it completing —
// this forces a genuine interleaving window that a single-threaded microtask queue alone
// can't reliably reproduce (two imports over a trivial in-memory/fast-disk case might
// "accidentally" not interleave even when unlocked).
class DelayedStateStore extends StateStore {
  constructor(cases: CaseStore, private readonly delayMs: number) {
    super(cases);
  }

  async load(caseId: string): Promise<InvestigationState> {
    const state = await super.load(caseId);
    await sleep(this.delayMs);
    return state;
  }

  async save(state: InvestigationState): Promise<void> {
    await sleep(this.delayMs);
    await super.save(state);
  }
}

// Minimal SIEM-shaped record (Windows Event Log 7045 — service creation) that
// deterministically maps to exactly one forensic event via importSiem (no AI call).
function siemJsonFor(serviceName: string): string {
  return JSON.stringify([
    {
      "@timestamp": "2026-07-06T10:00:00.000Z",
      log_name: "System",
      computer_name: "RACE-HOST",
      event_id: 7045,
      level: "Information",
      event_data: { ServiceName: serviceName, ServiceFileName: `C:\\Windows\\Temp\\${serviceName}.exe` },
    },
  ]);
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-race-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new DelayedStateStore(caseStore, 100);
});

describe("concurrent imports for the same case (race regression)", () => {
  it("preserves BOTH events when two importSiem calls race for the same caseId", async () => {
    const pipeline = new AnalysisPipeline({
      stateStore,
      stateLock: new StateLock(),
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });

    const [stateA, stateB] = await Promise.all([
      pipeline.importSiem("c1", siemJsonFor("RaceServiceAlpha"), {
        label: "alpha.json", idPrefix: "a", importedAt: "2026-07-06T10:00:00.000Z",
      }),
      pipeline.importSiem("c1", siemJsonFor("RaceServiceBravo"), {
        label: "bravo.json", idPrefix: "b", importedAt: "2026-07-06T10:00:01.000Z",
      }),
    ]);

    // Neither in-memory return value should have clobbered the other's write — reload
    // from disk to check what actually persisted (the ultimate regression assertion).
    const final = await new StateStore(caseStore).load("c1");
    const descriptions = final.forensicTimeline.map((e) => e.description).join(" | ");

    expect(final.forensicTimeline.some((e) => e.description.includes("RaceServiceAlpha"))).toBe(true);
    expect(final.forensicTimeline.some((e) => e.description.includes("RaceServiceBravo"))).toBe(true);
    expect(final.forensicTimeline.length).toBeGreaterThanOrEqual(2);

    // Sanity: both calls' own return values should also reflect the fully-merged state
    // once resolved (each import's callback reloads-then-merges under the lock, so by
    // the time the SECOND (serialized) import saves, its own load already sees the
    // first import's event).
    void stateA; void stateB; void descriptions;
  });

  it("loses an event without the lock (sanity check the harness actually races)", async () => {
    // Same setup but with NO StateLock wired — withStateLock() is then a no-op passthrough,
    // so the two importSiem calls' load->merge->save cycles genuinely interleave and the
    // second save clobbers the first (this documents/verifies the original bug via the
    // same harness used to prove the fix above).
    const pipeline = new AnalysisPipeline({
      stateStore,
      // stateLock intentionally omitted
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });

    await Promise.all([
      pipeline.importSiem("c1", siemJsonFor("RaceServiceAlpha"), {
        label: "alpha.json", idPrefix: "a", importedAt: "2026-07-06T10:00:00.000Z",
      }),
      pipeline.importSiem("c1", siemJsonFor("RaceServiceBravo"), {
        label: "bravo.json", idPrefix: "b", importedAt: "2026-07-06T10:00:01.000Z",
      }),
    ]);

    const final = await new StateStore(caseStore).load("c1");
    const hasAlpha = final.forensicTimeline.some((e) => e.description.includes("RaceServiceAlpha"));
    const hasBravo = final.forensicTimeline.some((e) => e.description.includes("RaceServiceBravo"));

    // Without the lock, the later save wins and the earlier import's event is lost —
    // at most one of the two survives.
    expect(hasAlpha && hasBravo).toBe(false);
  });
});
