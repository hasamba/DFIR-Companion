import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";

// #94 — characterization test: re-importing the SAME evidence file must stay idempotent.
//
// Re-import is the documented recovery path after an interrupted/crashed import, so it must not
// inflate the evidence set. It currently holds, but for a NON-OBVIOUS reason that nothing else
// asserts, and which two plausible refactors would silently break:
//
//   Each import gets a fresh sequence number (caseStore.nextImportSeq), and deterministic importers
//   derive event ids from it as `${seq}e${index}` — so a re-import produces DIFFERENT ids ("1e1" vs
//   "2e1"). Neither id-keyed dedup layer catches that: mergeDelta indexes by id (stateMerge.ts:195)
//   and SuperTimelineStore.append filters by id (superTimelineStore.ts:47).
//
//   What actually absorbs the re-import is correlateEvents "step 0" — the exact timestamp+description
//   merge (correlate.ts:207) — which collapses the re-imported events onto the originals and keeps the
//   lowest-index id. The super-timeline then stays clean for a second-order reason: it is fed from a
//   DIFF of the forensic timeline (routes/import.ts), and correlation already made that diff empty.
//
// So the invariant rests on (a) correlation keying on exact timestamp+description and (b) the
// super-timeline being diff-fed. Anything that perturbs a re-imported event's description or
// timestamp — or that feeds the super-timeline directly from the importer instead of the diff —
// reintroduces silent duplication of forensic evidence. Hence this test.
//
// Note this covers only the DETERMINISTIC importers, whose parse is pure and whose ids are
// index-derived. The AI csv/log paths emit events whose text/count depend on model output, so
// re-import there is genuinely not idempotent — that is the actual open work in #94.

const HUNT = (ts: string) => ([{
  group: "Sigma",
  kind: "individual",
  document: {
    kind: "evtx",
    path: "Sysmon.evtx",
    data: {
      Event: {
        System: {
          Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
          EventID: 1,
          Channel: "Microsoft-Windows-Sysmon/Operational",
          Computer: "WIN-DC01.corp.local",
          TimeCreated: { "#attributes": { SystemTime: ts } },
        },
        EventData: {
          UtcTime: ts.replace("T", " ").replace("Z", ""),
          Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
          ParentImage: "C:\\Program Files\\Microsoft Office\\winword.exe",
        },
      },
    },
  },
  rule: {
    name: "Suspicious Encoded PowerShell Command Line",
    level: "high",
    tags: ["attack.execution", "attack.t1059.001"],
  },
  timestamp: ts,
}]);

// The importer resolves an event's real time from EventData.UtcTime, so a variant must move BOTH
// that and the outer timestamps — otherwise it collides with the original on correlation step 0 and
// the test would assert idempotence while actually measuring an accidental merge.
const FILE_A = { filename: "hunt.json", text: JSON.stringify(HUNT("2023-01-02T10:00:00.000Z")) };
const FILE_B = { filename: "hunt2.json", text: JSON.stringify(HUNT("2023-01-03T11:22:33.000Z")) };

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-reimport-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  // No-AI pipeline: the deterministic chainsaw importer populates the timeline with no model call.
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore, importMetaStore: new ImportMetaStore(store), superTimelineStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, superTimelineStore };
}

async function counts(stateStore: StateStore, superStore: SuperTimelineStore) {
  const state = await stateStore.load("c1");
  const sup = await superStore.query("c1", { limit: 1000 } as never) as unknown as { total?: number };
  return { forensic: state.forensicTimeline.length, super: sup.total ?? 0 };
}

// Poll until the background import has landed at least `atLeast` forensic events, then let it settle.
async function settle(stateStore: StateStore, atLeast: number): Promise<void> {
  for (let i = 0; i < 150; i++) {
    const s = await stateStore.load("c1");
    if (s.forensicTimeline.length >= atLeast) break;
    await new Promise((r) => setTimeout(r, 20));
  }
  // Give any trailing super-timeline / tagging work a moment to finish before asserting.
  await new Promise((r) => setTimeout(r, 300));
}

describe("#94 — re-importing identical evidence is idempotent", () => {
  it("adds nothing to the forensic timeline or the super-timeline on a second identical import", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();

    expect((await request(app).post("/cases/c1/import").send(FILE_A)).status).toBe(202);
    await settle(stateStore, 1);
    const first = await counts(stateStore, superTimelineStore);
    expect(first.forensic).toBe(1);
    expect(first.super).toBe(1);

    // The recovery path after an interrupted import: send the exact same bytes again.
    expect((await request(app).post("/cases/c1/import").send(FILE_A)).status).toBe(202);
    await settle(stateStore, 1);
    const second = await counts(stateStore, superTimelineStore);

    expect(second.forensic).toBe(first.forensic);
    expect(second.super).toBe(first.super);
  }, 30000);

  it("still ingests genuinely different evidence as new events", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();

    expect((await request(app).post("/cases/c1/import").send(FILE_A)).status).toBe(202);
    await settle(stateStore, 1);

    expect((await request(app).post("/cases/c1/import").send(FILE_B)).status).toBe(202);
    await settle(stateStore, 2);

    // Guards the test above: proves the idempotence it asserts is real dedup of identical evidence,
    // not the importer silently dropping every second import.
    const after = await counts(stateStore, superTimelineStore);
    expect(after.forensic).toBe(2);
    expect(after.super).toBe(2);
  }, 30000);
});
