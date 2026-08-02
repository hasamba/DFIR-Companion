import { describe, it, expect } from "vitest";
import type { Express } from "express";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

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
  const importMetaStore = new ImportMetaStore(store);
  // No-AI pipeline: the deterministic chainsaw importer populates the timeline with no model call.
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore, superTimelineStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, superTimelineStore, importMetaStore };
}

async function counts(stateStore: StateStore, superStore: SuperTimelineStore) {
  const state = await stateStore.load("c1");
  const sup = await superStore.query("c1", { limit: 1000 }) as unknown as { total?: number };
  return { forensic: state.forensicTimeline.length, super: sup.total ?? 0 };
}

// Wait for the background work of ONE SPECIFIC import cycle, identified by the stored filename the
// 202 response returned ("0001_hunt.json", "0002_hunt.json" — each import gets its own sequence).
//
// It must be a per-cycle signal, not a timeline threshold. A re-import is expected to add nothing, so
// "poll until forensicTimeline.length >= N" is already satisfied by the PREVIOUS import's events: the
// probe returns on its first attempt and the assertions can run before the re-import has even started,
// passing vacuously. That was the flaw in this test's original hand-rolled loop, whose `break` fired on
// iteration 0 for the same reason, leaving a fixed sleep as the only thing covering the re-import.
//
// import-meta.json is the right signal: routes/import.ts writes it AFTER the importer's events have
// merged into the forensic timeline, been appended to the super-timeline and been demoted — and
// lastImportFile carries that import's own sequence-numbered name, so it can only match once the
// SECOND cycle is done. (The imports audit log is NOT usable here: it is written evidence-first,
// BEFORE analysis runs, so its presence would prove nothing about the merge.)
async function settle(importMetaStore: ImportMetaStore, storedFile: string): Promise<void> {
  let seen = "(nothing)";
  await pollFor(
    () => `import-meta to record the '${storedFile}' import cycle (last saw '${seen}')`,
    async () => {
      seen = (await importMetaStore.load("c1")).lastImportFile || "(nothing)";
      return seen === storedFile ? true : undefined;
    },
  );
  // import-meta lands before the route's trailing best-effort passes (whitelist / NSRL / deobfuscation
  // sweeps, re-synthesis). Those have no signal of their own in this app wiring — no jobManager is
  // configured here — so give them a moment. Unlike before, this sleep is no longer what covers the
  // import itself: the poll above already proved the timeline merge finished.
  await new Promise((r) => setTimeout(r, 300));
}

// Kick off an import and return the stored filename it will be recorded under (the 202 body's `file`),
// which is what `settle` waits on.
async function startImport(app: Express, file: { filename: string; text: string }): Promise<string> {
  const res = await request(app).post("/cases/c1/import").send(file);
  expect(res.status).toBe(202);
  expect(typeof res.body.file).toBe("string");
  return res.body.file as string;
}

describe("#94 — re-importing identical evidence is idempotent", () => {
  it("adds nothing to the forensic timeline or the super-timeline on a second identical import", async () => {
    const { app, stateStore, superTimelineStore, importMetaStore } = await makeApp();

    const firstFile = await startImport(app, FILE_A);
    await settle(importMetaStore, firstFile);
    const first = await counts(stateStore, superTimelineStore);
    expect(first.forensic).toBe(1);
    expect(first.super).toBe(1);

    // The recovery path after an interrupted import: send the exact same bytes again. Waiting on THIS
    // cycle's stored name is what makes the assertions below mean something — the timeline already
    // holds the first import's event, so any threshold on its length would be met before the re-import
    // even started, and the test would report idempotence for work that never landed.
    const reimportFile = await startImport(app, FILE_A);
    // The same bytes under a different stored name: each import takes a fresh sequence number, which is
    // what makes the wait above discriminating. Were the two names equal, matching lastImportFile would
    // be satisfied by the FIRST import's record and be exactly as vacuous as a timeline threshold.
    expect(reimportFile).not.toBe(firstFile);
    await settle(importMetaStore, reimportFile);
    const second = await counts(stateStore, superTimelineStore);

    expect(second.forensic).toBe(first.forensic);
    expect(second.super).toBe(first.super);
  }, POLL_TIMEOUT_MS * 3);   // TWO real settle() budgets (one per import cycle), plus the 300ms settles

  it("still ingests genuinely different evidence as new events", async () => {
    const { app, stateStore, superTimelineStore, importMetaStore } = await makeApp();

    await settle(importMetaStore, await startImport(app, FILE_A));
    await settle(importMetaStore, await startImport(app, FILE_B));

    // Guards the test above: proves the idempotence it asserts is real dedup of identical evidence,
    // not the importer silently dropping every second import.
    const after = await counts(stateStore, superTimelineStore);
    expect(after.forensic).toBe(2);
    expect(after.super).toBe(2);
  }, POLL_TIMEOUT_MS * 3);
});
