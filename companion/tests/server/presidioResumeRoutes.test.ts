// Clearing the last Presidio approval must tell the analyst the case is ready — and start nothing.
//
// REPORTED (#579): "i had presidio blocking, i handled all, the presidio chip is gone but ai does not
// continue." The chip is driven by the pending list, so it disappeared on the last approval, but the
// header pill stayed on "AI: on hold — Presidio…" indefinitely.
//
// #579 answered that by starting a synthesis on the last approval. #1599 took that away: clearing a
// gate is not one of the four synthesis triggers (AI on, Re-synthesize, import completion, the last
// duplicate-host resolve). The last approval now marks the case "ready — press Re-synthesize", and
// the analyst decides when to pay for the run. The kick spy stays wired so a regression shows up.
//
// Only on the LAST one: an earlier approval leaves the gate holding, and the pill must keep saying so.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import express from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { registerAnonymizationRoutes } from "../../src/routes/anonymization.js";
import type { RouteContext } from "../../src/routes/context.js";
import { PRESIDIO_CLEARED_REASON } from "../../src/analysis/aiState.js";

let app: express.Express;
let kick: ReturnType<typeof vi.fn>;
let mark: ReturnType<typeof vi.fn>;
let refresh: ReturnType<typeof vi.fn>;
let pendingStore: PresidioPendingStore;

/**
 * Seed `values` as pending Presidio findings and wire the routes with a spy on the kick. With
 * `heldBy`, the values arrive the way the gate writes them, naming the held feature; without it,
 * the list has no record — the shape a file written before features were recorded has.
 */
async function seed(values: string[], heldBy?: string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidio-resume-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  pendingStore = new PresidioPendingStore(cases);
  const entities = values.map((value) => ({ value, category: "PERSON" as const }));
  if (heldBy) await pendingStore.hold("c1", entities, heldBy);
  else await pendingStore.save("c1", entities);
  kick = vi.fn();
  mark = vi.fn(async () => {});
  refresh = vi.fn();
  app = express();
  app.use(express.json());
  // The route builds its own stores from ctx.store, so only the case store is wired here. It also
  // calls ctx.serverLogger.info on both resolve paths — omitting it makes every request 500, which
  // is how the first draft of this suite "failed" for the wrong reason.
  registerAnonymizationRoutes(app, {
    store: cases,
    options: { stateStore: new StateStore(cases) },
    serverLogger: { info: () => {}, warn: () => {}, error: () => {} },
    resynthesizeInBackground: kick,
    markConclusionsOutOfDate: mark,
    refreshAiStatus: refresh,
  } as unknown as RouteContext);
}

const approve = (value: string) =>
  request(app).post("/cases/c1/presidio-pending/approve").send({ value, category: "PERSON" });
const suppress = (value: string) => request(app).post("/cases/c1/presidio-pending/suppress").send({ value });

describe("clearing the last pending Presidio finding", () => {
  beforeEach(async () => {
    await seed(["Jane Doe"]);
  });

  it("marks the case ready when the last one is approved, and starts no synthesis", async () => {
    const res = await approve("Jane Doe");
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
    expect(mark).toHaveBeenCalledWith("c1", PRESIDIO_CLEARED_REASON);
    expect(kick).not.toHaveBeenCalled();
  });

  it("marks the case ready when the last one is suppressed, and starts no synthesis", async () => {
    const res = await suppress("Jane Doe");
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
    expect(mark).toHaveBeenCalledWith("c1", PRESIDIO_CLEARED_REASON);
    expect(kick).not.toHaveBeenCalled();
  });
});

describe("clearing one of several pending Presidio findings", () => {
  beforeEach(async () => {
    await seed(["Jane Doe", "John Smith"]);
  });

  it("does not mark the case ready while another is still pending", async () => {
    await approve("Jane Doe");
    expect(mark).not.toHaveBeenCalled();
  });

  it("marks it ready exactly once, on the last one, whichever way it is resolved", async () => {
    await approve("Jane Doe");
    await suppress("John Smith");
    expect(mark).toHaveBeenCalledTimes(1);
    expect(kick).not.toHaveBeenCalled();
  });
});

// A rejected request changes nothing, so it must not claim the gate has lifted.
describe("a malformed resolve", () => {
  beforeEach(async () => {
    await seed(["Jane Doe"]);
  });

  it("does not mark the case ready", async () => {
    const res = await request(app).post("/cases/c1/presidio-pending/suppress").send({ value: "  " });
    expect(res.status).toBe(400);
    expect(mark).not.toHaveBeenCalled();
    expect(await pendingStore.load("c1")).toHaveLength(1);
  });
});

// REPORTED: "i pressed suggest hunts, presidio held the run, i answered presidio findings, the ai
// button says re-synthesize which is not true and it stays even after i re-pressed the suggest
// hunts and it finished." The gate holds any AI call; only a held synthesis leaves the case ready.
describe("clearing a gate that held an on-demand feature", () => {
  beforeEach(async () => {
    await seed(["Jane Doe"], "suggest-language-hunts");
  });

  it("does not mark the conclusions, but still refreshes the pill off 'on hold'", async () => {
    const res = await approve("Jane Doe");
    expect(res.status).toBe(200);
    expect(mark).not.toHaveBeenCalled();
    expect(refresh).toHaveBeenCalledWith("c1");
    expect(kick).not.toHaveBeenCalled();
  });

  it("behaves the same when the last value is suppressed", async () => {
    await suppress("Jane Doe");
    expect(mark).not.toHaveBeenCalled();
    expect(refresh).toHaveBeenCalledWith("c1");
  });
});

describe("clearing a gate that held a synthesis", () => {
  it("marks the case ready", async () => {
    await seed(["Jane Doe"], "synthesis");
    await approve("Jane Doe");
    expect(mark).toHaveBeenCalledWith("c1", PRESIDIO_CLEARED_REASON);
    expect(refresh).not.toHaveBeenCalled();
  });

  it("marks it ready when a hunt and a synthesis were both held in the round", async () => {
    await seed(["Jane Doe"], "synthesis");
    await pendingStore.hold(
      "c1",
      [
        { value: "Jane Doe", category: "PERSON" },
        { value: "John Smith", category: "PERSON" },
      ],
      "suggest-language-hunts",
    );
    await approve("Jane Doe");
    expect(mark).not.toHaveBeenCalled(); // John Smith is still pending
    await suppress("John Smith");
    expect(mark).toHaveBeenCalledWith("c1", PRESIDIO_CLEARED_REASON);
  });

  it("marks it ready for a pending list with no record (written before features existed)", async () => {
    await seed(["Jane Doe"]);
    await approve("Jane Doe");
    expect(mark).toHaveBeenCalledWith("c1", PRESIDIO_CLEARED_REASON);
  });
});
