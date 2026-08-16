// Clearing the last Presidio approval must restart the synthesis it was holding.
//
// REPORTED: "i had presidio blocking, i handled all, the presidio chip is gone but ai does not
// continue." Exactly right. The chip is driven by the pending list, so it disappears on the last
// approval — but nothing kicked the held run, and nothing emitted a new ai_status either, so the
// header pill stayed on "AI: on hold — Presidio…" indefinitely. The only way forward was to press
// Re-synthesize and know to do so.
//
// The sibling gate has done this from the start: hostDuplicates.ts calls resynthesizeInBackground
// when the last pair resolves. These two gates are the same shape and must behave the same way —
// especially now that both report the same "blocked" status, which invites the same expectation.
//
// Only on the LAST one, for the reason the host-duplicate route documents: kicking per approval
// would spend a run per item, and every run but the last would re-throw on what is still pending.
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

let app: express.Express;
let kick: ReturnType<typeof vi.fn>;
let pendingStore: PresidioPendingStore;

/** Seed `values` as pending Presidio findings and wire the routes with a spy on the kick. */
async function seed(values: string[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidio-resume-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  pendingStore = new PresidioPendingStore(cases);
  await pendingStore.save(
    "c1",
    values.map((value) => ({ value, category: "PERSON" as const })),
  );
  kick = vi.fn();
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
  } as unknown as RouteContext);
}

const approve = (value: string) =>
  request(app).post("/cases/c1/presidio-pending/approve").send({ value, category: "PERSON" });
const suppress = (value: string) => request(app).post("/cases/c1/presidio-pending/suppress").send({ value });

describe("clearing the last pending Presidio finding", () => {
  beforeEach(async () => {
    await seed(["Jane Doe"]);
  });

  it("restarts the held synthesis when the last one is approved", async () => {
    const res = await approve("Jane Doe");
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
    expect(kick).toHaveBeenCalledWith("c1");
  });

  it("restarts the held synthesis when the last one is suppressed", async () => {
    const res = await suppress("Jane Doe");
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
    expect(kick).toHaveBeenCalledWith("c1");
  });
});

describe("clearing one of several pending Presidio findings", () => {
  beforeEach(async () => {
    await seed(["Jane Doe", "John Smith"]);
  });

  it("does not restart synthesis while another is still pending", async () => {
    await approve("Jane Doe");
    expect(kick).not.toHaveBeenCalled();
  });

  it("restarts exactly once, on the last one, whichever way it is resolved", async () => {
    await approve("Jane Doe");
    await suppress("John Smith");
    expect(kick).toHaveBeenCalledWith("c1");
    expect(kick).toHaveBeenCalledTimes(1);
  });
});

// A rejected request changes nothing, so it must not claim the gate has lifted.
describe("a malformed resolve", () => {
  beforeEach(async () => {
    await seed(["Jane Doe"]);
  });

  it("does not restart synthesis", async () => {
    const res = await request(app).post("/cases/c1/presidio-pending/suppress").send({ value: "  " });
    expect(res.status).toBe(400);
    expect(kick).not.toHaveBeenCalled();
    expect(await pendingStore.load("c1")).toHaveLength(1);
  });
});
