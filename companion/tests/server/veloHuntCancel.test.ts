// POST /cases/:id/velociraptor/hunt-jobs/:huntId/cancel — the job card's Cancel button
// (routes/veloHuntCancel.ts). The analyst chooses what happens on the Velociraptor server: nothing,
// stop the hunt, or delete it. Whatever they choose, the companion never collects the hunt again.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { privateBundleDir } from "../helpers/bundleDir.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { VelociraptorClient, type VqlRunner } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import { pollFor } from "../helpers/poll.js";

const HUNT = "H.CANCEL1";

// Stands in for the velociraptor binary. Records every program; the hunt reports STOPPED once it
// has been stopped, which is exactly what would make the status poller collect it if the cancel
// had not marked the job first. `refuse` makes the stop / delete fail the way a missing permission does.
function makeRunner(refuse?: "hunt_update" | "hunt_delete", hold?: Promise<void>) {
  const programs: string[] = [];
  let stopped = false;
  const runner: VqlRunner = async (statements) => {
    const p = statements[0];
    programs.push(p);
    if (p.includes("hunt(") && p.includes("artifacts=["))
      return { rows: [{ Hunt: { HuntId: HUNT, state: "RUNNING" } }], raw: "" };
    if (refuse && p.includes(refuse)) return { rows: [], raw: "", stderr: `PermissionDenied: ${refuse}` };
    if (p.includes("hunt_update(") && hold) await hold;
    if (p.includes("hunt_update(")) {
      stopped = true;
      return { rows: [{ Stopped: { HuntId: HUNT } }], raw: "" };
    }
    if (p.includes("FROM hunts()")) return { rows: [{ state: stopped ? "STOPPED" : "RUNNING" }], raw: "" };
    if (p.includes("hunt_results("))
      return { rows: [{ Name: "cmd.exe", Timestamp: "2026-07-01T10:00:00Z" }], raw: "" };
    return { rows: [], raw: "" };
  };
  return { runner, programs };
}

async function makeApp(refuse?: "hunt_update" | "hunt_delete", hold?: Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velocancel-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const { runner, programs } = makeRunner(refuse, hold);
  const client = new VelociraptorClient(
    {
      apiConfigPath: "/x/api.yaml",
      binary: "velociraptor",
      timeoutMs: 5000,
      maxRows: 1000,
      maxOutputBytes: 1024 * 1024,
      guiUrl: "https://velo.example/",
    },
    runner,
  );
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    serverClients: veloServerClients(client),
    artifactBundleStore: new ArtifactBundleStore(privateBundleDir(root)),
    veloHuntStore: new VeloHuntStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const launched = await request(app)
    .post("/cases/c1/velociraptor/run-bundle")
    .send({ bundleId: "best-practice", waitMinutes: 30 });
  expect(launched.status).toBeLessThan(300);
  return { app, programs, store };
}

const cancel = (app: Parameters<typeof request>[0], velociraptor: unknown, huntId = HUNT) =>
  request(app).post(`/cases/c1/velociraptor/hunt-jobs/${huntId}/cancel`).send({ velociraptor });
const jobOf = async (app: Parameters<typeof request>[0]) =>
  (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body[0];

describe("cancel a running bundle hunt", () => {
  it("stop: marks it cancelled and stops the hunt in Velociraptor", async () => {
    const { app, programs } = await makeApp();
    const res = await cancel(app, "stop");
    expect(res.status).toBe(200);
    expect(res.body.serverError).toBeUndefined();
    const job = await jobOf(app);
    expect(job.status).toBe("cancelled");
    expect(job.cancelled.action).toBe("stop");
    expect(job.cancelled.pending).toBeUndefined(); // Velociraptor's answer was recorded
    expect(programs).toContain(`SELECT hunt_update(hunt_id='${HUNT}', stop=TRUE) AS Stopped FROM scope()`);
    expect(programs.some((p) => p.includes("hunt_delete("))).toBe(false);
  });

  it("delete: stops and then deletes the hunt in Velociraptor", async () => {
    const { app, programs } = await makeApp();
    expect((await cancel(app, "delete")).status).toBe(200);
    expect((await jobOf(app)).cancelled.action).toBe("delete");
    expect(programs).toContain(`SELECT * FROM hunt_delete(hunt_id='${HUNT}', really_do_it=TRUE)`);
  });

  it("none: stops tracking it here and sends Velociraptor nothing", async () => {
    const { app, programs } = await makeApp();
    const before = programs.length;
    expect((await cancel(app, "none")).status).toBe(200);
    expect((await jobOf(app)).status).toBe("cancelled");
    expect(programs.slice(before).some((p) => p.includes("hunt_update(") || p.includes("hunt_delete("))).toBe(
      false,
    );
  });

  // Stopping the hunt makes Velociraptor report STOPPED — the signal the status poller collects on.
  // A cancel must never turn into an import.
  it("a cancelled hunt is never collected, even once Velociraptor reports it STOPPED", async () => {
    const { app, programs } = await makeApp();
    await cancel(app, "stop");
    expect((await request(app).post(`/cases/c1/velociraptor/hunt-jobs/${HUNT}/poll-status`)).status).toBe(
      200,
    );
    // The collect route refuses it outright instead of accepting a collect that would never run.
    const collect = await request(app).post("/cases/c1/velociraptor/collect").send({ huntId: HUNT });
    expect(collect.status).toBe(404);
    await new Promise((r) => setTimeout(r, 200));
    const job = await jobOf(app);
    expect(job.status).toBe("cancelled");
    expect(job.collectActive).toBe(false);
    expect(programs.some((p) => p.includes("hunt_results("))).toBe(false);
  });

  // The choice is written before Velociraptor answers. Until it does — or forever, if the companion
  // restarts mid-call — the record must not claim the hunt was stopped.
  it("marks the stop pending until Velociraptor answers", async () => {
    let release = (): void => {};
    const hold = new Promise<void>((r) => (release = r));
    const { app } = await makeApp(undefined, hold);
    const inFlight = cancel(app, "stop").then((r) => r);
    const mid = await pollFor(
      () => "the job to be marked cancelled while the stop is in flight",
      async () => {
        const j = (await jobOf(app)) as { status?: string; cancelled?: { pending?: boolean } };
        return j.status === "cancelled" ? j : undefined;
      },
    );
    expect(mid.status).toBe("cancelled");
    expect(mid.cancelled?.pending).toBe(true);
    release();
    expect((await inFlight).status).toBe(200);
    expect((await jobOf(app)).cancelled.pending).toBeUndefined();
  });

  it("records and returns a refused delete, so the card can say the hunt may still be there", async () => {
    const { app } = await makeApp("hunt_delete");
    const res = await cancel(app, "delete");
    expect(res.status).toBe(200);
    expect(res.body.serverError).toContain("PermissionDenied");
    const job = await jobOf(app);
    expect(job.status).toBe("cancelled");
    expect(job.cancelled.serverError).toContain("stopped, but not deleted: PermissionDenied");
  });

  it("refuses an unknown choice, an unknown hunt, and a hunt that is no longer running", async () => {
    const { app } = await makeApp();
    expect((await cancel(app, "archive")).status).toBe(400);
    expect((await cancel(app, "none", "H.NOPE")).status).toBe(404);
    expect((await cancel(app, "none")).status).toBe(200);
    expect((await cancel(app, "stop")).status).toBe(409); // already cancelled
  });
});

// #2867: a frozen case still lets the analyst stop work that was running when it froze — the same
// rule that keeps poll-status and monitor stop open. Deleting the hunt destroys its collected
// results on the Velociraptor server, so a frozen case refuses that one, before anything changes.
type Frozen = "closed" | "archived";
async function freeze(app: Parameters<typeof request>[0], store: CaseStore, frozen: Frozen) {
  if (frozen === "archived") return void (await store.archiveCaseFolder("c1", "archived"));
  expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
}

describe.each(["closed", "archived"] as const)("cancel a running hunt on a %s case (#2867)", (frozen) => {
  const unfreeze = frozen === "archived" ? "restore it" : "reopen it";

  it("stop tracking here is accepted", async () => {
    const { app, store } = await makeApp();
    await freeze(app, store, frozen);
    expect((await cancel(app, "none")).status).toBe(200);
    expect((await jobOf(app)).status).toBe("cancelled");
  });

  it("stop is accepted and stops the hunt in Velociraptor", async () => {
    const { app, programs, store } = await makeApp();
    await freeze(app, store, frozen);
    expect((await cancel(app, "stop")).status).toBe(200);
    expect((await jobOf(app)).cancelled.action).toBe("stop");
    expect(programs).toContain(`SELECT hunt_update(hunt_id='${HUNT}', stop=TRUE) AS Stopped FROM scope()`);
  });

  it("delete is refused and the hunt is left running, here and in Velociraptor", async () => {
    const { app, programs, store } = await makeApp();
    await freeze(app, store, frozen);
    const res = await cancel(app, "delete");
    expect(res.status).toBe(423);
    expect(res.body.error).toBe(
      `Case "c1" is ${frozen} — ${unfreeze} before deleting the hunt and its results from Velociraptor`,
    );
    const job = await jobOf(app);
    expect(job.status).toBe("running");
    expect(job.cancelled).toBeUndefined();
    expect(programs.some((p) => p.includes("hunt_update(") || p.includes("hunt_delete("))).toBe(false);
  });
});
