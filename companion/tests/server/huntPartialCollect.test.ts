// Rarity must see a collection's final completeness (#2670). Hunt grading runs at the import seam
// and reads coverage — including which artifacts were read only partly — from the persisted hunt job.
// The collect used to record skipped / cut-short / unread artifacts only in its LAST job write,
// after the seam had already graded, so a first collection with a partial artifact graded rare
// programs as if absence were proven. Through the real collect path, with a Velociraptor client fake.
// Since #2732 a partial artifact blocks rarity only for the items it reported, not for the case.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { huntSettle } from "../../src/analysis/huntSettle.js";
import { registerHuntSettle } from "../../src/analysis/huntSettleHook.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { wireHuntGrading } from "../../src/composition/huntGrading.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import type { VelociraptorRunResult } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import { pollFor } from "../helpers/poll.js";

const HOSTS = 30;
const PREFETCH = "Windows.Forensics.Prefetch";
// Fails to fetch: an artifact that reports autoruns only, so the rare PROGRAM keeps its grading (#2732).
const FAILING = "Windows.System.TaskScheduler";
const AMCACHE = "Windows.Forensics.Amcache";
const host = (i: number) => `WS-${String(i).padStart(3, "0")}`;
const prefetch = (i: number, exe: string, dir: string) => ({
  Fqdn: host(i),
  ClientId: `C.${i}`,
  Executable: exe.toUpperCase(),
  ExecutablePath: `${dir}\\${exe}`,
  RunCount: 1,
  LastRunTimes: "2026-01-01T00:00:00Z",
});
// chrome.exe on every host, rclone.exe on one: rare, if absence were proven.
const ROWS = [
  ...Array.from({ length: HOSTS }, (_, i) => prefetch(i, "chrome.exe", "C:\\Program Files\\Google")),
  prefetch(0, "rclone.exe", "C:\\Users\\x\\Downloads"),
];

async function world(failingFetch: boolean, truncatePrefetch = false, failing = FAILING) {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunt-partial-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const veloHuntStore = new VeloHuntStore(store);
  const incidentTypeStore = new IncidentTypeStore(store, join(root, "incident-types"));
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const reached = Array.from({ length: HOSTS }, (_, i) => ({
    clientId: `C.${i}`,
    hostname: host(i),
    fqdn: host(i),
    os: "windows",
  }));
  const client = {
    async huntStatus() {
      return { state: "RUNNING", clients: { scheduled: HOSTS, completed: HOSTS, errors: 0 } };
    },
    async huntReachedClients() {
      return reached;
    },
    async huntArtifactRows(_h: string, artifact: string): Promise<VelociraptorRunResult> {
      if (artifact === failing && failingFetch) throw new Error("fetch failed: upstream timeout");
      const rows = artifact === PREFETCH ? ROWS : [];
      const cut = truncatePrefetch && artifact === PREFETCH;
      return { rows, total: rows.length + (cut ? 1 : 0), truncated: cut };
    },
    async huntUploads() {
      return [];
    },
    huntGuiUrlFor() {
      return undefined;
    },
  };
  const app = createApp(store, {
    pipeline,
    stateStore,
    veloHuntStore,
    incidentTypeStore,
    serverClients: veloServerClients(client),
  });
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await incidentTypeStore.saveRecord("c1", "threat-hunt");
  const job: VeloHuntJob = {
    bundleId: "threat-hunt-starter",
    bundleName: "Threat Hunt Starter",
    artifacts: [PREFETCH, failing],
    huntId: "H.1",
    launchedAt: "2026-01-01T00:00:00Z",
    waitMinutes: 15,
    collectAt: "2026-01-01T00:15:00Z",
    status: "running",
  };
  await veloHuntStore.upsert("c1", job);
  const wired = wireHuntGrading({
    store,
    stateStore,
    incidentTypeStore,
    veloHuntStore,
    serverSetId: () => "stub",
  });
  // What the persisted job said about completeness each time the seam graded.
  const seen: { skipped: number; status: string }[] = [];
  registerHuntSettle(stateStore, async (caseId, added) => {
    const cur = await veloHuntStore.get(caseId, "H.1");
    seen.push({ skipped: cur?.skippedArtifacts?.length ?? 0, status: cur?.status ?? "" });
    return (await huntSettle(wired.deps, caseId, added)).changed;
  });
  return { app, stateStore, veloHuntStore, wired, seen };
}

async function collect(w: Awaited<ReturnType<typeof world>>) {
  const res = await request(w.app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.1" });
  expect(res.status).toBe(202);
  await pollFor("hunt H.1 imported", async () =>
    (await w.veloHuntStore.get("c1", "H.1"))?.status === "imported" ? true : null,
  );
}

const huntEntries = async (s: StateStore) =>
  (await s.load("c1")).forensicTimeline.filter((e) => e.id.startsWith("hunt-item:"));

const rareRclone = [expect.stringMatching(/^Hunt \(rare program\): rclone\.exe/)];
const partialOnJob = (w: Awaited<ReturnType<typeof world>>) =>
  w.veloHuntStore.get("c1", "H.1").then((j) => (j?.truncatedArtifacts ?? []).map((t) => t.name));

describe("rarity sees the collection's final completeness (#2670)", () => {
  it("a cut-short read of the artifact that reported the program grades nothing rare", async () => {
    const w = await world(false, true);
    await collect(w);
    expect(await partialOnJob(w)).toEqual([PREFETCH]);
    expect(await huntEntries(w.stateStore)).toEqual([]);
  });

  it("a failed fetch of ANOTHER artifact keeps rarity for the complete one (#2732)", async () => {
    const w = await world(true);
    await collect(w);
    expect(w.seen[0], "the seam graded with the failed artifact already on the job").toMatchObject({
      skipped: 1,
    });
    expect((await huntEntries(w.stateStore)).map((x) => x.description)).toEqual(rareRclone);
  });

  it("a failed fetch of Amcache blocks the program Prefetch alone reported: they share the item (#2732)", async () => {
    const w = await world(true, false, AMCACHE);
    await collect(w);
    expect(w.seen[0]).toMatchObject({ skipped: 1 });
    expect(await huntEntries(w.stateStore)).toEqual([]);
  });

  it("grades once more after the collection's final job write (the after-collect reconcile)", async () => {
    const w = await world(true);
    await collect(w);
    await pollFor("a grading after the final job write", async () =>
      w.seen.at(-1)?.status === "imported" ? true : null,
    );
    expect(w.seen.at(-1)).toMatchObject({ skipped: 1, status: "imported" });
    expect((await huntEntries(w.stateStore)).map((x) => x.description)).toEqual(rareRclone);
  });

  it("the same collection with every artifact read grades the rare program", async () => {
    const w = await world(false);
    await collect(w);
    const e = await huntEntries(w.stateStore);
    expect(e.map((x) => x.description)).toEqual(rareRclone);
  });
});
