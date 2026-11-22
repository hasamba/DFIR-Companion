// #2851: a server restart while a hunt collect is IMPORTING leaves the artifacts already imported in
// the forensic timeline, never settled: no raw-record copy, no tagger pass, no demote. The next
// settle's case-wide demote then moved them out untagged, so after one Collect now the AI was
// missing a High row an uninterrupted collect gives it. Start-up now settles those rows.
// Real createApp, real collect route, real state / super-timeline / tags / tagger stores, the real
// forensic gate and a one-rule tagger ruleset; a second app on the same case store is the restart.
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { INTERRUPTED_IMPORT_MESSAGE } from "../../src/composition/veloHuntStatusTimers.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import type { VelociraptorRunResult } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

const ARTIFACTS = ["Windows.Detection.Yara", "Windows.System.Pslist", "Custom.Hunt.Processes"];
const RULES = `marker2851:
  any:
    - { field: description, contains: ['marker2851'] }
  tags: ['marker2851']
  severity: High
`;
// Per process artifact: three rows the importer leaves at Info — one a tagger rule raises, two it does
// not. The YARA artifact holds a hit the importer itself grades above Info (its parser reads only
// YARA rows, so the process rows it is also handed are not imported).
const YARA_HIT = {
  Fqdn: "WS-001",
  ClientId: "C.1",
  Rule: "SyntheticRule_0",
  Namespace: "n",
  OSPath: "C:\\Users\\Public\\yarahit-0.dll",
  Created0x10: "2026-06-01T09:00:00Z",
};
const rows = (i: number) => [
  {
    Fqdn: "WS-001",
    ClientId: "C.1",
    Name: "rundll32.exe",
    Pid: 4000 + i,
    CommandLine: `rundll32.exe C:\\Users\\Public\\payload${i}.dll,Start`,
    Timestamp: `2026-06-01T10:0${i}:00Z`,
  },
  {
    Fqdn: "WS-001",
    ClientId: "C.1",
    Name: "notepad.exe",
    Pid: 5000 + i,
    CommandLine: `notepad.exe C:\\Docs\\marker2851-${i}.txt`,
    Timestamp: `2026-06-01T11:0${i}:00Z`,
  },
  {
    Fqdn: "WS-001",
    ClientId: "C.1",
    Name: "calc.exe",
    Pid: 6000 + i,
    CommandLine: `calc.exe /plain${i}`,
    Timestamp: `2026-06-01T12:0${i}:00Z`,
  },
];

async function world() {
  const root = await mkdtemp(join(tmpdir(), "dfir-2851-"));
  const store = new CaseStore(root);
  await writeFile(join(root, "rules.yaml"), RULES);
  const sw = { hangAt: 0, imports: 0 };
  const client = {
    async huntStatus() {
      return { state: "RUNNING", clients: { scheduled: 1, completed: 1, errors: 0 } };
    },
    async huntReachedClients() {
      return [{ clientId: "C.1", hostname: "WS-001", fqdn: "WS-001", os: "windows" }];
    },
    async huntArtifactRows(_h: string, artifact: string): Promise<VelociraptorRunResult> {
      const i = ARTIFACTS.indexOf(artifact);
      const r = i === 0 ? [YARA_HIT, ...rows(0)] : rows(i);
      return { rows: r, total: r.length, truncated: false };
    },
    async huntUploads() {
      return [];
    },
    huntGuiUrlFor() {
      return undefined;
    },
  };
  const build = (prepare?: (s: { stateStore: StateStore; veloHuntStore: VeloHuntStore }) => void) => {
    const stateStore = new StateStore(store);
    const veloHuntStore = new VeloHuntStore(store);
    prepare?.({ stateStore, veloHuntStore });
    const superTimelineStore = new SuperTimelineStore(store);
    const tagsStore = new TagsStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const real = pipeline.importVelociraptorArtifact.bind(pipeline);
    pipeline.importVelociraptorArtifact = async (...args) => {
      sw.imports += 1;
      if (sw.imports === sw.hangAt) await new Promise(() => {}); // the process "dies" here
      return real(...args);
    };
    const app = createApp(store, {
      pipeline,
      stateStore,
      veloHuntStore,
      importMetaStore: new ImportMetaStore(store),
      importUndoStore: new ImportUndoStore(store, 5),
      superTimelineStore,
      tagsStore,
      taggerStore: new TaggerStore(join(root, "user.yaml"), [join(root, "rules.yaml")]),
      forensicGateControlStore: new ForensicGateControlStore(store),
      serverClients: veloServerClients(client),
    });
    return { app, stateStore, veloHuntStore, superTimelineStore, tagsStore };
  };
  const a = build();
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const job: VeloHuntJob = {
    bundleId: "threat-hunt-starter",
    bundleName: "Threat Hunt Starter",
    artifacts: ARTIFACTS,
    huntId: "H.1",
    launchedAt: "2026-01-01T00:00:00Z",
    waitMinutes: 15,
    collectAt: "2026-01-01T00:15:00Z",
    status: "running",
  };
  await a.veloHuntStore.upsert("c1", job);
  return { a, build, sw };
}
type App = Awaited<ReturnType<typeof world>>["a"];

const label = (d: string) =>
  /marker2851/.test(d) ? "MARKER" : /payload/.test(d) ? "payload" : /calc/.test(d) ? "plain" : d;

async function view(x: App) {
  const forensic = (await x.stateStore.load("c1")).forensicTimeline;
  const superRows = new Map<string, string>();
  const superStamped = new Set<string>();
  for await (const b of x.superTimelineStore.eventBatches("c1"))
    for (const e of b) {
      superRows.set(e.id, e.description);
      if (e.importBatchId) superStamped.add(e.id);
    }
  const tagged = new Set(
    (await x.tagsStore.load("c1")).map((t) => (t as unknown as { targetId: string }).targetId),
  );
  const signature = forensic.map((e) => `${label(e.description)}:${e.severity}:${e.description}`).sort();
  return { forensic, superRows, superStamped, tagged, signature };
}

async function collect(x: App) {
  const j0 = await x.veloHuntStore.get("c1", "H.1");
  if (j0 && j0.status !== "running") await x.veloHuntStore.upsert("c1", { ...j0, status: "running" });
  expect((await request(x.app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.1" })).status).toBe(
    202,
  );
  return pollFor("hunt imported", async () => {
    const j = await x.veloHuntStore.get("c1", "H.1");
    return j?.status === "imported" ? j : null;
  });
}

describe("a hunt import cut off by a restart is settled at start-up (#2851)", () => {
  it(
    "grades and raw-records the stranded rows; one Collect now then equals the no-restart control",
    async () => {
      const control = await world();
      await collect(control.a);
      const expected = await view(control.a);

      const w = await world();
      w.sw.hangAt = 3; // two artifacts imported, the third never returns
      await request(w.a.app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.1" });
      await pollFor("cut off in the third artifact", async () => (w.sw.imports >= 3 ? true : null));
      const stranded = (await w.a.stateStore.load("c1")).forensicTimeline;
      expect(stranded.length).toBeGreaterThan(0);
      expect(stranded.every((e) => !e.importBatchId)).toBe(true); // never settled
      w.sw.hangAt = 0;

      const warn = vi.spyOn(getServerLogger(), "warn");
      const b = w.build(); // the restart: its start-up recovery runs
      const job = await pollFor("marked", async () => {
        const j = await b.veloHuntStore.get("c1", "H.1");
        return j?.status === "error" ? j : null;
      });
      expect(job.error).toBe(INTERRUPTED_IMPORT_MESSAGE); // #2849's sentence stands
      // The job is marked before the settle, so wait for the settle's own line (written after demote).
      await pollFor("settled", async () =>
        warn.mock.calls.some(([m]) => /settled \d+ row\(s\) of hunt H\.1/.test(String(m))) ? true : null,
      );
      warn.mockRestore();
      const after = await view(b);
      for (const e of stranded) {
        expect(after.superRows.has(e.id), e.description).toBe(true);
        expect(after.superStamped.has(e.id), e.description).toBe(true); // the raw copy is stamped too
      }
      // A row the importer graded above Info stays in the forensic record, now stamped and raw-recorded.
      const yara = after.forensic.find((e) => /yarahit|SyntheticRule/.test(e.description));
      expect(yara && yara.severity !== "Info").toBe(true);
      expect(after.forensic.some((e) => e.severity === "Info")).toBe(false);
      const marker = after.forensic.find((e) => /marker2851-1/.test(e.description));
      expect(marker?.severity).toBe("High");
      expect(after.tagged.has(marker!.id)).toBe(true);
      for (const e of after.forensic) {
        expect(e.importBatchId, e.description).toEqual(expect.any(String));
        expect(after.superRows.has(e.id), e.description).toBe(true);
      }

      await collect(b);
      const final = await view(b);
      expect(final.signature).toEqual(expected.signature);
      expect([...final.superRows.values()].sort()).toEqual([...expected.superRows.values()].sort());
    },
    POLL_TIMEOUT_MS * 6,
  );

  // Codex review: the start-up sweep is not awaited — the server serves, the monitors resume and the
  // drop watcher arms while it lists cases and marks jobs. An ordinary import that reached the case
  // first demoted the stranded Info rows case-wide, untagged, and the settle (which scans only the
  // forensic timeline) could no longer find them. Imports into the case now wait for its recovery.
  const SQUID_LINE =
    '10.30.10.14 - - [15/May/2024:06:50:28 +0000] "GET /plain/page HTTP/1.1" 200 512 "-" "Mozilla/5.0" TCP_HIT:HIER_NONE';
  for (const delayed of ["the job marking (enumeration)", "the settle's forensic read"] as const)
    it(
      `an ordinary import during a delayed start-up recovery waits for it — ${delayed}`,
      async () => {
        const w = await world();
        w.sw.hangAt = 3;
        await request(w.a.app).post("/cases/c1/velociraptor/collect").send({ huntId: "H.1" });
        await pollFor("cut off in the third artifact", async () => (w.sw.imports >= 3 ? true : null));
        w.sw.hangAt = 0;

        let release!: () => void;
        const gate = new Promise<void>((r) => (release = r));
        const b = w.build(({ stateStore, veloHuntStore }) => {
          if (delayed === "the job marking (enumeration)") {
            const update = veloHuntStore.update.bind(veloHuntStore);
            veloHuntStore.update = async (...args) => (await gate, update(...args));
          } else {
            const batches = stateStore.forensicTimelineBatches.bind(stateStore);
            stateStore.forensicTimelineBatches = async function* (...args) {
              await gate;
              yield* batches(...args);
            };
          }
        });
        const imported = request(b.app)
          .post("/cases/c1/import")
          .send({ filename: "proxy_access.log", text: SQUID_LINE, webLogFormat: "squid_combined" });
        expect((await imported).status).toBe(202);
        const importLanded = async () => {
          for await (const batch of b.superTimelineStore.eventBatches("c1"))
            if (batch.some((e) => /plain\/page/.test(e.description))) return true;
          return null;
        };
        // Give an unheld import every chance to finish (and demote) before the recovery goes on.
        await Promise.race([pollFor("import landed", importLanded), new Promise((r) => setTimeout(r, 1500))]);
        expect(await importLanded()).toBeNull(); // held: no import (and no demote) ahead of the recovery
        release();
        await pollFor("import landed", importLanded);
        await pollFor("job marked", async () =>
          (await b.veloHuntStore.get("c1", "H.1"))?.status === "error" ? true : null,
        );
        const after = await pollFor("marker graded", async () => {
          const v = await view(b);
          return v.forensic.some((e) => /marker2851-1/.test(e.description) && e.severity === "High")
            ? v
            : null;
        }).catch(() => view(b));
        const marker = after.forensic.find((e) => /marker2851-1/.test(e.description));
        expect(marker?.severity).toBe("High"); // tagged before any case-wide demote reached it
        expect(after.tagged.has(marker!.id)).toBe(true);
        expect(after.forensic.some((e) => e.severity === "Info")).toBe(false);
      },
      POLL_TIMEOUT_MS * 4,
    );
});
