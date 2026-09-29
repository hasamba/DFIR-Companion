import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";
import { pollFor } from "../helpers/poll.js";

// #1874 item 3, the property the delta checkpoint must keep: for real imports through the real
// spine (merge, tagger, demote), undo(import(S)) is S — every field, and the order of both the
// forensic timeline and the IOCs — and redo gives back exactly the post-import state. Only
// `updatedAt` differs: the undo route stamps the time of the undo.

const ndjson = (...rows: unknown[]): string => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";

function siem(names: string[], host = "S1-HOST"): string {
  return JSON.stringify(
    names.map((svc, i) => ({
      "@timestamp": `2026-07-06T10:00:${String(i).padStart(2, "0")}.000Z`,
      log_name: "System",
      computer_name: host,
      event_id: 7045,
      level: "Information",
      event_data: { ServiceName: svc, ServiceFileName: `C:\\Windows\\Temp\\${svc}.exe` },
    })),
  );
}

const thor = ndjson(
  {
    level: "Alert",
    module: "Filescan",
    message: "Malware found",
    time: "2026-05-02T10:00:00Z",
    file: "C:\\Temp\\a.exe",
    md5: "0".repeat(32),
  },
  {
    level: "Warning",
    module: "Filescan",
    message: "Suspicious file",
    time: "2026-05-02T10:01:00Z",
    file: "C:\\Temp\\b.exe",
  },
);

const hayabusa =
  "Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details\n" +
  "2026-05-02 10:00:00.000 +00:00,WS1,Sec,4688,high,Suspicious Proc,Cmd: powershell -enc AAAA ¦ Parent: C:\\Temp\\a.exe\n" +
  "2026-05-02 10:02:00.000 +00:00,WS1,Sec,4624,med,Logon,User: bob ¦ IP: 10.0.0.66\n";

const pslist = (names: string[]): string =>
  JSON.stringify(
    names.map((n, i) => ({
      _Source: "Windows.System.Pslist",
      Name: n,
      Pid: 100 + i,
      Ppid: 4,
      CommandLine: `C:\\Users\\Public\\${n} -connect 203.0.113.${i + 1}`,
      Exe: `C:\\Users\\Public\\${n}`,
      CreateTime: "2026-05-02T10:00:00Z",
    })),
  );

interface Pair {
  name: string;
  first: { filename: string; text: string };
  second: { filename: string; text: string };
  /** The collection in which the second import modifies rows the first one wrote. */
  changesRows?: "forensicTimeline" | "iocs";
}

const PAIRS: Pair[] = [
  {
    name: "siem, then an overlapping siem batch",
    first: { filename: "a.json", text: siem(["svcA", "svcB", "svcC"]) },
    // The first three rows repeat exactly: the merge folds them onto the existing rows.
    second: { filename: "b.json", text: siem(["svcA", "svcB", "svcC", "svcD", "svcE"]) },
    changesRows: "forensicTimeline",
  },
  {
    name: "thor, then hayabusa",
    first: { filename: "thor.json", text: thor },
    second: { filename: "hayabusa.csv", text: hayabusa },
  },
  {
    name: "velociraptor pslist, then another pslist",
    first: { filename: "pslist1.json", text: pslist(["evil.exe", "tool.exe"]) },
    second: { filename: "pslist2.json", text: pslist(["tool.exe", "other.exe"]) },
    changesRows: "iocs",
  },
  {
    name: "hayabusa, then siem",
    first: { filename: "hayabusa.csv", text: hayabusa },
    second: { filename: "s.json", text: siem(["svcZ"], "WS1") },
  },
];

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-1874-undo-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importUndoStore = new ImportUndoStore(store, 10);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore: new SuperTimelineStore(store),
    importMetaStore: new ImportMetaStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
    importUndoStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore };
}

type App = Awaited<ReturnType<typeof makeApp>>;

async function importAndWait(
  h: App,
  file: { filename: string; text: string },
  levels: number,
): Promise<void> {
  const res = await request(h.app).post("/cases/c1/import").send(file);
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  await pollFor(`the undo stack to reach ${levels} level(s)`, async () => {
    const s = (await request(h.app).get("/cases/c1/import/undo-stack")).body as { undo: unknown[] };
    return s.undo.length === levels ? true : undefined;
  });
}

const withoutStamp = (s: InvestigationState): Omit<InvestigationState, "updatedAt"> => {
  const { updatedAt: _ignored, ...rest } = s;
  return rest;
};

describe("delta undo round trip on real imports (#1874 item 3)", () => {
  for (const pair of PAIRS) {
    it(`${pair.name}: undo restores the exact pre-import state, redo the exact post-import state`, async () => {
      const h = await makeApp();
      await importAndWait(h, pair.first, 1);
      const S = await h.stateStore.load("c1");
      await importAndWait(h, pair.second, 2);
      const P = await h.stateStore.load("c1");
      expect(P.forensicTimeline.length + P.iocs.length).toBeGreaterThan(
        S.forensicTimeline.length + S.iocs.length,
      );

      // The checkpoint on disk is a delta, not a copy of the case.
      const file = JSON.parse(
        await readFile(join(h.store.stateDir("c1"), "import-undo-stack.json"), "utf8"),
      ) as {
        undo: Array<{
          state?: unknown;
          delta?: { keyed: Record<string, { added: string[]; restore: unknown[] }> };
        }>;
      };
      expect(file.undo[1].state).toBeUndefined();
      expect(file.undo[1].delta).toBeDefined();
      // The second import changed rows the first one wrote, so the delta carries their before-images.
      if (pair.changesRows)
        expect(file.undo[1].delta!.keyed[pair.changesRows].restore.length).toBeGreaterThan(0);

      expect((await request(h.app).post("/cases/c1/import/undo")).status).toBe(200);
      const undone = await h.stateStore.load("c1");
      expect(withoutStamp(undone)).toEqual(withoutStamp(S));
      expect(undone.forensicTimeline.map((e) => e.id)).toEqual(S.forensicTimeline.map((e) => e.id));
      expect(undone.iocs.map((i) => i.id)).toEqual(S.iocs.map((i) => i.id));

      expect((await request(h.app).post("/cases/c1/import/redo")).status).toBe(200);
      const redone = await h.stateStore.load("c1");
      expect(withoutStamp(redone)).toEqual(withoutStamp(P));
      expect(redone.forensicTimeline.map((e) => e.id)).toEqual(P.forensicTimeline.map((e) => e.id));
    });
  }
});
