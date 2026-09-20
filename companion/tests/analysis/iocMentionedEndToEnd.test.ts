// #1471, end to end: the `mentioned` marker (#1459 hash, #1461 network) and its absence on a real
// network record must survive the import seam. The Cyber Triage and Plaso delta builders used to
// whitelist `id`/`type`/`value` and drop the sink's provenance silently — every parser test stayed
// green while the case saw every value as sensor-observed. Same shape as the #1266 test: the real
// pipeline, the real store, one assertion per provenance story after a save/load round-trip.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const OBSERVED_IP = "192.0.2.44"; // an Active Connection's remote peer
const MENTIONED_IP = "198.51.100.7"; // named in a process argument only
const VISITED_URL = "http://c2.example/stage"; // a Chrome History row
const TYPED_URL = "http://typed.example/x"; // a bash_history row

const ctRows = [
  {
    datetime: "2026-01-28T01:48:00",
    hostName: "win11",
    message: `To ${OBSERVED_IP}:8000, Local Port: 49853`,
    score: "None",
    timestamp_desc: "Active Connection",
  },
  {
    datetime: "2026-01-28T01:49:00",
    hostName: "win11",
    message: "C:\\Users\\Public\\x.exe",
    path: "C:\\Users\\Public\\x.exe",
    args: `-c ping ${MENTIONED_IP}`,
    score: "Suspicious",
    threat_level: "Suspicious. Unusual process",
    timestamp_desc: "Process Start",
    item_type: "Process",
  },
]
  .map((o) => JSON.stringify(o))
  .join("\n");

const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
const plasoCsv = [
  ["datetime", "timestamp_desc", "source", "source_long", "message", "parser", "display_name", "tag"],
  [
    "2023-08-01T10:00:00+00:00",
    "Last Visited Time",
    "WEBHIST",
    "Chrome History",
    `${VISITED_URL} (stage) [count: 1] Visit Source: [SOURCE_SYNCED]`,
    "sqlite/chrome_27_history",
    "TSK:/Users/a/History",
    "-",
  ],
  [
    "2023-08-01T10:01:00+00:00",
    "Command Executed",
    "LOG",
    "Bash History",
    `Command executed: curl ${TYPED_URL}`,
    "bash_history",
    "TSK:/home/a/.bash_history",
    "-",
  ],
]
  .map((r) => r.map(esc).join(","))
  .join("\n");

let stateStore: StateStore;
let pipeline: AnalysisPipeline;

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-1471-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore: new SuperTimelineStore(cases),
    stateLock: new StateLock(),
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
});

describe("mentioned vs observed provenance survives the import seam (#1471)", () => {
  it("Cyber Triage: the Active Connection peer is observed, the process-argument address is mentioned", async () => {
    await pipeline.importCybertriage("c1", ctRows, {
      label: "ct.jsonl",
      idPrefix: "ct1",
      importedAt: "2026-09-10T11:00:00Z",
    });
    const state = await stateStore.load("c1");
    const observed = state.iocs.find((i) => i.type === "ip" && i.value === OBSERVED_IP);
    const mentioned = state.iocs.find((i) => i.type === "ip" && i.value === MENTIONED_IP);
    expect(observed).toBeDefined();
    expect(observed?.provenance).toBeUndefined();
    expect(mentioned?.provenance).toBe("mentioned");
  });

  it("Plaso: a Chrome History URL is observed, a bash_history URL is mentioned", async () => {
    await pipeline.importPlaso("c1", plasoCsv, {
      label: "timeline.csv",
      idPrefix: "pl1",
      importedAt: "2026-09-10T11:00:00Z",
    });
    const state = await stateStore.load("c1");
    const visited = state.iocs.find((i) => i.type === "url" && i.value === VISITED_URL);
    const typed = state.iocs.find((i) => i.type === "url" && i.value === TYPED_URL);
    expect(visited).toBeDefined();
    expect(visited?.provenance).toBeUndefined();
    expect(typed?.provenance).toBe("mentioned");
  });
});
