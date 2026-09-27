import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp, setServerLogger, buildRuntimePipeline } from "../../src/server.js";
import { LoggerImpl, createConsoleLogger } from "../../src/logging/logger.js";
import type { DebugLogSink } from "../../src/logging/debugLogSink.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { pollFor } from "../helpers/poll.js";

// #1736: every HTTP import entry point carries one debug recorder per attempt, from detection to its
// terminal seam — the success line in the always-on debug log, or the diagnostics ring on failure.

const CASE_ID = "c1";
// Unique markers in the rows. None may reach a debug line or the ring's importer detail.
const MARK_HOST = "WKS-MARKER-7731.example.com";
const MARK_CMD = "whoami /marker-cmd-5521";

const CHAINSAW_HUNT = [
  {
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
            Computer: MARK_HOST,
            TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
          },
          EventData: { UtcTime: "2023-01-02 10:00:00.000", CommandLine: MARK_CMD },
        },
      },
    },
    rule: { name: "Suspicious Command", level: "high", tags: ["attack.execution"] },
    timestamp: "2023-01-02T10:00:00.000Z",
  },
];

const SIEM_EXPORT = JSON.stringify({
  data: [
    {
      _source: {
        "@timestamp": "2017-03-20T06:33:40Z",
        log_name: "Security",
        computer_name: MARK_HOST,
        event_id: 4624,
        event_data: { TargetUserName: "martin", LogonType: "3", IpAddress: "10.10.200.11" },
      },
    },
  ],
});

let store: CaseStore;
let lines: string[];
let logger: LoggerImpl;

const sink = (): DebugLogSink => ({
  write: (line) => lines.push(line),
  files: () => ({ previous: "", current: "" }),
  close: () => undefined,
});

function importerLines(kind: string): string[] {
  return lines.filter((l) => l.includes(`[import-debug] importer ${kind}:`));
}

/** The JSON summary the one `[import-debug] importer <kind>:` line carries. */
function summaryOf(line: string): Record<string, unknown> {
  return JSON.parse(line.slice(line.indexOf("{"))) as Record<string, unknown>;
}

async function makeApp() {
  await store.createCase({ caseId: CASE_ID, name: "Case", investigator: "x", aiProvider: null });
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return createApp(store, { pipeline, stateStore });
}

async function writeHunt(): Promise<string> {
  const src = join(await mkdtemp(join(tmpdir(), "dfir-idbg-src-")), "hunt.json");
  await writeFile(src, JSON.stringify(CHAINSAW_HUNT), "utf8");
  return src;
}

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-idbg-")));
  lines = [];
  logger = new LoggerImpl({ level: "error", console: false, debugLog: sink() });
  setServerLogger(logger);
});

afterEach(async () => {
  await logger.close();
  setServerLogger(createConsoleLogger("error"));
});

describe("import entry points carry a per-attempt debug recorder (#1736)", () => {
  it("the generic /import-file route writes one succeeded line with the detection decision", async () => {
    const app = await makeApp();
    const res = await request(app)
      .post(`/cases/${CASE_ID}/import-file`)
      .send({ path: await writeHunt() });
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("chainsaw");

    const line = await pollFor("a chainsaw import-debug line", async () => importerLines("chainsaw")[0]);
    const summary = summaryOf(line);
    expect(summary.outcome).toBe("succeeded");
    expect(summary.kind).toBe("chainsaw");
    expect(summary.detection).toMatchObject({ decision: expect.any(String) });
    expect(importerLines("chainsaw")).toHaveLength(1);
    for (const value of [MARK_HOST, MARK_CMD]) expect(line).not.toContain(value);
  });

  it("a failed import stores the importer detail on the diagnostics ring entry", async () => {
    const app = await makeApp();
    // EEXIST on the evidence copy (see diagnostics.test.ts): a real failure after detection.
    await store.saveImport(CASE_ID, "0001_hunt.json", "x");
    const failed = await request(app)
      .post(`/cases/${CASE_ID}/import-file`)
      .send({ path: await writeHunt() });
    expect(failed.status).toBe(500);

    const diag = await request(app).get("/diagnostics");
    const entry = diag.body.report.importers.recentFailures[0];
    expect(entry.importer).toMatchObject({ kind: "chainsaw", outcome: "failed" });
    expect(entry.importer.detection).toMatchObject({ decision: expect.any(String) });
    expect(importerLines("chainsaw").map((l) => summaryOf(l).outcome)).toEqual(["failed"]);
  });

  it("a dedicated route records the explicit_route decision", async () => {
    const app = await makeApp();
    const res = await request(app)
      .post(`/cases/${CASE_ID}/import-siem`)
      .send({ text: SIEM_EXPORT, filename: "elastic.json" });
    expect(res.status).toBe(202);

    const line = await pollFor("a siem import-debug line", async () => importerLines("siem")[0]);
    const summary = summaryOf(line);
    expect(summary.outcome).toBe("succeeded");
    expect(summary.detection).toEqual({ confident: true, decision: "explicit_route" });
    for (const value of [MARK_HOST, "martin", "10.10.200.11"]) expect(line).not.toContain(value);
  });

  it("a locked case's support bundle leaves the importer detail out", async () => {
    const app = await makeApp();
    await store.saveImport(CASE_ID, "0001_hunt.json", "x");
    await request(app)
      .post(`/cases/${CASE_ID}/import-file`)
      .send({ path: await writeHunt() });
    const diag = await request(app).get("/diagnostics");
    expect(diag.body.report.importers.recentFailures[0].importer).toBeTruthy();

    await store.updateCaseMeta(CASE_ID, { password: await hashCasePassword("seed-pass-123") });
    const res = await request(app)
      .post("/diagnostics/support-bundle")
      .send({ caseId: CASE_ID })
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on("data", (c: Buffer) => chunks.push(c));
        r.on("end", () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    const files = new Map(readZip(res.body as Buffer).map((e) => [e.path, e.data.toString("utf8")]));
    const report = JSON.parse(files.get("imports/failure-1.json")!);
    expect(report.shapeUnavailable).toContain("locked");
    expect(report.importer).toBeUndefined();
  });
});
