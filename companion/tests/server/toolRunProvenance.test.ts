import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { loadToolConfig, type ToolId, type ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";

/**
 * The upload path of the external-tool runner, end to end (#688).
 *
 * Two things the analyst must be able to rely on afterwards: the raw evidence they uploaded is
 * still in the case, byte for byte, and the chain of custody says HOW the tool output beside it was
 * produced — which build, which arguments, which rule set, with what on stderr.
 */

// Bytes that are not valid UTF-8, on purpose: an EVTX file is binary, and the old upload path wrote
// evidence through a UTF-8 string round trip. A test with ASCII content would not catch that.
const RAW_EVTX = Buffer.from([0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00, 0xff, 0xfe, 0x00, 0x80]);

const HAYABUSA_CSV = [
  "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details",
  "2026-05-26 12:00:00.000 +00:00,Suspicious Logon,high,WS-01,Security,4624,884213,TgtUser: bob",
].join("\n");

function hayabusaCfg(): Map<ToolId, ToolConfig> {
  const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "/opt/hayabusa" })!;
  return new Map<ToolId, ToolConfig>([["hayabusa", cfg]]);
}

// Answers the version probe, then writes the canned timeline to whatever -o path it is handed.
const stubRunner: ToolRunner = async (_binary, args) => {
  if (args.includes("--version")) return { stdout: "Hayabusa v3.2.0", stderr: "", code: 0 };
  await writeFile(args[args.indexOf("-o") + 1], HAYABUSA_CSV, "utf8");
  return { stdout: "", stderr: "warning: 1 corrupted record skipped", code: 0 };
};

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-toolprov-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const app = createApp(store, {
    pipeline: buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    }),
    stateStore,
    custodyStore: new CustodyStore(store),
    toolRunner: stubRunner,
    loadToolConfigs: hayabusaCfg,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

describe("uploading raw EVTX to a parser (#688)", () => {
  it("keeps the uploaded original byte-for-byte, alongside the tool output", async () => {
    const { app, store } = await harness();
    const r = await request(app)
      .post("/cases/c1/tools/hayabusa/run-upload")
      .send({ filename: "Security.evtx", dataBase64: RAW_EVTX.toString("base64") });
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);

    const importsDir = join(store.caseDir("c1"), "imports");
    const stored = await readdir(importsDir);
    const original = stored.find((f) => f.endsWith("_Security.evtx"));
    expect(original).toBeTruthy();
    const kept = await readFile(join(importsDir, original!));
    expect(kept.equals(RAW_EVTX)).toBe(true); // byte-for-byte, not a UTF-8 round trip

    // The tool's output is stored too — preserving the original replaces nothing.
    expect(stored.some((f) => f.includes(".hayabusa.out"))).toBe(true);

    // The staging directory is scratch and must not linger.
    const work = join(store.caseDir("c1"), ".toolwork");
    const leftovers = await readdir(work).catch(() => [] as string[]);
    expect(leftovers.filter((d) => d.startsWith("up-"))).toEqual([]);
  });

  it("records the parser run in the chain of custody: version, argv, exit code and output hash", async () => {
    const { app, store } = await harness();
    await request(app)
      .post("/cases/c1/tools/hayabusa/run-upload")
      .send({ filename: "Security.evtx", dataBase64: RAW_EVTX.toString("base64") });

    const log = await readFile(store.custodyLogPath("c1"), "utf8");
    const records = log
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as { artifactPath: string; source: string; trigger: string });

    const output = records.find((rec) => rec.artifactPath.includes(".hayabusa.out"))!;
    expect(output.trigger).toBe("tool:hayabusa");
    expect(output.source).toContain("tool hayabusa Hayabusa v3.2.0");
    expect(output.source).toContain("binary /opt/hayabusa");
    expect(output.source).toContain("exit 0");
    expect(output.source).toContain("csv-timeline");
    expect(output.source).toContain("ruleset none"); // Hayabusa ships its own rules
    expect(output.source).toMatch(/output sha256:[a-f0-9]{64}/);
    expect(output.source).toContain("1 corrupted record skipped");

    // ...and it names the preserved original, so the two are tied together in the log.
    const original = records.find((rec) => rec.artifactPath.endsWith("_Security.evtx"))!;
    expect(original.trigger).toBe("raw-evidence");
    expect(output.source).toContain(`original ${original.artifactPath.split(/[\\/]/).pop()}`);
  });

  it("keeps the original even when the parser fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-toolprov-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const failing: ToolRunner = async (_b, args) =>
      args.includes("--version")
        ? { stdout: "Hayabusa v3.2.0", stderr: "", code: 0 }
        : { stdout: "", stderr: "error: unreadable chunk", code: 3 };
    const app = createApp(store, {
      pipeline: buildRuntimePipeline({
        provider: undefined,
        synthesisProvider: undefined,
        stateStore,
        store,
        imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      }),
      stateStore,
      custodyStore: new CustodyStore(store),
      toolRunner: failing,
      loadToolConfigs: hayabusaCfg,
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const r = await request(app)
      .post("/cases/c1/tools/hayabusa/run-upload")
      .send({ filename: "Security.evtx", dataBase64: RAW_EVTX.toString("base64") });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/refusing to import a partial parse/i);

    // The evidence survives the failed parse — it is preserved before the tool is spawned.
    const stored = await readdir(join(store.caseDir("c1"), "imports"));
    expect(stored.some((f) => f.endsWith("_Security.evtx"))).toBe(true);
    expect(stored.some((f) => f.includes(".hayabusa.out"))).toBe(false);
  });
});

describe("a case-relative tool run (#688)", () => {
  it("records the run's provenance without duplicating evidence already in the case", async () => {
    const { app, store } = await harness();
    const dropDir = join(store.caseDir("c1"), "drop");
    await mkdir(dropDir, { recursive: true });
    await writeFile(join(dropDir, "System.evtx"), RAW_EVTX);

    const r = await request(app).post("/cases/c1/tools/hayabusa/run").send({ path: "drop/System.evtx" });
    expect(r.status).toBe(200);

    const stored = await readdir(join(store.caseDir("c1"), "imports"));
    // Only the tool output: the original is already inside the case, so copying it would be waste.
    expect(stored.filter((f) => f.endsWith("_System.evtx"))).toEqual([]);

    const log = await readFile(store.custodyLogPath("c1"), "utf8");
    expect(log).toContain("tool hayabusa Hayabusa v3.2.0");
    expect(log).not.toContain("| original ");
  });
});
