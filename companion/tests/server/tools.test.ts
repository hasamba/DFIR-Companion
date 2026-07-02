import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { loadToolConfig, type ToolId, type ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";

// A canned yara config (stdout mode, rules set so runToolAgainstFile doesn't reject).
function yaraCfg(): Map<ToolId, ToolConfig> {
  const cfg = loadToolConfig("yara", { DFIR_TOOL_YARA_BINARY: "yara", DFIR_TOOL_YARA_RULES: "/rules/r.yar" })!;
  return new Map<ToolId, ToolConfig>([["yara", cfg]]);
}

// A stub runner that returns canned YARA output for a run and canned text for an update — never spawns.
const stubRunner: ToolRunner = async (binary) =>
  binary === "yara"
    ? { stdout: "EvilRule /x/a.bin\n0x10:$s: 4d 5a", stderr: "", code: 0 }
    : { stdout: "updated", stderr: "", code: 0 };

async function harness(opts: { withTools?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-tools-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const importUndoStore = new ImportUndoStore(store);
  const app = createApp(store, {
    pipeline, stateStore, importUndoStore,
    ...(opts.withTools ? { toolRunner: stubRunner, loadToolConfigs: yaraCfg } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

describe("external tools routes (#211)", () => {
  it("GET /tools/status reflects configured tools", async () => {
    const { app } = await harness({ withTools: true });
    const r = await request(app).get("/tools/status");
    expect(r.status).toBe(200);
    expect(r.body.enabled).toBe(true);
    const yara = r.body.tools.find((t: { id: string }) => t.id === "yara");
    expect(yara.configured).toBe(true);
    expect(yara.importKind).toBe("yara");
    const snort = r.body.tools.find((t: { id: string }) => t.id === "snort");
    expect(snort.configured).toBe(false);
  });

  it("501s the run route when tools are not configured", async () => {
    const { app } = await harness({ withTools: false });
    const r = await request(app).post("/cases/c1/tools/yara/run").send({ path: "drop/a.bin" });
    expect(r.status).toBe(501);
  });

  it("runs a tool and flows its output through the import chain into state", async () => {
    const { app, store } = await harness({ withTools: true });
    await mkdir(join(store.caseDir("c1"), "drop"), { recursive: true });
    await writeFile(join(store.caseDir("c1"), "drop", "a.bin"), "sample");

    const r = await request(app).post("/cases/c1/tools/yara/run").send({ path: "drop/a.bin" });
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(r.body.addedEvents).toBeGreaterThan(0);

    const state = await request(app).get("/cases/c1/state");
    expect(state.body.forensicTimeline.some((e: { description: string }) => /YARA: EvilRule/.test(e.description))).toBe(true);
  });

  it("a manual tool run pushes an undo checkpoint, and undo reverts the import", async () => {
    const { app, store } = await harness({ withTools: true });
    await mkdir(join(store.caseDir("c1"), "drop"), { recursive: true });
    await writeFile(join(store.caseDir("c1"), "drop", "a.bin"), "sample");

    await request(app).post("/cases/c1/tools/yara/run").send({ path: "drop/a.bin" });
    expect((await request(app).get("/cases/c1/state")).body.forensicTimeline.length).toBeGreaterThan(0);

    const stack = await request(app).get("/cases/c1/import/undo-stack");
    expect(stack.body.canUndo).toBe(true);
    expect(stack.body.nextUndo.label).toMatch(/Tool: yara/);

    const undo = await request(app).post("/cases/c1/import/undo").send({});
    expect(undo.status).toBe(200);
    expect((await request(app).get("/cases/c1/state")).body.forensicTimeline.length).toBe(0);
  });

  it("rejects a path that escapes the case directory", async () => {
    const { app } = await harness({ withTools: true });
    const r = await request(app).post("/cases/c1/tools/yara/run").send({ path: "../../etc/passwd" });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/outside the case/i);
  });

  it("rejects an unknown tool id", async () => {
    const { app } = await harness({ withTools: true });
    const r = await request(app).post("/cases/c1/tools/bogus/run").send({ path: "drop/a.bin" });
    expect(r.status).toBe(400);
  });

  it("POST /tools/reconnect returns configured tools", async () => {
    const { app } = await harness({ withTools: true });
    const r = await request(app).post("/tools/reconnect").send({});
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(r.body.enabled).toBe(true);
  });

  it("update-rules runs the tool's update command (no import)", async () => {
    // yara has no default update command → 400; suricata does. Build a suricata-configured harness.
    const root = await mkdtemp(join(tmpdir(), "dfir-tools-upd-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined, synthesisProvider: undefined, stateStore, store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    // Suricata has no DEFAULT update command (suricata-update is Linux-only) → configure one explicitly.
    const suricata = loadToolConfig("suricata", { DFIR_TOOL_SURICATA_BINARY: "suricata", DFIR_TOOL_SURICATA_UPDATE_CMD: "suricata-update" })!;
    const app = createApp(store, {
      pipeline, stateStore,
      toolRunner: stubRunner,
      loadToolConfigs: () => new Map<ToolId, ToolConfig>([["suricata", suricata]]),
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const r = await request(app).post("/cases/c1/tools/suricata/update-rules").send({});
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(r.body.output).toMatch(/updated/);

    // Without a configured update command, the route 400s (no silent Linux-only default).
    const noCmd = loadToolConfig("suricata", { DFIR_TOOL_SURICATA_BINARY: "suricata" })!;
    expect(noCmd.updateCommand).toBeUndefined();
  });
});
