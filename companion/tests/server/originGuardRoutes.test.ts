import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { CustomToolStore } from "../../src/integrations/tools/customToolStore.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";

// Records every spawn the routes attempt, so a test can assert nothing was executed.
function recordingRunner(): { runner: ToolRunner; spawned: string[] } {
  const spawned: string[] = [];
  const runner: ToolRunner = async (binary, args) => {
    spawned.push([binary, ...args].join(" "));
    return { stdout: "", stderr: "", code: 0 };
  };
  return { runner, spawned };
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-origin-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const { runner, spawned } = recordingRunner();
  const app = createApp(store, {
    pipeline,
    stateStore,
    importUndoStore: new ImportUndoStore(store),
    toolRunner: runner,
    customToolStore: new CustomToolStore(join(root, "custom-tools.json")),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, spawned };
}

describe("companion API origin guard (#211)", () => {
  it("refuses to register a custom tool for a malicious page's origin", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/tools/custom")
      .set("Origin", "https://evil.example")
      .send({ id: "pwn", name: "pwn", binary: "powershell", updateCommand: "powershell -c calc" });
    expect(res.status).toBe(403);

    // And nothing was persisted, so the tool cannot be triggered later by any route.
    const listed = await request(app).get("/tools/custom");
    expect(listed.body.tools ?? []).toHaveLength(0);
  });

  it("refuses to run a tool's update command for a malicious page's origin", async () => {
    const { app, spawned } = await harness();
    const res = await request(app)
      .post("/cases/c1/tools/yara/update-rules")
      .set("Origin", "https://evil.example")
      .send({});
    expect(res.status).toBe(403);
    expect(spawned).toEqual([]);
  });

  it("fails the preflight that would authorize the cross-origin POST", async () => {
    const { app } = await harness();
    const res = await request(app)
      .options("/tools/custom")
      .set("Origin", "https://evil.example")
      .set("Access-Control-Request-Method", "POST");
    expect(res.status).toBe(403);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["access-control-allow-private-network"]).toBeUndefined();
  });

  it("never advertises a wildcard origin on a normal request", async () => {
    const { app } = await harness();
    const res = await request(app).get("/health");
    expect(res.headers["access-control-allow-origin"]).not.toBe("*");
  });

  it("still serves the extension and scripted (no-Origin) callers", async () => {
    const { app } = await harness();
    const fromExtension = await request(app)
      .get("/health")
      .set("Origin", "chrome-extension://abcdefghijklmnopabcdefghijklmnop");
    expect(fromExtension.status).toBe(200);

    const fromScript = await request(app).get("/health");
    expect(fromScript.status).toBe(200);
  });
});

describe("tool update-rules case validation (#211)", () => {
  it("rejects a nonexistent case before spawning anything", async () => {
    const { app, spawned } = await harness();
    const res = await request(app).post("/cases/no-such-case/tools/yara/update-rules").send({});
    expect(res.status).toBe(404);
    expect(spawned).toEqual([]);
  });
});
