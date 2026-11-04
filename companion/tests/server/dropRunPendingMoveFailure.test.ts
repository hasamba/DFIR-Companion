import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { loadToolConfig, type ToolId, type ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";
import type { DropStuckTracker } from "../../src/composition/dropStuck.js";

// #2283. "Run <tool>" on a pending raw drop file (POST /cases/:id/drop/run-pending) runs the tool,
// then moves the file out of drop/. When that move fails, #2281 remembers the file as stuck so it is
// not run again — but the route passed no fingerprint of the version it ran, so a file that a writer
// was still appending to during the (slow) tool run was remembered in its CHANGED state, held back,
// and later archived to _processed/ by the move retry without the appended records ever processed.

const hooks = vi.hoisted(() => ({
  failRename: false,
  tracker: null as DropStuckTracker | null,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    rename: (async (...args: Parameters<typeof actual.rename>) => {
      if (hooks.failRename && /[\\/]_(processed|failed)[\\/]/.test(String(args[1]))) {
        throw Object.assign(new Error("EPERM: operation not permitted, rename"), { code: "EPERM" });
      }
      return actual.rename(...args);
    }) as typeof actual.rename,
  };
});

// The real tracker, captured so the test can read what the route left in it.
vi.mock("../../src/composition/dropStuck.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/composition/dropStuck.js")>();
  return {
    ...actual,
    createDropStuckTracker: (...args: Parameters<typeof actual.createDropStuckTracker>) => {
      hooks.tracker = actual.createDropStuckTracker(...args);
      return hooks.tracker;
    },
  };
});

const HAYABUSA_CSV = [
  "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details",
  "2026-05-26 12:00:00.000 +00:00,Suspicious Logon,high,WS-01,Security,4624,884213,TgtUser: bob",
].join("\n");

let prevDropEnabled: string | undefined;
beforeAll(() => {
  prevDropEnabled = process.env.DFIR_DROP_ENABLED;
  process.env.DFIR_DROP_ENABLED = "off"; // no poller sweeps racing the route
});
afterAll(() => {
  if (prevDropEnabled === undefined) delete process.env.DFIR_DROP_ENABLED;
  else process.env.DFIR_DROP_ENABLED = prevDropEnabled;
});
afterEach(() => {
  hooks.failRename = false;
});

/** `appendDuringRun`: the stub tool appends to the drop file while it "runs"; `exitCode` 0 = ok. */
async function runPending(opts: { appendDuringRun: boolean; exitCode: number }) {
  const root = await mkdtemp(join(tmpdir(), "dfir-run-pending-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const dropStatusStore = new DropStatusStore(store);
  const dropFile = () => join(store.caseDir("c1"), "drop", "Security.evtx");
  const runner: ToolRunner = async (_binary, args) => {
    if (args.includes("--version")) return { stdout: "Hayabusa v3.2.0", stderr: "", code: 0 };
    if (opts.appendDuringRun) await writeFile(dropFile(), "MORE-RECORDS", { flag: "a" });
    if (opts.exitCode !== 0) return { stdout: "", stderr: "error: unreadable chunk", code: opts.exitCode };
    await writeFile(args[args.indexOf("-o") + 1], HAYABUSA_CSV, "utf8");
    return { stdout: "", stderr: "", code: 0 };
  };
  const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "/opt/hayabusa" })!;
  const app = createApp(store, {
    pipeline: buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    }),
    stateStore,
    toolRunner: runner,
    loadToolConfigs: () => new Map<ToolId, ToolConfig>([["hayabusa", cfg]]),
    dropStatusStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await mkdir(join(store.caseDir("c1"), "drop"), { recursive: true });
  await writeFile(dropFile(), Buffer.from([0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00]));
  await dropStatusStore.record("c1", {
    dropPath: join(store.caseDir("c1"), "drop"),
    imported: [],
    failed: [],
    pendingRawInputs: [
      { relpath: "Security.evtx", ext: ".evtx", suggestedTool: "hayabusa", configured: true },
    ],
  });

  hooks.failRename = true;
  const res = await request(app).post("/cases/c1/drop/run-pending").send({});
  const stuck = [...(hooks.tracker?.stuck.get("c1")?.keys() ?? [])];
  return { res, stuck };
}

describe("run-pending: a failed move holds back only the version the tool ran on (#2283)", () => {
  it("holds back an unchanged file whose move to _processed/ failed", async () => {
    const { res, stuck } = await runPending({ appendDuringRun: false, exitCode: 0 });
    expect(res.status).toBe(200);
    expect(stuck).toEqual(["Security.evtx"]);
  });

  it("does not hold back a file that changed during a successful tool run", async () => {
    const { res, stuck } = await runPending({ appendDuringRun: true, exitCode: 0 });
    expect(res.status).toBe(200);
    expect(stuck).toEqual([]);
  });

  it("does not hold back a file that changed during a failed tool run", async () => {
    const { res, stuck } = await runPending({ appendDuringRun: true, exitCode: 3 });
    expect(res.status).toBe(200);
    expect(stuck).toEqual([]);
  });
});
