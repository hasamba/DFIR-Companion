import { describe, it, expect, vi } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { registerImportResumeHandler } from "../../src/routes/importRecovery.js";
import type { RouteContext, ImportBase } from "../../src/routes/context.js";

type ResumeHandler = (job: unknown, signal: AbortSignal) => Promise<unknown>;

// #1496: a resumed import runs with the SAME declared host the interrupted one ran with — the job
// parameters carry it, the recovery schema restores it, and a job saved before the field existed
// still resumes. Otherwise a partially committed import would land its remaining rows under the
// record names beside the rows already landed on the declared host.

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-resume-asset-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await mkdir(store.importsDir("c1"), { recursive: true });
  await writeFile(join(store.importsDir("c1"), "0007_chainsaw.json"), "[]", "utf8");
  let handler: ResumeHandler | undefined;
  const jobManager = {
    registerResumeHandler: (_kind: string, h: ResumeHandler) => {
      handler = h;
    },
    checkpoint: async () => {},
    progress: () => {},
    warn: async () => {},
  };
  const dispatchImport = vi.fn(
    async (_kind: string, _caseId: string, _text: string, _base: ImportBase) => undefined,
  );
  const ctx = {
    store,
    options: { pipeline: {}, stateStore, jobManager },
    dispatchImport,
    demoteForensicForCase: async (caseId: string) => stateStore.load(caseId),
    applyWhitelistToCase: async () => ({ added: 0 }),
    applyNsrlToCase: async () => ({ added: 0 }),
    applyDeobfuscationToCase: async () => ({ added: 0 }),
    recordImportFailure: () => {},
    resynthesizeInBackground: () => {},
    serverLogger: { info: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
  } as unknown as RouteContext;
  registerImportResumeHandler(ctx);
  if (!handler) throw new Error("handler not registered");
  const resume = handler;
  const run = (parameters: Record<string, unknown>) =>
    resume(
      {
        id: "j1",
        caseId: "c1",
        kind: "import",
        parameters,
        lastCheckpoint: undefined,
      },
      new AbortController().signal,
    );
  const base = () => dispatchImport.mock.calls[dispatchImport.mock.calls.length - 1][3];
  return { run, base };
}

const saved = {
  kind: "chainsaw",
  storedName: "0007_chainsaw.json",
  sequence: 7,
  importedAt: "2026-09-21T12:00:00.000Z",
  minSeverity: null,
  streaming: false,
};

describe("import resume — the declared host survives an interruption (#1496)", () => {
  it("restores assetHost from the job parameters onto the import base", async () => {
    const { run, base } = await harness();
    await run({ ...saved, assetHost: "DESKTOP-16OJFO6" });
    expect(base().assetHost).toBe("DESKTOP-16OJFO6");
  });

  it("a job saved before the field existed, or with a malformed value, resumes without one", async () => {
    const { run, base } = await harness();
    await run(saved);
    expect(base().assetHost).toBeUndefined();
    await run({ ...saved, assetHost: "-bad" });
    expect(base().assetHost).toBeUndefined();
  });
});
