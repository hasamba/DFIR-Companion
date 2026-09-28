import { describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { registerImportResumeHandler } from "../../src/routes/importRecovery.js";
import type { RouteContext } from "../../src/routes/context.js";

type ResumeHandler = (job: unknown, signal: AbortSignal) => Promise<unknown>;

// #1806 (Codex review): resuming an interrupted CSV/log import re-ran the model call with no look at
// the case's AI switch. The resume now refuses while AI is off, like the live routes.

async function harness(enabled: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-resume-ai-off-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await mkdir(store.importsDir("c1"), { recursive: true });
  await writeFile(join(store.importsDir("c1"), "0003_r.csv"), "a,b\n1,2\n", "utf8");
  let handler: ResumeHandler | undefined;
  const dispatchImport = vi.fn(async () => undefined);
  const ctx = {
    store,
    options: {
      pipeline: {},
      stateStore,
      jobManager: {
        registerResumeHandler: (_k: string, h: ResumeHandler) => (handler = h),
        checkpoint: async () => {},
        progress: () => {},
        warn: async () => {},
      },
    },
    getControl: async () => ({ enabled, lastAnalyzedSeq: 0 }),
    dispatchImport,
    demoteForensicForCase: async (caseId: string) => stateStore.load(caseId),
    recordImportFailure: () => {},
    resynthesizeInBackground: () => {},
    serverLogger: { info: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
  } as unknown as RouteContext;
  registerImportResumeHandler(ctx);
  const job = {
    id: "j1",
    caseId: "c1",
    kind: "import",
    parameters: {
      kind: "csv",
      storedName: "0003_r.csv",
      sequence: 3,
      importedAt: "2026-09-21T12:00:00.000Z",
      minSeverity: null,
      streaming: false,
    },
  };
  return { resume: () => handler!(job, new AbortController().signal), dispatchImport };
}

describe("import resume honours the AI switch for CSV/log (#1806)", () => {
  it("refuses to resume a CSV import while AI is off, and never dispatches it", async () => {
    const { resume, dispatchImport } = await harness(false);
    await expect(resume()).rejects.toThrow(/AI is off/);
    expect(dispatchImport).not.toHaveBeenCalled();
  });

  it("resumes it when AI is on", async () => {
    const { resume, dispatchImport } = await harness(true);
    await resume().catch(() => undefined); // settle steps past dispatch are not under test
    expect(dispatchImport).toHaveBeenCalledTimes(1);
  });
});
