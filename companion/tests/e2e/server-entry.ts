import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Request, Response } from "express";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { assertTempCasesRoot } from "./isolation.js";
import { startAiStub, type AiStub } from "./aiStub.js";

// The ONLY supported way to boot the app for the browser suite.
//
// Everything that keeps a test run from touching real data lives here, in one file, rather than
// being spread across env vars each spec has to remember to set: the temp cases root, the hard
// assertion that it IS a temp root, the stub AI provider, and the teardown. There is deliberately
// no way to point this at a configured DFIR_CASES_ROOT — see isolation.ts for why.

const PORT = 4788;
const REPO_ROOT = join(import.meta.dirname, "..", "..", "..");

const casesRoot = assertTempCasesRoot(mkdtempSync(join(tmpdir(), "dfir-e2e-")), REPO_ROOT);

let stub: AiStub | undefined;
let closing = false;

async function main(): Promise<void> {
  stub = await startAiStub();
  // The provider is configured in-process rather than from a .env file, so nothing on the
  // developer's machine can leak a real key or endpoint into a test run.
  process.env.DFIR_AI_PROVIDER = "openai";
  process.env.DFIR_AI_SYNTH_BASE_URL = `${stub.url}/v1`;
  process.env.DFIR_AI_SYNTH_KEY = "stub-key";
  process.env.DFIR_AI_MODEL = "stub-model";
  process.env.DFIR_AI_SYNTH_MODEL = "stub-model";
  process.env.DFIR_CASES_ROOT = casesRoot;

  const app = createApp(new CaseStore(casesRoot));
  // Playwright's webServer.url polls this; createApp owns every other route.
  app.get("/healthz", (_req: Request, res: Response) => res.status(200).json({ ok: true, casesRoot }));

  await new Promise<void>((resolve) => {
    app.listen(PORT, "127.0.0.1", resolve);
  });
  console.log(`E2E server listening on http://127.0.0.1:${PORT}`);
  console.log(`E2E cases root ${casesRoot}`);
}

function removeCasesRoot(): void {
  try {
    rmSync(casesRoot, { recursive: true, force: true });
  } catch {
    // Best effort — the OS reclaims its own temp dir, and throwing here would mask the real exit.
  }
}

function teardown(code: number): void {
  if (closing) return;
  closing = true;
  // Remove the temp root on SIGINT/SIGTERM too, not just on clean exit. vitest.config.ts records
  // that stranded temp dirs once reached 388,954 (#173); an interrupted E2E run must not restart
  // that pile.
  removeCasesRoot();
  if (stub) {
    void stub.close().finally(() => process.exit(code));
  } else {
    process.exit(code);
  }
}

process.on("SIGINT", () => teardown(0));
process.on("SIGTERM", () => teardown(0));
process.on("exit", removeCasesRoot);

main().catch((err: unknown) => {
  console.error("[e2e] server-entry failed to start:", err);
  teardown(1);
});
