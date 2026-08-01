import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startServer } from "../../src/server.js";
import { assertTempCasesRoot } from "./isolation.js";
import { startAiStub, type AiStub } from "./aiStub.js";

// The ONLY supported way to boot the app for the browser suite.
//
// Everything that keeps a test run from touching real data lives here, in one file, rather than
// being spread across env vars each spec has to remember to set: the temp cases root, the hard
// assertion that it IS a temp root, the stub AI provider, and the teardown. There is deliberately
// no way to point this at a configured DFIR_CASES_ROOT — see isolation.ts for why.
//
// This calls startServer(), NOT createApp() directly. createApp(store) with no options builds a
// skeleton: no state store, no pipeline, no template/bundle/tagger stores, so /cases/:id/state
// answers "state store not configured" and the dashboard hangs on the loading overlay forever.
// startServer is where those ~15 stores get wired, and duplicating that list here would drift out
// of sync the first time one is added.

const PORT = 4788;
const REPO_ROOT = join(import.meta.dirname, "..", "..", "..");

// cases/ is nested INSIDE the throwaway root on purpose. startServer derives its sibling
// directories from dirname(casesRoot) — templates/, bundles/, logs/, tagger/, report-templates/,
// dashboard-views/ and more. With a bare mkdtemp dir as the cases root, dirname() is the OS temp
// dir itself and every one of those would be scattered into /tmp on each run.
const TEMP_ROOT = mkdtempSync(join(tmpdir(), "dfir-e2e-"));
const CASES_ROOT = join(TEMP_ROOT, "cases");
mkdirSync(CASES_ROOT, { recursive: true });

const casesRoot = assertTempCasesRoot(CASES_ROOT, REPO_ROOT);

let stub: AiStub | undefined;
let closing = false;

async function main(): Promise<void> {
  stub = await startAiStub();
  // The provider is configured in-process rather than from a .env file, so nothing on the
  // developer's machine can leak a real key or endpoint into a test run.
  //
  // EVERY provider family must point at the stub, not just the synthesis one. Providers default
  // their base URL to their vendor's endpoint — openrouter.ts falls back to
  // https://openrouter.ai/api/v1 — so a route using a family this file forgot will make a REAL
  // outbound call. That is exactly what happened: /velociraptor/suggest-hunts used the VISION
  // family, which was unset, and the suite dialled OpenRouter and got a 401 back from it.
  //
  // For a forensics tool this is not a tidiness issue. Case evidence is in those prompts, so an
  // unset family means a test run can ship real case content to a third party.
  // Pin the .env the server may read to one inside the throwaway root — which does not exist, so
  // it reads nothing.
  //
  // resolveEnvFilePath() falls back to resolve(process.cwd(), ".env") in dev, and POST
  // /settings/ai-reload calls reloadEnvPrefix("DFIR_VISION_"/"DFIR_AI_"), which OVERWRITES
  // process.env from that file. This worktree has no companion/.env, so the stub pinning below
  // survived by accident; the main checkout has a real one. Running the suite from there would
  // have loaded real API keys over the stub mid-run and sent case data to a live provider.
  //
  // DFIR_ENV_FILE is the explicit override and wins over both the SEA and cwd branches, so this
  // holds no matter which directory the suite is started from.
  process.env.DFIR_ENV_FILE = join(TEMP_ROOT, "e2e.env");
  process.env.DFIR_AI_PROVIDER = "openai";
  process.env.DFIR_AI_SYNTH_BASE_URL = `${stub.url}/v1`;
  process.env.DFIR_AI_SYNTH_KEY = "stub-key";
  process.env.DFIR_AI_MODEL = "stub-model";
  process.env.DFIR_AI_SYNTH_MODEL = "stub-model";
  process.env.DFIR_VISION_PROVIDER = "openai";
  process.env.DFIR_VISION_BASE_URL = `${stub.url}/v1`;
  process.env.DFIR_VISION_KEY = "stub-key";
  process.env.DFIR_VISION_MODEL = "stub-model";
  process.env.DFIR_AI_SECOND_OPINION_MODEL = "stub-model";
  process.env.DFIR_CASES_ROOT = casesRoot;

  startServer(casesRoot, PORT, "127.0.0.1", join(TEMP_ROOT, "logs"));
  console.log(`E2E server listening on http://127.0.0.1:${PORT}`);
  console.log(`E2E cases root ${casesRoot}`);
}

function removeTempRoot(): void {
  try {
    rmSync(TEMP_ROOT, { recursive: true, force: true });
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
  removeTempRoot();
  if (stub) {
    void stub.close().finally(() => process.exit(code));
  } else {
    process.exit(code);
  }
}

process.on("SIGINT", () => teardown(0));
process.on("SIGTERM", () => teardown(0));
process.on("exit", removeTempRoot);

main().catch((err: unknown) => {
  console.error("[e2e] server-entry failed to start:", err);
  teardown(1);
});
