// First-start migration: build the "Testing" server set from the current DFIR_* settings and link
// every existing case to it. Runs on every start; after the first it only links unlinked cases.
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { ServerSetStore } from "../integrations/serverSets/serverSetStore.js";
import type { ServerSetInput } from "../integrations/serverSets/types.js";
import { logLine } from "../logging/serverLogger.js";

const SEED_NAME = "Testing";
const ARCHIVED_DIRNAME = "_archived";

const get = (env: NodeJS.ProcessEnv, k: string): string => (env[k] ?? "").trim();
const flag = (env: NodeJS.ProcessEnv, k: string): boolean => /^(1|true|yes)$/i.test(get(env, k));
const anySet = (...v: string[]): boolean => v.some((x) => x !== "");

function buildInput(env: NodeJS.ProcessEnv, skip: ReadonlySet<string>): ServerSetInput {
  const input: ServerSetInput = { name: SEED_NAME };
  const iris = {
    url: get(env, "DFIR_IRIS_URL"),
    apiKey: get(env, "DFIR_IRIS_KEY"),
    ca: get(env, "DFIR_IRIS_CA"),
    customerId: get(env, "DFIR_IRIS_CUSTOMER_ID"),
    classificationId: get(env, "DFIR_IRIS_CLASSIFICATION_ID"),
  };
  const irisInsecure = flag(env, "DFIR_IRIS_INSECURE");
  if (!skip.has("iris") && (anySet(...Object.values(iris)) || irisInsecure)) {
    input.iris = { ...iris, insecure: irisInsecure };
  }
  const ts = {
    url: get(env, "DFIR_TIMESKETCH_URL"),
    user: get(env, "DFIR_TIMESKETCH_USER"),
    password: get(env, "DFIR_TIMESKETCH_PASSWORD"),
    ca: get(env, "DFIR_TIMESKETCH_CA"),
    timeline: get(env, "DFIR_TIMESKETCH_TIMELINE"),
  };
  const tsInsecure = flag(env, "DFIR_TIMESKETCH_INSECURE");
  if (!skip.has("timesketch") && (anySet(...Object.values(ts)) || tsInsecure)) {
    input.timesketch = { ...ts, insecure: tsInsecure };
  }
  const velo = {
    apiConfigPath: get(env, "DFIR_VELOCIRAPTOR_API_CONFIG"),
    org: get(env, "DFIR_VELOCIRAPTOR_ORG"),
    guiUrl: get(env, "DFIR_VELOCIRAPTOR_GUI_URL"),
  };
  if (!skip.has("velociraptor") && anySet(...Object.values(velo))) input.velociraptor = velo;
  return input;
}

// Creates "Testing" when the store is empty (a tool the store rejects is dropped with a warning),
// then links every case that has no link to the default set. Returns what it did.
export function seedServerSets(
  store: ServerSetStore,
  env: NodeJS.ProcessEnv,
  caseIds: string[],
): { seeded: boolean; linked: number } {
  let seeded = false;
  if (store.list().length === 0) {
    const skip = new Set<string>();
    for (let attempt = 0; attempt < 4 && !seeded; attempt++) {
      try {
        const set = store.create(buildInput(env, skip));
        store.setDefault(set.id);
        seeded = true;
      } catch (err) {
        const tool = /^(iris|timesketch) url must be http/.exec((err as Error).message)?.[1];
        if (!tool || skip.has(tool)) throw err;
        skip.add(tool);
        logLine(`[server-sets] ${tool} settings were not valid and were left out of the Testing set`);
      }
    }
  }
  const def = store.defaultId();
  let linked = 0;
  if (def) {
    for (const id of caseIds) {
      if (store.caseSetId(id) === undefined) {
        store.linkCase(id, def);
        linked++;
      }
    }
  }
  return { seeded, linked };
}

// Case ids on disk (active and archived), read-only. Startup is synchronous, so this avoids
// CaseStore.listCases (async).
export function listCaseIdsSync(casesRoot: string): string[] {
  const ids: string[] = [];
  for (const dir of [casesRoot, join(casesRoot, ARCHIVED_DIRNAME)]) {
    if (!existsSync(dir)) continue;
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (!e.isDirectory() || (dir === casesRoot && e.name === ARCHIVED_DIRNAME)) continue;
      if (existsSync(join(dir, e.name, "case.json"))) ids.push(e.name);
    }
  }
  return ids;
}

const OWN_ERROR = /^server set secret cannot decrypt[^\n]*$/;

// Startup wrapper: a broken store (corrupt file, changed instance secret) must not stop the
// server. Logs one line with the store directory and a safe reason, never a secret value.
export function runServerSetSeed(
  store: ServerSetStore,
  env: NodeJS.ProcessEnv,
  caseIds: string[],
  storeDir: string,
  log: (line: string) => void,
): void {
  try {
    seedServerSets(store, env, caseIds);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "";
    const reason = OWN_ERROR.test(msg) ? msg : err instanceof Error ? err.name : "unknown error";
    log(`[server-sets] could not read the server set store in ${storeDir}: ${reason}`);
  }
}
