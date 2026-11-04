// First-start migration: build the "Testing" server set from the current DFIR_* settings and link
// every existing case to it. Runs once per install: a marker beside the cases root records that it
// finished, and later starts neither seed nor link (a case left unlinked stays unlinked).
import { existsSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ServerSetStore } from "../integrations/serverSets/serverSetStore.js";
import type { ServerSetInput } from "../integrations/serverSets/types.js";
import { logLine, warnLine } from "../logging/serverLogger.js";

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

// The Velociraptor client inventory is per set (clients-<setId>.json). The one global file that
// existed before server sets belongs to the server the Testing set was seeded from.
function adoptLegacyInventory(inventoryDir: string, setId: string): void {
  const legacy = join(inventoryDir, "clients.json");
  const target = join(inventoryDir, `clients-${setId}.json`);
  if (!existsSync(legacy) || existsSync(target)) return;
  try {
    renameSync(legacy, target);
  } catch (err) {
    // Not fatal: the set starts with an empty inventory and the next fleet refresh fills it.
    logLine(`[server-sets] could not move clients.json to ${target}: ${(err as Error).message}`);
  }
}

export interface SeedOptions {
  inventoryDir?: string;
  /** `<casesRoot>/.server-sets-migrated`. When given, the migration runs only while it is absent. */
  markerPath?: string;
  /** For the warning text only. */
  storeDir?: string;
  log?: (line: string) => void;
}

// Creates "Testing" from env when the store is empty (a tool the store rejects is dropped with a
// warning) and makes it the default. A partial earlier run that left "Testing" without a default
// gets the default; a second "Testing" is never made.
function seedTesting(store: ServerSetStore, env: NodeJS.ProcessEnv, opts: SeedOptions): boolean {
  if (store.defaultId() === undefined) {
    const partial = store.list().find((s) => s.name === SEED_NAME);
    if (partial) store.setDefault(partial.id);
  }
  if (store.list().length > 0) return false;
  const skip = new Set<string>();
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const set = store.create(buildInput(env, skip));
      store.setDefault(set.id);
      if (opts.inventoryDir) adoptLegacyInventory(opts.inventoryDir, set.id);
      return true;
    } catch (err) {
      const tool = /^(iris|timesketch) url must be http/.exec((err as Error).message)?.[1];
      if (!tool || skip.has(tool)) throw err;
      skip.add(tool);
      logLine(`[server-sets] ${tool} settings were not valid and were left out of the Testing set`);
    }
  }
  return false;
}

function linkUnlinked(store: ServerSetStore, caseIds: string[]): number {
  const def = store.defaultId();
  if (!def) return 0;
  let linked = 0;
  for (const id of caseIds) {
    if (store.caseSetId(id) === undefined) {
      store.linkCase(id, def);
      linked++;
    }
  }
  return linked;
}

// Seeds "Testing" and links every case that has no link to the default set, then writes the
// marker. With the marker present it does neither; an empty store then logs one warning.
export function seedServerSets(
  store: ServerSetStore,
  env: NodeJS.ProcessEnv,
  caseIds: string[],
  opts: SeedOptions = {},
): { seeded: boolean; linked: number } {
  if (opts.markerPath && existsSync(opts.markerPath)) {
    if (store.list().length === 0) {
      (opts.log ?? warnLine)(
        `[server-sets] Server set store is empty but this install was already migrated; cases have no server set until you create one in Settings → Server sets. Check that ${opts.storeDir ?? "the server-sets folder"} is persisted.`,
      );
    }
    return { seeded: false, linked: 0 };
  }
  const seeded = seedTesting(store, env, opts);
  const linked = linkUnlinked(store, caseIds);
  if (opts.markerPath) writeFileSync(opts.markerPath, `${new Date().toISOString()}\n`);
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
  opts: SeedOptions & { caseIds: string[]; storeDir: string; log: (line: string) => void },
): void {
  try {
    seedServerSets(store, env, opts.caseIds, opts);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "";
    const reason = OWN_ERROR.test(msg) ? msg : err instanceof Error ? err.name : "unknown error";
    opts.log(`[server-sets] could not read the server set store in ${opts.storeDir}: ${reason}`);
  }
}
