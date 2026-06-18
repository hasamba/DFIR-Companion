import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { CaseMeta } from "../types.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import {
  buildSnapshot,
  prepareImport,
  SNAPSHOT_STATE_FILES,
  type CaseSnapshot,
} from "./snapshot.js";
import { getAppVersion } from "../version.js";

// Filesystem orchestration for investigation snapshots (issue #56). The portability rules live in
// snapshot.ts (pure); this module just reads the case directory into a snapshot and writes a
// snapshot back into a (new) case directory. The Companion version stamped into a snapshot is
// informational. getAppVersion() resolves it across dev/Docker/SEA (npm_package_version is unset
// inside the EXE, hence the shared helper).
function appVersion(): string {
  return getAppVersion();
}

// Thrown when an import targets a case id that already exists. The route maps it to HTTP 409 so the
// dashboard can prompt for a different id rather than clobbering an existing investigation.
export class SnapshotImportConflictError extends Error {
  constructor(public readonly caseId: string) {
    super(`case ${caseId} already exists — import under a different case id`);
    this.name = "SnapshotImportConflictError";
  }
}

async function readJsonFile(path: string): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
}

async function readJsonl(path: string): Promise<unknown[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const rows: unknown[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed));
    } catch {
      // a corrupt audit line shouldn't sink the whole export — skip it
    }
  }
  return rows;
}

// Read a case directory into a portable snapshot. Reads only the allowlisted state files (absent
// ones are skipped) plus the capture/import audit logs (evidence REFERENCES, not bytes). Throws if
// the case has no case.json (the route maps that to 404).
export async function exportCaseSnapshot(cases: CaseStore, caseId: string): Promise<CaseSnapshot> {
  const meta = (await readJsonFile(cases.caseMetaPath(caseId))) as CaseMeta | undefined;
  if (!meta) throw new Error(`case ${caseId} does not exist`);

  const state: Record<string, unknown> = {};
  for (const name of SNAPSHOT_STATE_FILES) {
    const value = await readJsonFile(join(cases.stateDir(caseId), name));
    if (value !== undefined) state[name] = value;
  }

  const captures = await readJsonl(cases.capturesLogPath(caseId));
  const imports = await readJsonl(cases.importsLogPath(caseId));

  return buildSnapshot({
    caseMeta: { caseId: meta.caseId, name: meta.name, createdAt: meta.createdAt, investigator: meta.investigator },
    state,
    captures,
    imports,
    exportedAt: new Date().toISOString(),
    generatedBy: appVersion(),
  });
}

export interface ImportSnapshotOptions {
  targetCaseId?: string;   // import under a different case id (default: the snapshot's own id)
}

// Write a validated snapshot into a NEW case directory. The case must not already exist; pass a
// fresh targetCaseId to resolve a conflict. Restores the allowlisted state files, the capture/
// import audit logs (references), and a case.json with the original metadata (aiProvider is dropped
// — it is machine config, not investigation data). Returns the created case meta.
export async function importCaseSnapshot(
  cases: CaseStore,
  snapshot: CaseSnapshot,
  options: ImportSnapshotOptions = {},
): Promise<CaseMeta> {
  const targetCaseId = (options.targetCaseId ?? snapshot.case.caseId).trim();
  const prepared = prepareImport(snapshot, targetCaseId);

  if (await cases.caseExists(targetCaseId)) throw new SnapshotImportConflictError(targetCaseId);

  // createCase mkdirs the case layout and writes a base case.json (aiProvider null — excluded).
  await cases.createCase({
    caseId: targetCaseId,
    name: prepared.caseMeta.name,
    investigator: prepared.caseMeta.investigator,
    aiProvider: null,
  });
  // Preserve the original creation time from the snapshot for fidelity.
  const meta: CaseMeta = {
    caseId: targetCaseId,
    name: prepared.caseMeta.name,
    createdAt: prepared.caseMeta.createdAt,
    investigator: prepared.caseMeta.investigator,
    aiProvider: null,
  };
  await atomicWrite(cases.caseMetaPath(targetCaseId), JSON.stringify(meta, null, 2));

  for (const { filename, json } of prepared.stateFiles) {
    await atomicWrite(join(cases.stateDir(targetCaseId), filename), JSON.stringify(json, null, 2));
  }

  // Restore the evidence-reference audit logs (one JSON object per line, as appended at ingest).
  if (prepared.captures.length) {
    await atomicWrite(cases.capturesLogPath(targetCaseId), prepared.captures.map((r) => JSON.stringify(r)).join("\n") + "\n");
  }
  if (prepared.imports.length) {
    await atomicWrite(cases.importsLogPath(targetCaseId), prepared.imports.map((r) => JSON.stringify(r)).join("\n") + "\n");
  }

  return meta;
}
