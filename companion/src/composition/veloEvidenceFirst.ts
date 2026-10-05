/**
 * Evidence first, then the import section — for the Velociraptor hunt collect
 * (composition/veloHunts.ts) and the external hunt/flow ingest (composition/veloExternalIngest.ts).
 *
 * The import memory guard (analysis/importMemoryGuard.ts, #1874) may refuse an import when its
 * section is taken. It runs only for a caller that passes a size hint, because a hint means "the
 * evidence is already stored, a refusal loses nothing". These two paths used to store the rows they
 * fetched from Velociraptor INSIDE the section, so they passed no hint and a large hunt into a large
 * case was never checked. Now they store every artifact and upload as case evidence first — the same
 * persistEvidence, with its audit line — and only then take the section with a size. A refusal leaves
 * the evidence stored and changes nothing else.
 *
 * The collect's memory bound holds: each artifact's rows are read from their scratch file, stored,
 * and dropped before the next is read, so at most one artifact is in memory at a time.
 */
import { readFile } from "node:fs/promises";
import type { HuntUpload } from "../integrations/velociraptor/velociraptorApi.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import {
  IMPORT_INPUT_BYTES_PER_EVENT,
  type ImportAdmissionHint,
  type RefusalWording,
} from "../analysis/importMemoryGuard.js";

export interface StoredEvidence {
  storedName: string;
  importedAt: string;
  seq: number;
}

export type PersistEvidence = (caseId: string, originalName: string, text: string) => Promise<StoredEvidence>;

/** A hunt refusal: the rows are evidence, and "Collect now" on the hunt card is the retry. */
export const HUNT_REFUSAL_WORDING: RefusalWording = {
  saved: "The hunt's rows are saved in the case as evidence",
  retry: "press Collect now on this hunt",
};

/** An external import refusal: the analyst pasted a link, so pasting it again is the retry. */
export const EXTERNAL_REFUSAL_WORDING: RefusalWording = {
  saved: "What Velociraptor returned is saved in the case as evidence",
  retry: "paste the hunt or flow link again and choose Re-import anyway",
};

/**
 * Store each hunt artifact's scratch file as case evidence, one at a time: read, store, drop.
 * The evidence name is the one the collect has always used. Each artifact gets its import attempt's
 * recorder here (#1736), handed to `onAttempt` first, so a failure storing it is still that
 * artifact's failure in the diagnostics ring.
 */
export async function storeHuntArtifacts<T extends { name: string; file: string }>(
  persistEvidence: PersistEvidence,
  caseId: string,
  huntId: string,
  artifacts: T[],
  onAttempt: (debug: ImportDebugRecorder) => void,
): Promise<Array<T & StoredEvidence & { debug: ImportDebugRecorder }>> {
  const stored: Array<T & StoredEvidence & { debug: ImportDebugRecorder }> = [];
  for (const artifact of artifacts) {
    const debug = createImportDebugRecorder(); // one recorder per artifact (#1736)
    debug.detected("velociraptor", { confident: true, decision: "explicit_route" }); // a row map
    onAttempt(debug);
    const json = await readFile(artifact.file, "utf8");
    const evidence = await persistEvidence(caseId, `velo-hunt_${huntId}_${artifact.name}.json`, json);
    stored.push({ ...artifact, ...evidence, debug });
  }
  return stored;
}

/** CSV and log imports are themselves an LLM call, gated by the case's AI toggle. */
export function needsAi(kind: string): boolean {
  return kind === "csv" || kind === "log";
}

/**
 * The AI gate again, at dispatch, inside the import section: the plan was made before the section,
 * and the analyst may have turned AI off while this import waited its turn.
 */
export async function aiGateClosed(
  kind: string,
  getControl: (caseId: string) => Promise<{ enabled: boolean }>,
  caseId: string,
): Promise<boolean> {
  return needsAi(kind) && !(await getControl(caseId)).enabled;
}

export interface PlannedUpload {
  up: HuntUpload;
  kind: string;
  debug: ImportDebugRecorder;
}

export interface UploadPlanDeps {
  resolveImportKind: (filename: string, text: string, debug?: ImportDebugRecorder) => string;
  /** The case's AI toggle; CSV/log are themselves an LLM call and are skipped while it is off. */
  aiEnabled: () => Promise<boolean>;
  /** A super-only hunt skips every upload: its only importer merges into the forensic timeline. */
  superOnly?: boolean;
  logLine: (msg: string) => void;
}

/**
 * Decide which uploads will import — the same skips the import loops used to make inside the
 * section. A skipped upload is not stored, as before.
 */
export async function planUploads(
  uploads: HuntUpload[],
  deps: UploadPlanDeps,
): Promise<{ planned: PlannedUpload[]; skipped: string[] }> {
  const planned: PlannedUpload[] = [];
  const skipped: string[] = [];
  for (const up of uploads) {
    const debug = createImportDebugRecorder(); // one recorder per uploaded file (#1736)
    const kind = deps.resolveImportKind(up.name, up.content, debug); // honors custom importers too
    if (kind === "unknown") {
      skipped.push(up.name);
      continue;
    }
    if (deps.superOnly) {
      deps.logLine(
        `[velociraptor] super-only bundle: skipping uploaded ${kind} report ${up.name} (upload-based artifacts aren't ingested for super-only bundles — collect them via a normal bundle)`,
      );
      skipped.push(up.name);
      continue;
    }
    if (needsAi(kind) && !(await deps.aiEnabled())) {
      skipped.push(up.name);
      continue;
    }
    planned.push({ up, kind, debug });
  }
  return { planned, skipped };
}

/**
 * Store each planned upload as case evidence. A store that fails is reported through `onFailure`
 * and the upload is left out of the import — the outcome the import loops gave it before.
 */
export async function storeUploads(
  persistEvidence: PersistEvidence,
  caseId: string,
  planned: PlannedUpload[],
  onFailure: (upload: PlannedUpload, error: unknown) => void,
): Promise<Array<PlannedUpload & StoredEvidence>> {
  const stored: Array<PlannedUpload & StoredEvidence> = [];
  for (const upload of planned) {
    try {
      stored.push({ ...upload, ...(await persistEvidence(caseId, upload.up.name, upload.up.content)) });
    } catch (error) {
      onFailure(upload, error);
    }
  }
  return stored;
}

/** UTF-8 bytes, the unit the guard's per-event figure is calibrated in — not UTF-16 `.length`. */
export function utf8Bytes(texts: string[]): number {
  return texts.reduce((sum, text) => sum + Buffer.byteLength(text, "utf8"), 0);
}

/**
 * The guard's size hint, or none when there is nothing to import — a no-op must never be refused.
 * Rows are counted exactly; uploads are sized in bytes and converted with the guard's own figure, so
 * a collect with both reports one total.
 */
export function evidenceSizeHint(
  size: { rows?: number; bytes?: number },
  wording: RefusalWording,
): ImportAdmissionHint | undefined {
  const rows = size.rows ?? 0;
  const bytes = size.bytes ?? 0;
  if (rows <= 0 && bytes <= 0) return undefined;
  if (size.rows === undefined) return { incomingBytes: bytes, wording };
  return { incomingEvents: rows + Math.ceil(bytes / IMPORT_INPUT_BYTES_PER_EVENT), wording };
}

/** What the collect's evidence step needs from the collect — its own deps, passed through. */
export interface HuntEvidenceDeps {
  persistEvidence: PersistEvidence;
  resolveImportKind: UploadPlanDeps["resolveImportKind"];
  getControl: (caseId: string) => Promise<{ enabled: boolean }>;
  recordImportFailure?: (
    caseId: string,
    kind: string,
    filename: string,
    err: unknown,
    debug?: ImportDebugRecorder,
  ) => void;
  logLine: (msg: string) => void;
}

export interface HuntEvidenceInput<T extends { name: string; file: string }> {
  caseId: string;
  huntId: string;
  /** The artifacts' scratch files, as step 1 of the collect wrote them. */
  artifacts: T[];
  totalRows: number;
  uploads: HuntUpload[];
  superOnly: boolean;
}

/**
 * The collect's evidence step: store every artifact, plan the uploads and store those that will
 * import, and size
 * the import section that follows. Returns what the section imports and the guard's hint.
 * `onAttempt` is told which artifact's import attempt is in progress — see storeHuntArtifacts.
 */
export async function storeHuntEvidence<T extends { name: string; file: string }>(
  deps: HuntEvidenceDeps,
  input: HuntEvidenceInput<T>,
  onAttempt: (debug: ImportDebugRecorder | undefined) => void,
) {
  const { caseId } = input;
  // The rows first: they are fetched and on scratch disk, and nothing that can fail — the upload
  // plan reads the case's AI toggle — may run before they are stored.
  const artifacts = await storeHuntArtifacts(
    deps.persistEvidence,
    caseId,
    input.huntId,
    input.artifacts,
    onAttempt,
  );
  onAttempt(undefined); // every artifact is stored; a later failure is not one of theirs
  const { planned } = await planUploads(input.uploads, {
    resolveImportKind: deps.resolveImportKind,
    aiEnabled: async () => (await deps.getControl(caseId)).enabled,
    superOnly: input.superOnly,
    logLine: deps.logLine,
  });
  const uploads = await storeUploads(deps.persistEvidence, caseId, planned, (p, e) => {
    deps.logLine(`[velociraptor] upload import failed (${p.up.name}): ${(e as Error).message}`);
    deps.recordImportFailure?.(caseId, `velociraptor-upload:${p.kind}`, p.up.name, e, p.debug); // FAILED line (#1438)
  });
  const bytes = utf8Bytes(uploads.map((u) => u.up.content));
  return {
    artifacts,
    uploads,
    hint: evidenceSizeHint({ rows: input.totalRows, bytes }, HUNT_REFUSAL_WORDING),
  };
}
