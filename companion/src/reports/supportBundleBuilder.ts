import { basename, dirname, join } from "node:path";
import { homedir } from "node:os";
import { open, readdir } from "node:fs/promises";
import { deriveKnownEntities, type CustomEntity, type KnownEntities } from "../analysis/anonymize.js";
import { collectEnvSecrets, createSupportRedactor } from "../analysis/supportLogRedact.js";
import { countNewlines, describeImportShape } from "../analysis/importShape.js";
import {
  SUPPORT_LOG_CAPS,
  SUPPORT_MAX_SHAPE_REPORTS,
  assembleSupportBundle,
  rowFromMessage,
  tailLines,
  tailText,
  type SupportImportReport,
  type SupportLogPart,
} from "../analysis/supportBundleZip.js";
import type { ImporterFailure } from "../analysis/diagnostics.js";
import { sanitizeImportDebugSummary } from "../analysis/importDebug.js";
import type { LogPaths } from "../logging/logger.js";
import { isValidCaseId, type CaseStore } from "../storage/caseStore.js";
import { openCaseFile, readCaseFileTail, type CaseScope } from "../storage/caseFileRead.js";

// I/O half of the redacted support bundle (#1735). One redactor instance per bundle, so a real value
// gets the same placeholder in every file. The redactor's vocabulary is every case's ID, name and
// investigator, plus the entity lists (hosts, accounts, domains, analyst and auto-discovered
// entities) of every case the selected logs mention. A case whose vocabulary cannot be loaded does
// not weaken the redaction: its lines are withheld instead (fail-closed).

const SHAPE_HEAD_BYTES = 1024 * 1024;
const SHAPE_SCAN_BUDGET_BYTES = 256 * 1024 * 1024;
const SHAPE_SCAN_PER_FILE_BYTES = 64 * 1024 * 1024;
const SCAN_CHUNK_BYTES = 1024 * 1024;

export interface SupportBundleDeps {
  store: Pick<CaseStore, "casesRoot" | "listCases" | "caseDir" | "importsDir" | "caseExists">;
  loadState?: (caseId: string) => Promise<Parameters<typeof deriveKnownEntities>[0]>;
  loadCustomEntities?: (caseId: string) => Promise<CustomEntity[]>;
  loadDiscovered?: (caseId: string) => Promise<{ discovered: CustomEntity[] }>;
  logPaths: LogPaths | null;
  recentImportFailures: readonly ImporterFailure[];
  /** True when this requester may see this case (no password, or unlocked in this session). */
  canSee: (caseId: string) => boolean;
  env?: Record<string, string | undefined>;
  /** The last `maxBytes` of a file and its full size. Injectable for tests; see readFileTail. */
  readTail?: (path: string, maxBytes: number) => Promise<{ bytes: Buffer; size: number }>;
}

/**
 * Read only the end of a log. A session log on a long-running install, or a debug log with a raised
 * cap, can be gigabytes; reading it whole to keep 5 MB would stall or kill the server (#1735 review).
 */
export async function readFileTail(path: string, maxBytes: number): Promise<{ bytes: Buffer; size: number }> {
  const handle = await open(path, "r");
  try {
    const { size } = await handle.stat();
    const length = Math.min(size, Math.max(0, maxBytes));
    const bytes = Buffer.alloc(length);
    if (length > 0) await handle.read(bytes, 0, length, size - length);
    return { bytes, size };
  } finally {
    await handle.close();
  }
}

/** A tail read that cut the file loses its first, partial line (see tailLines). */
function cutTail(t: { bytes: Buffer; size: number }): { text: string; truncated: boolean } {
  if (t.bytes.length >= t.size) return { text: t.bytes.toString("utf8"), truncated: false };
  return tailLines(Buffer.concat([Buffer.from([0x00]), t.bytes]), t.bytes.length);
}

export interface SupportBundleRequest {
  generatedAt: string;
  version: string;
  diagnosticsText: string;
  supportJson: string;
  caseId?: string;
  includeCaseLog: boolean;
}

async function readTail(deps: SupportBundleDeps, path: string, maxBytes: number): Promise<SupportLogPart> {
  try {
    return cutTail(await (deps.readTail ?? readFileTail)(path, maxBytes));
  } catch {
    return { text: "", truncated: false, omitted: "the log file could not be read." };
  }
}

async function readDebugTail(deps: SupportBundleDeps): Promise<SupportLogPart> {
  const files = deps.logPaths?.debugLog;
  if (!files) return { text: "", truncated: false, omitted: "the always-on debug log is turned off." };
  // Newest first: the current file's tail, then only as much of the previous file as still fits.
  const read = deps.readTail ?? readFileTail;
  const tailOf = async (path: string, max: number) => {
    try {
      return await read(path, max);
    } catch {
      return { bytes: Buffer.alloc(0), size: 0 }; // a missing half is normal before the first rotation
    }
  };
  const cap = SUPPORT_LOG_CAPS.debugBytes;
  const current = await tailOf(files.current, cap);
  if (current.bytes.length < current.size) return cutTail(current);
  const room = cap - current.bytes.length;
  const previous = room > 0 ? await tailOf(files.previous, room) : { bytes: Buffer.alloc(0), size: 0 };
  const older = cutTail(previous);
  return {
    text: older.text + current.bytes.toString("utf8"),
    truncated: older.truncated || (room <= 0 && previous.size > 0),
  };
}

function mentioned(caseIds: readonly string[], texts: readonly string[]): string[] {
  return caseIds.filter((id) => texts.some((t) => t.includes(id)));
}

async function listImportNames(deps: SupportBundleDeps, caseId: string): Promise<string[]> {
  try {
    return await readdir(deps.store.importsDir(caseId));
  } catch {
    return [];
  }
}

/** Vocabulary of the referenced cases. A case that fails to load is returned in `withheld`. */
async function loadVocabulary(
  deps: SupportBundleDeps,
  caseIds: readonly string[],
): Promise<{ known: KnownEntities; withheld: string[] }> {
  const known: KnownEntities = { hosts: [], accounts: [], usernames: [], internalDomains: [], custom: [] };
  const withheld: string[] = [];
  for (const caseId of caseIds) {
    try {
      if (deps.loadState) {
        const derived = deriveKnownEntities(await deps.loadState(caseId));
        known.hosts.push(...derived.hosts);
        known.accounts.push(...derived.accounts);
        known.usernames!.push(...(derived.usernames ?? []));
        known.internalDomains.push(...derived.internalDomains);
        known.custom!.push(...(derived.custom ?? []));
      }
      if (deps.loadCustomEntities) known.custom!.push(...(await deps.loadCustomEntities(caseId)));
      if (deps.loadDiscovered) known.custom!.push(...(await deps.loadDiscovered(caseId)).discovered);
    } catch {
      withheld.push(caseId);
    }
  }
  return { known, withheld };
}

async function scanShape(scope: CaseScope, path: string, budget: { left: number }) {
  // One judged handle (#1846): no link at the file or above it, and a FIFO is refused, not waited on.
  const { handle } = await openCaseFile(scope, path);
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new Error("not a regular file");
    const head = Buffer.alloc(Math.min(SHAPE_HEAD_BYTES, st.size));
    await handle.read(head, 0, head.length, 0);
    const limit = Math.min(st.size, SHAPE_SCAN_PER_FILE_BYTES, Math.max(0, budget.left));
    const chunk = Buffer.alloc(SCAN_CHUNK_BYTES);
    let count = 0;
    let pos = 0;
    while (pos < limit) {
      const { bytesRead } = await handle.read(chunk, 0, Math.min(chunk.length, limit - pos), pos);
      if (bytesRead === 0) break;
      count += countNewlines(chunk.subarray(0, bytesRead));
      pos += bytesRead;
    }
    budget.left -= pos;
    return describeImportShape(head, st.size, { count, exact: pos >= st.size });
  } finally {
    await handle.close();
  }
}

/**
 * The ring holds the stored `NNNN_name` for most paths and the ORIGINAL name for a failure before the
 * copy (an import-file request whose evidence copy collided). Prefer an exact match, else the newest
 * stored copy of that original name. Always a bare entry of the imports folder — never a path.
 */
async function storedImportName(deps: SupportBundleDeps, caseId: string, name: string): Promise<string> {
  const names = await listImportNames(deps, caseId);
  if (names.includes(name)) return name;
  const copies = names.filter((n) => /^\d{4,}_/.test(n) && n.slice(n.indexOf("_") + 1) === name).sort();
  return copies.at(-1) ?? name;
}

type Redact = (text: string) => string;

async function importReports(
  deps: SupportBundleDeps,
  redact: Redact,
): Promise<{ reports: SupportImportReport[]; omitted: string[] }> {
  const seen = new Set<string>();
  const reports: SupportImportReport[] = [];
  const omitted: string[] = [];
  const budget = { left: SHAPE_SCAN_BUDGET_BYTES };
  let dropped = 0;
  for (const f of deps.recentImportFailures) {
    const name = basename(f.filename);
    const key = `${f.caseId}\u0000${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (reports.length >= SUPPORT_MAX_SHAPE_REPORTS) {
      dropped++;
      continue;
    }
    const base: SupportImportReport = {
      at: f.at,
      kind: redact(f.kind),
      caseToken: redact(f.caseId),
      fileToken: redact(name),
      error: redact(f.error),
      row: rowFromMessage(f.error),
    };
    if (!isValidCaseId(f.caseId) || !deps.canSee(f.caseId)) {
      reports.push({ ...base, shapeUnavailable: "the case is password-protected and locked." });
      continue;
    }
    // Importer detail follows the same lock decision as the shape. It is NOT run through the text
    // redactor (field paths such as host.name would read as domains); it is re-validated instead.
    const importer = sanitizeImportDebugSummary(f.importer);
    if (importer) base.importer = importer;
    if (budget.left <= 0) {
      reports.push({ ...base, shapeUnavailable: "the scan budget for this bundle was used up." });
      continue;
    }
    try {
      const stored = await storedImportName(deps, f.caseId, name);
      const scope = { casesRoot: deps.store.casesRoot, caseDir: deps.store.caseDir(f.caseId) };
      const shape = await scanShape(scope, join(deps.store.importsDir(f.caseId), stored), budget);
      reports.push({ ...base, shape });
    } catch {
      reports.push({ ...base, shapeUnavailable: "the stored file is missing or could not be read safely." });
    }
  }
  if (dropped > 0)
    omitted.push(`${dropped} more failed import(s) — only the newest ${SUPPORT_MAX_SHAPE_REPORTS}.`);
  return { reports, omitted };
}

function caseLogPath(deps: SupportBundleDeps, caseId: string): string | null {
  const session = deps.logPaths?.sessionLogPath;
  return session ? join(deps.store.caseDir(caseId), "logs", basename(session)) : null;
}

async function readCaseLog(
  deps: SupportBundleDeps,
  req: SupportBundleRequest,
): Promise<SupportLogPart | undefined> {
  if (!req.includeCaseLog) return undefined;
  const id = req.caseId;
  if (!id || !isValidCaseId(id) || !(await deps.store.caseExists(id))) {
    return { text: "", truncated: false, omitted: "no case is open." };
  }
  if (!deps.canSee(id))
    return { text: "", truncated: false, omitted: "the case is password-protected and locked." };
  const path = caseLogPath(deps, id);
  if (!path) return { text: "", truncated: false, omitted: "file logging is off." };
  // The case log sits inside the case folder, so it is read from one judged handle (#1846): a name
  // swapped for a link would put another case's log, or a host file, into the bundle.
  const scope = { casesRoot: deps.store.casesRoot, caseDir: deps.store.caseDir(id) };
  const guarded = deps.readTail
    ? deps
    : { ...deps, readTail: (p: string, n: number) => readCaseFileTail(scope, p, n) };
  return readTail(guarded, path, SUPPORT_LOG_CAPS.caseBytes);
}

export async function buildSupportBundleZip(
  deps: SupportBundleDeps,
  req: SupportBundleRequest,
): Promise<Buffer> {
  const session = deps.logPaths?.sessionLogPath;
  const sessionLog = session
    ? await readTail(deps, session, SUPPORT_LOG_CAPS.sessionBytes)
    : { text: "", truncated: false, omitted: "file logging is off." };
  const debugLog = await readDebugTail(deps);
  const caseLog = await readCaseLog(deps, req);

  const cases = await deps.store.listCases();
  const texts = [sessionLog.text, debugLog.text, caseLog?.text ?? "", req.diagnosticsText];
  const referenced = mentioned(
    cases.map((c) => c.caseId),
    [...texts, ...deps.recentImportFailures.map((f) => f.caseId)],
  );
  const { known, withheld } = await loadVocabulary(deps, referenced);
  const people: CustomEntity[] = cases
    .map((c) => c.investigator?.trim())
    .filter((v): v is string => !!v)
    .map((value) => ({ value, category: "PERSON" as const }));
  known.custom = [...(known.custom ?? []), ...people];

  const fileNames = new Set<string>(deps.recentImportFailures.map((f) => basename(f.filename)));
  for (const id of referenced) for (const n of await listImportNames(deps, id)) fileNames.add(n);

  const roots = [deps.store.casesRoot, homedir(), process.cwd()];
  if (session) roots.push(dirname(session));
  const redactor = createSupportRedactor({
    cases: cases.map((c) => ({ caseId: c.caseId, title: c.name })),
    fileNames: [...fileNames],
    secrets: collectEnvSecrets(deps.env ?? process.env),
    roots,
    known,
  });
  const redactPart = (part: SupportLogPart, cap: number): SupportLogPart => {
    if (part.omitted) return part;
    const redacted = tailText(redactor.redactLog(part.text, { withheldCaseIds: withheld }), cap);
    return { text: redacted.text, truncated: part.truncated || redacted.truncated };
  };
  const redact: Redact = (t) => redactor.redactText(t);

  const { reports, omitted } = await importReports(deps, redact);
  const caseToken =
    req.includeCaseLog && req.caseId && isValidCaseId(req.caseId) ? redact(req.caseId) : undefined;
  return assembleSupportBundle({
    generatedAt: req.generatedAt,
    version: req.version,
    diagnosticsText: redactor.redactLog(req.diagnosticsText, { withheldCaseIds: withheld }),
    supportJson: redact(req.supportJson),
    sessionLog: redactPart(sessionLog, SUPPORT_LOG_CAPS.sessionBytes),
    debugLog: redactPart(debugLog, SUPPORT_LOG_CAPS.debugBytes),
    caseLog: caseLog ? redactPart(caseLog, SUPPORT_LOG_CAPS.caseBytes) : undefined,
    caseToken,
    imports: reports,
    importsOmitted: omitted,
    summary: redactor.summary(),
    withheldCases: withheld.length,
  });
}
