import type { ForensicEvent } from "./stateTypes.js";
import {
  cleanDescription,
  eventHashes,
  eventPath,
  LEAPP_ROW,
  MOBILE_ORIGIN_TAG,
  shortHost,
  withSignature,
} from "./correlate.js";
import { yearOf } from "./timeYearClamp.js";
import { DERIVED_NOTE_NAMES } from "./derivedNote.js";
import { isHiddenStream, isMark } from "./downloadExecution.js";
import { TIMESTOMP_CORROBORATION_MARKER } from "./timestompCorroborate.js";
import { isRpcPipeCall, isSmbStagedWrite } from "./smbExecution.js";
import { PRECURSOR_CLASSES } from "./ransomwarePrecursor.js";
import {
  CLOUD_AUDIT_RE,
  COVERAGE_EVENT_ID,
  isInstanceRoleIdentity,
  metadataTarget,
  searchText,
} from "./cloudMetadataAccess.js";
import { readCloudRecord } from "./cloudBulkRead.js";
import { readBrowsing } from "./serviceAccountBrowsing.js";
import { commandOf, configRisks, escapeBehavior } from "./containerEscape.js";
import { isTransferToolRow } from "./transferToolStaging.js";

/**
 * What the incremental importer merge keeps per forensic row (#1874), computed from the row exactly
 * as the next merge will read it. Stored in the case database (caseSqliteWorkerMerge.ts).
 *
 * - `timeMs`: the time byEventTime sorts on (null when unparseable — it sorts last).
 * - `year` / `yearInferred`: the clamp's histogram vote and whether the clamp may move the row.
 * - `keys`: every correlation bucket the row sits in (correlate.ts groupEvents), UNSCOPED — a whole
 *   hash or path bucket, never the host-split part, because host scoping reads the whole bucket.
 * - `flags`: TRIGGER when some chain pass could act on the case because of this row (then the merge
 *   takes the full path); LOAD when a pass that reads only rows like it could (the merge then reads
 *   every such row, and the pass runs over all of them); PROCESS / CLOUD_AUDIT feed the metadata
 *   coverage row's case-wide condition.
 */
export interface MergeIndexEntry {
  timeMs: number | null;
  year: number | null;
  yearInferred: boolean;
  keys: string[];
  flags: number;
}

export const MERGE_FLAG_TRIGGER = 1;
export const MERGE_FLAG_PROCESS = 2;
export const MERGE_FLAG_CLOUD_AUDIT = 4;
/** A row a subset-safe pass reads: every merge reads all of them (mergeLoadAlways). */
export const MERGE_FLAG_LOAD = 8;

/**
 * The correlation bucket keys of a row, as groupEvents would key it (on its signature-stamped copy).
 * Each step's key is coarser than or equal to the step's own bucket, so a set closed under these keys
 * holds every bucket that touches it whole.
 */
export function correlationKeys(event: ForensicEvent): string[] {
  const e = withSignature(event);
  const keys = new Set<string>();
  const host = shortHost(e.asset);
  const cleaned = cleanDescription(e.description);
  const exact = `${e.timestamp} ${cleaned} ${host}`;
  keys.add(`x:${exact}`);
  // The LEAPP legacy join (#988) pairs an untagged row's exact key with a tagged row's legacy key.
  if (LEAPP_ROW.test(cleaned)) {
    keys.add(
      MOBILE_ORIGIN_TAG.test(cleaned)
        ? `l:${e.timestamp} ${cleaned.replace(MOBILE_ORIGIN_TAG, "")} ${host}`
        : `l:${exact}`,
    );
  }
  if (e.sourceRecordId) keys.add(`r:${e.sourceRecordId} ${host}`);
  for (const h of eventHashes(e)) keys.add(`h:${h}`);
  const path = eventPath(e);
  if (path) keys.add(`p:${path.path}`);
  if (e.pid !== undefined) {
    keys.add(`i:${host}|${e.pid}`);
    if (e.chainSignature) keys.add(`s:${e.chainSignature}`);
  }
  return [...keys];
}

// Derived notes the chain passes never strip or recompute, or that importers and settle write: a row
// carrying one is inert for the chain. Every other registered note belongs to a pass that re-reads or
// strips it, so its presence makes the merge take the full path. A note added to the registry later
// is a trigger until someone shows it is inert.
const INERT_NOTES = new Set([
  "unexpected parent", // processLifetime: per-row rule, marked rows are skipped
  "sacrificial process", // processLifetime: needs an injector, which is a trigger
  "initial access", // initialAccess: marked rows are skipped, never stripped
  "confirmed exfiltration", // exfilCorrelate: never stripped
  "timestomp corroboration", // timestompCorroborate: never stripped
  "ransomware precursors", // ransomwarePrecursor: never stripped; its rows are LOAD rows anyway
  "cloud bulk read", // summaries: inert without read records, which are a trigger
  "renamed binary",
  "build-time",
  "shared source mtime",
  "inherited modified time",
  "CLR usage log",
  "own-child handle",
  "normal OS behaviour",
  "transfer tool staged", // transferToolStaging: its rows are LOAD rows, read on every merge
  "look-alike account", // lookalikeCaseAccount: written by the import settle, no chain pass reads it
]);
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const TRIGGER_NOTE = new RegExp(
  `\\[(?:${DERIVED_NOTE_NAMES.filter((n) => !INERT_NOTES.has(n))
    .map(escapeRe)
    .join("|")}):`,
  "u",
);
const PRECURSOR_TECHNIQUES = new Set(PRECURSOR_CLASSES.flatMap((c) => c.techniques));

/**
 * Why a chain pass could act on the case because of this row, or null. The contract (#1874): when no
 * row of the whole timeline has a trigger, every pass in runTimelineChain is the identity or a
 * per-row rewrite, so running the chain over only the rows a delta touches gives the full result.
 * Each entry is a superset of the pass's own "is there anything to do" test; see the pass modules.
 */
export function mergeTrigger(e: ForensicEvent): string | null {
  const description = e.description ?? "";
  const mitre = e.mitreTechniques ?? [];
  const c = e.canonical;
  if (TRIGGER_NOTE.test(description)) return "a correlation note";
  if ((e.sources ?? []).includes("Email")) return "email delivery";
  if (e.processName && /executable memory region flagged|malfind/i.test(description))
    return "memory injection";
  // The only rows the timestomp pass changes; with none, it returns its input.
  if (
    mitre.includes("T1070.006") &&
    !description.includes(TIMESTOMP_CORROBORATION_MARKER) &&
    /MFT/i.test((e.sources ?? []).join(" "))
  )
    return "timestomp";
  // The download pass's own "anything to corroborate" test; with neither, it only strips its notes.
  if (isMark(e) || isHiddenStream(e)) return "download mark or hidden stream";
  if (c?.quarantine || c?.quarantineAttribute) return "quarantine record";
  if (isSmbStagedWrite(e) || isRpcPipeCall(e) !== null) return "SMB staging or pipe call";
  if (c?.defender) return "Defender record";
  if (c?.mobile) return "mobile record";
  if (c?.event?.category === "process" && (c.event.type === "remote_thread" || c.event.type === "tamper"))
    return "process injection";
  if (/certutil/i.test(`${e.processName ?? ""} ${e.commandLine ?? ""} ${description}`)) return "certutil";
  if (metadataTarget(searchText(e)) !== "" || isInstanceRoleIdentity(`${description} ${e.path ?? ""}`))
    return "instance metadata";
  if (readCloudRecord(e) !== null) return "cloud object read";
  if (c?.event?.type === "storage-key-list") return "storage key listing";
  if (c?.awsCompute) return "AWS compute record";
  if (readBrowsing(e) !== null) return "browsing record";
  const cmd = commandOf(e);
  if (escapeBehavior(cmd).length > 0 || configRisks(cmd).length > 0) return "container command";
  if (e.labIntel !== undefined) return "lab intel";
  return null;
}

/**
 * Whether a pass that reads only its own rows could read this one (#1874): the archive-staging →
 * upload link (exfilCorrelate.ts reads staging rows and transfer candidates, nothing else) and the
 * ransomware-precursor clustering (ransomwarePrecursor.ts reads rows carrying a precursor technique).
 * The transfer-tool staging join (transferToolStaging.ts, #1955) reads only rows whose path names a
 * transfer tool or its config. All are supersets of what the pass reads; the merge reads every such
 * row, so the pass sees all of its input, in timeline order, however many of them the delta touched.
 */
export function mergeLoadAlways(e: ForensicEvent): boolean {
  if (!e.asset) return false;
  const mitre = e.mitreTechniques ?? [];
  if (mitre.includes("T1560.001") || mitre.includes("T1041")) return true;
  if (/^SRUM total:/.test(e.description ?? "")) return true;
  if (isTransferToolRow(e)) return true;
  return mitre.some((t) => PRECURSOR_TECHNIQUES.has(t));
}

/** The index entry of a row as the next merge will read it. `clean` is decided by the caller. */
export function mergeIndexEntry(e: ForensicEvent): MergeIndexEntry {
  const t = Date.parse(e.timestamp);
  let flags = mergeTrigger(e) ? MERGE_FLAG_TRIGGER : 0;
  if (mergeLoadAlways(e)) flags |= MERGE_FLAG_LOAD;
  if (e.id !== COVERAGE_EVENT_ID && e.processName) flags |= MERGE_FLAG_PROCESS;
  if (e.id !== COVERAGE_EVENT_ID && CLOUD_AUDIT_RE.test(e.description ?? "")) flags |= MERGE_FLAG_CLOUD_AUDIT;
  return {
    timeMs: Number.isNaN(t) ? null : t,
    year: yearOf(e.timestamp),
    yearInferred: e.yearInferred === true,
    keys: correlationKeys(e),
    flags,
  };
}
