// S3 ransomware precursors, raised only in context (#2542, user decision Q1).
//
// Before overwriting or deleting objects, an S3 ransomware operator checks whether the bucket can
// recover them: `GetBucketVersioning`, `GetBucketObjectLockConfiguration` — or turns versioning off
// with `PutBucketVersioning` (Suspended). On their own these are routine: every S3 console bucket
// page and every inventory tool makes the two reads, so a blanket grade would bury the timeline.
// They are raised to High only when the SAME access key made a successful privileged change
// EARLIER in the same upload: a policy grant to the caller itself, or a new access key
// (`CreateAccessKey`). Otherwise the row is left exactly as the importer graded it.
//
// Scope, said on the row: one upload (or one streamed batch). Compared by `eventTime`, never by file
// position. Only ever raises. Every change and check row also gets a `canonical.awsPrecursor` block,
// whether or not it joins here: the case-wide join reads that block when the other half arrives in
// another file (cloudPrecursorMerge.ts, ingest/cloudPrecursorPromote.ts, #2563).

import { boundedAggKey } from "./aggKey.js";
import { readAccessKeyIssuance } from "./awsAccessKeyIssuance.js";
import { isSelfGrant } from "./iamChange.js";
import { getCI, getPath, normalizeTime, str, type MappedEvent } from "./siemImport.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { AwsPrecursorBlock } from "./canonicalAwsPrecursor.js";
import { raisePrecursorCheck, type PrecursorChange } from "./cloudPrecursorMerge.js";
import { neutraliseRowNotes } from "./derivedNote.js";

type Row = Record<string, unknown>;

const PRECURSOR_READS = new Set(["getbucketversioning", "getbucketobjectlockconfiguration"]);
const CALL_MAX = 160;

const timeOf = (rec: Row): number => Date.parse(normalizeTime(str(getCI(rec, "eventTime"))));
const keyOf = (rec: Row): string => str(getPath(rec, "userIdentity.accessKeyId")).trim().toLowerCase();
const service = (rec: Row): string =>
  str(getCI(rec, "eventSource"))
    .trim()
    .toLowerCase()
    .replace(/\.amazonaws\.com$/, "");

/** The privileged change a record is, when it succeeded: a self policy grant or a new access key. */
function privilegedChange(rec: Row): string | null {
  if (service(rec) !== "iam" || str(getCI(rec, "errorCode")).trim()) return null;
  const name = str(getCI(rec, "eventName")).trim();
  if (readAccessKeyIssuance(rec)) return `iam ${name}`;
  if (isSelfGrant(name, getCI(rec, "requestParameters"), getCI(rec, "userIdentity")))
    return `iam ${name} (granted to the caller itself)`;
  return null;
}

/** The check a record is: a recovery check on a bucket, or versioning being suspended. */
function precursorCheck(rec: Row): string | null {
  if (service(rec) !== "s3") return null;
  const name = str(getCI(rec, "eventName")).trim();
  if (PRECURSOR_READS.has(name.toLowerCase())) return `s3 ${name}`;
  const suspends =
    name.toLowerCase() === "putbucketversioning" &&
    /^suspended$/i.test(str(getPath(rec, "requestParameters.VersioningConfiguration.Status")).trim());
  return suspends ? `s3 ${name} (Suspended)` : null;
}

/** The join block a record's row carries, or null when the record is neither half. */
function precursorBlock(rec: Row | undefined): AwsPrecursorBlock | null {
  if (!rec || !keyOf(rec)) return null;
  const change = privilegedChange(rec);
  if (change) return { role: "change", call: change.slice(0, CALL_MAX) };
  const check = precursorCheck(rec);
  return check ? { role: "check", call: check.slice(0, CALL_MAX) } : null;
}

/** The earliest successful privileged change per access key. */
function earliestChanges(recs: readonly Row[]): Map<string, PrecursorChange> {
  const changes = new Map<string, PrecursorChange>();
  for (const rec of recs) {
    const call = privilegedChange(rec);
    const key = keyOf(rec);
    const time = timeOf(rec);
    if (!call || !key || !Number.isFinite(time)) continue;
    const cur = changes.get(key);
    if (!cur || time < cur.time) changes.set(key, { time, call: call.slice(0, CALL_MAX) });
  }
  return changes;
}

/** The row with its join block; a suspend is kept apart from an enable under aggregation. */
function stamped(row: MappedEvent, block: AwsPrecursorBlock): MappedEvent {
  if (!row.canonical) return row;
  return {
    ...row,
    canonical: { ...row.canonical, awsPrecursor: block },
    ...(block.call.endsWith("(Suspended)") ? { aggKey: boundedAggKey(`${row.aggKey}|suspended`) } : {}),
  };
}

/** The fields the shared join reads, from an importer row (its time is the record's own). */
function asJoinRow(row: MappedEvent): ForensicEvent {
  return {
    id: "",
    timestamp: row.timestamp,
    description: row.description,
    severity: row.severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(row.canonical ? { canonical: row.canonical } : {}),
  };
}

/**
 * Stamp each change and check row with its join block, then raise each check whose access key made a
 * privileged change earlier in this upload. `recs[i]` is the raw record behind `rows[i]`.
 */
export function raiseRansomwarePrecursors(rows: readonly MappedEvent[], recs: readonly Row[]): MappedEvent[] {
  const changes = earliestChanges(recs);
  return rows.map((row, i) => {
    const block = precursorBlock(recs[i]);
    if (!block) return row;
    const marked = stamped(row, block);
    if (block.role !== "check" || !changes.size) return marked;
    // The note goes on before aggregation, so neutralise forged notes in the row first (#2574).
    const raised = raisePrecursorCheck(asJoinRow(neutraliseRowNotes(marked)), changes, "upload");
    if (!raised) return marked;
    return {
      ...marked,
      severity: raised.severity,
      description: raised.description,
      // Never folded with the same call made before the change.
      aggKey: boundedAggKey(`${marked.aggKey}|precursor`),
    };
  });
}
