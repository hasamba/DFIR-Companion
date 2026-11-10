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
// Scope, said on the row: one upload (or one streamed window) — a change in another file is not
// seen. Compared by `eventTime`, never by file position. Only ever raises.

import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { readAccessKeyIssuance } from "./awsAccessKeyIssuance.js";
import { isSelfGrant } from "./iamChange.js";
import { getCI, getPath, normalizeTime, str, worst, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

const PRECURSOR_GRADE: Severity = "High";
const PRECURSOR_READS = new Set(["getbucketversioning", "getbucketobjectlockconfiguration"]);

interface Change {
  time: number;
  call: string;
}

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

/** True when a record is a recovery check on a bucket, or versioning being suspended. */
function isPrecursor(rec: Row): boolean {
  if (service(rec) !== "s3") return false;
  const name = str(getCI(rec, "eventName")).trim().toLowerCase();
  if (PRECURSOR_READS.has(name)) return true;
  return (
    name === "putbucketversioning" &&
    /^suspended$/i.test(str(getPath(rec, "requestParameters.VersioningConfiguration.Status")).trim())
  );
}

/** The earliest successful privileged change per access key. */
function earliestChanges(recs: readonly Row[]): Map<string, Change> {
  const changes = new Map<string, Change>();
  for (const rec of recs) {
    const call = privilegedChange(rec);
    const key = keyOf(rec);
    const time = timeOf(rec);
    if (!call || !key || !Number.isFinite(time)) continue;
    const cur = changes.get(key);
    if (!cur || time < cur.time) changes.set(key, { time, call });
  }
  return changes;
}

/**
 * Raise each precursor row whose access key made a privileged change earlier in this upload.
 * `recs[i]` is the raw record behind `rows[i]`.
 */
export function raiseRansomwarePrecursors(rows: readonly MappedEvent[], recs: readonly Row[]): MappedEvent[] {
  const changes = earliestChanges(recs);
  if (!changes.size) return [...rows];
  return rows.map((row, i) => {
    const rec = recs[i];
    if (!rec || !isPrecursor(rec)) return row;
    const change = changes.get(keyOf(rec));
    const time = timeOf(rec);
    if (!change || !Number.isFinite(time) || change.time >= time) return row;
    const at = new Date(change.time).toISOString().slice(0, 19);
    return {
      ...row,
      severity: worst(row.severity, PRECURSOR_GRADE),
      description: `${row.description} [ransomware precursor: the same access key made a privileged change earlier in this upload — ${change.call} at ${at}Z]`,
      // Never folded with the same call made before the change.
      aggKey: boundedAggKey(`${row.aggKey}|precursor`),
    };
  });
}
