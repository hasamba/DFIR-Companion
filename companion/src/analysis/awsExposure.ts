// Data-exposure readings of three CloudTrail calls (#2306): the importer grades ModifySnapshotAttribute,
// PutBucketAcl and PutBucketPolicy High on the event name alone, but its description said nothing
// about what the request did — a snapshot shared with the world read the same as one un-shared, a
// public bucket policy the same as an account-scoped one. This reads the request and states it, so
// an analyst (and the tagger's exposure rules in data/tags.yaml) can tell them apart.
//
// What one reading establishes, and what it never says:
//   - the REQUESTED posture of a call, as its own parameters state it — never whether it took effect
//     (S3 Block Public Access can override a public ACL or policy, and that is not in the record);
//   - "public" only for the documented world principals: a snapshot `group: all`, the S3 AllUsers /
//     AuthenticatedUsers grantee groups or their canned ACLs, an Allow statement for Principal "*"
//     with no Condition. A conditional "*" statement is shown as conditional, never as public. Pure.

import { getCI, isObject, str } from "./siemImport.js";
import { show } from "./loggingChange.js";
import type { Severity } from "./stateTypes.js";

type Row = Record<string, unknown>;
const LIST_MAX = 5;

const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const at = (o: unknown, ...keys: string[]): unknown => {
  let cur = o;
  for (const k of keys) cur = isObject(cur) ? getCI(cur, k) : undefined;
  return cur;
};
const listed = (names: string[]): string =>
  names
    .slice(0, LIST_MAX)
    .map((n) => show(n, 60))
    .join(", ") + (names.length > LIST_MAX ? ` (+${names.length - LIST_MAX} more)` : "");

function snapshotReading(request: Row): string {
  const snap = show(str(getCI(request, "snapshotId")) || "?", 60);
  const side = (k: "add" | "remove") =>
    asList(at(request, "createVolumePermission", k, "items")).filter(isObject) as Row[];
  const describe = (items: Row[]): { world: boolean; accounts: string[] } => ({
    world: items.some((i) => /^all$/i.test(str(getCI(i, "group")))),
    accounts: items.map((i) => str(getCI(i, "userId")).trim()).filter(Boolean),
  });
  const add = describe(side("add"));
  const remove = describe(side("remove"));
  if (add.world) return `shares snapshot ${snap} publicly (createVolumePermission group "all")`;
  if (add.accounts.length) return `shares snapshot ${snap} with account ${listed(add.accounts)}`;
  if (remove.world || remove.accounts.length)
    return `removes sharing of snapshot ${snap}${remove.world ? " (public)" : ` from account ${listed(remove.accounts)}`}`;
  return "";
}

const PUBLIC_CANNED = /^(public-read|public-read-write|authenticated-read)$/i;
const PUBLIC_GROUP = /acs\.amazonaws\.com\/groups\/global\/(AllUsers|AuthenticatedUsers)/i;

function aclReading(request: Row): string {
  const bucket = show(str(getCI(request, "bucketName")) || "?", 60);
  const canned = asList(getCI(request, "x-amz-acl")).map((v) => str(v).trim());
  const cannedPublic = canned.find((c) => PUBLIC_CANNED.test(c));
  if (cannedPublic) return `makes bucket ${bucket} public (canned ACL ${show(cannedPublic, 30)})`;
  const grants = asList(at(request, "AccessControlPolicy", "AccessControlList", "Grant")).filter(
    isObject,
  ) as Row[];
  for (const g of grants) {
    const group = PUBLIC_GROUP.exec(str(at(g, "Grantee", "URI")));
    if (group)
      return `makes bucket ${bucket} public (ACL grants ${show(str(getCI(g, "Permission")) || "?", 20)} to ${group[1]})`;
  }
  for (const header of [
    "x-amz-grant-read",
    "x-amz-grant-write",
    "x-amz-grant-read-acp",
    "x-amz-grant-write-acp",
    "x-amz-grant-full-control",
  ]) {
    const group = PUBLIC_GROUP.exec(asList(getCI(request, header)).map(str).join(" "));
    if (group)
      return `makes bucket ${bucket} public (${header.replace("x-amz-grant-", "")} granted to ${group[1]})`;
  }
  return "";
}

function policyDoc(v: unknown): Row | null {
  if (isObject(v)) return v;
  if (typeof v !== "string") return null;
  try {
    const parsed: unknown = JSON.parse(v);
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

const isWorld = (principal: unknown): boolean =>
  principal === "*" || asList(at(principal, "AWS")).some((p) => str(p).trim() === "*");

function policyReading(request: Row): string {
  const bucket = show(str(getCI(request, "bucketName")) || "?", 60);
  const doc = policyDoc(getCI(request, "bucketPolicy") ?? getCI(request, "policy"));
  if (!doc) return "";
  const world = (asList(getCI(doc, "Statement")).filter(isObject) as Row[]).filter(
    (s) => /^allow$/i.test(str(getCI(s, "Effect"))) && isWorld(getCI(s, "Principal")),
  );
  if (world.some((s) => getCI(s, "Condition") === undefined))
    return `makes bucket ${bucket} public (policy allows Principal "*" with no condition)`;
  if (world.length)
    return `bucket ${bucket} policy allows Principal "*" under a condition (shown, not evaluated)`;
  return "";
}

/** The exposure posture a ModifySnapshotAttribute / PutBucketAcl / PutBucketPolicy request states, or "". */
export function awsExposurePosture(eventName: string, request: unknown, errorCode: string): string {
  if (!isObject(request)) return "";
  const n = eventName.toLowerCase();
  const reading =
    n === "modifysnapshotattribute"
      ? snapshotReading(request)
      : n === "putbucketacl"
        ? aclReading(request)
        : n === "putbucketpolicy"
          ? policyReading(request)
          : "";
  return reading && errorCode ? `requested: ${reading} — failed (${show(errorCode, 30)})` : reading;
}

// True only when a ModifySnapshotAttribute request positively states that its sole effect is
// removing sharing: no add side at all (an add side in a shape this reader does not understand is
// unknown, not "none"), and every removal item names the world group or an account.
function snapshotRemovesOnly(request: Row): boolean {
  const perm = getCI(request, "createVolumePermission");
  if (!isObject(perm)) return false;
  const add = getCI(perm, "add");
  if (add !== undefined && add !== null) {
    if (!isObject(add)) return false;
    if (asList(getCI(add, "items")).length) return false;
  }
  const remove = asList(at(perm, "remove", "items"));
  return (
    remove.length > 0 &&
    remove.every(
      (i) => isObject(i) && (/^all$/i.test(str(getCI(i, "group"))) || str(getCI(i, "userId")).trim() !== ""),
    )
  );
}

/**
 * The base grade the request itself establishes (#2338), or undefined to keep the action table's.
 * Only a ModifySnapshotAttribute whose sole effect is removing sharing is lowered, to Low: it stays
 * in the forensic timeline (an un-share can be cleanup after exfiltration) but is not High. Every
 * share, a mixed add/remove, and any missing or unreadable request keeps the table's High.
 * PutBucketAcl / PutBucketPolicy are deliberately NOT lowered: an empty reading there cannot tell a
 * private policy from a cross-account grant (T1537) or a truncated request — deferred to #2345.
 */
export function awsExposureGrade(eventName: string, request: unknown): Severity | undefined {
  if (!isObject(request)) return undefined;
  if (eventName.toLowerCase() !== "modifysnapshotattribute") return undefined;
  return snapshotRemovesOnly(request) ? "Low" : undefined;
}
