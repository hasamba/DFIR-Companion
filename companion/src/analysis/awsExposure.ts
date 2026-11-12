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
import { policyDoc, trustedOnlyGrant } from "./awsPolicyPrincipals.js";
import { securityGroupRuleReading } from "./awsSecurityGroupRule.js";
import { resourceSharingReading } from "./awsResourceSharing.js";
import { createHash } from "node:crypto";

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

const isWorld = (principal: unknown): boolean =>
  principal === "*" || asList(at(principal, "AWS")).some((p) => str(p).trim() === "*");

const requestedPolicy = (request: Row): unknown => getCI(request, "bucketPolicy") ?? getCI(request, "policy");

/** The trusted-only reading of a bucket policy (#2542): AWS services and/or the bucket's own account. */
function trustedOnlyWords(request: Row, recipient: string): string {
  const grant = trustedOnlyGrant(requestedPolicy(request), recipient);
  if (!grant) return "";
  const who = [
    ...(grant.services.length ? [`AWS services (${listed(grant.services)})`] : []),
    ...(grant.ownAccount ? ["this account"] : []),
  ];
  return `policy grants only ${who.join(" and ")}`;
}

function policyReading(request: Row, recipient: string): string {
  const bucket = show(str(getCI(request, "bucketName")) || "?", 60);
  const doc = policyDoc(requestedPolicy(request));
  if (!doc) return "";
  const world = (asList(getCI(doc, "Statement")).filter(isObject) as Row[]).filter(
    (s) => /^allow$/i.test(str(getCI(s, "Effect"))) && isWorld(getCI(s, "Principal")),
  );
  if (world.some((s) => getCI(s, "Condition") === undefined))
    return `makes bucket ${bucket} public (policy allows Principal "*" with no condition)`;
  if (world.length)
    return `bucket ${bucket} policy allows Principal "*" under a condition (shown, not evaluated)`;
  const trusted = trustedOnlyWords(request, recipient);
  return trusted ? `bucket ${bucket} ${trusted}` : "";
}

/**
 * The readings added by #2605 — a security-group ingress rule, an RDS snapshot share, a Lambda
 * resource-policy grant — each gated on the service that recorded the call. "" for any other call.
 */
function requestReading(eventName: string, eventSource: string, request: Row, recipient: string): string {
  return (
    securityGroupRuleReading(eventName, eventSource, request) ||
    resourceSharingReading(eventName, eventSource, request, recipient)
  );
}

/** The exposure posture a request states (#2306, #2605), or "". */
export function awsExposurePosture(
  eventName: string,
  request: unknown,
  errorCode: string,
  recipient = "",
  eventSource = "",
): string {
  if (!isObject(request)) return "";
  const n = eventName.toLowerCase();
  const reading =
    n === "modifysnapshotattribute"
      ? snapshotReading(request)
      : n === "putbucketacl"
        ? aclReading(request)
        : n === "putbucketpolicy"
          ? policyReading(request, recipient)
          : requestReading(eventName, eventSource, request, recipient);
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
 * - A ModifySnapshotAttribute whose sole effect is removing sharing is lowered, to Low: it stays in
 *   the forensic timeline (an un-share can be cleanup after exfiltration) but is not High. Every
 *   share, a mixed add/remove, and any missing or unreadable request keeps the table's High.
 * - A PutBucketPolicy is Medium when EVERY Allow principal is an AWS service principal or the
 *   bucket's own (recipient) account (#2542, user decision Q3 — this reverses the #2345 deferral,
 *   which held that an empty reading could not tell a private policy from a cross-account grant).
 *   The reading is positive: an outside account, `*` (even conditional), `NotPrincipal`, a
 *   federated principal, no Allow statement, or a missing / unreadable / truncated policy keeps the
 *   table's High.
 * - PutBucketAcl is not lowered.
 */
export function awsExposureGrade(eventName: string, request: unknown, recipient = ""): Severity | undefined {
  if (!isObject(request)) return undefined;
  const n = eventName.toLowerCase();
  if (n === "putbucketpolicy")
    return trustedOnlyGrant(requestedPolicy(request), recipient) ? "Medium" : undefined;
  if (n !== "modifysnapshotattribute") return undefined;
  return snapshotRemovesOnly(request) ? "Low" : undefined;
}

/**
 * Both readings of one raw CloudTrail record, for the importer's single call site, plus the
 * aggregation-key segment of a #2605 reading (rendered in the object slot): two ingress rules on different ports, or two grants to
 * different principals, by the same caller never fold into one counted row. The digest is over the
 * whole request (the reading is bounded, the request is not); "" when there is no such reading.
 */
export function awsRecordExposure(
  eventName: string,
  rec: Row,
  recipient: string,
): { posture: string; object: string; grade: Severity | undefined; keySegment: string } {
  const request = getCI(rec, "requestParameters");
  const source = str(getCI(rec, "eventSource"));
  const own = isObject(request) ? requestReading(eventName, source, request, recipient) : "";
  const reading = awsExposurePosture(eventName, request, str(getCI(rec, "errorCode")), recipient, source);
  // A #2605 reading names a port list or a principal and its resource: it goes in the row's wider
  // object slot, so the deciding value is not clipped off the narrow posture slot.
  return {
    posture: own ? "" : reading,
    object: own ? reading : "",
    grade: awsExposureGrade(eventName, request, recipient),
    keySegment: own
      ? `|exposure|${createHash("sha256").update(JSON.stringify(request)).digest("hex").slice(0, 16)}`
      : "",
  };
}
