// CloudTrail's veto on ATT&CK techniques its own reading proves wrong (#2542, user decision Q2).
//
// Bundled Sigma / Suzaku rules are kept verbatim, and a matched rule's techniques join the row. A
// few generic rules select on the event name alone and tag rows that CloudTrail's own content shows
// are not what the technique means. For exactly these, the technique is WITHHELD from the row — the
// rule's match line stays in the message, a note says what was withheld and why, and the grade
// never moves. CloudTrail only: no other importer calls this.
//
// - T1565 (data manipulation) on an S3 object write by an AWS service acting on its own
//   (`userIdentity.type: AWSService`, written by AWS): log delivery, not an attacker.
// - T1486 (data encrypted for impact) on a successful KMS `CreateKey` with `AWS_KMS` origin whose key
//   policy grants the CloudTrail service and otherwise only this account (a `*` held to this account
//   by `kms:CallerAccount` counts): the key CloudTrail makes for its own log files. Keyed on the
//   policy and the origin, never on the user agent or the description (both client-supplied).
// - T1048 (exfiltration over another protocol) on a `PutBucketPolicy` that grants only AWS service
//   principals or this account (the same reading that grades it Medium, awsExposure.ts).
// - T1110 (brute force) on a failed console sign-in when it is the ONLY failure from that source IP
//   within the window and the same principal then signed in from that IP: a mistyped password. The
//   importer's own T1110 and a rule's are withheld alike. Several failures keep T1110.
//
// Cross-record (the sign-in rule) sees one upload, or one streamed window. Pure.

import { boundedAggKey } from "./aggKey.js";
import { trustedOnlyGrant } from "./awsPolicyPrincipals.js";
import { getCI, getPath, normalizeTime, str, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

export interface TagVeto {
  /** Techniques withheld, each with its sub-techniques. */
  techniques: string[];
  reason: string;
}

/** A failed sign-in counts as a lone mistype only when the success follows within this window. */
export const LONE_FAILURE_WINDOW_MS = 10 * 60 * 1000;

const S3_OBJECT_WRITES = new Set([
  "putobject",
  "copyobject",
  "createmultipartupload",
  "uploadpart",
  "uploadpartcopy",
  "completemultipartupload",
]);

const lower = (v: unknown): string => str(v).trim().toLowerCase();
const service = (rec: Row): string => lower(getCI(rec, "eventSource")).replace(/\.amazonaws\.com$/, "");
const action = (rec: Row): string => lower(getCI(rec, "eventName"));
const timeOf = (rec: Row): number => Date.parse(normalizeTime(str(getCI(rec, "eventTime"))));
const failedCall = (rec: Row): boolean => str(getCI(rec, "errorCode")).trim() !== "";

function serviceObjectWrite(rec: Row): TagVeto | undefined {
  if (lower(getPath(rec, "userIdentity.type")) !== "awsservice") return undefined;
  if (service(rec) !== "s3" || !S3_OBJECT_WRITES.has(action(rec))) return undefined;
  const by = str(getPath(rec, "userIdentity.invokedBy")).trim() || "an AWS service";
  return { techniques: ["T1565"], reason: `an AWS service (${by.slice(0, 60)}) wrote the object on its own` };
}

function cloudTrailLogKey(rec: Row): TagVeto | undefined {
  if (service(rec) !== "kms" || action(rec) !== "createkey" || failedCall(rec)) return undefined;
  const origins = [
    getPath(rec, "requestParameters.origin"),
    getPath(rec, "responseElements.keyMetadata.origin"),
  ]
    .map((o) => str(o).trim())
    .filter(Boolean);
  if (!origins.length || !origins.every((o) => o === "AWS_KMS")) return undefined;
  const grant = trustedOnlyGrant(
    getPath(rec, "requestParameters.policy"),
    str(getCI(rec, "recipientAccountId")),
    {
      starHeldToAccount: true,
    },
  );
  if (!grant?.services.includes("cloudtrail.amazonaws.com")) return undefined;
  return {
    techniques: ["T1486"],
    reason:
      "an AWS-managed (AWS_KMS) key whose policy grants only CloudTrail and this account — a log-encryption key",
  };
}

function trustedBucketPolicy(rec: Row): TagVeto | undefined {
  if (service(rec) !== "s3" || action(rec) !== "putbucketpolicy") return undefined;
  const policy = getPath(rec, "requestParameters.bucketPolicy") ?? getPath(rec, "requestParameters.policy");
  if (!trustedOnlyGrant(policy, str(getCI(rec, "recipientAccountId")))) return undefined;
  return {
    techniques: ["T1048"],
    reason: "the bucket policy grants only AWS service principals or this account",
  };
}

// ── The lone failed sign-in (cross-record) ──────────────────────────────────────────────────────

const isConsoleLogin = (rec: Row): boolean => service(rec) === "signin" && action(rec) === "consolelogin";
const loginFailed = (rec: Row): boolean =>
  /fail/i.test(str(getPath(rec, "responseElements.ConsoleLogin"))) ||
  /failed authentication/i.test(str(getCI(rec, "errorMessage")));
const loginSucceeded = (rec: Row): boolean =>
  /^success$/i.test(str(getPath(rec, "responseElements.ConsoleLogin")).trim()) && !failedCall(rec);
const sourceOf = (rec: Row): string => lower(getCI(rec, "sourceIPAddress"));

/** The principal of a sign-in record, in a form a failure and a success share. */
function principalOf(rec: Row): string {
  const type = lower(getPath(rec, "userIdentity.type"));
  const account = lower(getPath(rec, "userIdentity.accountId"));
  const name =
    type === "root"
      ? "root"
      : lower(getPath(rec, "userIdentity.userName")) ||
        lower(getPath(rec, "userIdentity.arn")).split("/").pop();
  return name ? `${account}|${type}|${name}` : "";
}

interface Login {
  index: number;
  time: number;
  source: string;
  principal: string;
}

/** Record indexes of failed console sign-ins that were the lone failure before a same-source success. */
export function loneFailedSignIns(records: readonly Row[]): Set<number> {
  const failures: Login[] = [];
  const successes: Login[] = [];
  for (const [index, rec] of records.entries()) {
    if (!isConsoleLogin(rec)) continue;
    const login = { index, time: timeOf(rec), source: sourceOf(rec), principal: principalOf(rec) };
    if (!Number.isFinite(login.time) || !login.source || !login.principal) continue;
    if (loginFailed(rec)) failures.push(login);
    else if (loginSucceeded(rec)) successes.push(login);
  }
  const lone = new Set<number>();
  for (const f of failures) {
    const success = successes.find(
      (s) =>
        s.source === f.source &&
        s.principal === f.principal &&
        s.time >= f.time &&
        s.time - f.time <= LONE_FAILURE_WINDOW_MS,
    );
    if (!success) continue;
    // Every failure from this source in the window before the success, whoever it named.
    const near = failures.filter(
      (o) =>
        o.source === f.source && o.time <= success.time && success.time - o.time <= LONE_FAILURE_WINDOW_MS,
    );
    if (near.length === 1) lone.add(f.index);
  }
  return lone;
}

const LONE_FAILURE_VETO: TagVeto = {
  techniques: ["T1110"],
  reason:
    "the only failed sign-in from this source in 10 minutes, followed by a successful sign-in of the same principal from the same source (a mistyped password, not brute force)",
};

/** The veto for one CloudTrail record, or undefined when every technique stands. */
export function cloudTrailTagVeto(rec: Row | undefined, loneFailure: boolean): TagVeto | undefined {
  if (!rec) return undefined;
  if (loneFailure) return LONE_FAILURE_VETO;
  return serviceObjectWrite(rec) ?? cloudTrailLogKey(rec) ?? trustedBucketPolicy(rec);
}

const covers = (techniques: readonly string[], t: string): boolean =>
  techniques.some((v) => t === v || t.startsWith(`${v}.`));

/** The row without the vetoed techniques, with one note per withheld technique; never a grade change. */
export function withholdTechniques(event: MappedEvent, veto: TagVeto | undefined): MappedEvent {
  if (!veto) return event;
  const removed = event.mitre.filter((t) => covers(veto.techniques, t));
  if (!removed.length) return event;
  const notes = removed.map((t) => `ATT&CK ${t} withheld — ${veto.reason}; any rule match above stands`);
  return {
    ...event,
    mitre: event.mitre.filter((t) => !covers(veto.techniques, t)),
    message: [event.message, ...notes].filter(Boolean).join("\n"),
    // Never folded with a row that kept the technique.
    aggKey: boundedAggKey(`${event.aggKey}|withheld:${removed.join(",")}`),
  };
}
