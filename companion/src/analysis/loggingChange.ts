// Logging-configuration calls read for the STATE their request establishes (#931 item 14,
// coverage half — record part): CloudTrail trails, selectors, event data stores, VPC flow
// logs, GuardDuty detectors, S3 bucket logging; GCP Cloud Logging sinks, exclusions, log
// buckets and the IAM audit-config deltas; Azure diagnostic settings and log profiles.
//
// What one row rests on, and what it never says:
//   - a request establishes the requested / resulting posture after a successful call — never a
//     change from a prior value the record does not carry, so "reduces" and "extends" are never
//     said; a selector set is stated as the RESULTING configuration (PutEventSelectors replaces
//     the set), and "the prior configuration is not in this record" is always beside it;
//   - "enabling a source does not reconstruct its past" on every enabled row; CreateTrail is
//     "recording state not established" (StartLogging is a separate call);
//   - a GCP audit-config delta is exact and "effective audit logging is the union of
//     configurations — not established by this record";
//   - metrics never bear T1562.008; a publishing frequency is delivery cadence, not coverage;
//   - a denied call is an attempt; a call that failed for a reason this evidence does not
//     distinguish from denial or absence (#1081) is ALSO only an attempt, never guessed either way.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import type { LoggingChangeBlock, LoggingFailureKind, LoggingState } from "./canonicalLogging.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

// A small, documented AWS naming convention for "the resource does not exist" — never for "you
// are not allowed." Checked before the denied pattern (the two families do not overlap in AWS's
// own naming, but not-found first keeps the intent explicit). Matches
// NoSuchConfigurationRecorderException, NoSuchDeliveryChannel(Exception), TrailNotFoundException,
// EventDataStoreNotFoundException, InvalidFlowLogId.NotFound, InvalidVpcID.NotFound.
const AWS_NOT_FOUND_RE = /notfound|^nosuch/i;
// A small, documented AWS naming convention for "you are not allowed" — AccessDenied(Exception),
// UnauthorizedOperation, Client.UnauthorizedOperation, NotAuthorized,
// InsufficientPermissionsException, InsufficientDependencyServiceAccessPermissionException,
// OperationNotPermittedException, Forbidden.
const AWS_DENIED_RE = /denied|unauthorized|notauthorized|insufficientpermission|notpermitted|forbidden/i;

/** Classifies a non-empty AWS `errorCode` (#1081): `not-found` and `denied` are positively
 * identified from AWS's own documented naming conventions; everything else — GuardDuty's generic
 * `BadRequestException`, `ConflictException`, `ThrottlingException`, S3's ambiguous
 * `InvalidTargetBucketForLogging`, and anything unrecognized — is `"failed"`: an honest "the
 * reason is not established from this code," never guessed as either outcome. */
export function classifyAwsFailure(errorCode: string): LoggingFailureKind {
  const c = errorCode.trim();
  if (AWS_NOT_FOUND_RE.test(c)) return "not-found";
  if (AWS_DENIED_RE.test(c)) return "denied";
  return "failed";
}

export const NAME_MAX = 120;
const FACTS_MAX = 12;
export const LIST_MAX = 8;
export const TECHNIQUE = "T1562.008";
const PAST_NOTE = "enabling a source does not reconstruct its past";
const PRIOR_NOTE = "the prior configuration is not in this record";
const UNION_NOTE = "effective audit logging is the union of configurations — not established by this record";
const FORMAT_CHARS = /[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;

export const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v.replace(FORMAT_CHARS, "")));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
export const lower = (s: string): string => s.trim().toLowerCase();
const seg = (v: string): string => `${v.length}:${v}`;
export const field = (o: unknown, ...keys: string[]): string => {
  let cur: unknown = o;
  for (const k of keys) cur = isObject(cur) ? getCI(cur, k) : undefined;
  return cur === undefined || cur === null ? "" : str(cur).trim();
};
export const has = (o: unknown, key: string): boolean =>
  isObject(o) && getCI(o, key) !== undefined && getCI(o, key) !== null;
export const bool = (v: unknown): boolean | undefined =>
  v === true || v === "true" ? true : v === false || v === "false" ? false : undefined;
export const list = (v: unknown, max = LIST_MAX): string[] =>
  (Array.isArray(v) ? v : [])
    .map((x) => (isObject(x) ? str(getCI(x, "content")) : str(x)).trim())
    .filter(Boolean)
    .slice(0, max);
export const objects = (v: unknown, max = LIST_MAX): Row[] =>
  Array.isArray(v) ? v.filter(isObject).slice(0, max) : [];

export interface LoggingReading {
  severity: Severity;
  mitre: string[];
  /** The state sentence: `logging stopped for trail …`, `resulting selectors: …`. */
  posture: string;
  /** The quoted fields, `; `-joined, or "". */
  detail: string;
  qualifiers: string[];
  keySegment: string;
  block: LoggingChangeBlock;
}

export interface Fact {
  name: string;
  value: string;
}
export const factWords = (facts: readonly Fact[]): string =>
  facts.map((f) => `${show(f.name, 40)} ${show(f.value, 100)}`).join("; ");

/** A short digest of the normalised request facts — the key carries what the row asserts, not a display clip. */
const digest = (parts: readonly string[]): string =>
  createHash("sha256").update(parts.map(seg).join("|")).digest("hex").slice(0, 16);

const FAILURE_WORD: Record<LoggingFailureKind, string> = {
  denied: "denied",
  "not-found": "target not found",
  failed: "failed",
};
/** The qualifier for each failure kind — evidence-bounded: `not-found` states only that nothing
 * was established, never an inference about intent (#1081, Codex design review finding #7). */
const FAILURE_QUALIFIER: Record<LoggingFailureKind, string> = {
  denied: "attempted, denied — the resulting state is not established",
  "not-found":
    "the request failed because a referenced resource was not found; no configuration state was established",
  failed:
    "attempted; the reason for the failure is not established from the recorded error — never asserted as authorization denial or an absent target",
};

export function reading(
  provider: LoggingChangeBlock["provider"],
  targetKind: string,
  target: string,
  state: Exclude<LoggingState, "requested">,
  severity: Severity,
  posture: string,
  facts: Fact[],
  qualifiers: string[],
  failure: LoggingFailureKind | null,
  opts: { effectiveNotEstablished?: boolean; mitre?: string[]; key?: string; detail?: string } = {},
): LoggingReading {
  const bounded = facts.slice(0, FACTS_MAX);
  const detail = opts.detail ?? "";
  // not-found is the one positively-evidenced-benign outcome (Low); denied and an unclassified
  // failure both keep today's conservative Medium — neither is downgraded without evidence
  // (#1081, Codex design review finding #1).
  const grade: Severity = failure === "not-found" ? "Low" : failure ? "Medium" : severity;
  const technique = opts.mitre ?? (grade === "High" ? [TECHNIQUE] : []);
  // A call that did not establish state says so; the words name WHY, never guessing beyond it.
  const words = failure ? `requested (${FAILURE_WORD[failure]}): ${posture}` : posture;
  return {
    severity: grade,
    mitre: failure ? [] : technique,
    posture: words,
    detail,
    qualifiers: [
      ...(!failure && (state === "enabled" || state === "created") ? [PAST_NOTE] : []),
      ...(!failure && (state === "reconfigured" || state === "prior-state-not-in-record")
        ? [PRIOR_NOTE]
        : []),
      ...(opts.effectiveNotEstablished ? [UNION_NOTE] : []),
      ...qualifiers,
      ...(failure ? [FAILURE_QUALIFIER[failure]] : []),
    ],
    // The state-slot stays a single bare "requested" for every failure kind (#1081, Codex design
    // review Low finding #8 — AWS's/GCP's own OUTER aggregation keys already include the raw
    // error code / status code, so splitting this slot by failure kind would only be churn).
    keySegment: `|logging|${[provider, targetKind, target, failure ? "requested" : state].map(seg).join("|")}|${digest([opts.key ?? "", ...bounded.map((f) => `${f.name}=${f.value}`)])}`,
    block: {
      provider,
      target,
      targetKind,
      state: failure ? "requested" : state,
      ...(failure ? { requestedState: state } : {}),
      facts: bounded,
      priorStateInRecord: false,
      effectiveNotEstablished: opts.effectiveNotEstablished ?? false,
      denied: failure === "denied",
      ...(failure ? { failure } : {}),
    },
  };
}

// ───────────────────────────── CloudTrail ─────────────────────────────

const TRAIL_FIELDS = [
  "isMultiRegionTrail",
  "includeGlobalServiceEvents",
  "enableLogFileValidation",
  "isOrganizationTrail",
  "s3BucketName",
  "s3KeyPrefix",
  "snsTopicName",
  "cloudWatchLogsLogGroupArn",
  "cloudWatchLogsRoleArn",
  "kmsKeyId",
];
const NARROWING: Record<string, string> = {
  isMultiRegionTrail: "multi-region off",
  includeGlobalServiceEvents: "global service events off",
  enableLogFileValidation: "log-file validation off",
};
const trailName = (request: Row): string => field(request, "name") || field(request, "trailName");
/** The trail fields the request carries, in the request's own order. */
const trailFacts = (request: Row): Fact[] =>
  Object.keys(request)
    .filter((k) => TRAIL_FIELDS.includes(k) && has(request, k))
    .map((k) => ({ name: k, value: field(request, k) }));
const shortTrail = (name: string): string =>
  name.includes("/") ? name.slice(name.lastIndexOf("/") + 1) : name;

interface Selectors {
  words: string;
  /** The resulting set itself excludes coverage: management not selected / narrowed, or a source excluded. */
  excludesCoverage: boolean;
  facts: Fact[];
  /** True when the request carried neither selector list. */
  none: boolean;
}
const OPERATORS = ["equals", "notEquals", "startsWith", "endsWith", "notStartsWith", "notEndsWith"];
function selectorWords(request: Row): Selectors {
  const basic = objects(getCI(request, "eventSelectors"));
  const advanced = objects(getCI(request, "advancedEventSelectors"));
  if (advanced.length) {
    let management = false;
    let narrowed = false;
    const parts = advanced.map((s) => {
      const fields = objects(getCI(s, "fieldSelectors"), 16).map((f) => {
        const name = field(f, "field");
        const ops = OPERATORS.filter((k) => list(getCI(f, k)).length);
        const values = ops.map(
          (op) =>
            `${op} ${list(getCI(f, op))
              .map((v) => show(v, 60))
              .join("|")}`,
        );
        if (lower(name) === "eventcategory") {
          const eq = list(getCI(f, "equals")).map(lower);
          if (eq.includes("management")) management = true;
          if (list(getCI(f, "notEquals")).map(lower).includes("management")) narrowed = true;
        } else if (management && ["readonly", "eventsource", "eventname"].includes(lower(name)))
          narrowed = true;
        return `${show(name, 40)}${values.length ? ` ${values.join(" ")}` : ""}`;
      });
      return `${show(field(s, "name"), 40) || "(unnamed)"} (${fields.join(", ")})`;
    });
    const facts = advanced.map((sel, i) => ({ name: `advancedEventSelector[${i}]`, value: parts[i] }));
    return {
      words: `resulting advanced selectors: ${parts.join("; ")}${management ? "" : "; management events: not selected by any selector"}`,
      excludesCoverage: !management || narrowed,
      facts,
      none: false,
    };
  }
  if (!basic.length)
    return {
      words: "resulting selectors: none in the request",
      excludesCoverage: false,
      facts: [],
      none: true,
    };
  let excludesCoverage = false;
  const parts = basic.map((s) => {
    const include = bool(getCI(s, "includeManagementEvents"));
    const rw = field(s, "readWriteType") || "All";
    const excluded = list(getCI(s, "excludeManagementEventSources"));
    const data = objects(getCI(s, "dataResources")).map((d) =>
      `${show(field(d, "type"), 40)} ${list(getCI(d, "values"))
        .map((v) => show(v, 80))
        .join(", ")}`.trim(),
    );
    if (include === false || lower(rw) !== "all" || excluded.length) excludesCoverage = true;
    const mgmt =
      include === false
        ? "management events excluded"
        : `management ${show(rw, 12)}${excluded.length ? ` (excluding ${excluded.map((e) => show(e, 40)).join(", ")})` : ""}`;
    return `${mgmt}; data events: ${data.length ? data.join(", ") : "none selected"}; network activity: none (basic selectors)`;
  });
  const facts = basic.map((sel, i) => ({ name: `eventSelector[${i}]`, value: parts[i] }));
  return { words: `resulting selectors: ${parts.join(" | ")}`, excludesCoverage, facts, none: false };
}

function guardDuty(request: Row, failure: LoggingFailureKind | null): LoggingReading {
  const id = field(request, "detectorId") || "(detector id not recorded)";
  const enable = bool(getCI(request, "enable"));
  const parts: string[] = [];
  const facts: Fact[] = [];
  let anyOff = false;
  if (enable !== undefined) {
    parts.push(`detector ${enable ? "enabled" : "disabled"}`);
    facts.push({ name: "enable", value: String(enable) });
    if (!enable) anyOff = true;
  }
  const walk = (o: unknown, path: string[]): void => {
    if (!isObject(o)) return;
    for (const [k, v] of Object.entries(o)) {
      if (k === "enable") {
        const on = bool(v);
        if (on === undefined) continue;
        const name = path.join(".");
        parts.push(`${show(name, 40)} ${on ? "enabled" : "disabled"}`);
        facts.push({ name, value: String(on) });
        if (!on) anyOff = true;
      } else walk(v, [...path, k]);
    }
  };
  walk(getCI(request, "dataSources"), []);
  for (const f of objects(getCI(request, "features"), 32)) {
    const name = field(f, "name");
    const status = field(f, "status");
    if (!name || !status) continue;
    parts.push(`${show(name, 40)} ${show(status, 12)}`);
    facts.push({ name, value: status });
    if (lower(status) === "disabled") anyOff = true;
  }
  const cadence = field(request, "findingPublishingFrequency");
  if (cadence) facts.push({ name: "findingPublishingFrequency", value: cadence });
  const cadenceWords = cadence
    ? [`findingPublishingFrequency ${show(cadence, 20)} — delivery cadence, no coverage change`]
    : [];
  if (enable === false && parts.length === 1)
    return reading(
      "aws",
      "detector",
      id,
      "disabled",
      "High",
      `detector ${show(id, 40)} disabled`,
      facts,
      cadenceWords,
      failure,
    );
  if (enable === true && parts.length === 1)
    return reading(
      "aws",
      "detector",
      id,
      "enabled",
      "Low",
      `detector ${show(id, 40)} enabled`,
      facts,
      cadenceWords,
      failure,
    );
  if (parts.length)
    return reading(
      "aws",
      "detector",
      id,
      "reconfigured",
      anyOff ? "High" : "Low",
      `detector ${show(id, 40)} reconfigured: ${parts.join("; ")}`,
      facts,
      cadenceWords,
      failure,
    );
  if (cadence)
    return reading(
      "aws",
      "detector",
      id,
      "reconfigured",
      "Low",
      `detector ${show(id, 40)}: ${cadenceWords[0]}`,
      facts,
      [],
      failure,
      { mitre: [] },
    );
  return reading(
    "aws",
    "detector",
    id,
    "prior-state-not-in-record",
    "Medium",
    `detector ${show(id, 40)} updated; no coverage field in the request`,
    [],
    [],
    failure,
  );
}

/** Every value under a key that names a flow-log id, whatever container the request used. */
function flowLogIds(v: unknown, out: string[] = [], depth = 0, underKey = false): string[] {
  if (depth > 6 || out.length >= 32) return out;
  if (typeof v === "string") {
    if (underKey && v.trim()) out.push(v.trim());
  } else if (Array.isArray(v)) for (const x of v) flowLogIds(x, out, depth + 1, underKey);
  else if (isObject(v))
    for (const [k, x] of Object.entries(v)) {
      if (/^flowlogid/i.test(k)) flowLogIds(x, out, depth + 1, true);
      else if (/^(items|item|content)$/i.test(k)) flowLogIds(x, out, depth + 1, underKey);
      else if (/flowlog/i.test(k)) flowLogIds(x, out, depth + 1, false);
    }
  return [...new Set(out)];
}

/** One id AWS's own `responseElements.unsuccessful` named, with its own error classified the SAME
 * way a whole-call `errorCode` is (#1095, surfaced by #1081's design review). */
interface FlowLogFailure {
  id: string;
  failure: LoggingFailureKind;
}

/** `DeleteFlowLogs` returns per-item failures in `responseElements.unsuccessful` — an id in that
 * list was NOT deleted, even when the call itself carries no top-level `errorCode` at all (#1095).
 * `resourceId` is AWS's own documented field name; `flowLogId` is read too, defensively, in case
 * an export normalizes it differently — neither is invented, both are the same id this record's
 * own request already names. */
function flowLogUnsuccessful(responseElements: unknown): FlowLogFailure[] {
  const resp: Row = isObject(responseElements) ? responseElements : {};
  return objects(getCI(resp, "unsuccessful"), 32).map((item) => {
    const id = field(item, "resourceId") || field(item, "flowLogId") || "(id not recorded)";
    const code = field(item, "error", "code");
    return { id, failure: code ? classifyAwsFailure(code) : "failed" };
  });
}

/** A CloudTrail record's logging-configuration reading, or null when the call is not one. */
export function decodeCloudTrailLogging(
  source: string,
  name: string,
  request: unknown,
  errorCode: string,
  responseElements: unknown = null,
): LoggingReading | null {
  const svc = lower(source).replace(/\.amazonaws\.com$/, "");
  const n = lower(name);
  const req: Row = isObject(request) ? request : {};
  const failure = errorCode.trim() ? classifyAwsFailure(errorCode) : null;
  if (svc === "cloudtrail") {
    const trail = trailName(req);
    const t = trail || "(trail not recorded)";
    if (n === "stoplogging")
      return reading(
        "aws",
        "trail",
        t,
        "disabled",
        "High",
        `logging stopped for trail ${show(t)}`,
        [],
        [],
        failure,
      );
    if (n === "startlogging")
      return reading(
        "aws",
        "trail",
        t,
        "enabled",
        "Low",
        `logging started for trail ${show(t)}`,
        [],
        [],
        failure,
      );
    if (n === "deletetrail")
      return reading("aws", "trail", t, "deleted", "High", `trail deleted: ${show(t)}`, [], [], failure);
    if (n === "createtrail") {
      const facts = trailFacts(req);
      return reading(
        "aws",
        "trail",
        t,
        "created",
        "Low",
        `trail created: ${show(shortTrail(t), 60)} — recording state not established (StartLogging is a separate call)`,
        facts,
        [],
        failure,
        { detail: factWords(facts) },
      );
    }
    if (n === "updatetrail") {
      const facts = trailFacts(req);
      const narrowed = facts
        .filter((f) => NARROWING[f.name] && f.value === "false")
        .map((f) => NARROWING[f.name]);
      const coverageField = facts.some((f) => NARROWING[f.name]);
      return reading(
        "aws",
        "trail",
        t,
        coverageField ? "reconfigured" : "prior-state-not-in-record",
        narrowed.length ? "High" : "Medium",
        `trail reconfigured: ${factWords(facts) || "(no fields in the request)"}`,
        facts,
        narrowed.length ? [`resulting configuration excludes coverage (${narrowed.join(", ")})`] : [],
        failure,
        { key: facts.map((f) => `${f.name}=${f.value}`).join(",") },
      );
    }
    if (n === "puteventselectors") {
      const sel = selectorWords(req);
      return reading(
        "aws",
        "trail",
        t,
        sel.none ? "prior-state-not-in-record" : "reconfigured",
        sel.excludesCoverage ? "High" : "Medium",
        sel.words,
        sel.facts,
        ["the prior selectors are not in this record"],
        failure,
        { key: sel.words },
      );
    }
    if (n === "putinsightselectors") {
      const present = has(req, "insightSelectors");
      const kinds = objects(getCI(req, "insightSelectors"))
        .map((s) => field(s, "insightType"))
        .filter(Boolean);
      return reading(
        "aws",
        "trail",
        t,
        "reconfigured",
        "Medium",
        `resulting insight selectors: ${!present ? "not in the request" : kinds.length ? kinds.map((k) => show(k, 30)).join(", ") : "none"}`,
        kinds.map((k) => ({ name: "insightType", value: k })),
        ["the prior selectors are not in this record"],
        failure,
        { key: present ? kinds.join(",") : "absent" },
      );
    }
    if (n === "deleteeventdatastore") {
      const store = field(req, "eventDataStore") || "(store not recorded)";
      return reading(
        "aws",
        "event-data-store",
        store,
        "deleted",
        "High",
        `event data store deleted: ${show(store)}`,
        [],
        [],
        failure,
      );
    }
    return null;
  }
  // AWS Config recorder calls (#1071) are decoded in awsConfigLogging.ts, called directly by
  // awsImport.ts — never delegated to from here, since that file imports this one's `reading()`
  // and shared helpers, and importing it back here would create a cycle.
  if (svc === "ec2" && n === "deleteflowlogs") {
    const requested = flowLogIds(req);
    // A per-item failure exists even when the WHOLE call carries no top-level errorCode at all
    // (#1095) — only an id NEVER named in `unsuccessful` was actually deleted.
    const unsuccessful = failure ? [] : flowLogUnsuccessful(responseElements);
    const unsuccessfulIds = new Set(unsuccessful.map((u) => u.id));
    // A whole-call failure means nothing succeeded, regardless of any per-item data — the call
    // itself was rejected before any id-level outcome could occur.
    const succeeded = failure ? [] : requested.filter((id) => !unsuccessfulIds.has(id));
    const unsuccessfulWords = unsuccessful
      .map((u) => `${show(u.id, 30)} (${FAILURE_WORD[u.failure]})`)
      .join(", ");
    const unsuccessfulQualifier = unsuccessful.length
      ? [
          `${unsuccessful.length} of ${requested.length || unsuccessful.length} id(s) not deleted: ${unsuccessfulWords}`,
        ]
      : [];
    // No failure evidence at all (no top-level errorCode, no responseElements.unsuccessful item)
    // — every named id is reported deleted, matching this branch's own behavior before #1095.
    if (!failure && !unsuccessful.length)
      return reading(
        "aws",
        "flow-logs",
        requested.join(",") || "(ids not recorded)",
        "deleted",
        "High",
        `flow logs deleted: ${requested.map((i) => show(i, 30)).join(", ") || "(ids not recorded)"}`,
        requested.map((i) => ({ name: "flowLogId", value: i })),
        [],
        null,
      );
    if (succeeded.length)
      return reading(
        "aws",
        "flow-logs",
        succeeded.join(","),
        "deleted",
        "High",
        `flow logs deleted: ${succeeded.map((i) => show(i, 30)).join(", ")}`,
        succeeded.map((i) => ({ name: "flowLogId", value: i })),
        unsuccessfulQualifier,
        null,
      );
    // Nothing succeeded — the whole call failed, or every named id individually failed. The row
    // is an ATTEMPT only, never "deleted" (#1095). A whole-call `failure` wins when present;
    // otherwise, if every unsuccessful id shares ONE classification, state that — a MIXED set of
    // reasons is never collapsed into one specific claim it does not support.
    const kinds = new Set(unsuccessful.map((u) => u.failure));
    const overall: LoggingFailureKind = failure ?? (kinds.size === 1 ? [...kinds][0] : "failed");
    const ids = requested.length ? requested : unsuccessful.map((u) => u.id);
    return reading(
      "aws",
      "flow-logs",
      ids.join(",") || "(ids not recorded)",
      "deleted",
      "High",
      `flow logs deletion requested: ${ids.map((i) => show(i, 30)).join(", ") || "(ids not recorded)"}`,
      ids.map((i) => ({ name: "flowLogId", value: i })),
      unsuccessfulQualifier,
      overall,
    );
  }
  if (svc === "ec2" && n === "createflowlogs") {
    const ids = list(getCI(req, "resourceIds"));
    const traffic = field(req, "trafficType");
    return reading(
      "aws",
      "flow-logs",
      ids.join(","),
      "created",
      "Low",
      `flow logs created for ${ids.map((i) => show(i, 30)).join(", ") || "(resources not recorded)"}${traffic ? ` (${show(traffic, 10)})` : ""}`,
      [],
      [],
      failure,
    );
  }
  if (svc === "guardduty" && n === "updatedetector") return guardDuty(req, failure);
  if (svc === "guardduty" && n === "deletedetector") {
    const id = field(req, "detectorId") || "(detector id not recorded)";
    return reading(
      "aws",
      "detector",
      id,
      "deleted",
      "High",
      `detector deleted: ${show(id, 40)}`,
      [],
      [],
      failure,
    );
  }
  if (svc === "s3" && n === "putbucketlogging") {
    const bucket = field(req, "bucketName") || "(bucket not recorded)";
    const status = getCI(req, "BucketLoggingStatus") ?? getCI(req, "bucketLoggingStatus");
    const enabled = isObject(status)
      ? (getCI(status, "LoggingEnabled") ?? getCI(status, "loggingEnabled"))
      : undefined;
    if (isObject(enabled)) {
      const target = `${field(enabled, "TargetBucket")}/${field(enabled, "TargetPrefix")}`;
      return reading(
        "aws",
        "bucket",
        bucket,
        "enabled",
        "Low",
        `bucket access logging enabled for bucket ${show(bucket, 60)} → ${show(target, 80)}`,
        [
          { name: "TargetBucket", value: field(enabled, "TargetBucket") },
          { name: "TargetPrefix", value: field(enabled, "TargetPrefix") },
        ],
        [],
        failure,
      );
    }
    return reading(
      "aws",
      "bucket",
      bucket,
      "disabled",
      "High",
      `bucket access logging disabled for bucket ${show(bucket, 60)}`,
      [],
      [],
      failure,
    );
  }
  return null;
}

// ───────────────────────────── the words ─────────────────────────────

const HEAD_MAX = 140;
const POSTURE_MAX = 260;
const DETAIL_MAX = 150;
const IDENTITY_MAX = 100;
const QUALIFIERS_MAX = 170;
const TOTAL_MAX = 600;
const clip = (v: string, max: number): string =>
  max <= 0 ? "" : v.length <= max ? v : `${v.slice(0, max - 1)}…`;

/** A logging row's words: every slot neutralised; the qualifiers and the tail are reserved, then the head and the state sentence, then the quoted fields and the identity. */
export function renderLoggingDescription(
  head: string,
  identity: string,
  r: LoggingReading,
  tail = "",
): string {
  const qualifiers = clip(show(r.qualifiers.filter(Boolean).join("; "), QUALIFIERS_MAX), QUALIFIERS_MAX);
  const t = clip(show(tail, 80), 80);
  let room = TOTAL_MAX - (qualifiers ? qualifiers.length + 3 : 0) - (t ? t.length + 1 : 0);
  const h = clip(show(head, HEAD_MAX), Math.max(0, Math.min(HEAD_MAX, room)));
  room -= h.length;
  const posture = clip(show(r.posture, POSTURE_MAX), Math.max(0, Math.min(POSTURE_MAX, room - 3)));
  room -= posture ? posture.length + 3 : 0;
  const detail = r.detail.trim()
    ? clip(show(r.detail, DETAIL_MAX), Math.max(0, Math.min(DETAIL_MAX, room - 3)))
    : "";
  room -= detail ? detail.length + 3 : 0;
  const who = identity.trim()
    ? clip(show(identity, IDENTITY_MAX), Math.max(0, Math.min(IDENTITY_MAX, room - 3)))
    : "";
  const parts = [h, posture, detail.length > 8 ? detail : "", who.length > 8 ? who : ""].filter(Boolean);
  return `${parts.join(" — ")}${t ? ` ${t}` : ""}${qualifiers ? ` [${qualifiers}]` : ""}`.slice(0, TOTAL_MAX);
}
