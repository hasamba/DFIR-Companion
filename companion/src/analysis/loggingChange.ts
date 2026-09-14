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
//   - a denied call is an attempt.

import type { Severity } from "./stateTypes.js";
import type { LoggingChangeBlock, LoggingState } from "./canonicalLogging.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

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

export function reading(
  provider: LoggingChangeBlock["provider"],
  targetKind: string,
  target: string,
  state: LoggingState,
  severity: Severity,
  posture: string,
  facts: Fact[],
  qualifiers: string[],
  denied: boolean,
  opts: { effectiveNotEstablished?: boolean; mitre?: string[]; key?: string; detail?: string } = {},
): LoggingReading {
  const bounded = facts.slice(0, FACTS_MAX);
  const detail = opts.detail ?? "";
  const grade: Severity = denied ? "Medium" : severity;
  const technique = opts.mitre ?? (grade === "High" ? [TECHNIQUE] : []);
  return {
    severity: grade,
    mitre: denied ? [] : technique,
    posture,
    detail,
    qualifiers: [
      ...(state === "enabled" || state === "created" ? [PAST_NOTE] : []),
      ...(state === "reconfigured" || state === "prior-state-not-in-record" ? [PRIOR_NOTE] : []),
      ...(opts.effectiveNotEstablished ? [UNION_NOTE] : []),
      ...qualifiers,
      ...(denied ? ["attempted, denied"] : []),
    ],
    keySegment: `|logging|${[provider, targetKind, target, state, opts.key ?? "", ...bounded.map((f) => `${f.name}=${f.value}`)].map(seg).join("|")}`,
    block: {
      provider,
      target,
      targetKind,
      state,
      facts: bounded,
      priorStateInRecord: false,
      effectiveNotEstablished: opts.effectiveNotEstablished ?? false,
      denied,
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

function selectorWords(request: Row): { words: string; excludesManagement: boolean; facts: Fact[] } {
  const basic = objects(getCI(request, "eventSelectors"));
  const advanced = objects(getCI(request, "advancedEventSelectors"));
  const facts: Fact[] = [];
  if (advanced.length) {
    const parts = advanced.map((s) => {
      const fields = objects(getCI(s, "fieldSelectors"))
        .map((f) => {
          const name = field(f, "field");
          const op = ["equals", "notEquals", "startsWith", "endsWith", "notStartsWith", "notEndsWith"].find(
            (k) => list(getCI(f, k)).length,
          );
          return op
            ? `${show(name, 40)} ${op} ${list(getCI(f, op))
                .map((v) => show(v, 60))
                .join("|")}`
            : show(name, 40);
        })
        .join(", ");
      return `${show(field(s, "name"), 40) || "(unnamed)"} (${fields})`;
    });
    facts.push({ name: "advancedEventSelectors", value: String(advanced.length) });
    return { words: `resulting advanced selectors: ${parts.join("; ")}`, excludesManagement: false, facts };
  }
  if (!basic.length)
    return { words: "resulting selectors: none in the request", excludesManagement: false, facts };
  let excludesManagement = false;
  const parts = basic.map((s) => {
    const include = bool(getCI(s, "includeManagementEvents"));
    const rw = field(s, "readWriteType") || "All";
    const excluded = list(getCI(s, "excludeManagementEventSources"));
    const data = objects(getCI(s, "dataResources")).map((d) =>
      `${show(field(d, "type"), 40)} ${list(getCI(d, "values"))
        .map((v) => show(v, 80))
        .join(", ")}`.trim(),
    );
    if (include === false) excludesManagement = true;
    const mgmt =
      include === false
        ? "management events excluded"
        : `management ${show(rw, 12)}${excluded.length ? ` (excluding ${excluded.map((e) => show(e, 40)).join(", ")})` : ""}`;
    return `${mgmt}; data events: ${data.length ? data.join(", ") : "none selected"}`;
  });
  facts.push({ name: "eventSelectors", value: String(basic.length) });
  return { words: `resulting selectors: ${parts.join(" | ")}`, excludesManagement, facts };
}

function guardDuty(request: Row, denied: boolean): LoggingReading {
  const id = field(request, "detectorId") || "(detector id not recorded)";
  const enable = bool(getCI(request, "enable"));
  if (enable === false)
    return reading(
      "aws",
      "detector",
      id,
      "disabled",
      "High",
      `detector ${show(id, 40)} disabled`,
      [],
      [],
      denied,
    );
  if (enable === true)
    return reading(
      "aws",
      "detector",
      id,
      "enabled",
      "Low",
      `detector ${show(id, 40)} enabled`,
      [],
      [],
      denied,
    );
  const parts: string[] = [];
  const facts: Fact[] = [];
  let anyOff = false;
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
  for (const f of objects(getCI(request, "features"))) {
    const name = field(f, "name");
    const status = field(f, "status");
    if (!name || !status) continue;
    parts.push(`${show(name, 40)} ${show(status, 12)}`);
    facts.push({ name, value: status });
    if (lower(status) === "disabled") anyOff = true;
  }
  const cadence = field(request, "findingPublishingFrequency");
  if (parts.length)
    return reading(
      "aws",
      "detector",
      id,
      "reconfigured",
      anyOff ? "High" : "Low",
      `detector ${show(id, 40)} reconfigured: ${parts.join("; ")}`,
      facts,
      cadence
        ? [`findingPublishingFrequency ${show(cadence, 20)} — delivery cadence, no coverage change`]
        : [],
      denied,
    );
  if (cadence)
    return reading(
      "aws",
      "detector",
      id,
      "reconfigured",
      "Low",
      `detector ${show(id, 40)}: findingPublishingFrequency ${show(cadence, 20)} — delivery cadence, no coverage change`,
      [{ name: "findingPublishingFrequency", value: cadence }],
      [],
      denied,
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
    denied,
  );
}

/** A CloudTrail record's logging-configuration reading, or null when the call is not one. */
export function decodeCloudTrailLogging(
  source: string,
  name: string,
  request: unknown,
  errorCode: string,
): LoggingReading | null {
  const svc = lower(source).replace(/\.amazonaws\.com$/, "");
  const n = lower(name);
  const req: Row = isObject(request) ? request : {};
  const denied = !!errorCode.trim();
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
        `logging ${denied ? "stop requested" : "stopped"} for trail ${show(t)}`,
        [],
        [],
        denied,
      );
    if (n === "startlogging")
      return reading(
        "aws",
        "trail",
        t,
        "enabled",
        "Low",
        `logging ${denied ? "start requested" : "started"} for trail ${show(t)}`,
        [],
        [],
        denied,
      );
    if (n === "deletetrail")
      return reading(
        "aws",
        "trail",
        t,
        "deleted",
        "High",
        `trail ${denied ? "deletion requested" : "deleted"}: ${show(t)}`,
        [],
        [],
        denied,
      );
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
        denied,
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
        denied,
        { key: facts.map((f) => `${f.name}=${f.value}`).join(",") },
      );
    }
    if (n === "puteventselectors") {
      const sel = selectorWords(req);
      return reading(
        "aws",
        "trail",
        t,
        "reconfigured",
        sel.excludesManagement ? "High" : "Medium",
        denied
          ? `requested selectors: ${sel.words.replace(/^resulting (advanced )?selectors: /, "")}`
          : sel.words,
        sel.facts,
        ["the prior selectors are not in this record"],
        denied,
        { key: sel.words },
      );
    }
    if (n === "putinsightselectors") {
      const kinds = objects(getCI(req, "insightSelectors"))
        .map((s) => field(s, "insightType"))
        .filter(Boolean);
      return reading(
        "aws",
        "trail",
        t,
        "reconfigured",
        kinds.length ? "Low" : "Medium",
        `resulting insight selectors: ${kinds.length ? kinds.map((k) => show(k, 30)).join(", ") : "none"}`,
        [],
        ["the prior selectors are not in this record"],
        denied,
        { key: kinds.join(",") },
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
        `event data store ${denied ? "deletion requested" : "deleted"}: ${show(store)}`,
        [],
        [],
        denied,
      );
    }
    return null;
  }
  if (svc === "ec2" && n === "deleteflowlogs") {
    const ids = [
      ...new Set([
        ...list(getCI(req, "flowLogIds")),
        ...list(
          isObject(getCI(req, "DeleteFlowLogsRequest"))
            ? getCI(getCI(req, "DeleteFlowLogsRequest") as Row, "FlowLogId")
            : undefined,
        ),
      ]),
    ];
    return reading(
      "aws",
      "flow-logs",
      ids.join(",") || "(ids not recorded)",
      "deleted",
      "High",
      `flow logs ${denied ? "deletion requested" : "deleted"}: ${ids.map((i) => show(i, 30)).join(", ") || "(ids not recorded)"}`,
      [],
      [],
      denied,
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
      denied,
    );
  }
  if (svc === "guardduty" && n === "updatedetector") return guardDuty(req, denied);
  if (svc === "guardduty" && n === "deletedetector") {
    const id = field(req, "detectorId") || "(detector id not recorded)";
    return reading(
      "aws",
      "detector",
      id,
      "deleted",
      "High",
      `detector ${denied ? "deletion requested" : "deleted"}: ${show(id, 40)}`,
      [],
      [],
      denied,
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
        [],
        [],
        denied,
      );
    }
    return reading(
      "aws",
      "bucket",
      bucket,
      "disabled",
      "High",
      `bucket access logging ${denied ? "disable requested" : "disabled"} for bucket ${show(bucket, 60)}`,
      [],
      [],
      denied,
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
const clip = (v: string, max: number): string => (v.length <= max ? v : `${v.slice(0, max - 1)}…`);

/** A logging row's words: the head and the state sentence, the quoted fields, the identity, then the reserved qualifiers. */
export function renderLoggingDescription(
  head: string,
  identity: string,
  r: LoggingReading,
  tail = "",
): string {
  const qualifiers = clip(r.qualifiers.filter(Boolean).join("; "), QUALIFIERS_MAX);
  const h = clip(head.trim(), HEAD_MAX);
  const posture = clip(r.posture.trim(), POSTURE_MAX);
  let room =
    TOTAL_MAX -
    h.length -
    posture.length -
    (qualifiers ? qualifiers.length + 3 : 0) -
    (tail ? tail.length + 1 : 0) -
    4;
  const detail = r.detail.trim() ? clip(r.detail.trim(), Math.max(0, Math.min(DETAIL_MAX, room - 3))) : "";
  room -= detail ? detail.length + 3 : 0;
  const who = identity.trim() ? clip(identity.trim(), Math.max(0, Math.min(IDENTITY_MAX, room - 3))) : "";
  const parts = [h, posture, detail.length > 8 ? detail : "", who.length > 8 ? who : ""].filter(Boolean);
  return `${parts.join(" — ")}${tail ? ` ${tail}` : ""}${qualifiers ? ` [${qualifiers}]` : ""}`.slice(
    0,
    TOTAL_MAX,
  );
}
