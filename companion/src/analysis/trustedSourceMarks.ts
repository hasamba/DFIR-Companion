// Analyst-marked trusted sources (#2561): a value the analyst labelled `ours` or `responder` in the
// IOC attribution (iocAttribution.ts, #2543 part 1b) — an IP, an AWS access key id, or an AWS
// principal ARN (account root, IAM user, role, assumed-role session) — tags the ROUTINE forensic rows
// it produced `trusted-activity`, so the analyst can count, filter and hide its own side's activity.
//
// TAG AND NOTE ONLY (owner decision Q3 = option A). Severity, MITRE, `origin` and the description are
// never touched and no row is dropped. The author carries the provenance —
// `tagger:trusted-activity:<label>:<value>` — and the `tagger:` prefix keeps the tag from protecting a
// row against the super-timeline cap, like the collector footprint (cloudCollectorFootprint.ts).
//
// FAIL CLOSED. A mark is broad and timeless (a shared company NAT, a whole role), so a compromised
// admin must not be able to hide behind it. A matched row is tagged only when it is, all of:
//   - an AWS row (v1; other providers are a follow-up);
//   - not Critical; High only for a successful console sign-in; never a failed call;
//   - one of: a listed metadata read (SAFE_READS); a successful sign-in; a logging
//     change that turned logging on or created it; a short list of routine writes; or a
//     credential-lineage summary with no shape (no enumeration, privileged change or remote
//     execution), whose every source is a marked IP (or whose key is marked) and none beyond;
//   - not also matched by an `attacker`-labelled value (IP, key or principal).
// Every IAM write, key, policy, trust, event-selector, trail-reconfiguration, data-access or execution
// call therefore stays untagged: the record facts that would prove it benign (a `*` action, a key for
// another user, an outside-account trust) are not on the row.
//
// Pure: no state, no super-timeline, no AI. The whole-case recompute and its triggers live in
// trustedActivitySync.ts; consumers re-check every tag with honouredTrustedRows().

import { isIP } from "node:net";
import { FRIENDLY_ATTRIBUTIONS, type IocAttributionLabel, type IocAttributionMap } from "./iocAttribution.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { NewTag, Tag } from "./tags.js";
import { TAGGER_AUTHOR_PREFIX } from "./superTimeline.js";

export const TRUSTED_LABEL = "trusted-activity";
export const TRUSTED_AUTHOR_PREFIX = `${TAGGER_AUTHOR_PREFIX}trusted-activity:`;

export type TrustedMarkKind = "ip" | "access-key" | "aws-root" | "aws-user" | "aws-role" | "aws-assumed-role";
export type FriendlyLabel = "ours" | "responder";

export interface TrustedMark {
  kind: TrustedMarkKind;
  /** The value as the analyst labelled it (display, and the author's tail). */
  value: string;
  label: IocAttributionLabel;
  /** Normalised match key: lower-case IP, upper-case key id, or the lower-case ARN. */
  key: string;
  account?: string;
  name?: string;
  session?: string;
}

export interface TrustedMarks {
  friendly: TrustedMark[];
  attacker: TrustedMark[];
}

const ACCESS_KEY = /^(?:AKIA|ASIA)[A-Z0-9]{16}$/;
const ROOT_ARN = /^arn:[a-z-]+:iam::(\d{12}):root$/i;
const USER_ARN = /^arn:[a-z-]+:iam::(\d{12}):user\/(?:[^:]*\/)?([^/:]+)$/i;
const ROLE_ARN = /^arn:[a-z-]+:iam::(\d{12}):role\/(?:[^:]*\/)?([^/:]+)$/i;
const ASSUMED_ARN = /^arn:[a-z-]+:sts::(\d{12}):assumed-role\/([^/:]+)\/([^/:]+)$/i;

/** One attribution value as a mark, or null when it is none of the supported forms. */
export function classifyMark(value: string, label: IocAttributionLabel): TrustedMark | null {
  const v = value.trim();
  if (isIP(v)) return { kind: "ip", value: v, label, key: v.toLowerCase() };
  if (ACCESS_KEY.test(v.toUpperCase())) return { kind: "access-key", value: v, label, key: v.toUpperCase() };
  const arn = (re: RegExp, kind: TrustedMarkKind): TrustedMark | null => {
    const m = re.exec(v);
    if (!m) return null;
    const [, account, name, session] = m;
    return {
      kind,
      value: v,
      label,
      key: v.toLowerCase(),
      account,
      ...(name ? { name: name.toLowerCase() } : {}),
      ...(session ? { session } : {}),
    };
  };
  return (
    arn(ROOT_ARN, "aws-root") ??
    arn(USER_ARN, "aws-user") ??
    arn(ROLE_ARN, "aws-role") ??
    arn(ASSUMED_ARN, "aws-assumed-role")
  );
}

const markOrder = (a: TrustedMark, b: TrustedMark): number =>
  a.kind === b.kind ? a.key.localeCompare(b.key) : a.kind.localeCompare(b.kind);

/** The friendly and attacker marks of a case, in a deterministic order. Pure. */
export function parseTrustedMarks(map: IocAttributionMap): TrustedMarks {
  const friendly: TrustedMark[] = [];
  const attacker: TrustedMark[] = [];
  for (const entry of Object.values(map)) {
    const isFriendly = FRIENDLY_ATTRIBUTIONS.has(entry.label);
    if (!isFriendly && entry.label !== "attacker") continue;
    const mark = classifyMark(entry.value, entry.label);
    if (mark) (isFriendly ? friendly : attacker).push(mark);
  }
  return { friendly: friendly.sort(markOrder), attacker: attacker.sort(markOrder) };
}

type Canonical = NonNullable<ForensicEvent["canonical"]>;

const ROLE_ISSUER = /^arn:[a-z-]+:iam::(\d{12}):role\/(?:.*\/)?([^/]+)$/i;

/** True when the single-call row's own identity facts are this principal mark's. */
function principalMatches(c: Canonical, m: TrustedMark): boolean {
  if (!m.account || (c.cloud?.accountId ?? "") !== m.account) return false;
  const issuer = ROLE_ISSUER.exec(c.authentication?.issuer ?? "");
  const roleIs = (name?: string) => !!issuer && issuer[1] === m.account && issuer[2].toLowerCase() === name;
  switch (m.kind) {
    case "aws-root":
      return c.cloud?.principalType === "Root";
    case "aws-user":
      return (
        c.cloud?.principalType === "IAMUser" &&
        !c.authentication?.issuer &&
        (c.actor?.name ?? "").toLowerCase() === m.name
      );
    case "aws-role":
      return roleIs(m.name);
    case "aws-assumed-role":
      return roleIs(m.name) && !!m.session && (c.cloud?.principalId ?? "").endsWith(`:${m.session}`);
    default:
      return false;
  }
}

/** The first mark in `list` that this row's source IP, key or principal matches. */
function firstMatch(c: Canonical, list: readonly TrustedMark[]): TrustedMark | null {
  // A source IP confers trust only when the recorder observed it (ARCHITECTURE.md § "The
  // `network.source.provenance` trust flag"): fail closed on a claimed or unstamped address.
  const source = c.network?.source;
  const ip = source?.provenance === "edge-observed" ? (source.address ?? "").trim().toLowerCase() : "";
  const key = (c.authentication?.credentialId ?? "").trim().toUpperCase();
  for (const m of list) {
    if (m.kind === "ip") {
      if (ip && m.key === ip) return m;
    } else if (m.kind === "access-key") {
      if (key && m.key === key) return m;
    } else if (principalMatches(c, m)) return m;
  }
  return null;
}

/**
 * The reads a trusted source may have tagged: an EXPLICIT list of metadata reads — names, settings
 * and state, never content. Anything else (an unknown or new call, a version-suffixed variant, an
 * object listing, instance user data, metric values, log events, query results, code, objects,
 * secrets, tokens) stays untagged: unknown defaults to untrusted (Codex code and stop-time reviews,
 * #2561). Lower-case action names.
 */
const SAFE_READS = new Set([
  // identity and IAM configuration
  "getcalleridentity",
  "getaccountsummary",
  "getaccountpasswordpolicy",
  "getaccountauthorizationdetails",
  "getuser",
  "getgroup",
  "getrole",
  "getpolicy",
  "getpolicyversion",
  "getinstanceprofile",
  "getloginprofile",
  "getaccesskeylastused",
  "listusers",
  "listroles",
  "listgroups",
  "listpolicies",
  "listpolicyversions",
  "listattacheduserpolicies",
  "listattachedrolepolicies",
  "listattachedgrouppolicies",
  "listuserpolicies",
  "listrolepolicies",
  "listgrouppolicies",
  "listgroupsforuser",
  "listaccesskeys",
  "listmfadevices",
  "listinstanceprofiles",
  "listinstanceprofilesforrole",
  "listaccountaliases",
  "listentitiesforpolicy",
  "simulateprincipalpolicy",
  "simulatecustompolicy",
  // S3 bucket configuration (never object listings or object reads)
  "listbuckets",
  "headbucket",
  "getbucketacl",
  "getbucketpolicy",
  "getbucketpolicystatus",
  "getbucketlocation",
  "getbucketlogging",
  "getbucketversioning",
  "getbucketencryption",
  "getbucketobjectlockconfiguration",
  "getbuckettagging",
  "getbucketnotification",
  "getbucketnotificationconfiguration",
  "getbucketlifecycle",
  "getbucketlifecycleconfiguration",
  "getbucketreplication",
  "getbucketwebsite",
  "getbucketcors",
  "getbucketownershipcontrols",
  "getbucketrequestpayment",
  "getpublicaccessblock",
  // logging and monitoring configuration
  "describetrails",
  "gettrail",
  "gettrailstatus",
  "geteventselectors",
  "getinsightselectors",
  "listtrails",
  "describeloggroups",
  "describelogstreams",
  "describemetricfilters",
  "describesubscriptionfilters",
  "listdashboards",
  "getdashboard",
  "describealarms",
  "listmetrics",
  "listdetectors",
  "getdetector",
  "describeconfigurationrecorders",
  "describeconfigurationrecorderstatus",
  "describedeliverychannels",
  "describeconfigrules",
  "describeflowlogs",
  // KMS key configuration
  "listkeys",
  "listaliases",
  "describekey",
  "getkeypolicy",
  "getkeyrotationstatus",
  // EC2 / network / compute inventory (never instance attributes, console output or launch templates)
  "describeregions",
  "describeavailabilityzones",
  "describeaccountattributes",
  "describeinstances",
  "describeinstancestatus",
  "describesecuritygroups",
  "describesecuritygrouprules",
  "describevpcs",
  "describesubnets",
  "describenetworkinterfaces",
  "describeroutetables",
  "describeaddresses",
  "describekeypairs",
  "describeimages",
  "describesnapshots",
  "describevolumes",
  "getebsencryptionbydefault",
  "listfunctions",
  "listfunctions20150331",
  "describestacks",
  "describedbinstances",
  // billing
  "getcostandusage",
]);
/** Writes routine enough to tag for a trusted source: a log group/stream, a dashboard, a key alias. */
const ROUTINE_WRITES = new Set(["createloggroup", "createlogstream", "putdashboard", "createalias"]);
const SINGLE_CALL_TYPES = new Set(["api", "api-call"]);
const SIGN_IN = "consolelogin";

/** True when a single-call row's action is one a trusted source may have tagged. */
function routineCall(row: ForensicEvent, c: Canonical): boolean {
  const action = (c.event.action ?? "").trim().toLowerCase();
  if (!action || c.event.outcome !== "success") return false;
  if (action === SIGN_IN) return true;
  if (row.severity === "High") return false;
  const logging = c.loggingChange;
  if (logging) return !logging.failure && (logging.state === "enabled" || logging.state === "created");
  if (ROUTINE_WRITES.has(action)) return true;
  return SAFE_READS.has(action);
}

/** The friendly mark a lineage row qualifies under, or null. */
function lineageMark(row: ForensicEvent, c: Canonical, marks: TrustedMarks): TrustedMark | null {
  const block = c.awsLineage;
  if (!block || row.severity === "High" || block.shapes.length || block.sourcesBeyond) return null;
  if (!block.sources.length) return null;
  const key = block.credentialId.trim().toUpperCase();
  const addresses = block.sources.map((s) => s.address.trim().toLowerCase());
  const keyHit = (list: readonly TrustedMark[]) => list.find((m) => m.kind === "access-key" && m.key === key);
  const ipHit = (list: readonly TrustedMark[], a: string) => list.find((m) => m.kind === "ip" && m.key === a);
  if (keyHit(marks.attacker) || addresses.some((a) => ipHit(marks.attacker, a))) return null;
  const byKey = keyHit(marks.friendly);
  if (byKey) return byKey;
  const perSource = addresses.map((a) => ipHit(marks.friendly, a));
  return perSource.every(Boolean) ? (perSource[0] ?? null) : null;
}

/** The friendly mark this row is tagged under, or null (the never-tag gate included). Pure. */
export function trustedMarkFor(row: ForensicEvent, marks: TrustedMarks): TrustedMark | null {
  const c = row.canonical;
  if (!marks.friendly.length || !c || c.event.category !== "cloud") return null;
  if (c.cloud?.provider !== "aws" || row.severity === "Critical") return null;
  if (c.event.type === "credential-lineage") return lineageMark(row, c, marks);
  if (!SINGLE_CALL_TYPES.has(c.event.type)) return null;
  if (firstMatch(c, marks.attacker)) return null;
  const hit = firstMatch(c, marks.friendly);
  return hit && routineCall(row, c) ? hit : null;
}

export function trustedAuthor(mark: Pick<TrustedMark, "label" | "value">): string {
  return `${TRUSTED_AUTHOR_PREFIX}${mark.label}:${mark.value}`;
}

/** The label and value a trusted tag's author names, or null when it is not one. */
export function parseTrustedAuthor(author: string): { label: FriendlyLabel; value: string } | null {
  if (!author.startsWith(TRUSTED_AUTHOR_PREFIX)) return null;
  const rest = author.slice(TRUSTED_AUTHOR_PREFIX.length);
  const at = rest.indexOf(":");
  if (at < 1) return null;
  const label = rest.slice(0, at);
  const value = rest.slice(at + 1);
  return (label === "ours" || label === "responder") && value ? { label, value } : null;
}

/** The tags to write for `rows`: one per tagged row. Pure. */
export function trustedActivityTags(rows: readonly ForensicEvent[], marks: TrustedMarks): NewTag[] {
  if (!marks.friendly.length) return [];
  const out: NewTag[] = [];
  for (const row of rows) {
    const mark = trustedMarkFor(row, marks);
    if (mark)
      out.push({ targetType: "event", targetId: row.id, label: TRUSTED_LABEL, author: trustedAuthor(mark) });
  }
  return out;
}

export interface HonouredTrust {
  label: FriendlyLabel;
  value: string;
}

/**
 * The rows whose trusted tag still holds: the tag carries this pass's author, the value it names is
 * STILL friendly with the same label, and the row is still eligible under the current gate. Every
 * consumer (count, hide filter, synthesis) reads this, never the raw tags — so a removal that failed,
 * a row raised to Critical later, or an analyst's hand-made `trusted-activity` tag hides nothing.
 */
export function honouredTrustedRows(
  rows: readonly ForensicEvent[],
  tags: readonly Pick<Tag, "targetType" | "targetId" | "label" | "author">[],
  map: IocAttributionMap,
): Map<string, HonouredTrust> {
  const out = new Map<string, HonouredTrust>();
  const marks = parseTrustedMarks(map);
  if (!marks.friendly.length) return out;
  const byId = new Map(rows.map((r) => [r.id, r]));
  for (const tag of tags) {
    if (tag.targetType !== "event" || tag.label !== TRUSTED_LABEL) continue;
    const named = parseTrustedAuthor(tag.author);
    if (!named) continue;
    const current = map[named.value.trim().toLowerCase()];
    if (!current || current.label !== named.label) continue;
    const row = byId.get(tag.targetId);
    if (row && trustedMarkFor(row, marks)) out.set(row.id, named);
  }
  return out;
}
