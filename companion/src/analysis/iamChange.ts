import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import {
  actionMatches,
  CONDITIONAL_NOTE,
  POLICY_CAVEAT,
  readPolicyDocument,
  type PolicyReading,
  type PolicyStatement,
} from "./iamPolicyDocument.js";
import { FIELD_LABELS, POSTURES, RESPONSE_FIELDS, type Posture } from "./iamPostures.js";
export { renderAwsDescription, type AwsDescriptionParts } from "./awsDescription.js";

// AWS permission changes, read from the one record CloudTrail gives us (#931 item 6).
//
// A record establishes four things and this decoder claims exactly those: the POSTURE of the call
// (attaches, replaces, removes — a verb, never a direction: attaching a Deny narrows, detaching one
// widens, and a Put replaces a document the record does not hold); the OBJECT it names (every
// identity-bearing field, from the request AND the response — a new access key's id exists only in
// the response — digested whole into the key, because two changes sharing a key overwrite each
// other's evidence); the WORDS of any document it carries (iamPolicyDocument.ts); and the role a
// service call BINDS to a workload (`iam:PassRole` is a permission, not an event — the role passed
// sits in the RunInstances / CreateFunction / RegisterTaskDefinition / CreateStack request).
//
// A failed call did not change state: its posture is `attempted to …`, its readings are
// `requested …`, and no success-only floor applies. Nothing here lowers a grade — the importer's
// table stands; the decoder only supplies floors that raise.

type Obj = Record<string, unknown>;

export interface IamBinding {
  label: string;
  role: string;
  destination: string;
}

export interface IamChange {
  postureId: string;
  /** Rendered verb phrase — `attaches managed policy`, or `attempted to attach managed policy`. */
  posture: string;
  attempted: boolean;
  /** `denied (<code>)` when attempted, else "". */
  outcome: string;
  /** The labeled object tuple, display-bounded; the key digests the complete tuple. */
  object: string;
  /** What the record lacks for this posture — `— its document and version are not in this record`. */
  note: string;
  /** The document's words (prefixed `requested document:` when attempted); "" when none. */
  reading: string;
  trust: string;
  bindings: IamBinding[];
  bindingsText: string;
  severityFloor: Severity | null;
  mitre: string[];
  /** Mandatory qualifiers — what the record does NOT establish. */
  qualifiers: string[];
  /** Posture, object, outcome, note, readings — everything but the importer's head and tail. */
  summary: string;
  keySegment: string;
}

const IAM_SOURCE = "iam.amazonaws.com";
const DIGEST_HEX = 16;
const VALUE_MAX = 80;
const OBJECT_MAX = 150;
const READING_PREFIX_ATTEMPT = "requested ";
const ASSUME_ACTIONS = ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"];
const PASSROLE_DENIED = /iam:PassRole on resource:\s*(arn:[^\s"']+)/i;
const ACCOUNT_ARN = /^arn:[^:]*:(?:iam|sts)::(\d{12}):/i;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const raw = (v: unknown): string =>
  typeof v === "string" ? v.trim() : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
const getCI = (o: unknown, key: string): unknown =>
  isObj(o) ? o[Object.keys(o).find((k) => k.toLowerCase() === key.toLowerCase()) ?? ""] : undefined;
const path = (o: unknown, keys: string[]): unknown => keys.reduce<unknown>((cur, k) => getCI(cur, k), o);
const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, DIGEST_HEX);
const arnName = (arn: string): string => arn.split("/").pop() || arn;

// The verb of the three postures whose wording depends on the request or the outcome.
function postureVerb(p: Posture, nameLower: string, req: Obj, attempted: boolean): string {
  if (attempted) {
    const version = nameLower === "deletepolicyversion" ? ` ${raw(req.versionId) || "?"}` : "";
    return `attempted to ${p.infinitive}${version}`;
  }
  if (nameLower === "updateaccesskey") {
    const status = raw(getCI(req, "status")).toLowerCase();
    return status === "active"
      ? "re-enables access key"
      : status === "inactive"
        ? "disables access key"
        : p.verb;
  }
  if (nameLower === "createpolicyversion" && /^true$/i.test(raw(getCI(req, "setAsDefault"))))
    return `${p.verb} and activates it`;
  if (nameLower === "setdefaultpolicyversion" || nameLower === "deletepolicyversion")
    return `${p.verb} ${raw(getCI(req, "versionId")) || "?"}`;
  return p.verb;
}

function objectTuple(
  p: Posture,
  nameLower: string,
  req: Obj,
  res: unknown,
): { display: string; key: string } {
  const pairs: Array<[string, string]> = [];
  for (const f of p.fields) {
    const v = raw(getCI(req, f));
    if (v) pairs.push([FIELD_LABELS[f] ?? f, v]);
  }
  for (const [label, keys] of RESPONSE_FIELDS[nameLower] ?? []) {
    const v = raw(path(res, keys));
    if (v) pairs.push([label, v]);
  }
  const display = pairs
    .map(([l, v]) => `${l}=${(l === "policy" || l === "boundary" ? arnName(v) : v).slice(0, VALUE_MAX)}`)
    .join(" ")
    .slice(0, OBJECT_MAX);
  return { display, key: digest(pairs.map(([l, v]) => `${l}=${v.toLowerCase()}`).join("|")) };
}

// ───────────────────────────── trust ─────────────────────────────

function accountOf(principal: string): string | null {
  if (/^\d{12}$/.test(principal)) return principal;
  const m = ACCOUNT_ARN.exec(principal);
  return m ? m[1] : null;
}

function principalClasses(
  st: PolicyStatement,
  recipient: string,
): { words: string[]; external: boolean; any: boolean } {
  const p = st.principal;
  const words: string[] = [];
  let external = false;
  if (!p) return { words, external, any: false };
  if (p.any) words.push("any principal");
  for (const a of p.aws) {
    const id = accountOf(a);
    if (!id) words.push(`principal of unknown form: ${a.slice(0, 60)}`);
    else if (!recipient) words.push(`account ${id} — not compared: recipient account not in this record`);
    else if (id === recipient) words.push("same-account");
    else {
      words.push(`external account ${id}`);
      external = true;
    }
  }
  for (const s of p.service) words.push(`service ${s}`);
  for (const f of p.federated) words.push(`federated ${f}`);
  for (const o of p.other) words.push(`principal of unknown form: ${o.slice(0, 60)}`);
  return { words: [...new Set(words)], external, any: p.any };
}

function trustReading(reading: PolicyReading, recipient: string): { text: string; floor: Severity | null } {
  const parts: string[] = [];
  let floor: Severity | null = null;
  for (const st of reading.statements) {
    if (st.effect !== "Allow" || st.actions.op !== "Action") continue;
    const assumed = ASSUME_ACTIONS.filter((a) => st.actions.values.some((v) => actionMatches(v, a)));
    if (!assumed.length) continue;
    const { words, external, any } = principalClasses(st, recipient);
    if (!words.length) continue;
    const unrestricted = any && !st.hasCondition;
    parts.push(
      `allows ${assumed.join("/")} to ${words.join(", ")}${unrestricted ? " — unrestricted public assumption" : ""}${st.hasCondition ? " (conditional)" : ""}`,
    );
    if (any || external) floor = worstOf(floor, st.hasCondition ? "Medium" : "High");
  }
  return { text: parts.join("; "), floor };
}

// ───────────────────────────── bindings ─────────────────────────────

function bindingsFor(source: string, nameLower: string, req: Obj, res: unknown): IamBinding[] {
  const svc = source.toLowerCase().replace(/\.amazonaws\.com$/, "");
  if (svc === "ec2" && nameLower === "runinstances") {
    const profile =
      raw(path(req, ["iamInstanceProfile", "arn"])) || raw(path(req, ["iamInstanceProfile", "name"]));
    if (!profile) return [];
    const items = path(res, ["instancesSet", "items"]);
    const ids = Array.isArray(items)
      ? items
          .map((i) => raw(getCI(i, "instanceId")))
          .filter(Boolean)
          .sort()
      : [];
    return [
      {
        label: "instance profile",
        role: profile,
        destination: ids.join(",") || raw(getCI(req, "clientToken")),
      },
    ];
  }
  if (svc === "lambda" && /^(createfunction|updatefunctionconfiguration)/.test(nameLower)) {
    const role = raw(getCI(req, "role"));
    return role ? [{ label: "role", role, destination: raw(getCI(req, "functionName")) }] : [];
  }
  if (svc === "ecs" && nameLower === "registertaskdefinition") {
    const family = raw(getCI(req, "family"));
    const revision = raw(path(res, ["taskDefinition", "revision"]));
    const dest = revision ? `${family}:${revision}` : family;
    const out: IamBinding[] = [];
    const task = raw(getCI(req, "taskRoleArn"));
    const exec = raw(getCI(req, "executionRoleArn"));
    if (task) out.push({ label: "task role", role: task, destination: dest });
    if (exec) out.push({ label: "execution role", role: exec, destination: dest });
    return out;
  }
  if (svc === "cloudformation" && (nameLower === "createstack" || nameLower === "updatestack")) {
    const role = raw(getCI(req, "roleARN"));
    return role
      ? [{ label: "role", role, destination: raw(getCI(res, "stackId")) || raw(getCI(req, "stackName")) }]
      : [];
  }
  return [];
}

const SEVERITY_RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const worstOf = (a: Severity | null, b: Severity | null): Severity | null =>
  !a ? b : !b ? a : SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a;

/**
 * Decode one CloudTrail record as an IAM change or a role binding, or null when it is neither.
 * `recipientAccountId` is the account the changed resource lives in; without it a trust policy's
 * accounts are named but not compared.
 */
export function decodeIamChange(
  source: string,
  name: string,
  request: unknown,
  response: unknown,
  errorCode: string,
  errorMessage: string,
  recipientAccountId: string,
): IamChange | null {
  const req: Obj = isObj(request) ? request : {};
  const nameLower = name.toLowerCase();
  const attempted = !!errorCode.trim();
  const posture = source.toLowerCase() === IAM_SOURCE ? POSTURES[nameLower] : undefined;
  const bindings = bindingsFor(source, nameLower, req, response);
  const deniedRole = PASSROLE_DENIED.exec(errorMessage)?.[1] ?? "";
  if (!posture && !bindings.length && !deniedRole) return null;

  const mitre: string[] = [];
  let floor: Severity | null = attempted ? "Medium" : null;
  const qualifiers: string[] = [];
  const add = (t: string | undefined) => t && !mitre.includes(t) && mitre.push(t);

  let verb = "";
  let object = { display: "", key: "" };
  let reading = "";
  let trust = "";
  let docDigest = "";
  if (posture) {
    verb = postureVerb(posture, nameLower, req, attempted);
    object = objectTuple(posture, nameLower, req, response);
    if (posture.qualifier) qualifiers.push(posture.qualifier);
    if (!attempted && posture.floor) floor = worstOf(floor, posture.floor);
    if (posture.floor) for (const t of posture.mitre ?? []) add(t);
    if (nameLower === "updateaccesskey" && !attempted && verb.startsWith("re-enables")) {
      floor = worstOf(floor, "Medium");
      add("T1098.001");
    }
    if (posture.docField) {
      const read = readPolicyDocument(getCI(req, posture.docField));
      // The canonical digest folds a reordered copy; an unreadable document keeps its raw digest,
      // so two different malformed documents never share a key.
      docDigest = read.readable ? read.digest : read.rawDigest;
      const prefix = attempted ? READING_PREFIX_ATTEMPT : "";
      if (!read.readable) reading = `${prefix}document: unreadable (${read.reason})`;
      else {
        const isTrust = nameLower === "createrole" || nameLower === "updateassumerolepolicy";
        if (isTrust) {
          const t = trustReading(read, recipientAccountId.trim());
          trust = t.text ? `${prefix}trust: ${t.text}` : "";
          if (!attempted) floor = worstOf(floor, t.floor);
          if (t.floor) add("T1098");
        } else {
          reading = `${prefix}document: ${read.effect} — ${read.reading}`;
          if (read.broad && !attempted) floor = worstOf(floor, "High");
          if (read.broad) add("T1098.003");
        }
        if (read.conditional) qualifiers.push(CONDITIONAL_NOTE);
        qualifiers.push(POLICY_CAVEAT);
      }
    }
  }

  // A PassRole denial IS the binding's evidence: the denial line replaces "requested passing" for
  // that role, so a denied pass is never worded as a pass.
  const bindingWords = bindings
    .filter((b) => !deniedRole || b.role.toLowerCase() !== deniedRole.toLowerCase())
    .map(
      (b) =>
        `${attempted ? "requested " : ""}passing ${b.label} ${b.role.slice(0, VALUE_MAX)}${b.destination ? ` → ${b.destination.slice(0, VALUE_MAX)}` : ""}`,
    );
  if (bindings.length && !attempted) {
    floor = worstOf(floor, "Medium");
    add("T1078.004");
  }
  if (deniedRole) {
    bindingWords.push(`role passing denied: ${deniedRole.slice(0, VALUE_MAX)}`);
    floor = worstOf(floor, "Medium");
    add("T1078.004");
  }
  const bindingsText = bindingWords.join("; ");
  const bindingsDigest = bindings.length
    ? digest(
        bindings.map((b) => `${b.label}=${b.role.toLowerCase()}→${b.destination.toLowerCase()}`).join("|"),
      )
    : "";

  const outcome = attempted ? `denied (${errorCode.trim().slice(0, 30)})` : "";
  const note = posture && !attempted ? (posture.note ?? "") : "";
  const summary = [verb, object.display, outcome ? `— ${outcome}` : "", note, reading, trust, bindingsText]
    .filter(Boolean)
    .join(" ");
  const postureId = posture?.id ?? (deniedRole && !bindings.length ? "passrole-denied" : "binding");
  return {
    postureId,
    posture: verb,
    attempted,
    outcome,
    object: object.display,
    note,
    reading,
    trust,
    bindings,
    bindingsText,
    severityFloor: floor,
    mitre,
    qualifiers,
    summary,
    keySegment: `|iam:${postureId}|${attempted ? "denied" : "ok"}|${object.key || "-"}|${docDigest || "-"}|${bindingsDigest || "-"}`,
  };
}
