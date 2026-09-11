import { createHash } from "node:crypto";

// The IAM policy-document reader (#931 item 6).
//
// A CloudTrail record carries the document a call SENT — a policy body, a trust policy — and
// nothing else: not the document it replaced, not the boundary or the organisation controls the
// grant runs under, not the managed policy an ARN points at. So this reader reports the document's
// OWN WORDS — which operators, which effects, which principals — and never what access "became".
// The one grading signal it exports is `broad`: the four exclusion-or-wildcard forms and the
// documented privilege-escalation primitives, matched with AWS's own glob semantics, because an
// `Allow NotAction iam:* Resource *` is a near-universal grant that a naive "look for `*`" misses.
//
// Order of operations is part of the contract: the raw string is digested BEFORE any decode (two
// unreadable documents are two rows, not one), JSON is parsed BEFORE any percent-decode (a literal
// `%25` inside a JSON string must survive), and percent-decoding runs only when the text is
// demonstrably encoded.

export type ActionOp = "Action" | "NotAction";
export type ResourceOp = "Resource" | "NotResource";

export interface PolicyPrincipal {
  /** `Principal: "*"` or `AWS: "*"` — any principal. */
  any: boolean;
  aws: string[];
  service: string[];
  federated: string[];
  /** CanonicalUser and any key this reader does not name — kept, never dropped. */
  other: string[];
}

export interface PolicyStatement {
  effect: "Allow" | "Deny";
  actions: { op: ActionOp; values: string[] };
  resources: { op: ResourceOp; values: string[] };
  principal: PolicyPrincipal | null;
  /** `NotPrincipal` — the statement applies to EVERY principal except those listed. */
  principalExcluded: boolean;
  hasCondition: boolean;
}

export interface PolicyReading {
  readable: true;
  /** 16-hex digest of the raw text as received — set for every outcome, before any decode. */
  rawDigest: string;
  /** 16-hex digest of the canonical (key-sorted) parsed document — reordered keys fold. */
  digest: string;
  statements: PolicyStatement[];
  effect: "grants" | "denies" | "mixed" | "empty";
  /** The document's words, ≤ READING_MAX, tail kept. */
  reading: string;
  /** A broad form or an escalation primitive in an Allow statement. */
  broad: boolean;
  /** Escalation primitives an Allow statement's Action covers, canonical names. */
  primitives: string[];
  conditional: boolean;
}

export interface PolicyUnreadable {
  readable: false;
  /** Empty when the input had no text to digest (an object that could not be serialised). */
  rawDigest: string;
  reason: string;
}

/** The standing qualifier every reading carries — rendered by the caller, once. */
export const POLICY_CAVEAT = "effective access depends on controls not in this record";
export const CONDITIONAL_NOTE = "conditional — not evaluated here";

// The documented privilege-escalation primitives: the IAM paths (policy attach/put/version,
// credential creation, trust rewrite, PassRole and the services that consume it) plus the
// controls whose removal AWS documents as potentially increasing permissions. A test asserts every
// High-graded IAM entry of the importer's action table is here, so the two cannot drift apart.
export const ESCALATION_PRIMITIVES: readonly string[] = [
  "iam:AttachUserPolicy",
  "iam:AttachRolePolicy",
  "iam:AttachGroupPolicy",
  "iam:PutUserPolicy",
  "iam:PutRolePolicy",
  "iam:PutGroupPolicy",
  "iam:CreatePolicyVersion",
  "iam:SetDefaultPolicyVersion",
  "iam:CreateAccessKey",
  "iam:CreateLoginProfile",
  "iam:UpdateLoginProfile",
  "iam:AddUserToGroup",
  "iam:UpdateAssumeRolePolicy",
  "iam:PassRole",
  "iam:DeactivateMFADevice",
  "iam:DeleteVirtualMFADevice",
  "iam:DeleteUserPermissionsBoundary",
  "iam:DeleteRolePermissionsBoundary",
  "sts:AssumeRole",
  "lambda:CreateFunction",
  "lambda:UpdateFunctionCode",
  "ec2:RunInstances",
  "cloudformation:CreateStack",
  "glue:CreateDevEndpoint",
  "glue:UpdateDevEndpoint",
];

const DOCUMENT_MAX = 65536;
const READING_MAX = 220;
const READING_TAIL = 60;
const LIST_SHOWN = 3;
const DIGEST_HEX = 16;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const digest = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, DIGEST_HEX);
const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : typeof v === "string" ? [v] : [];

// Key-sorted JSON, so a document that differs only in key order has one digest. Bounded in depth
// and node count: an already-parsed object can be small in bytes and thousands of levels deep, and
// an unbounded recursion there would abort the import. Over the bound → a controlled failure the
// reader turns into "unreadable".
const CANONICAL_MAX_DEPTH = 32;
const CANONICAL_MAX_NODES = 20000;
class DocumentTooLarge extends Error {}
function canonical(v: unknown, depth = 0, budget = { nodes: 0 }): string {
  if (depth > CANONICAL_MAX_DEPTH || ++budget.nodes > CANONICAL_MAX_NODES) throw new DocumentTooLarge();
  if (Array.isArray(v)) return `[${v.map((x) => canonical(x, depth + 1, budget)).join(",")}]`;
  if (isObj(v))
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(v[k], depth + 1, budget)}`)
      .join(",")}}`;
  return JSON.stringify(v) ?? "null";
}
// Null for ANY failure — the bound, a throwing getter, a BigInt JSON.stringify refuses: this reader
// is total over unknown input, and an adapter's in-memory object is unknown input.
function canonicalOrNull(v: unknown): string | null {
  try {
    return canonical(v);
  } catch {
    return null;
  }
}

/**
 * AWS action glob: `*` any run, `?` one character, case-insensitive, whole string. A two-pointer
 * matcher, never a RegExp — a document under the size bound can still hold tens of thousands of
 * `*`, and V8 refuses to compile that pattern, which would abort the whole import. The cost is
 * O(pattern × action) in the worst case, and the ACTION side is always one of this module's own
 * constants (a primitive, an assumption action — under 50 characters); only the pattern is the
 * document's, so a hostile document costs linear time in its own length.
 */
export function actionMatches(pattern: string, action: string): boolean {
  const p = pattern.toLowerCase().replace(/\*{2,}/g, "*");
  const a = action.toLowerCase();
  let pi = 0;
  let ai = 0;
  let star = -1;
  let mark = 0;
  while (ai < a.length) {
    if (pi < p.length && (p[pi] === "?" || p[pi] === a[ai])) {
      pi++;
      ai++;
    } else if (pi < p.length && p[pi] === "*") {
      star = pi++;
      mark = ai;
    } else if (star >= 0) {
      pi = star + 1;
      ai = ++mark;
    } else return false;
  }
  while (pi < p.length && p[pi] === "*") pi++;
  return pi === p.length;
}

const coversAll = (pattern: string): boolean => /^\*+(?::\*+)?$/.test(pattern);
const serviceWildcard = (pattern: string): string | null => {
  const m = /^([a-z0-9-]+):\*$/i.exec(pattern);
  return m ? m[1].toLowerCase() : null;
};

function readPrincipal(v: unknown): PolicyPrincipal | null {
  if (v === undefined || v === null) return null;
  const p: PolicyPrincipal = { any: false, aws: [], service: [], federated: [], other: [] };
  if (v === "*") return { ...p, any: true };
  if (!isObj(v)) return { ...p, other: strings(v) };
  for (const [key, value] of Object.entries(v)) {
    const vals = strings(value);
    const k = key.toLowerCase();
    if (k === "aws") {
      if (vals.includes("*")) p.any = true;
      p.aws.push(...vals.filter((x) => x !== "*"));
    } else if (k === "service") p.service.push(...vals);
    else if (k === "federated") p.federated.push(...vals);
    else p.other.push(...vals.map((x) => `${key}:${x}`));
  }
  return p;
}

function readStatement(v: unknown): PolicyStatement | null {
  if (!isObj(v)) return null;
  const effect = v.Effect === "Deny" ? "Deny" : v.Effect === "Allow" ? "Allow" : null;
  if (!effect) return null;
  const actions =
    v.NotAction !== undefined
      ? { op: "NotAction" as const, values: strings(v.NotAction) }
      : { op: "Action" as const, values: strings(v.Action) };
  const resources =
    v.NotResource !== undefined
      ? { op: "NotResource" as const, values: strings(v.NotResource) }
      : { op: "Resource" as const, values: strings(v.Resource) };
  return {
    effect,
    actions,
    resources,
    principal: readPrincipal(v.Principal ?? v.NotPrincipal),
    principalExcluded: v.Principal === undefined && v.NotPrincipal !== undefined,
    hasCondition: isObj(v.Condition) && Object.keys(v.Condition).length > 0,
  };
}

// Percent-decoding is a FALLBACK, and only for text that is demonstrably encoded — an encoded
// document begins with `%7B` (`{`); a lone `%` in it is a malformed document, said so.
function decodeDocument(raw: string): { doc: unknown } | { reason: string } {
  try {
    return { doc: JSON.parse(raw) };
  } catch {
    /* fall through to the percent-encoded reading */
  }
  const encoded = /^\s*%7b/i.test(raw) || raw.includes("%22");
  if (!encoded) return { reason: "not JSON" };
  let text: string;
  try {
    text = decodeURIComponent(raw);
  } catch {
    return { reason: "malformed percent-encoding" };
  }
  try {
    return { doc: JSON.parse(text) };
  } catch {
    return { reason: "percent-decoded text is not JSON" };
  }
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const list = (values: string[]): string =>
  values.slice(0, LIST_SHOWN).join(", ") +
  (values.length > LIST_SHOWN ? ` (+${values.length - LIST_SHOWN} more)` : "");

// One clause per Allow statement, the broad forms first; a plain grant is summarised by count.
function allowClause(st: PolicyStatement): { words: string; broad: boolean; primitives: string[] } {
  const { actions, resources } = st;
  const allActions = actions.op === "Action" && actions.values.some(coversAll);
  const allResources = resources.op === "Resource" && resources.values.includes("*");
  const actionsPart =
    actions.op === "NotAction"
      ? `all actions except ${list(actions.values)}`
      : allActions
        ? "all actions"
        : null;
  const resourcesPart =
    resources.op === "NotResource"
      ? `all resources except ${list(resources.values)}`
      : allResources
        ? "all resources"
        : null;
  // A bare `*` is the all-actions form, not a list of primitives; every other pattern (`iam:*`,
  // `iam:Attach*`) names the primitives it covers.
  const primitives =
    actions.op === "Action"
      ? ESCALATION_PRIMITIVES.filter((p) => actions.values.some((v) => !coversAll(v) && actionMatches(v, p)))
      : [];
  const services =
    actions.op === "Action"
      ? [...new Set(actions.values.map(serviceWildcard).filter((s): s is string => s !== null))]
      : [];
  // The four broad forms — and only those: an exclusion or an all-actions grant scoped to named
  // resources is summarised, not promoted.
  if (actionsPart && resourcesPart)
    return { words: `${actionsPart} on ${resourcesPart}`, broad: true, primitives };
  const parts: string[] = [];
  if (actionsPart) parts.push(`${actionsPart} on ${plural(resources.values.length, "resource")}`);
  for (const s of services) parts.push(`all ${s} actions`);
  if (primitives.length) parts.push(`grants ${list(primitives)}`);
  if (!parts.length)
    parts.push(
      `${plural(actions.values.length, "action")} on ${resourcesPart ?? plural(resources.values.length, "resource")}`,
    );
  return { words: parts.join("; "), broad: primitives.length > 0, primitives };
}

function boundReading(text: string): string {
  if (text.length <= READING_MAX) return text;
  return `${text.slice(0, READING_MAX - READING_TAIL - 1)}…${text.slice(-READING_TAIL)}`;
}

/**
 * Read one policy or trust document as CloudTrail carried it: the escaped-JSON string, its
 * percent-encoded variant, or an object an exporter parsed already. Never throws — whatever the
 * input does (a getter that throws, a BigInt, a Proxy), the result is an unreadable reading. An
 * object that cannot be serialised has NO digest (`rawDigest` is ""): the caller must key such a
 * row on a per-record identity, never on the reason text, or every over-limit document would fold.
 */
export function readPolicyDocument(raw: unknown): PolicyReading | PolicyUnreadable {
  try {
    return readDocument(raw);
  } catch {
    return { readable: false, rawDigest: "", reason: "not readable" };
  }
}

function readDocument(raw: unknown): PolicyReading | PolicyUnreadable {
  if (isObj(raw) || Array.isArray(raw)) {
    const text = canonicalOrNull(raw);
    if (text === null)
      return { readable: false, rawDigest: "", reason: "too deep, too wide or not serialisable" };
    return readDocument(text);
  }
  const text = typeof raw === "string" ? raw : "";
  const rawDigest = digest(text);
  if (!text) return { readable: false, rawDigest, reason: "no document" };
  if (text.length > DOCUMENT_MAX) return { readable: false, rawDigest, reason: "over 64 KiB" };
  const decoded = decodeDocument(text);
  if ("reason" in decoded) return { readable: false, rawDigest, reason: decoded.reason };
  const doc = decoded.doc;
  if (!isObj(doc) || doc.Statement === undefined)
    return { readable: false, rawDigest, reason: "no Statement" };
  const canon = canonicalOrNull(doc);
  if (canon === null) return { readable: false, rawDigest, reason: "too deep, too wide or not serialisable" };
  const rawStatements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
  const statements = rawStatements.map(readStatement).filter((s): s is PolicyStatement => s !== null);
  const allows = statements.filter((s) => s.effect === "Allow");
  const denies = statements.length - allows.length;
  const clauses = allows.map(allowClause);
  const words: string[] = clauses.map((c) => c.words);
  if (denies) words.push(`denies ${plural(denies, "statement")}`);
  return {
    readable: true,
    rawDigest,
    digest: digest(canon),
    statements,
    effect: !statements.length ? "empty" : !allows.length ? "denies" : denies ? "mixed" : "grants",
    reading: boundReading(words.join("; ")),
    broad: clauses.some((c) => c.broad),
    primitives: [...new Set(clauses.flatMap((c) => c.primitives))],
    conditional: statements.some((s) => s.hasCondition),
  };
}
