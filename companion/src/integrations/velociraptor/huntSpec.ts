// The `spec` clause of a hunt: per-artifact parameter overrides, sent to the endpoint byte for byte.
import { ARTIFACT_RE } from "./artifactRefs.js";

const PARAM_RE = /^[A-Za-z_][A-Za-z0-9_]*$/; // valid Velociraptor parameter name
// A declared name that is not a plain identifier, safe inside backticks: printable ASCII, no backtick or backslash.
const QUOTABLE_PARAM_RE = /^[\x20-\x5B\x5D-\x5F\x61-\x7E]+$/;
const PLAIN_PARAM_VALUE_RE = /^[\x20-\x7E]*$/; // printable ASCII: safe as a literal once quotes are ruled out
const MAX_PARAM_VALUE_CHARS = 64_000;
const MAX_NAME_IN_MESSAGE = 120; // names come from stored bundle JSON: cap what a message echoes back
const MAX_DECLARED_IN_MESSAGE = 12;

// A hunt refused BEFORE launch because its parameters are wrong. The cause is the analyst's bundle, not
// the Velociraptor server, so the run-bundle route answers 400 and the message names what to fix. Every
// refusal here exists because the silent alternative is worse: a dropped override runs the artifact with
// its own defaults, and for a narrowing parameter (Hayabusa RuleLevel) that BROADENS a fleet-wide hunt.
export class HuntSpecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HuntSpecError";
  }
}

// What the bundle pre-flight learned (structurally a BundlePreflight): the bundle artifacts it left out
// of the launch, and each artifact's declared parameters on THIS server.
export interface HuntSpecCheck {
  unknownArtifacts: readonly string[];
  unavailableArtifacts: readonly { artifact: string }[];
  definitions: readonly { name: string; parameters?: readonly { name: string }[] }[];
}

const quoted = (s: string): string =>
  JSON.stringify(s.length > MAX_NAME_IN_MESSAGE ? `${s.slice(0, MAX_NAME_IN_MESSAGE)}…` : s);

// A JSON object — not an array, not a class instance. Stored bundle files bypass the save sanitizer's
// shape guarantees, so the TypeScript type alone does not hold at run time.
function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// One parameter value as a VQL expression that evaluates to EXACTLY that string. A plain value stays a
// readable single-quoted literal. Anything else — a CSV parameter's newlines (Hayabusa RuleExclusions),
// a quote, a backslash, non-ASCII — goes through base64decode(), which no character can break out of.
// Folding those into one line used to turn a CSV's rows into one header row and drop the exclusions.
// Too long is refused rather than truncated: a cut CSV or glob fails silently on the endpoint.
function vqlParamValue(artifact: string, key: string, raw: unknown): string {
  if (raw == null || typeof raw === "object") {
    throw new HuntSpecError(`parameter ${key} for artifact ${quoted(artifact)} must be a text value`);
  }
  const value = String(raw);
  if (value.length > MAX_PARAM_VALUE_CHARS) {
    throw new HuntSpecError(
      `parameter ${key} is too long (${value.length} > ${MAX_PARAM_VALUE_CHARS} chars) for artifact ${quoted(artifact)}`,
    );
  }
  if (PLAIN_PARAM_VALUE_RE.test(value) && !/['\\]/.test(value)) return `'${value}'`;
  return `base64decode(string='${Buffer.from(value, "utf8").toString("base64")}')`;
}

// Each artifact's declared parameter names, for the artifacts whose definition lists any. An artifact
// with no reported parameters is absent: missing metadata is not evidence that it takes none.
function declaredParams(check?: HuntSpecCheck): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const def of check?.definitions ?? []) {
    const names = (def.parameters ?? []).map((p) => String(p?.name ?? "")).filter(Boolean);
    if (names.length) out.set(def.name, names);
  }
  return out;
}

const malformed = (artifact: string, key: string): HuntSpecError =>
  new HuntSpecError(
    `invalid parameter name ${quoted(key)} for artifact ${quoted(artifact)} — use letters, digits and _ only; fix it in the bundle's parameters`,
  );

// The parameter name to SEND. When the server reports the artifact's parameters, the name must be one of
// them: a well-formed name it does not declare ("RuleLevl") is ignored on the endpoint exactly like a
// malformed one. Velociraptor matches names case-sensitively, so a case-only difference is sent in the
// artifact's own spelling, and a declared name with spaces (Autoruns' `Boot execute`) is sent backtick-
// quoted. Without metadata, only a plain identifier can be trusted.
function paramName(artifact: string, key: string, declared: string[] | undefined): string {
  if (!declared) {
    if (!PARAM_RE.test(key)) throw malformed(artifact, key);
    return key;
  }
  const match =
    declared.find((d) => d === key) ?? declared.find((d) => d.toLowerCase() === key.toLowerCase());
  if (match && PARAM_RE.test(match)) return match;
  if (match && QUOTABLE_PARAM_RE.test(match)) return `\`${match}\``;
  if (match || !PARAM_RE.test(key)) throw malformed(artifact, key);
  const extra = declared.length - MAX_DECLARED_IN_MESSAGE;
  const shown = declared.slice(0, MAX_DECLARED_IN_MESSAGE).join(", ") + (extra > 0 ? `, +${extra} more` : "");
  throw new HuntSpecError(
    `artifact ${quoted(artifact)} on this Velociraptor server has no parameter ${key} (it declares: ${shown}) — fix the name in the bundle's parameters`,
  );
}

function artifactSpec(artifact: string, kv: unknown, declared: string[] | undefined): string | undefined {
  if (!isPlainObject(kv)) {
    throw new HuntSpecError(`parameters for artifact ${quoted(artifact)} must be an object of name: value`);
  }
  const sent = new Set<string>();
  const pairs = Object.entries(kv).map(([k, v]) => {
    const name = paramName(artifact, k, declared);
    if (sent.has(name)) {
      throw new HuntSpecError(`parameter ${name} is set twice for artifact ${quoted(artifact)}`);
    }
    sent.add(name);
    return `${name}=${vqlParamValue(artifact, k, v)}`;
  });
  return pairs.length ? `\`${artifact}\`=dict(${pairs.join(", ")})` : undefined;
}

// Build the hunt's `spec` clause from per-artifact parameter overrides so a heavy artifact runs with
// fewer/narrower outputs at the source (e.g. `Windows.Hayabusa.Rules`=dict(RuleLevel='Critical, High, and Medium')).
// Returns undefined when there's nothing to set. Throws HuntSpecError rather than drop anything the
// analyst asked for (#1606). The ONE silent skip is params for an artifact the pre-flight left out of
// this hunt (not on this server, or its tool is unavailable): the launch already reports those, and a
// narrower launch legitimately leaves their params unused. With `check`, any OTHER artifact outside the
// hunt is refused — it is not in the bundle, so its key is a typo or a leftover. Without `check` (no
// pre-flight ran), params for artifacts outside the hunt are skipped, as before.
export function buildHuntSpec(
  names: string[],
  params?: Record<string, Record<string, string>>,
  check?: HuntSpecCheck,
): string | undefined {
  if (params == null) return undefined;
  if (!isPlainObject(params)) throw new HuntSpecError("hunt parameters must be an object keyed by artifact");
  const inHunt = new Set(names);
  const leftOut = check
    ? new Set([...check.unknownArtifacts, ...check.unavailableArtifacts.map((u) => u.artifact)])
    : undefined;
  const declared = declaredParams(check);
  const entries: string[] = [];
  for (const [artifact, kv] of Object.entries(params)) {
    if (!ARTIFACT_RE.test(artifact)) {
      throw new HuntSpecError(`parameters are set for an invalid artifact name ${quoted(artifact)}`);
    }
    if (!inHunt.has(artifact)) {
      if (!leftOut || leftOut.has(artifact)) continue;
      throw new HuntSpecError(
        `parameters are set for artifact ${quoted(artifact)}, which is not in this bundle — fix the artifact name or remove its parameters`,
      );
    }
    const entry = artifactSpec(artifact, kv, declared.get(artifact));
    if (entry) entries.push(entry);
  }
  return entries.length ? `spec=dict(${entries.join(", ")})` : undefined;
}
