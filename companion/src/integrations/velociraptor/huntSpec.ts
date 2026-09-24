// The `spec` clause of a hunt: per-artifact parameter overrides, sent to the endpoint byte for byte.
import { ARTIFACT_RE } from "./artifactRefs.js";

const PARAM_RE = /^[A-Za-z_][A-Za-z0-9_]*$/; // valid Velociraptor parameter name
const PLAIN_PARAM_VALUE_RE = /^[\x20-\x7E]*$/; // printable ASCII: safe as a literal once quotes are ruled out
const MAX_PARAM_VALUE_CHARS = 64_000;

// One parameter value as a VQL expression that evaluates to EXACTLY that string. A plain value stays a
// readable single-quoted literal. Anything else — a CSV parameter's newlines (Hayabusa RuleExclusions),
// a quote, a backslash, non-ASCII — goes through base64decode(), which no character can break out of.
// Folding those into one line used to turn a CSV's rows into one header row and drop the exclusions.
// Too long is refused rather than truncated: a cut CSV or glob fails silently on the endpoint.
function vqlParamValue(key: string, value: string): string {
  if (value.length > MAX_PARAM_VALUE_CHARS) {
    throw new Error(`parameter ${key} is too long (${value.length} > ${MAX_PARAM_VALUE_CHARS} chars)`);
  }
  if (PLAIN_PARAM_VALUE_RE.test(value) && !/['\\]/.test(value)) return `'${value}'`;
  return `base64decode(string='${Buffer.from(value, "utf8").toString("base64")}')`;
}

// Build the hunt's `spec` clause from per-artifact parameter overrides so a heavy artifact runs with
// fewer/narrower outputs at the source (e.g. `Windows.Hayabusa.Rules`=dict(RuleLevel='Critical, High, and Medium')). Only
// artifacts actually in this hunt are included; param names are validated and values reach the
// endpoint byte for byte (see vqlParamValue). Returns undefined when there's nothing to set.
export function buildHuntSpec(
  names: string[],
  params?: Record<string, Record<string, string>>,
): string | undefined {
  if (!params || typeof params !== "object") return undefined;
  const inHunt = new Set(names);
  const entries: string[] = [];
  for (const [artifact, kv] of Object.entries(params)) {
    if (!ARTIFACT_RE.test(artifact) || !inHunt.has(artifact) || !kv || typeof kv !== "object") continue;
    const pairs = Object.entries(kv)
      .filter(([k]) => PARAM_RE.test(k))
      .map(([k, v]) => `${k}=${vqlParamValue(k, String(v))}`);
    if (pairs.length) entries.push(`\`${artifact}\`=dict(${pairs.join(", ")})`);
  }
  return entries.length ? `spec=dict(${entries.join(", ")})` : undefined;
}
