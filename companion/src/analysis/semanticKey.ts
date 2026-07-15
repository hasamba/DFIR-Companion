import type { Finding } from "./stateTypes.js";

// Stable, wording-resilient identity for a finding (issue #69). The second-opinion pass matches
// findings across two independent synthesis runs; keying by the raw title made a trivial rewording
// ("Encoded PowerShell execution" vs "PowerShell encoded command") register as a brand-new delta,
// so the disagreement list filled with noise. A semanticKey anchors the identity on the dominant
// ATT&CK technique plus an ORDER-INDEPENDENT noun phrase from the title, so reworded-but-equivalent
// findings collapse to one key, e.g. `T1059.001:encoded_powershell`.
//
// PURE + deterministic (no I/O, no AI). Populated post-synthesis by groundAndScoreFindings and used
// as the primary delta key in secondOpinion.ts, falling back to the normalized title.

// Stopwords + generic DFIR filler dropped when deriving the noun phrase. These carry no
// discriminating meaning, so removing them lets equivalent titles converge on the same phrase.
const STOPWORDS = new Set<string>([
  // grammatical
  "a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "with", "via", "by", "from", "at",
  "as", "is", "was", "were", "be", "into", "over", "this", "that", "these", "those",
  // generic security / DFIR filler
  "detected", "detection", "suspicious", "possible", "potential", "likely", "observed", "activity",
  "attempt", "attempted", "execution", "executed", "command", "commands", "behavior", "behaviour",
  "event", "events", "alert", "alerts", "indicator", "indicators", "evidence", "use", "usage",
  "using", "seen", "found", "multiple", "unusual", "anomalous", "malicious", "unknown",
]);

// Max salient tokens kept in the phrase — bounds key length and, combined with sorting, keeps the
// key stable when a longer wording adds trailing qualifiers.
const MAX_TOKENS = 4;

const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;

const lower = (s: string): string => String(s ?? "").trim().toLowerCase();

// The dominant technique = the first well-formed ATT&CK id on the finding (synthesis lists the
// primary technique first). "" when the finding maps none.
function dominantTechnique(mitreTechniques: readonly string[] | undefined): string {
  for (const raw of mitreTechniques ?? []) {
    const id = String(raw ?? "").trim().toUpperCase();
    if (TECHNIQUE_RE.test(id)) return id;
  }
  return "";
}

// A token is "descriptive" — a word that anchors identity — only if it carries a letter and isn't a
// hash/blob. VOLATILE, non-descriptive tokens are dropped so they can't dominate the phrase:
//   - pure-numeric (no letter): IP octets, event IDs, PIDs, CVE numbers, counts, timestamps
//   - long hex strings (≥16 all-hex chars): SHA/MD5 hashes, GUIDs
// Without this, IP-heavy or hash-heavy titles produced keys like "256_a1b2c3…" or "101_185_220_47",
// which erase the real subject and collapse genuinely-different findings that share an IP (#69 live).
// Short tokens like "dc01"/"web01"/"c2"/"svchost32" keep their letters and survive.
function isDescriptive(token: string): boolean {
  if (!/[a-z]/.test(token)) return false;             // pure-numeric → drop
  if (token.length >= 16 && /^[0-9a-f]+$/.test(token)) return false; // hash/hex blob → drop
  return true;
}

// An order-independent noun phrase: split the title into tokens, drop stopwords/filler and volatile
// non-descriptive tokens (numbers/hashes), de-dupe, sort alphabetically (so reordered wording
// produces the SAME phrase), cap, and join with "_". Falls back to a slug of the whole normalized
// title when nothing salient survives, so it's never empty. Exported for direct testing.
export function nounPhrase(title: string): string {
  const tokens = lower(title)
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
    .filter((t) => !STOPWORDS.has(t))
    .filter(isDescriptive);
  const salient = [...new Set(tokens)].sort().slice(0, MAX_TOKENS);
  const phrase = salient.join("_");
  if (phrase) return phrase;
  return lower(title).replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

// Derive the stable semanticKey for a finding: `${dominantTechnique}:${nounPhrase}` when a technique
// is mapped, else just the noun phrase. Deterministic and idempotent.
export function deriveSemanticKey(finding: Pick<Finding, "title" | "mitreTechniques">): string {
  const tech = dominantTechnique(finding.mitreTechniques);
  const phrase = nounPhrase(finding.title ?? "");
  return tech ? `${tech}:${phrase}` : phrase;
}
