import type { Baseline, BaselineMark, BaselineVerdict } from "./clientProfile.js";
import type { IdentityCoverage } from "./huntItemCoverage.js";

/**
 * Strict baseline matching (#2670, #2731). PURE. An attacker must not be able to hide behind a name:
 *   - An APPROVAL matches only on program name AND normalised path pattern AND either a VERIFIED signer
 *     or an approved hash (SHA-256, or an Amcache SHA1). Publisher text alone never approves anything.
 *   - Every hash observed for the item, in each algorithm the approval names, must be approved: one
 *     host running a different binary at the same path is a changed hash, and the approval does not
 *     cover it. An item that also carries hashes of an algorithm the approval does NOT name stays
 *     Unknown: the approval cannot vouch for them.
 *   - Every HOST must have its own observation in an algorithm the approval names: a host seen only
 *     through SHA1 is not covered by a SHA-256-only approval, and the reverse. A hash list or host
 *     list cut short by its cap is incomplete too.
 *   - An Amcache SHA1 counts only for a file whose size Amcache recorded within 30 MiB (Amcache hashes
 *     only the first 30 MiB); a larger or unsized file is Unknown (huntItemCoverage.ts).
 *   - A SIGNER approval needs every host verified by that same signer, no other signer seen, and no
 *     failed signature check — one signed host never approves an unsigned one.
 *   - A field the approval needs that is missing or unverified gives UNKNOWN, never a weaker match.
 *   - An expired approval no longer applies.
 *   - NOT ALLOWED matches on program (+ path pattern when given) and WINS over any approval.
 * Path patterns: segments separated by "\", `*` = exactly one segment, `**` = any number (0+).
 */
export interface MatchItem extends IdentityCoverage {
  family: BaselineMark["family"];
  program: string;
  pathPattern: string;
  sha256: readonly string[];
  /** Hosts with no SHA-256 observation (huntInventory.ts). Absent = unknown, never approved by hash. */
  unhashedHosts?: readonly string[];
  /** The hash list lost a value to its cap. Absent = unknown, never approved by hash. */
  hashesCapped?: boolean;
  /** Hosts the item could not record (host cap): their binaries are unknown. */
  hostOverflow?: number;
}

export type MatchResult = "match" | "no-match" | "unknown";

const segs = (p: string): string[] => p.toLowerCase().split("\\").filter(Boolean);

function segMatch(pat: readonly string[], dir: readonly string[]): boolean {
  if (!pat.length) return !dir.length;
  const [head, ...rest] = pat;
  if (head === "**") return segMatch(rest, dir) || (dir.length > 0 && segMatch(pat, dir.slice(1)));
  if (!dir.length) return false;
  return (head === "*" || head === dir[0]) && segMatch(rest, dir.slice(1));
}

/** Does `pattern` match the item's directory? Whole segments only: `\program files` ≠ `\program files2`. */
export function pathPatternMatches(pattern: string, dir: string): boolean {
  return segMatch(segs(pattern), segs(dir));
}

const sameName = (m: BaselineMark, i: MatchItem): boolean =>
  m.family === i.family && m.program.toLowerCase() === i.program.toLowerCase();

const expired = (m: BaselineMark, now: string): boolean => !!m.expiresAt && m.expiresAt <= now;

/** Every observed signer is the approved one, every host verified, nothing capped or failed. */
function signerResult(signer: string, i: MatchItem): MatchResult {
  const seen = i.signers ?? [];
  if (!seen.length) return "unknown";
  if (seen.some((s) => s !== signer)) return "no-match";
  const complete =
    Array.isArray(i.unsignedHosts) &&
    i.unsignedHosts.length === 0 &&
    i.signersCapped === false &&
    !i.signatureUnverified &&
    !i.hostOverflow;
  return complete ? "match" : "unknown";
}

/** No host lacks an observation in every algorithm the approval names, and nothing was capped. */
function hostsCovered(i: MatchItem, want256: boolean, want1: boolean): boolean {
  if (i.hostOverflow) return false;
  if (want256 && (!Array.isArray(i.unhashedHosts) || i.hashesCapped !== false)) return false;
  if (want1 && (!Array.isArray(i.noSha1Hosts) || i.sha1Capped !== false)) return false;
  // Sticky: one observation of a file over 30 MiB, or with no size, means that host's binary is not
  // identified by its SHA1 — even when an earlier observation of the same host was.
  if (want1 && (i.sha1OverLimit || i.sha1NoSize)) return false;
  if (want256 && want1) return i.unhashedHosts!.every((k) => i.noSha1Hosts!.includes(k) === false);
  return (want256 ? i.unhashedHosts! : i.noSha1Hosts!).length === 0;
}

const allIn = (seen: readonly string[], ok: readonly string[]): boolean => {
  const set = new Set(ok.map((h) => h.toLowerCase()));
  return seen.every((h) => set.has(h.toLowerCase()));
};

function hashResult(m: BaselineMark, i: MatchItem): MatchResult {
  const sha1 = i.sha1 ?? [];
  const want256 = m.sha256.length > 0;
  const want1 = (m.sha1 ?? []).length > 0;
  if (!want256 && !want1) return "unknown";
  if ((!want256 && i.sha256.length) || (!want1 && sha1.length)) return "unknown";
  const seen = (want256 ? i.sha256.length : 0) + (want1 ? sha1.length : 0);
  if (!seen || !hostsCovered(i, want256, want1)) return "unknown";
  const ok = (!want256 || allIn(i.sha256, m.sha256)) && (!want1 || allIn(sha1, m.sha1 ?? []));
  return ok ? "match" : "no-match";
}

export function approvalMatch(m: BaselineMark, item: MatchItem, now: string): MatchResult {
  if (m.verdict !== "approved" || expired(m, now) || !sameName(m, item)) return "no-match";
  if (!m.pathPattern || !item.pathPattern) return "unknown";
  if (!pathPatternMatches(m.pathPattern, item.pathPattern)) return "no-match";
  if (m.signer) {
    const s = signerResult(m.signer, item);
    if (s !== "unknown") return s;
  }
  return hashResult(m, item);
}

export function notAllowedMatch(m: BaselineMark, item: MatchItem): boolean {
  if (m.verdict !== "not-allowed" || !sameName(m, item)) return false;
  return !m.pathPattern || (!!item.pathPattern && pathPatternMatches(m.pathPattern, item.pathPattern));
}

export interface ItemVerdict {
  verdict: BaselineVerdict;
  markId?: string;
  reason: string;
}

export function itemVerdict(baseline: Baseline, item: MatchItem, now: string): ItemVerdict {
  const blocked = baseline.marks.find((m) => notAllowedMatch(m, item));
  if (blocked)
    return { verdict: "not-allowed", markId: blocked.id, reason: "marked Not allowed by the client" };
  let needs = false;
  for (const m of baseline.marks) {
    const r = approvalMatch(m, item, now);
    if (r === "match") return { verdict: "approved", markId: m.id, reason: "Approved by client" };
    if (r === "unknown") needs = true;
  }
  const base = needs
    ? "an approval names this program, but a verified signer or an approved hash is missing — not covered"
    : "not in the reviewed baseline";
  return { verdict: "unknown", reason: [base, ...identityNotes(item)].join("; ") };
}

/** Why a recorded hash or signature cannot approve the item (#2731), shown on the confirm list. */
function identityNotes(i: MatchItem): string[] {
  return [
    ...(i.sha1OverLimit
      ? [
          "the Amcache SHA1 cannot approve it: the file is over 30 MiB and Amcache hashes only the first 30 MiB",
        ]
      : []),
    ...(i.sha1NoSize ? ["the Amcache SHA1 cannot approve it: Amcache recorded no file size"] : []),
    ...(i.signatureUnverified ? ["its signature was checked and NOT verified"] : []),
  ];
}
