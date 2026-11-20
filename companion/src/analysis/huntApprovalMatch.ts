import type { Baseline, BaselineMark, BaselineVerdict } from "./clientProfile.js";

/**
 * Strict baseline matching (#2670). PURE. An attacker must not be able to hide behind a name:
 *   - An APPROVAL matches only on program name AND normalised path pattern AND either a VERIFIED signer
 *     or an approved hash. Publisher text alone never approves anything.
 *   - Every hash observed for the item must be approved: one host running a different binary at the
 *     same path is a changed hash, and the approval does not cover it.
 *   - Every HOST must have its own hashed observation: one host's approved hash says nothing about a
 *     host seen only through a hash-less row, so such an item stays Unknown. A hash list or host list
 *     cut short by its cap is incomplete too.
 *   - A field the approval needs that is missing or unverified gives UNKNOWN, never a weaker match.
 *   - An expired approval no longer applies.
 *   - NOT ALLOWED matches on program (+ path pattern when given) and WINS over any approval.
 * Path patterns: segments separated by "\", `*` = exactly one segment, `**` = any number (0+).
 */
export interface MatchItem {
  family: BaselineMark["family"];
  program: string;
  pathPattern: string;
  sha256: readonly string[];
  /** Hosts with no hashed observation (huntInventory.ts). Absent = unknown, never approved by hash. */
  unhashedHosts?: readonly string[];
  /** The hash list lost a value to its cap. Absent = unknown, never approved by hash. */
  hashesCapped?: boolean;
  /** Hosts the item could not record (host cap): their binaries are unknown. */
  hostOverflow?: number;
  /** A VERIFIED Authenticode signer. Absent in this release: no importer records one. */
  signer?: string;
}

/** Every host has its own hashed observation and no hash or host was dropped by a cap. */
const hashesComplete = (i: MatchItem): boolean =>
  Array.isArray(i.unhashedHosts) &&
  i.unhashedHosts.length === 0 &&
  i.hashesCapped === false &&
  !i.hostOverflow;

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

export function approvalMatch(m: BaselineMark, item: MatchItem, now: string): MatchResult {
  if (m.verdict !== "approved" || expired(m, now) || !sameName(m, item)) return "no-match";
  if (!m.pathPattern || !item.pathPattern) return "unknown";
  if (!pathPatternMatches(m.pathPattern, item.pathPattern)) return "no-match";
  if (m.signer) {
    if (item.signer) return item.signer === m.signer ? "match" : "no-match";
    if (!m.sha256.length) return "unknown";
  }
  if (!m.sha256.length) return "unknown";
  if (!item.sha256.length || !hashesComplete(item)) return "unknown";
  const ok = new Set(m.sha256.map((h) => h.toLowerCase()));
  return item.sha256.every((h) => ok.has(h.toLowerCase())) ? "match" : "no-match";
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
  return {
    verdict: "unknown",
    reason: needs
      ? "an approval names this program, but a verified signer or an approved hash is missing — not covered"
      : "not in the reviewed baseline",
  };
}
