// Password-spray fan-out (930.5, 931.3 password-spray half — #1086, #1100 item 1): one source IP
// failing against many DISTINCT accounts on one host/tenant, inside one window, inside ONE upload.
//
// Why inside one upload, never at merge time: a successful sign-in is Info severity, and Info rows
// never reach the forensic timeline (see mailboxChain.ts's own header, and CLAUDE.md's severity
// gating rule) — a post-merge pass could not see the very rows this feature needs to count and to
// link forward. So this runs over an importer's own pre-cap record set, the same seam
// mailboxChains()/entraPrivilegePaths() already use in m365Import.ts. Cross-upload spray detection
// (attempts split across two separate imports) needs a persistent observation store and is a
// separate, later feature — not built here.
//
// What one emitted row establishes, and what it never claims:
//   - "this source IP failed against N distinct accounts on this host/tenant, inside this window,
//     inside this export" — a pattern, never a verdict;
//   - account identity is byte-equal after trim+lowercase, nothing more — two spellings of one real
//     account that differ any other way count as two accounts (undercounts, never overcounts);
//   - a candidate with no source IP is never counted at all — never merged into a shared bucket;
//   - `followedBySuccess` states only that a targeted account authenticated successfully from the
//     same source, strictly after this episode closed, within a bounded grace window, in the same
//     upload — never "compromised".

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { normalizeTime, type MappedEvent } from "./siemImport.js";

export type SprayOutcome = "failed" | "success";

export interface SprayCandidate {
  timestamp: string; // ISO, already normalized by the caller
  account: string; // raw account identity as the source record spells it
  sourceIp: string; // REQUIRED — callers must never build a candidate without one
  hostOrTenant: string;
  outcome: SprayOutcome;
  locator: string; // e.g. "record:12" — this candidate's own raw-record locator
}

export interface SprayPatternMeta {
  source: string; // stamped on the row's `sources` field, e.g. "ECAR", "Microsoft 365"
  importer: string; // canonical.producer.importer, e.g. "ecar", "m365"
  mappingVersion: string;
}

export interface PasswordSprayPattern {
  sourceIp: string;
  hostOrTenant: string;
  windowKind: "burst" | "slow";
  start: string;
  end: string;
  accountsTotal: number;
  accountsShown: string[];
  accountsTruncated: boolean;
  locators: string[];
  followedBySuccess?: { account: string; timestamp: string };
}

function envInt(name: string, fallback: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export const SPRAY_BURST_MINUTES_DEFAULT = 10;
export const SPRAY_SLOW_HOURS_DEFAULT = 24;
export const SPRAY_THRESHOLD_DEFAULT = 5;
export const SPRAY_SUCCESS_GRACE_MINUTES_DEFAULT = 120;
export const SPRAY_PATTERNS_MAX = 256;
export const ACCOUNTS_PER_ROW_MAX = 50;

export function sprayBurstMinutes(): number {
  return envInt("DFIR_SPRAY_BURST_MINUTES", SPRAY_BURST_MINUTES_DEFAULT);
}
export function sprayLowSlowHours(): number {
  return envInt("DFIR_SPRAY_SLOW_HOURS", SPRAY_SLOW_HOURS_DEFAULT);
}
export function sprayThreshold(): number {
  return envInt("DFIR_SPRAY_THRESHOLD", SPRAY_THRESHOLD_DEFAULT);
}
export function spraySuccessGraceMinutes(): number {
  return envInt("DFIR_SPRAY_SUCCESS_GRACE_MINUTES", SPRAY_SUCCESS_GRACE_MINUTES_DEFAULT);
}

// Byte-equal after trim+lowercase, nothing more — see module header.
function normalizeAccount(account: string): string {
  return account.trim().toLowerCase();
}

function toMs(iso: string): number {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : NaN;
}

function groupKey(c: Pick<SprayCandidate, "sourceIp" | "hostOrTenant">): string {
  return `${c.sourceIp}|${c.hostOrTenant}`;
}

interface Episode {
  sourceIp: string;
  hostOrTenant: string;
  windowKind: "burst" | "slow";
  startMs: number;
  endMs: number;
  accounts: Map<string, string>; // normalized -> raw (first seen)
  locators: string[];
}

// One tumbling (non-overlapping) pass over one group's failed candidates, sorted by time.
// Deterministic: a window closes the instant the next candidate falls outside it, never re-opens.
function tumblingEpisodes(
  sourceIp: string,
  hostOrTenant: string,
  windowKind: "burst" | "slow",
  windowMs: number,
  sorted: SprayCandidate[],
): Episode[] {
  const episodes: Episode[] = [];
  let current: Episode | null = null;
  for (const c of sorted) {
    const ms = toMs(c.timestamp);
    if (!Number.isFinite(ms)) continue;
    if (!current || ms - current.startMs > windowMs) {
      current = {
        sourceIp,
        hostOrTenant,
        windowKind,
        startMs: ms,
        endMs: ms,
        accounts: new Map(),
        locators: [],
      };
      episodes.push(current);
    }
    current.endMs = ms;
    const norm = normalizeAccount(c.account);
    if (norm && !current.accounts.has(norm)) current.accounts.set(norm, c.account);
    current.locators.push(c.locator);
  }
  return episodes;
}

// Exact-duplicate guard: same normalized account + same source + same host + same
// timestamp-to-the-second counts once. This is double-ingestion protection (one NDJSON line
// appearing twice), never a cross-sensor merge — see module header.
function dedupExact(candidates: SprayCandidate[]): SprayCandidate[] {
  const seen = new Set<string>();
  const out: SprayCandidate[] = [];
  for (const c of candidates) {
    const secondFloor = c.timestamp.slice(0, 19); // ISO up to whole seconds
    const key = `${c.sourceIp}|${c.hostOrTenant}|${normalizeAccount(c.account)}|${secondFloor}|${c.outcome}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}

export function passwordSprayPatterns(candidates: SprayCandidate[]): PasswordSprayPattern[] {
  const threshold = sprayThreshold();
  const burstMs = sprayBurstMinutes() * 60_000;
  const slowMs = sprayLowSlowHours() * 3_600_000;
  const graceMs = spraySuccessGraceMinutes() * 60_000;

  const usable = dedupExact(
    candidates.filter((c) => c.sourceIp && c.hostOrTenant && c.account && toMs(c.timestamp)),
  );
  const byGroup = new Map<string, SprayCandidate[]>();
  for (const c of usable) {
    const k = groupKey(c);
    (byGroup.get(k) ?? byGroup.set(k, []).get(k)!).push(c);
  }

  const patterns: PasswordSprayPattern[] = [];
  for (const [, groupCandidates] of byGroup) {
    const failed = groupCandidates
      .filter((c) => c.outcome === "failed")
      .sort((a, b) => toMs(a.timestamp) - toMs(b.timestamp));
    if (failed.length === 0) continue;
    const { sourceIp, hostOrTenant } = failed[0];

    for (const [windowKind, windowMs] of [
      ["burst", burstMs],
      ["slow", slowMs],
    ] as const) {
      const episodes = tumblingEpisodes(sourceIp, hostOrTenant, windowKind, windowMs, failed);
      for (const ep of episodes) {
        if (ep.accounts.size < threshold) continue;
        const accountNames = [...ep.accounts.values()];
        const accountsShown = accountNames.slice(0, ACCOUNTS_PER_ROW_MAX);
        const accountsTruncated = accountNames.length > ACCOUNTS_PER_ROW_MAX;

        // followedBySuccess: earliest success in the SAME group, for one of the episode's
        // accounts, strictly after episode close, within the bounded grace window.
        const successes = groupCandidates
          .filter(
            (c) =>
              c.outcome === "success" &&
              ep.accounts.has(normalizeAccount(c.account)) &&
              toMs(c.timestamp) > ep.endMs &&
              toMs(c.timestamp) <= ep.endMs + graceMs,
          )
          .sort((a, b) => toMs(a.timestamp) - toMs(b.timestamp));

        patterns.push({
          sourceIp,
          hostOrTenant,
          windowKind,
          start: new Date(ep.startMs).toISOString(),
          end: new Date(ep.endMs).toISOString(),
          accountsTotal: accountNames.length,
          accountsShown,
          accountsTruncated,
          locators: ep.locators.slice(0, ACCOUNTS_PER_ROW_MAX),
          ...(successes[0]
            ? { followedBySuccess: { account: successes[0].account, timestamp: successes[0].timestamp } }
            : {}),
        });
      }
    }
  }

  // Deterministic order: earliest episode first, tie-broken by source+host+windowKind.
  patterns.sort(
    (a, b) =>
      toMs(a.start) - toMs(b.start) ||
      a.sourceIp.localeCompare(b.sourceIp) ||
      a.hostOrTenant.localeCompare(b.hostOrTenant) ||
      a.windowKind.localeCompare(b.windowKind),
  );
  return patterns;
}

function bumpSeverity(sev: Severity): Severity {
  const order: Severity[] = ["Info", "Low", "Medium", "High", "Critical"];
  const i = order.indexOf(sev);
  return i >= 0 && i < order.length - 1 ? order[i + 1] : sev;
}

// Renders one PasswordSprayPattern as the shared MappedEvent shape, reused by every importer's
// call site (ecarImport.ts, m365Import.ts) so the aggKey/description/canonical shape is identical
// no matter which importer found the pattern.
export function sprayPatternToMappedEvent(p: PasswordSprayPattern, meta: SprayPatternMeta): MappedEvent {
  const baseSeverity: Severity = p.windowKind === "burst" ? "Medium" : "Low";
  const severity = p.followedBySuccess ? bumpSeverity(baseSeverity) : baseSeverity;
  const windowWords = p.windowKind === "burst" ? "burst" : "low-and-slow";
  const identity = createHash("sha256")
    .update(`${p.sourceIp}|${p.hostOrTenant}|${p.windowKind}|${p.start}`)
    .digest("hex")
    .slice(0, 16);

  const truncNote = p.accountsTruncated
    ? ` (+${p.accountsTotal - p.accountsShown.length} more not shown)`
    : "";
  const successNote = p.followedBySuccess
    ? `; ${p.followedBySuccess.account} authenticated successfully from the same source at ${p.followedBySuccess.timestamp}`
    : "";
  const description = boundedTextTo(
    `Password-spray pattern (${windowWords}): ${p.sourceIp} failed against ${p.accountsTotal} distinct accounts on ${p.hostOrTenant} between ${p.start} and ${p.end} [${p.accountsShown.join(", ")}${truncNote}]${successNote}`,
    600,
  );

  return {
    timestamp: normalizeTime(p.start),
    description,
    severity,
    mitre: ["T1110.003"],
    aggKey: boundedAggKey(`spray-pattern|${meta.importer}|${identity}`),
    sources: [meta.source],
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "password-spray-pattern", outcome: "pattern" },
      actor: { kind: "network", address: p.sourceIp },
      target: { kind: "host", name: p.hostOrTenant },
      network: { source: { address: p.sourceIp } },
      time: { observed: p.start, normalized: normalizeTime(p.start) },
      evidence: { rawRecords: p.locators.map((locator) => ({ source: meta.importer, locator })) },
      producer: {
        importer: meta.importer,
        parserVersion: "1",
        mappingVersion: meta.mappingVersion,
        ruleVersions: ["password-spray-fanout-v1"],
      },
    }),
  };
}

// The MAILBOX_CHAINS_MAX-style overflow row: names how many further patterns exist beyond
// SPRAY_PATTERNS_MAX without silently dropping them.
export function sprayOmittedRow(count: number, meta: SprayPatternMeta): MappedEvent {
  const description = `Password-spray pattern: ${count} further pattern${count === 1 ? "" : "s"} in this export beyond the ${SPRAY_PATTERNS_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity: "Low",
    mitre: [],
    aggKey: boundedAggKey(`spray-pattern|${meta.importer}|omitted|${count}`),
    sources: [meta.source],
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "password-spray-pattern", action: "omitted" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: meta.importer, locator: "omitted" }] },
      producer: { importer: meta.importer, parserVersion: "1", mappingVersion: meta.mappingVersion },
    }),
  };
}

export function sprayPatternRows(candidates: SprayCandidate[], meta: SprayPatternMeta): MappedEvent[] {
  const patterns = passwordSprayPatterns(candidates);
  const kept = patterns.slice(0, SPRAY_PATTERNS_MAX);
  const rows = kept.map((p) => sprayPatternToMappedEvent(p, meta));
  if (patterns.length > SPRAY_PATTERNS_MAX) {
    rows.push(sprayOmittedRow(patterns.length - SPRAY_PATTERNS_MAX, meta));
  }
  return rows;
}
