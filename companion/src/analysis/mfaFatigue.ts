// MFA fatigue (#2306, T1621 Multi-Factor Authentication Request Generation): at least
// MFA_FATIGUE_THRESHOLD denied or timed-out MFA prompts for ONE account in ONE tenant inside
// MFA_FATIGUE_WINDOW_MINUTES, then a successful sign-in by that account in that tenant.
//
// Built on the sign-in observation store (#2301), never on the forensic or super-timeline: the
// success row is graded Info by m365Import.ts's mapSignIn and so never reaches the forensic
// timeline (CLAUDE.md §7) — the store's extracted observations are the only place both halves of
// the sequence exist. The rows this file renders go through the ordinary import → merge → tagger →
// demote path, like passwordSprayFanout.ts's (the model for this file).
//
// What one row establishes, and what it never claims:
//   - a prompt counts ONLY when its real MFA detail (signInObservation.ts mfaDetailOf) says denied
//     or timed out — a 50074 "MFA required" interruption is normal and never counts, and a 500121
//     whose detail does not say how it failed is "unconfirmed" and never counts;
//   - account identity is byte-equal after trim + lowercase; the tenant must be identical — prompts
//     in one tenant never pair with a success in another;
//   - a success resets the count: prompts before an earlier success belong to that one;
//   - "possible" MFA fatigue — a pattern, never a verdict. The success's source IP is shown, never
//     claimed to be the attacker's.
//
// Idempotence: an episode is identified by tenant + account + the success's second. An import emits
// an episode only when it is new — it qualifies over the combined observations but NOT over the
// observations stored by earlier imports (newFatigueEpisodes). The store keeps the FIRST import's
// batch on a re-appended observation, so a re-import or an overlapping export never emits twice.

import { createHash } from "node:crypto";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { normalizeTime, type MappedEvent } from "./siemImport.js";
import type { StoredAuthObservation } from "./authObservationStore.js";

export const MFA_FATIGUE_THRESHOLD = 3;
export const MFA_FATIGUE_WINDOW_MINUTES = 60;
export const MFA_FATIGUE_PATTERNS_MAX = 256;
const REFS_MAX = 50;
const IPS_SHOWN_MAX = 8;
const IMPORTER = "m365";

type Obs = StoredAuthObservation;

export interface FatigueEpisode {
  identity: string;
  hostOrTenant: string;
  account: string; // as the success record spells it
  prompts: number;
  denied: number;
  timedOut: number;
  start: string; // first counted prompt
  end: string; // last counted prompt
  promptIps: string[];
  success: Obs;
  refs: Obs[]; // the counted prompts (bounded) and the success, oldest first
  batches: string[]; // every import batch that contributed
}

/** A denied or timed-out MFA prompt — confirmed by the record's own MFA detail. */
export function isFatiguePrompt(o: Pick<Obs, "outcome" | "mfaDetail">): boolean {
  return o.outcome === "interrupted" && (o.mfaDetail === "denied" || o.mfaDetail === "timed out");
}

const norm = (account: string): string => account.trim().toLowerCase();
const ms = (o: Obs): number => Date.parse(o.timestamp);

// Prompts sort before a success in the same millisecond, so the success can count them.
function compare(a: Obs, b: Obs): number {
  return (
    ms(a) - ms(b) ||
    Number(a.outcome === "success") - Number(b.outcome === "success") ||
    a.importBatch.localeCompare(b.importBatch) ||
    a.locator.localeCompare(b.locator)
  );
}

function usable(observations: readonly Obs[]): Obs[] {
  const seen = new Set<string>();
  const out: Obs[] = [];
  for (const o of observations) {
    if (!o.hostOrTenant || !norm(o.account) || !Number.isFinite(ms(o))) continue;
    if (!isFatiguePrompt(o) && o.outcome !== "success") continue;
    const key = o.recordId ?? `${o.importBatch}|${o.locator}|${o.timestamp}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(o);
  }
  return out;
}

function episodeOf(prompts: Obs[], s: Obs): FatigueEpisode {
  const identity = createHash("sha256")
    .update(`${s.hostOrTenant}|${norm(s.account)}|${s.timestamp.slice(0, 19)}`)
    .digest("hex")
    .slice(0, 16);
  const refs = [...prompts.slice(-(REFS_MAX - 1)), s];
  return {
    identity,
    hostOrTenant: s.hostOrTenant,
    account: s.account,
    prompts: prompts.length,
    denied: prompts.filter((p) => p.mfaDetail === "denied").length,
    timedOut: prompts.filter((p) => p.mfaDetail === "timed out").length,
    start: new Date(ms(prompts[0])).toISOString(),
    end: new Date(ms(prompts[prompts.length - 1])).toISOString(),
    promptIps: [...new Set(prompts.map((p) => p.sourceIp).filter(Boolean))].sort(),
    success: s,
    refs,
    batches: [...new Set([...prompts, s].map((o) => o.importBatch))].sort(),
  };
}

/** Every fatigue episode in the observations, earliest success first. Pure, order-independent. */
export function mfaFatigueEpisodes(observations: readonly Obs[]): FatigueEpisode[] {
  const windowMs = MFA_FATIGUE_WINDOW_MINUTES * 60_000;
  const groups = new Map<string, Obs[]>();
  for (const o of usable(observations)) {
    const k = `${o.hostOrTenant}\n${norm(o.account)}`;
    (groups.get(k) ?? groups.set(k, []).get(k)!).push(o);
  }
  const episodes: FatigueEpisode[] = [];
  for (const group of groups.values()) {
    let pending: Obs[] = [];
    for (const o of group.sort(compare)) {
      if (o.outcome !== "success") {
        pending.push(o);
        continue;
      }
      const counted = pending.filter((p) => ms(o) - ms(p) <= windowMs);
      if (counted.length >= MFA_FATIGUE_THRESHOLD) episodes.push(episodeOf(counted, o));
      pending = [];
    }
  }
  return episodes.sort((a, b) => ms(a.success) - ms(b.success) || a.identity.localeCompare(b.identity));
}

/**
 * The episodes this import makes new: they qualify over every observation, involve this import's
 * batch, and did not already qualify over the observations earlier imports stored.
 */
export function newFatigueEpisodes(observations: readonly Obs[], currentBatch: string): FatigueEpisode[] {
  const prior = new Set(
    mfaFatigueEpisodes(observations.filter((o) => o.importBatch !== currentBatch)).map((e) => e.identity),
  );
  return mfaFatigueEpisodes(observations).filter(
    (e) => e.batches.includes(currentBatch) && !prior.has(e.identity),
  );
}

function fatigueRow(e: FatigueEpisode, truncatedHistory: boolean): MappedEvent {
  const s = e.success;
  const ips = e.promptIps.length
    ? `; prompt source IPs: ${e.promptIps.slice(0, IPS_SHOWN_MAX).join(", ")}${e.promptIps.length > IPS_SHOWN_MAX ? ` (+${e.promptIps.length - IPS_SHOWN_MAX} more)` : ""}`
    : "";
  const across = e.batches.length > 1 ? ` (across ${e.batches.length} uploads)` : "";
  const history = truncatedHistory
    ? "; prior observations beyond the query cap were not available — this count may be a floor, not a total"
    : "";
  const description = boundedTextTo(
    `Possible MFA fatigue: ${e.prompts} rejected or timed-out MFA prompts for ${e.account}, then a successful sign-in` +
      ` — tenant ${e.hostOrTenant}; ${e.denied} denied, ${e.timedOut} timed out between ${e.start} and ${e.end};` +
      ` success at ${s.timestamp}${s.sourceIp ? ` from ${s.sourceIp}` : ""}${across}${ips}${history}`,
    600,
  );
  return {
    timestamp: normalizeTime(e.start),
    description,
    severity: "High",
    mitre: ["T1621", "T1078.004"],
    aggKey: boundedAggKey(`mfa-fatigue|${IMPORTER}|${e.identity}`),
    sources: ["Microsoft 365"],
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "mfa-fatigue-pattern", outcome: "pattern" },
      actor: { kind: "account", name: e.account },
      account: { name: e.account },
      target: { kind: "host", name: e.hostOrTenant },
      ...(s.sourceIp ? { network: { source: { address: s.sourceIp, provenance: "edge-observed" } } } : {}),
      time: { observed: e.start, normalized: normalizeTime(e.start) },
      evidence: {
        rawRecords: e.refs.map((o) => ({
          source: IMPORTER,
          locator: `${o.importBatch}:${o.locator}`,
          ...(o.recordId ? { recordId: o.recordId } : {}),
        })),
      },
      producer: {
        importer: IMPORTER,
        parserVersion: "1",
        mappingVersion: "m365-mfa-fatigue-v1",
        ruleVersions: ["mfa-fatigue-v1"],
      },
    }),
  };
}

/** The rows for these episodes, bounded at MFA_FATIGUE_PATTERNS_MAX plus one disclosed overflow row. */
export function fatigueRows(episodes: FatigueEpisode[], opts: { truncatedHistory: boolean }): MappedEvent[] {
  const rows = episodes.slice(0, MFA_FATIGUE_PATTERNS_MAX).map((e) => fatigueRow(e, opts.truncatedHistory));
  const omitted = episodes.length - MFA_FATIGUE_PATTERNS_MAX;
  if (omitted <= 0) return rows;
  return [
    ...rows,
    {
      timestamp: "",
      description: `Possible MFA fatigue: ${omitted} further episode${omitted === 1 ? "" : "s"} in this import beyond the ${MFA_FATIGUE_PATTERNS_MAX} reported — not shown`,
      severity: "Medium",
      mitre: ["T1621"],
      aggKey: boundedAggKey(`mfa-fatigue|${IMPORTER}|omitted|${omitted}`),
      sources: ["Microsoft 365"],
      canonical: createCanonicalEvent({
        event: { category: "authentication", type: "mfa-fatigue-pattern", action: "omitted" },
        time: { observed: "", normalized: "" },
        evidence: { rawRecords: [{ source: IMPORTER, locator: "omitted" }] },
        producer: { importer: IMPORTER, parserVersion: "1", mappingVersion: "m365-mfa-fatigue-v1" },
      }),
    },
  ];
}
