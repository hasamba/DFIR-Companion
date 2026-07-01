// Exfiltration correlation: stitch archive STAGING (T1560.001 — Compress-Archive/zip/tar/7z, tagged
// by reconTechniques) to a subsequent UPLOAD (T1041, tagged by reconTechniques' curl/wget-upload rule
// or tradecraftRules' Invoke-RestMethod/-WebRequest upload rule) on the SAME host within a bounded
// window. That SEQUENCE — not the upload destination — is the exfil signal: a lone upload to
// sharepoint.com/blob.core.windows.net/a CI runner is routine enterprise automation and must not be
// escalated; a zip of client data followed minutes later by an upload to ANY destination is not.
//
// This pure pass raises the matched upload to High and tags it, so it rides the existing
// high-severity backfill into a guaranteed "Data Exfiltration" finding instead of depending on the
// synthesis model to notice the pairing on its own.
//
// Conservative + idempotent: only a same-host, staging-then-upload pair within the window matches,
// the marker is appended once, and severity uses a worst() floor — so re-running over an
// already-merged timeline is a no-op. No AI, no network.

import type { ForensicEvent, Severity } from "./stateTypes.js";

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
function worst(a: Severity, b: Severity): Severity { return SEV_RANK[b] < SEV_RANK[a] ? b : a; }

const MARKER = "[confirmed exfiltration:";
// Ransomware crews typically upload within minutes to a few hours of staging (the Meridian ground
// truth: 16:15 stage -> 17:00 upload, 45 min); default generous enough for a slower manual actor
// without spanning into unrelated later-day activity.
const DEFAULT_WINDOW_MINUTES = 360;

export interface ExfilCorrelateOptions {
  windowMinutes?: number;
}

export function linkArchiveToExfil(events: ForensicEvent[], opts: ExfilCorrelateOptions = {}): ForensicEvent[] {
  const windowMs = (opts.windowMinutes ?? DEFAULT_WINDOW_MINUTES) * 60_000;

  // Earliest archive-staging time per host.
  const stagedAt = new Map<string, number>();
  for (const e of events) {
    if (!e.asset || !(e.mitreTechniques ?? []).includes("T1560.001")) continue;
    const t = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(t)) continue;
    const cur = stagedAt.get(e.asset);
    if (cur === undefined || t < cur) stagedAt.set(e.asset, t);
  }
  if (stagedAt.size === 0) return events;

  return events.map((e) => {
    if (!e.asset || !(e.mitreTechniques ?? []).includes("T1041")) return e;
    if ((e.description ?? "").includes(MARKER)) return e; // idempotent
    const staged = stagedAt.get(e.asset);
    if (staged === undefined) return e;
    const t = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(t) || t < staged || t - staged > windowMs) return e;
    return {
      ...e,
      severity: worst(e.severity, "High"),
      description: `${e.description ?? ""} ${MARKER} preceded by archive staging on ${e.asset}]`.slice(0, 600),
    };
  });
}
