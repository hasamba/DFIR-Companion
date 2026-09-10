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
// the marker is appended once, and severity uses a worstSeverity() floor — so re-running over an
// already-merged timeline is a no-op. No AI, no network.

import { worstSeverity, type ForensicEvent } from "./stateTypes.js";

const MARKER = "[confirmed exfiltration:";

// "Confirmed exfiltration" must name an actual OUTBOUND TRANSFER, not merely carry a T1041 tag.
// T1041 is applied broadly by the mappers, so on a busy host the staging→window match was decorating
// unrelated neighbours — port-scan output, a generic PowerShell module, a repeated Sigma hit — with a
// High "confirmed exfiltration" label they did not earn. A real transfer leaves one of these marks:
// a resolved destination IP, an upload URL, or an upload verb / tool on the command line.
const OUTBOUND_TRANSFER_RE =
  /https?:\/\/|invoke-(?:restmethod|webrequest)|-infile\b|-method\s+(?:put|post)|\bcurl\b|\bwget\b|\brclone\b|\bs?ftp\b|\bscp\b|bitsadmin|start-bitstransfer|uploadfile|net\.webclient|megatools|\bpscp\b/i;

function hasOutboundTransfer(e: ForensicEvent): boolean {
  if (e.dstIp) return true;
  return OUTBOUND_TRANSFER_RE.test(e.description ?? "") || OUTBOUND_TRANSFER_RE.test(e.commandLine ?? "");
}
// Ransomware crews typically upload within minutes to a few hours of staging (the Meridian ground
// truth: 16:15 stage -> 17:00 upload, 45 min); default generous enough for a slower manual actor
// without spanning into unrelated later-day activity.
const DEFAULT_WINDOW_MINUTES = 360;

export interface ExfilCorrelateOptions {
  windowMinutes?: number;
}

export function linkArchiveToExfil(
  events: ForensicEvent[],
  opts: ExfilCorrelateOptions = {},
): ForensicEvent[] {
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
    // A SRUM outbound TOTAL counts as a transfer candidate (#909 item 9). SRUM is graded at import
    // time, where there is no case to compare against, so the staging pairing the issue asks for
    // could only ever happen here — where every host's evidence is already in one timeline.
    const isSrumTotal = /^SRUM total:/.test(e.description ?? "");
    if (!e.asset) return e;
    if (!isSrumTotal && !(e.mitreTechniques ?? []).includes("T1041")) return e;
    if ((e.description ?? "").includes(MARKER)) return e; // idempotent
    // A T1041 tag alone is not an exfil transfer — require an attributable outbound send, so a
    // mis-tagged neighbour in the staging window is not escalated to "confirmed exfiltration".
    // A SRUM total IS the attributable outbound send; the byte counter is the attribution.
    if (!isSrumTotal && !hasOutboundTransfer(e)) return e;
    const staged = stagedAt.get(e.asset);
    if (staged === undefined) return e;
    const t = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(t) || t < staged || t - staged > windowMs) return e;
    return {
      ...e,
      severity: worstSeverity(e.severity, "High"),
      ...(isSrumTotal ? { mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), "T1041"])] } : {}),
      description:
        `${e.description ?? ""} ${MARKER} preceded by archive staging on ${e.asset}` +
        (isSrumTotal
          ? ". SRUM records the volume and the application, not the destination or the contents, so this" +
            " pairs a staging event with a large send — it does not show what left."
          : "") +
        `]`.slice(0, 900),
    };
  });
}
