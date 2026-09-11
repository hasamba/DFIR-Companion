import type { InvestigationState, LabIntelRecord } from "../analysis/stateTypes.js";
import { isLabProduced, normalizeSha256, selectLabIntelForDisplay } from "../analysis/labIntel.js";
import { cellMd } from "./mdText.js";

/**
 * "Sandbox reports" section (#932 item 5 part C): every detonation record the case holds, and for
 * each one whether the sample was actually SEEN in the collected evidence.
 *
 * Incident-neutral by construction. A sandbox says what a file does in a lab; this section never
 * claims the behaviour happened on a host. The sighting column is the only link to the incident,
 * and it says exactly what it is: the earliest forensic event carrying that hash, or nothing.
 *
 * The empty state is worded for what it can honestly say. A report can be imported and produce
 * super-timeline rows without a registry record — the sample had no usable SHA-256 — so "none were
 * imported" would deny an import that happened. "No hash-addressable records" is what is true.
 */
export function sandboxReportsSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Sandbox reports", "");
  const records = state.labIntel ?? [];
  if (records.length === 0) {
    lines.push(
      "No hash-addressable sandbox records are held for this case. A report whose sample carried no usable SHA-256 still produces super-timeline rows but no record here.",
      "",
    );
    return;
  }
  lines.push(
    "Each row is one detonation of one sample in a lab. It describes what the FILE does; it is not an observation from any host. The sighting column is the earliest collected event carrying the same SHA-256, or nothing.",
    "",
  );
  const sightings = firstSightings(state);
  lines.push(
    "| Sample | Source | Run | Verdict | Family | Score | Detonated | Signatures | Sighting |",
    "|---|---|---|---|---|---|---|---|---|",
  );
  const bySha = new Map<string, LabIntelRecord[]>();
  for (const r of records) (bySha.get(r.sha256) ?? bySha.set(r.sha256, []).get(r.sha256)!).push(r);
  for (const [sha, group] of [...bySha.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const { shown, omitted } = selectLabIntelForDisplay(group);
    for (const r of shown) {
      const seen = sightings.get(sha);
      lines.push(
        `| \`${sha.slice(0, 12)}…\` | ${cellMd(r.source)} | ${cellMd(r.runId || "—")} | ${r.verdict} | ${cellMd(r.family || "—")} | ${r.score} | ${cellMd(r.detonatedAt || "—")} | ${cellMd(r.signatures.join(", ") || "—")} | ${seen ? cellMd(`seen on ${seen.host} at ${seen.time}`) : "not observed in collected evidence"} |`,
      );
    }
    if (omitted)
      lines.push(`| \`${sha.slice(0, 12)}…\` | | | | | | | +${omitted} older run(s) not shown | |`);
  }
  lines.push("");
}

// The earliest non-lab forensic event per normalised sha256: host (or "unknown host") and time.
function firstSightings(state: InvestigationState): Map<string, { host: string; time: string }> {
  const out = new Map<string, { host: string; time: string }>();
  for (const e of state.forensicTimeline) {
    // isLabProduced, not `origin === "lab"`: a sandbox row persisted before the field existed
    // carries no origin, and a sighting that is really another sandbox result is exactly the false
    // attribution this section must never print. A row already merged with a host source is a
    // genuine sighting and the helper keeps it.
    if (isLabProduced(e)) continue;
    const sha = normalizeSha256(e.sha256);
    if (!sha) continue;
    const prev = out.get(sha);
    if (!prev || (e.timestamp && e.timestamp < prev.time))
      out.set(sha, { host: e.asset || "unknown host", time: e.timestamp || "undated" });
  }
  return out;
}
