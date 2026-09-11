import type { CustodyRecord } from "../analysis/custody.js";
import { cellMd } from "./mdText.js";

// Extracted from markdown.ts verbatim when that file reached its size ledger (#932 item 5 part C
// needed one builder line). Nothing here changed.
/**
 * "Chain of Custody" appendix (#231 item 4): every artifact under custody, with its hash and the
 * full sequence of events that touched it.
 *
 * Grouped by artifact rather than listed as a flat log, because the question a reader of the report
 * actually has is "what happened to THIS piece of evidence" — a chronological dump of every event
 * across every artifact answers it only after manual sorting.
 *
 * An empty case still renders the heading and says so. A court-facing deliverable that silently
 * omits the section is indistinguishable from one where custody was never recorded at all.
 */
export function chainOfCustodySection(custody: CustodyRecord[] | undefined, lines: string[]): void {
  lines.push("## Appendix — Chain of Custody", "");
  const records = custody ?? [];
  if (records.length === 0) {
    lines.push("No custody records were captured for this case.", "");
    return;
  }

  // Insertion order = the order artifacts entered the case.
  const byArtifact = new Map<string, CustodyRecord[]>();
  for (const record of records) {
    const existing = byArtifact.get(record.artifactPath);
    if (existing) existing.push(record);
    else byArtifact.set(record.artifactPath, [record]);
  }

  lines.push(`${byArtifact.size} artifact(s) under custody, ${records.length} recorded event(s).`, "");
  for (const [artifactPath, chain] of byArtifact) {
    const name = artifactPath.split(/[\\/]/).pop() || artifactPath;
    lines.push(`### ${cellMd(name)}`, "");
    lines.push(`- Path: \`${artifactPath}\``);
    // The hash from the most recent event: what the artifact was last known to be.
    lines.push(`- SHA-256: \`${chain[chain.length - 1].sha256}\``, "");
    lines.push("| # | Event | When (UTC) | By | Source | Trigger |", "| --- | --- | --- | --- | --- | --- |");
    for (const r of chain) {
      lines.push(
        `| ${r.seq ?? ""} | ${cellMd(r.event ?? "collected")} | ${cellMd(r.collectedAt)} | ${cellMd(r.collectedBy)} | ${cellMd(r.source)} | ${cellMd(r.trigger)} |`,
      );
    }
    lines.push("");
  }
}
