import type { InvestigationState } from "../analysis/stateTypes.js";
import type { WeaknessItem, WeaknessSummary } from "../analysis/awsAccountWeaknessSummary.js";
import { codeSpanMd, oneLineMd } from "./mdText.js";
import { row as csvRow } from "./csv.js";

// "AWS account weaknesses" report section and CSV (#2560): what the CloudTrail records prove about
// an account's hygiene, each item with the record it rests on. Every evidence value (account,
// bucket, eventID, time) is attacker-reachable text: in Markdown it goes in a code span, so link,
// image, emphasis, backtick and raw-HTML syntax stay literal (html.ts then escapes the markup); in
// the CSV it is formula-guarded by the shared cell writer.

const NOT_RECORDED = "not recorded";

function citeWords(item: WeaknessItem): string {
  return item.cites
    .map((c) => `${oneLineMd(c.role)} ${codeSpanMd(c.eventId)} at ${codeSpanMd(c.time)}`)
    .join("; ");
}

function itemLine(item: WeaknessItem): string {
  const where = `account ${codeSpanMd(item.account || NOT_RECORDED)}${item.bucket !== undefined ? `, bucket ${codeSpanMd(item.bucket)}` : ""}`;
  return `- **${oneLineMd(item.title)}** — ${where}. ${oneLineMd(item.detail)} Record: ${citeWords(item)}.`;
}

/**
 * Omitted when the case holds no weakness file (no CloudTrail import since #2560), so a report of a
 * case without cloud evidence is unchanged.
 */
export function cloudWeaknessSection(state: InvestigationState, lines: string[]): void {
  const s = state.cloudWeaknesses;
  if (!s?.read) return;
  lines.push(
    "## AWS account weaknesses",
    "",
    "What the imported CloudTrail records prove about each account's hygiene, each with the record it rests on (eventID and time). Not a timeline event and not graded.",
    "",
  );
  if (!s.items.length) lines.push("- None of the checks matched the CloudTrail records read so far.");
  else lines.push(...s.items.map(itemLine));
  lines.push("", "Limits:", ...s.limits.map((l) => `- ${oneLineMd(l)}`), "");
}

/** One row per cited record; the header is fixed. */
export function cloudWeaknessCsv(summary: WeaknessSummary): string {
  const header = ["kind", "title", "account", "bucket", "detail", "record_role", "event_id", "event_time"];
  const rows = summary.items.flatMap((i) =>
    i.cites.map((c) => [i.kind, i.title, i.account, i.bucket ?? "", i.detail, c.role, c.eventId, c.time]),
  );
  return [header, ...rows].map(csvRow).join("\n") + "\n";
}
