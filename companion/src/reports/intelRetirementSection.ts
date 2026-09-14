import type { InvestigationState } from "../analysis/stateTypes.js";
import { intelRetirementReview } from "../analysis/intelRetirement.js";
import { cellMd } from "./mdText.js";

/**
 * "Intel retirement review" section (#933 item 19, second half — #1024): the findings whose intel
 * corroboration rests only on assertions that are no longer actionable (expired, revoked, not
 * returned, errored, legacy), each with the assertions named and the analyst's decision when one
 * is on file. A list to review, never an action: nothing in it changed a finding's severity or
 * status, and a "retire" decision is a recorded recommendation — the evidence the finding rests on
 * stays in the report as history.
 */
export function intelRetirementSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Intel retirement review", "");
  const review = intelRetirementReview(state);
  if (review.items.length === 0) {
    lines.push(
      `No finding rests only on intel that is no longer actionable${review.stillActionable ? ` (${review.stillActionable} finding(s) still carry a live assertion)` : ""}.`,
      "",
    );
    return;
  }
  lines.push(
    "Each row is a finding whose threat-intel corroboration rested on assertions that are now expired, revoked, not returned by the provider, errored on the last check, or recorded before assertion tracking. The assertions stay in the case as history; the decision column is the analyst's recorded recommendation and changed nothing else.",
    "",
    "| Finding | Severity | Assertions (last known) | Other corroboration | Decision |",
    "|---|---|---|---|---|",
  );
  for (const it of review.items) {
    const assertions = it.assertions
      .slice(0, 6)
      .map((a) => `${a.source}: ${a.verdict} on ${a.iocValue} — ${a.label || a.status}`)
      .join("; ");
    const more = it.assertions.length > 6 ? ` (+${it.assertions.length - 6} more)` : "";
    const other = it.otherCorroboration
      ? `${it.otherCorroboration.distinctTools} tool(s), ${it.otherCorroboration.distinctHosts} host(s)${it.otherCorroboration.graphLinked ? ", graph-linked" : ""}${it.otherCorroboration.kevLinked ? ", KEV-linked" : ""}`
      : "no rollup on file";
    const decision = it.decision
      ? `${it.decision.decision} (${it.decision.decidedAt.slice(0, 10)})${it.decision.note ? `: ${it.decision.note}` : ""}`
      : "undecided";
    lines.push(
      `| ${cellMd(it.title)} | ${it.severity} | ${cellMd(assertions + more)} | ${cellMd(other)} | ${cellMd(decision)} |`,
    );
  }
  lines.push("");
}
