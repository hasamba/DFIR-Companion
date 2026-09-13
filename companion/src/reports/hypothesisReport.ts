import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { Hypothesis } from "../analysis/hypothesis.js";
import {
  assessHypothesisEvidence,
  describeHypothesisEvidence,
  hypothesisQualifier,
  type EvidenceRow,
  type HypothesisAssessment,
} from "../analysis/hypothesisDiagnostics.js";
import { blockMd, oneLineMd } from "./mdText.js";

// The Hypotheses report section (#140), with the evidence assessment of #933 item 22: a conclusion
// names what it rests on — the observations that separate it from a named alternative, the
// alternatives considered, and what is unresolved — and the analyst's exclusions are printed as the
// audit trail they are. Counts are counts of observations; nothing here is a probability.
//
// Lifted out of markdown.ts, which sits at its size cap.

const STATUS_LABEL: Record<Hypothesis["status"], string> = {
  supported: "Supported",
  refuted: "Refuted",
  open: "Open",
  unknown: "Unknown",
};

// The report's timeline is the SCOPED, false-positive-filtered one, so "not in the timeline" here
// means either — the section says so rather than guessing which.
const NOT_IN_REPORT = "not in this report's timeline (out of scope or marked false positive)";

function eventLine(row: EvidenceRow | undefined, id: string): string {
  if (!row || !row.present) return `\`${oneLineMd(id)}\` — observation no longer in the timeline`;
  const when = row.timestamp ? `${oneLineMd(row.timestamp)} — ` : "";
  const notes = row.uncertainty.length ? ` _[${row.uncertainty.map(oneLineMd).join("; ")}]_` : "";
  return `${when}${oneLineMd(row.description)}${notes}`;
}

const titles = (refs: readonly { title: string }[]): string =>
  refs.map((r) => `'${oneLineMd(r.title)}'`).join(", ");

function assessmentBlock(
  h: Hypothesis,
  a: HypothesisAssessment,
  rows: Map<string, EvidenceRow>,
  lines: string[],
): void {
  lines.push("**Evidence assessment**", "");
  if (a.support.distinguishing.length) {
    lines.push("Decisive evidence — separates this from a named alternative:", "");
    for (const d of a.support.distinguishing)
      lines.push(
        `- ${eventLine(rows.get(d.eventId), d.eventId)} — separates this from ${titles(d.separatesFrom)}`,
      );
    lines.push("");
  } else if (a.alternatives.length) {
    lines.push("Decisive evidence: none — no supporting observation separates this from an alternative.", "");
  }
  if (a.contradiction.distinguishing.length) {
    lines.push("Decisive contradictions — each supports a named alternative:", "");
    for (const d of a.contradiction.distinguishing)
      lines.push(`- ${eventLine(rows.get(d.eventId), d.eventId)} — supports ${titles(d.supports)}`);
    lines.push("");
  }
  lines.push(
    `Alternatives considered${a.alternativesSource === "analyst" ? " (named by the analyst)" : ""}: ` +
      (a.alternatives.length
        ? a.alternatives
            .map((x) => `'${oneLineMd(x.title)}' (${STATUS_LABEL[x.status] ?? x.status})`)
            .join(", ")
        : "none — this is the only explanation offered, so no observation could separate it from one."),
    "",
  );
  const notDistinguishing: string[] = [];
  if (a.support.consistentWithAlternatives.length)
    notDistinguishing.push(
      `${a.support.consistentWithAlternatives.length} supporting observation(s) consistent with the alternatives that assessed them (they do not choose between them)`,
    );
  for (const r of a.contradiction.againstEveryAssessed)
    notDistinguishing.push(
      `\`${oneLineMd(r.eventId)}\` contradicts every one of the ${r.assessedBy} explanations that assessed it; ${r.notAssessedBy} did not assess it — the set of explanations may be incomplete`,
    );
  const unassessed = a.support.notAssessedElsewhere.length + a.contradiction.notAssessedElsewhere.length;
  if (unassessed)
    notDistinguishing.push(`${unassessed} observation(s) not assessed against the alternatives`);
  if (notDistinguishing.length) lines.push(`Not distinguishing: ${notDistinguishing.join("; ")}.`, "");
  const unresolved: string[] = [];
  if (a.restsOnSingleObservation) {
    const only = a.support.distinguishing[0];
    const row = rows.get(only.eventId);
    unresolved.push(
      row?.uncertainty.length
        ? `rests on one distinguishing observation, and that observation's own record carries an uncertainty: ${row.uncertainty.map(oneLineMd).join("; ")}`
        : "rests on one distinguishing observation",
    );
  }
  if (a.assessedBothWays.length)
    unresolved.push(
      `${a.assessedBothWays.length} observation(s) assessed both ways and counted for nothing: ${a.assessedBothWays.map(oneLineMd).join(", ")}`,
    );
  if (a.notCounted.length)
    unresolved.push(
      `${a.notCounted.length} linked observation(s) not counted: ${a.notCounted
        .map(
          (n) =>
            `\`${oneLineMd(n.eventId)}\` (${n.reason === "not in the timeline" ? NOT_IN_REPORT : n.reason})`,
        )
        .join(", ")}`,
    );
  if (h.needsReview)
    unresolved.push(`review required${h.reviewReason ? `: ${oneLineMd(h.reviewReason)}` : ""}`);
  if (unresolved.length) lines.push(`Unresolved: ${unresolved.join("; ")}.`, "");
  // The audit trail: every exclusion, active or restored, in the order they were made.
  const trail = h.excludedEvidence ?? [];
  if (trail.length) {
    lines.push("Excluded from this assessment by the analyst (the observation and its link were kept):", "");
    for (const x of trail) {
      const restored = x.restoredAt
        ? ` (restored ${oneLineMd(x.restoredAt.slice(0, 10))}${x.restoredBy === "unlinked" ? ", unlinked" : ""})`
        : "";
      lines.push(
        `- ${oneLineMd(x.by || "analyst")} on ${oneLineMd(x.excludedAt.slice(0, 10))}: ${eventLine(rows.get(x.eventId), x.eventId)} — ${oneLineMd(x.reason)}${restored}`,
      );
    }
    lines.push("");
  }
}

export function hypothesesSection(
  hypotheses: Hypothesis[],
  events: readonly ForensicEvent[],
  lines: string[],
): void {
  lines.push("## Hypotheses", "");
  lines.push(
    "_What we investigated and concluded. Each hypothesis is a testable claim about the incident, " +
      "tracked from open to supported / refuted / unknown — a lead to test, not a verdict. The status " +
      "word is the analyst's; the evidence assessment under it says what the conclusion rests on. " +
      "Counts are counts of observations. They are not a probability that the explanation is true._",
    "",
  );
  // Negative knowledge (issue #95): a refuted hypothesis, or one whose linked hunts came back empty
  // (`exhausted`), is a settled, ruled-out theory — call it out up front so a reader doesn't mistake it
  // for an open lead buried further down the section.
  const negative = hypotheses.filter((h) => h.status === "refuted" || h.exhausted);
  if (negative.length) {
    lines.push(
      "> **Negative knowledge — ruled out.** These theories were refuted by the evidence or exhausted " +
        "(hunted for and not found); treat them as settled, not as open leads.",
      "",
    );
    for (const h of negative) {
      const tag = h.status === "refuted" ? "Refuted" : "Exhausted";
      const reason = h.status === "refuted" ? h.notes : h.exhaustedReason;
      lines.push(`- **[${tag}]** ${oneLineMd(h.title)}${reason ? ` — ${oneLineMd(reason)}` : ""}`);
    }
    lines.push("");
  }
  const assessments = assessHypothesisEvidence(hypotheses, {
    eligibleEventIds: new Set(events.map((e) => e.id)),
  });
  // Concluded hypotheses first (supported, then refuted), then the outstanding ones (open, unknown).
  const order: Hypothesis["status"][] = ["supported", "refuted", "open", "unknown"];
  const sorted = [...hypotheses].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status));
  for (const h of sorted) {
    const a = assessments.get(h.id)!;
    const exhaustedTag = h.exhausted ? " ⊘ Exhausted" : "";
    // The qualifier sits on the status line, never only inside the block below (#933 item 22).
    const qualifier = hypothesisQualifier(h, a);
    lines.push(
      `### ${oneLineMd(h.title)} — ${STATUS_LABEL[h.status] ?? h.status}${exhaustedTag}${qualifier ? ` — ${oneLineMd(qualifier)}` : ""}`,
      "",
    );
    if (h.description) lines.push(blockMd(h.description), "");
    if (h.expectedOutcome)
      lines.push(
        `**Expected outcome (what would prove or disprove this):** ${oneLineMd(h.expectedOutcome)}`,
        "",
      );
    if (h.exhausted && h.exhaustedReason) lines.push(`**Exhausted:** ${oneLineMd(h.exhaustedReason)}`, "");
    const bits: string[] = [];
    if (h.relatedTechniques.length) bits.push(`ATT&CK: ${h.relatedTechniques.join(", ")}`);
    if (h.relatedEventIds.length)
      bits.push(`${h.relatedEventIds.length} supporting event${h.relatedEventIds.length === 1 ? "" : "s"}`);
    if (h.relatedIocIds.length)
      bits.push(`${h.relatedIocIds.length} related IOC${h.relatedIocIds.length === 1 ? "" : "s"}`);
    if (bits.length) lines.push(`_${bits.join(" · ")}._`, "");
    assessmentBlock(h, a, describeHypothesisEvidence(a, events), lines);
    if (h.notes) lines.push(`**Analyst notes:** ${oneLineMd(h.notes)}`, "");
    // Status-change audit trail (issue #95): a dated open → … chain, skipped when there's only the
    // initial entry (nothing has changed since the hypothesis was created).
    const history = h.statusHistory ?? [];
    if (history.length > 1) {
      const chain = history
        .map((s) => `${STATUS_LABEL[s.status] ?? s.status} (${(s.changedAt || "").slice(0, 10)})`)
        .join(" → ");
      lines.push(`**Status history:** ${chain}`, "");
    }
  }
}
