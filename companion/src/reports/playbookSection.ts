import { playbookStats, type PlaybookStatus, type PlaybookTask } from "../analysis/playbook.js";
import type { ContainmentAnswer, ContainmentAttribution } from "../analysis/playbookContainment.js";
import { cellMd } from "./mdText.js";

// The report's "Response Playbook" section: the analyst's tracked checklist, plus (#1925) an
// attribution block for every task the Jev containment check suggested. Model names, labels and
// verdicts are escaped like table cells: a pipe or newline in them must not change the report's
// structure.

export const PLAYBOOK_STATUS_LABEL: Record<PlaybookStatus, string> = {
  todo: "To do",
  in_progress: "In progress",
  done: "Done",
  skipped: "Skipped",
};

const IN_PROGRESS_NOTE =
  '"In progress" means the activity was still going on at the end of the collected evidence, not necessarily now.';

function answerText(a: ContainmentAnswer): string {
  const value = a.value.toFixed(2);
  const manual = a.checkManually ? ", check manually" : "";
  const detail = a.kind === "choice" ? `confidence ${value}${manual}` : `${value}${manual}`;
  return `${cellMd(a.label)}: ${cellMd(a.verdict)} (${detail})`;
}

function attributionLine(ref: string, c: ContainmentAttribution): string {
  const basis = new Set(c.basis);
  const answers = c.answers.filter((a) => basis.has(a.id)).map(answerText);
  const source =
    `- ${ref} — suggested by the Jev containment check of finding ${cellMd(c.findingId)} ` +
    `(model ${cellMd(c.model)}, ${cellMd(c.checkedAt.slice(0, 10))}, rule ${cellMd(c.rule)})`;
  return answers.length ? `${source}: ${answers.join("; ")}.` : `${source}.`;
}

function containmentAttributionBlock(tasks: PlaybookTask[], lines: string[]): void {
  const attributed = tasks
    .map((t, i) => ({ t, ref: `#${i + 1}${t.shortId ? ` (${cellMd(t.shortId)})` : ""}` }))
    .filter(({ t }) => t.containmentCheck);
  if (!attributed.length) return;
  lines.push("**Containment-check attribution**", "");
  for (const { t, ref } of attributed) lines.push(attributionLine(ref, t.containmentCheck!));
  if (attributed.some(({ t }) => t.containmentCheck!.inProgressCaveat)) lines.push("", IN_PROGRESS_NOTE);
  lines.push("");
}

export function playbookSection(tasks: PlaybookTask[], lines: string[]): void {
  lines.push("## Response Playbook", "");
  const stats = playbookStats(tasks);
  lines.push(
    `_Actionable remediation/investigation checklist derived from the recommended next steps and high-severity findings, tracked by the analyst. **${stats.done}/${stats.total} complete (${stats.completionPct}%)**._`,
    "",
  );
  lines.push(
    "| # | Status | Priority | Task | Assignee | Due | Notes |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  );
  tasks.forEach((t, i) => {
    const status = PLAYBOOK_STATUS_LABEL[t.status] ?? t.status;
    lines.push(
      `| ${i + 1} | ${status} | ${t.priority.toUpperCase()} | ${cellMd(t.title)} | ${cellMd(t.assignee || "—")} | ${cellMd(t.dueDate || "—")} | ${cellMd(t.notes || "—")} |`,
    );
  });
  lines.push("");
  containmentAttributionBlock(tasks, lines);
}
