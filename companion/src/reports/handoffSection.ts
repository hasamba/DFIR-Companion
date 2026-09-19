import type { InvestigationState } from "../analysis/stateTypes.js";
import type { NotebookEntry } from "../analysis/notebookStore.js";
import { buildHandoffBrief } from "../analysis/handoffBrief.js";
import { renderHandoffMarkdown } from "./handoffMarkdown.js";

/**
 * "Handoff brief" section (#1406): what the case holds, what is open, what to check next, and the
 * outgoing analyst's own handoff note(s) from the notebook — the same brief the dashboard panel
 * shows, rendered for the report. The report path carries no finding-workflow or import-meta
 * side data, so owners and the last import are not stated here; the section says so. Off by
 * default (a shift-change surface belongs in a report the analyst chose to carry it).
 */
export function handoffBriefSection(
  state: InvestigationState,
  notebookEntries: NotebookEntry[] | undefined,
  hypotheses: { title: string; status: string }[] | undefined,
  lines: string[],
): void {
  const brief = buildHandoffBrief(state, {
    ...(notebookEntries ? { notebook: notebookEntries } : {}),
    ...(hypotheses ? { hypotheses } : {}),
  });
  // The report's own HTML escaping sits in front of this text (reports/html.ts); the brief's
  // angle-bracket neutralisation is for the pasteable copy, not here.
  lines.push(renderHandoffMarkdown(brief, { neutralizeHtml: false }), "");
  lines.push("_Finding owners and the last import are on the dashboard's Handoff Brief panel._", "");
}
