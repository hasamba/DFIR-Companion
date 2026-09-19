// The shift-handoff brief as Markdown (#1406) — the pasteable copy the dashboard hands to a shift
// log, and the report section's body. Lives in reports/ because the brief itself is analysis
// state and the analysis tier may not reach into the report helpers (ARCHITECTURE.md layering).

import type { Finding, Severity } from "../analysis/stateTypes.js";
import type { HandoffBrief } from "../analysis/handoffBrief.js";
import { blockMd, cellMd, oneLineMd } from "./mdText.js";

const when = (iso: string): string => (iso ? iso.slice(0, 16).replace("T", " ") + " UTC" : "unknown");
const more = (n: number, what: string): string[] => (n > 0 ? [`- _… and ${n} more ${what}_`] : []);

/**
 * The brief as Markdown. `neutralizeHtml` (the default) also turns `<` and `>` into entities: the
 * pasteable copy lands in shift logs and chat tools that render raw HTML, where the report path's
 * own HTML escaping (reports/html.ts) is not in front of it. The report section passes false.
 */
export function renderHandoffMarkdown(b: HandoffBrief, opts: { neutralizeHtml?: boolean } = {}): string {
  const html = opts.neutralizeHtml ?? true;
  const ent = (s: string): string => (html ? s.replace(/</g, "&lt;").replace(/>/g, "&gt;") : s);
  const line = (s: string): string => ent(cellMd(oneLineMd(s)));
  const block = (s: string): string => ent(blockMd(s));
  const out: string[] = [];
  out.push(`## Handoff Brief — ${line(b.caseId)} (${when(b.generatedAt)})`, "");
  out.push(
    `_Derived from the case as of ${when(b.stateUpdatedAt)}${b.lastImport ? `; last import ${when(b.lastImport.at)} (${line(b.lastImport.kind)}${b.lastImport.source ? `, ${line(b.lastImport.source)}` : ""})` : "; no import recorded"}; a count is not a conclusion._`,
    "",
  );
  out.push("### From the outgoing analyst", "");
  if (!b.handoffNotes.length) out.push("_No handoff note recorded yet._", "");
  else {
    const [latest, ...earlier] = b.handoffNotes;
    out.push(`**${line(latest.author)}** — ${when(latest.timestamp)}`, "", block(latest.text), "");
    for (const n of earlier)
      out.push(
        `- _Earlier: ${line(n.author)}, ${when(n.timestamp)}_ — ${line(n.text.slice(0, 160))}${n.text.length > 160 ? "…" : ""}`,
      );
    if (earlier.length) out.push("");
    if (b.handoffNotesNotShown)
      out.push(`_… and ${b.handoffNotesNotShown} earlier note(s) in the notebook._`, "");
  }
  out.push("### What the case holds", "");
  const sev = (Object.keys(b.findings.bySeverity) as Severity[])
    .map((k) => `${k} ${b.findings.bySeverity[k]}`)
    .join(", ");
  out.push(`- Findings: ${state_(b.findings.byStatus)} — ${sev}`);
  out.push(
    `- IOCs: ${b.iocs.total}${b.iocs.unenriched ? ` (${b.iocs.unenriched} not yet checked by any provider)` : ""}`,
    "",
  );
  out.push("### Open", "");
  out.push(
    `**Findings still open (${b.findings.openTotal}; ${b.findings.inProgress} in progress, ${b.findings.unassigned} unassigned):**`,
    "",
  );
  if (!b.findings.open.length) out.push("- _none_");
  for (const f of b.findings.open)
    out.push(
      `- [${f.severity}] ${line(f.title)} \`${line(f.id)}\`${f.assignee ? ` — ${line(f.assignee)}` : ""}${f.workflowStatus ? ` (${line(f.workflowStatus)})` : ""}`,
    );
  out.push(...more(b.findings.openNotShown, "findings"), "");
  out.push("**Key questions not answered:**", "");
  if (!b.questions.length) out.push("- _none_");
  for (const q of b.questions)
    out.push(`- (${q.status}) ${line(q.question)}${q.pointer ? ` — ${line(q.pointer)}` : ""}`);
  out.push(...more(b.questionsNotShown, "questions"), "");
  out.push("**Hypotheses still open:**", "");
  if (!b.hypotheses.length) out.push("- _none_");
  for (const h of b.hypotheses) out.push(`- ${line(h.title)}`);
  out.push(...more(b.hypothesesNotShown, "hypotheses"), "");
  out.push("**Threads open:**", "");
  if (!b.threads.length) out.push("- _none_");
  for (const t of b.threads) out.push(`- ${line(t.description)} _(since ${when(t.openedAt)})_`);
  out.push(...more(b.threadsNotShown, "threads"), "");
  out.push("### Check next", "");
  if (!b.nextSteps.length) out.push("- _no critical or high next step recorded_");
  for (const n of b.nextSteps)
    out.push(`- [${line(n.priority)}] ${line(n.action)}${n.pointer ? ` — ${line(n.pointer)}` : ""}`);
  out.push(...more(b.nextStepsNotShown, "steps"), "");
  return out.join("\n");
}

const state_ = (s: Record<Finding["status"], number>): string =>
  `${s.open + s.confirmed + s.dismissed} (${s.open} open, ${s.confirmed} confirmed, ${s.dismissed} dismissed)`;
