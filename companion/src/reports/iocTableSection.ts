// Report section 4.4, the IOC table (moved out of markdown.ts, which sits at its size ledger, when
// #2543 added two columns). The HTML report renders this same Markdown, so its table is this one.
//
// Columns added by #2543:
//   - Label: the analyst's attribution (attacker / ours / responder / unknown), stamped onto the
//     report's IOCs by filteredState.ts; "—" when unset. An enum, never free text.
//   - Context: the importer's note (e.g. "AWS access key — issued by CreateAccessKey for … at …").
//     Both the value and the note can carry attacker-chosen text (an IAM policy named
//     `=HYPERLINK(…)`, a user name with `|`), so every cell goes through cellMd.

import type { InvestigationState } from "../analysis/stateTypes.js";
import { cellMd } from "./mdText.js";
import { iocValueLabel } from "../analysis/iocMentioned.js";
import { iocSourcesLabel } from "../analysis/iocProvenanceLabel.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { scoreIocsFromState } from "../analysis/iocRiskScore.js";

export function iocTableSection(state: InvestigationState, lines: string[]): void {
  lines.push("### 4.4 Indicators of compromise", "");
  if (state.iocs.length === 0) {
    lines.push("_No IOCs extracted yet._", "");
    return;
  }
  const iocSrc = deriveIocSources(state.iocs, state.forensicTimeline); // corroboration: tools that saw it
  const iocRisk = scoreIocsFromState(state); // composite risk (#63); role splits indicator vs observation
  // An IOC the analyst labelled (#2543) is listed whatever its score: the label is their call that
  // the value matters (a cloud principal with no threat signal is otherwise an observation).
  const indicators = state.iocs.filter((i) => iocRisk[i.id]?.role !== "observation" || i.attribution);
  lines.push(
    "| ID | Type | Value | First seen | Sources | Risk | Label | Context |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
  );
  for (const i of indicators) {
    const srcCell = iocSourcesLabel(i, iocSrc[i.id]); // "(⊕ N)" is corroboration; a mention is "(referenced in N)" (#1474)
    const r = iocRisk[i.id];
    const riskCell = r ? `**${r.score}**${r.factors.length ? ` — ${r.factors[0]}` : ""}` : "—";
    const valueCell = iocValueLabel(i); // #1266 "(client-reported)"; #1461 "referenced …; no network record"
    lines.push(
      `| ${cellMd(i.id)} | ${cellMd(i.type)} | ${cellMd(valueCell)} | ${cellMd(i.firstSeen)} | ${cellMd(srcCell)} | ${cellMd(riskCell)} | ${cellMd(i.attribution ?? "—")} | ${cellMd(i.note ?? "")} |`,
    );
  }
  const obs = state.iocs.length - indicators.length;
  if (obs) lines.push("", `_Plus ${obs} observation(s) with no threat signal (searchable in the case)._`);
  lines.push("");
}
