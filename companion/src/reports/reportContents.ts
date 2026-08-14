import type { InvestigationState } from "../analysis/stateTypes.js";
import type { AssetGraph } from "../analysis/assetGraph.js";
import type { CustodyRecord } from "../analysis/custody.js";
import type { HostScopeLedger } from "../analysis/hostScope.js";
import type { Hypothesis } from "../analysis/hypothesis.js";
import type { KevCatalog } from "../analysis/kev.js";
import type { LateralPath } from "../analysis/evidenceGraph.js";
import type { ComplianceControl } from "../analysis/complianceControl.js";
import type { CustomerExposureSummary } from "../analysis/customerExposure.js";
import type { NotebookEntry } from "../analysis/notebookStore.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import type { SynthesisCoverage, ModelPerfSnapshot } from "../analysis/synthMeta.js";
import { renderMarkdownReport } from "./markdown.js";
import { renderHtmlReport } from "./html.js";
import { renderScopeSection } from "./scopeSection.js";
import { defaultReportTemplate, type ReportTemplate } from "./reportTemplate.js";
import type { ReportMeta } from "./reportMeta.js";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv } from "./csv.js";
import type { RedactedReportContents } from "../analysis/redactedExport.js";

// Assembly of every report artifact from an already-loaded state, lifted out of reportWriter.ts —
// that file is frozen at its recorded length by the size ratchet, and the rule when the gate fails
// is a new module rather than a raised ceiling (CONTRIBUTING.md). Keeping it as one function also
// preserves what it guarantees: writeAll and the redacted in-memory render produce byte-for-byte
// consistent structure because they call the same code.

// Render every report artifact (as strings) from an already-loaded state + its metadata/graph.
// Shared by writeAll (persists the REAL report) and redactedReportContents (renders an
// anonymized copy in-memory) so both stay byte-for-byte consistent in structure.
export function renderReportContents(
  state: InvestigationState,
  meta: ReportMeta,
  exposure: CustomerExposureSummary | undefined,
  graph: AssetGraph,
  notebookEntries: NotebookEntry[] | undefined,
  playbookTasks: PlaybookTask[] | undefined,
  template: ReportTemplate = defaultReportTemplate(),
  kevCatalog?: KevCatalog,
  hypotheses?: Hypothesis[],
  secondLookLeads?: string[],
  coverage?: SynthesisCoverage | null,
  lateralPaths?: LateralPath[],
  modelPerf?: ModelPerfSnapshot | null,
  complianceControl?: ComplianceControl,
  custody?: CustodyRecord[],
  hostScope?: HostScopeLedger | null,
): RedactedReportContents {
  const scopeSection = hostScope ? `\n\n${renderScopeSection(hostScope)}` : "";
  return {
    markdown:
      renderMarkdownReport(
        state,
        meta,
        exposure,
        graph,
        notebookEntries,
        playbookTasks,
        template,
        kevCatalog,
        hypotheses,
        secondLookLeads,
        coverage,
        lateralPaths,
        modelPerf,
        complianceControl,
        custody,
      ) + scopeSection,
    html: renderHtmlReport(
      state,
      meta,
      exposure,
      graph,
      notebookEntries,
      playbookTasks,
      template,
      hypotheses,
      custody,
      hostScope,
    ),
    findingsCsv: findingsCsv(state),
    iocsCsv: iocsCsv(state),
    timelineCsv: timelineCsv(state),
    forensicTimelineCsv: forensicTimelineCsv(state),
    stateJson: JSON.stringify(state, null, 2),
  };
}
