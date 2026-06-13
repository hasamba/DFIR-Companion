import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
import { projectScope } from "../analysis/scopeProject.js";
import { applyLegitimate, filterLegitimateEvents, type LegitimateStore } from "../analysis/legitimate.js";
import { renderMarkdownReport } from "./markdown.js";
import { renderHtmlReport } from "./html.js";
import { renderDocxReport } from "./docx.js";
import { emptyReportMeta, type ReportMetaStore } from "./reportMeta.js";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv } from "./csv.js";
import { buildAttackLayer, type NavigatorLayer } from "./attackLayer.js";
import { toTimesketchJsonl } from "../integrations/timesketch/timesketchMap.js";
import { buildAssetGraph, type AssetGraph } from "../analysis/assetGraph.js";
import { buildEvidenceGraph, type EvidenceGraph } from "../analysis/evidenceGraph.js";
import { buildAttackPhases, DEFAULT_GAP_SECONDS, type AttackPhase } from "../analysis/burstDetect.js";
import { detectBeacons, beaconEnvOptions, type BeaconCandidate } from "../analysis/beaconDetect.js";
import { detectTimelineGaps, gapEnvOptions, type TimelineGap } from "../analysis/gapDetect.js";
import { buildSwimlaneData, type SwimlaneData, type SwimlaneGroupBy } from "../analysis/swimlane.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { buildAdversaryHintsResult, type AdversaryHintsResult } from "../analysis/adversaryHints.js";
import { buildMobileSummary, mobileSummaryEnvOptions, type MobileCaseSummary } from "../analysis/mobileSummary.js";
import { loadAdversaryGroupsDataset, adversaryHintEnvOptions } from "../analysis/adversaryGroupsData.js";
import { buildStixBundle, type StixBundle } from "./stix.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { CustomerExposureStore, type CustomerExposureSummary } from "../analysis/customerExposure.js";
import type { NotebookStore, NotebookEntry } from "../analysis/notebookStore.js";
import type { PlaybookStore } from "../analysis/playbookStore.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import { AssetOverridesStore, applyAssetOverrides, emptyOverrides } from "../analysis/assetOverrides.js";
import { defaultReportTemplate, type ReportTemplate } from "./reportTemplate.js";
import type { ReportTemplateStore } from "./reportTemplateStore.js";
import type { ReportTemplateControlStore } from "./reportTemplateControl.js";
import { applyAnonDeep, type RedactedReportContents } from "../analysis/redactedExport.js";
import type { ReportMeta } from "./reportMeta.js";

export interface ReportPaths {
  markdown: string;
  html: string;
  findingsCsv: string;
  iocsCsv: string;
  timelineCsv: string;
  forensicTimelineCsv: string;
  stateJson: string;
}

export class ReportWriter {
  constructor(
    private readonly cases: CaseStore,
    private readonly state: StateStore,
    private readonly scope?: ScopeStore,
    private readonly legitimate?: LegitimateStore,
    private readonly reportMeta?: ReportMetaStore,
    private readonly customerExposure?: CustomerExposureStore,
    private readonly notebook?: NotebookStore,
    private readonly assetOverrides?: AssetOverridesStore,
    private readonly playbook?: PlaybookStore,
    private readonly reportTemplates?: ReportTemplateStore,
    private readonly reportTemplateControl?: ReportTemplateControlStore,
  ) {}

  // Resolve the report template selected for the case (issue #60). Falls back to the default
  // "standard" template when no selection is stored, the stores aren't wired, or the selected
  // template was since deleted — so report generation never breaks on a dangling id.
  private async loadTemplate(caseId: string): Promise<ReportTemplate> {
    if (!this.reportTemplates || !this.reportTemplateControl) return defaultReportTemplate();
    const { templateId } = await this.reportTemplateControl.load(caseId);
    const tpl = await this.reportTemplates.get(templateId);
    return tpl ?? defaultReportTemplate();
  }

  // Load the case state with the same deterministic report filters applied: drop
  // out-of-scope events (and the findings/IOCs/MITRE supported only by them) and exclude
  // client-confirmed legitimate items — so every export is scope/legit-consistent even if
  // AI re-synthesis hasn't run. Shared by the full report and single-section exports.
  private async loadFilteredState(caseId: string): Promise<InvestigationState> {
    const loaded = await this.state.load(caseId);
    const scoped = projectScope(loaded, this.scope ? await this.scope.load(caseId) : NO_SCOPE);
    const markers = this.legitimate ? await this.legitimate.load(caseId) : [];
    return applyLegitimate(
      { ...scoped, forensicTimeline: filterLegitimateEvents(scoped.forensicTimeline, markers) },
      markers,
    );
  }

  private async loadNotebook(caseId: string): Promise<NotebookEntry[] | undefined> {
    if (!this.notebook) return undefined;
    const entries = await this.notebook.load(caseId);
    return entries.length ? entries : undefined;
  }

  private async loadPlaybook(caseId: string): Promise<PlaybookTask[] | undefined> {
    if (!this.playbook) return undefined;
    const tasks = await this.playbook.load(caseId);
    return tasks.length ? tasks : undefined;
  }

  // Build the Word (.docx) export on demand. Uses the same scope/legitimate filtering as
  // the canonical report so the .docx matches report.md and report.html exactly. NOT added
  // to writeAll: the .docx is a snapshot deliverable, and writing a binary into the
  // (often-Dropbox-synced) cases/ folder on every report regeneration causes sync churn.
  async docx(caseId: string): Promise<Buffer> {
    const state = await this.loadFilteredState(caseId);
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    return renderDocxReport(state, meta, await this.loadExposure(caseId), await this.loadTemplate(caseId));
  }

  private async loadExposure(caseId: string): Promise<CustomerExposureSummary | undefined> {
    if (!this.customerExposure) return undefined;
    const exposure = await this.customerExposure.load(caseId);
    return exposure.checkedAt ? exposure : undefined;
  }

  // Export just the incident (forensic) timeline as CSV, on demand — without writing the
  // full report. Uses the same scope/legitimate filtering so it matches the report's 3.1.
  async incidentTimelineCsv(caseId: string): Promise<string> {
    return forensicTimelineCsv(await this.loadFilteredState(caseId));
  }

  // Build a MITRE ATT&CK Navigator layer for the case (same scope/legitimate filtering as the
  // report) — the JSON drops straight into the Navigator's "Open Existing Layer" upload. The
  // stamped ATT&CK version follows DFIR_ATTACK_VERSION (default DEFAULT_ATTACK_VERSION) so a new
  // ATT&CK release doesn't make the Navigator prompt to upgrade every exported layer.
  async attackLayer(caseId: string): Promise<NavigatorLayer> {
    const attackVersion = process.env.DFIR_ATTACK_VERSION?.trim() || undefined;
    return buildAttackLayer(await this.loadFilteredState(caseId), attackVersion ? { attackVersion } : {});
  }

  // Export the forensic timeline as Timesketch-compatible JSONL (same scope/legitimate filtering).
  // Used by the "Export Timesketch JSONL" download and as the payload for the Timesketch push.
  async timesketchJsonl(caseId: string): Promise<string> {
    return toTimesketchJsonl(await this.loadFilteredState(caseId));
  }

  // The case state with the report's scope/legitimate filters applied — so the Timesketch push
  // uploads exactly the timeline the report (and the JSONL export) show.
  async filteredState(caseId: string): Promise<InvestigationState> {
    return this.loadFilteredState(caseId);
  }

  // The asset ↔ IoC graph for the case (same scope/legitimate filtering as the report),
  // with any analyst overrides (renames, additions, suppressions) applied on top.
  async assetGraph(caseId: string): Promise<AssetGraph> {
    const state = await this.loadFilteredState(caseId);
    const graph = buildAssetGraph(state);
    const overrides = this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides();
    return applyAssetOverrides(graph, overrides);
  }

  // The causal evidence chain graph (process trees + lateral movement) for the case,
  // derived on demand with the same scope/legitimate filtering as the report.
  async evidenceGraph(caseId: string): Promise<EvidenceGraph> {
    return buildEvidenceGraph(await this.loadFilteredState(caseId));
  }

  // Temporal attack phases (bursts of activity grouped by time gap) for the case, derived on
  // demand with the same scope/legitimate filtering as the report. The burst gap threshold is
  // configurable via DFIR_PHASE_GAP_S (seconds; default 5 min).
  async phases(caseId: string): Promise<AttackPhase[]> {
    const state = await this.loadFilteredState(caseId);
    const gapSeconds = Number(process.env.DFIR_PHASE_GAP_S) || DEFAULT_GAP_SECONDS;
    return buildAttackPhases(state.forensicTimeline, { gapSeconds });
  }

  // Beacon / C2 candidates (#82): outbound connection channels whose inter-arrival intervals are too
  // regular to be human traffic, derived on demand with the same scope/legitimate filtering as the
  // report. Thresholds from DFIR_BEACON_MIN_COUNT / DFIR_BEACON_MAX_JITTER_PCT. No AI call.
  async beaconCandidates(caseId: string): Promise<BeaconCandidate[]> {
    const state = await this.loadFilteredState(caseId);
    return detectBeacons(state.forensicTimeline, beaconEnvOptions());
  }

  // Timeline gaps (#83): suspiciously long silent periods in the forensic timeline — a complete gap
  // (every source dark) is the classic log-tampering signature, a partial gap is a single-tool
  // coverage blindspot. Derived on demand with the same scope/legitimate filtering as the report.
  // Thresholds from DFIR_GAP_MIN_MINUTES / DFIR_GAP_DENSITY_FACTOR / DFIR_GAP_ACTIVE_HOURS. No AI call.
  async timelineGaps(caseId: string): Promise<TimelineGap[]> {
    const state = await this.loadFilteredState(caseId);
    return detectTimelineGaps(state.forensicTimeline, gapEnvOptions());
  }

  // Swimlane data for the visual timeline chart — events grouped into lanes by the chosen
  // groupBy axis (asset | severity | tactic). Same scope/legitimate filtering as the report.
  async swimlane(caseId: string, groupBy: SwimlaneGroupBy = "asset"): Promise<SwimlaneData> {
    const state = await this.loadFilteredState(caseId);
    return buildSwimlaneData(state.forensicTimeline, groupBy);
  }

  // Per-IOC corroboration: iocId → distinct tools that observed the indicator (derived by matching
  // the IOC value against the forensic events' `sources`). Same scope/legitimate filtering as the
  // report. Powers the dashboard's "⊕ N sources" badge on IOCs.
  async iocSources(caseId: string): Promise<Record<string, string[]>> {
    const state = await this.loadFilteredState(caseId);
    return deriveIocSources(state.iocs, state.forensicTimeline);
  }

  // Adversary group hints (#46): rank known ATT&CK groups by how much their technique set overlaps
  // the case's identified techniques — offline hypothesis fuel, NOT attribution. Derived on demand
  // from the bundled dataset with the same scope/legitimate filtering as the report.
  async adversaryHints(caseId: string): Promise<AdversaryHintsResult> {
    const state = await this.loadFilteredState(caseId);
    return buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
  }

  // Compact, READ-ONLY case summary for the mobile companion PWA (#59): case status, the worst
  // findings, the most severe/recent timeline events, and the IOC list with verdicts. Derived on
  // demand with the same scope/legitimate filtering as the report so the phone view agrees with
  // the desktop dashboard. Per-list caps come from DFIR_MOBILE_MAX_* (defaults in mobileSummary).
  async mobileSummary(caseId: string): Promise<MobileCaseSummary> {
    const state = await this.loadFilteredState(caseId);
    const meta = await this.cases.getCaseMeta(caseId);
    return buildMobileSummary(state, { ...mobileSummaryEnvOptions(), caseName: meta?.name });
  }

  // Build a STIX 2.1 bundle for the case (same scope/legitimate filtering as the report) — the
  // portable, vendor-neutral export every TIP (OpenCTI, MISP, Anomali…) ingests. The victim
  // identity, producing firm, and incident id come from the human-authored report metadata.
  async stixBundle(caseId: string): Promise<StixBundle> {
    const state = await this.loadFilteredState(caseId);
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    return buildStixBundle(state, {
      organization: meta.organization,
      producer: meta.companyName,
      incidentId: meta.incidentId,
    });
  }

  // Render every report artifact (as strings) from an already-loaded state + its metadata/graph.
  // Shared by writeAll (persists the REAL report) and redactedReportContents (renders an
  // anonymized copy in-memory) so both stay byte-for-byte consistent in structure.
  private renderContents(
    state: InvestigationState,
    meta: ReportMeta,
    exposure: CustomerExposureSummary | undefined,
    graph: AssetGraph,
    notebookEntries: NotebookEntry[] | undefined,
    playbookTasks: PlaybookTask[] | undefined,
    template: ReportTemplate = defaultReportTemplate(),
  ): RedactedReportContents {
    return {
      markdown: renderMarkdownReport(state, meta, exposure, graph, notebookEntries, playbookTasks, template),
      html: renderHtmlReport(state, meta, exposure, graph, notebookEntries, playbookTasks, template),
      findingsCsv: findingsCsv(state),
      iocsCsv: iocsCsv(state),
      timelineCsv: timelineCsv(state),
      forensicTimelineCsv: forensicTimelineCsv(state),
      stateJson: JSON.stringify(state, null, 2),
    };
  }

  async writeAll(caseId: string): Promise<ReportPaths> {
    const state = await this.loadFilteredState(caseId);
    const dir = this.cases.reportsDir(caseId);
    const paths: ReportPaths = {
      markdown: join(dir, "report.md"),
      html: join(dir, "report.html"),
      findingsCsv: join(dir, "findings.csv"),
      iocsCsv: join(dir, "iocs.csv"),
      timelineCsv: join(dir, "timeline.csv"),
      forensicTimelineCsv: join(dir, "forensic-timeline.csv"),
      stateJson: join(dir, "state-export.json"),
    };
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    const exposure = await this.loadExposure(caseId);
    const notebookEntries = await this.loadNotebook(caseId);
    const playbookTasks = await this.loadPlaybook(caseId);
    const template = await this.loadTemplate(caseId);
    const overrides = this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides();
    const graph = applyAssetOverrides(buildAssetGraph(state), overrides);
    const c = this.renderContents(state, meta, exposure, graph, notebookEntries, playbookTasks, template);
    await writeFile(paths.markdown, c.markdown, "utf8");
    await writeFile(paths.html, c.html, "utf8");
    await writeFile(paths.findingsCsv, c.findingsCsv, "utf8");
    await writeFile(paths.iocsCsv, c.iocsCsv, "utf8");
    await writeFile(paths.timelineCsv, c.timelineCsv, "utf8");
    await writeFile(paths.forensicTimelineCsv, c.forensicTimelineCsv, "utf8");
    await writeFile(paths.stateJson, c.stateJson, "utf8");
    return paths;
  }

  // Render the report artifacts from an ANONYMIZED copy of the case (for the redacted export, #54).
  // `redact` is the anonymizer's apply(): the loaded state, metadata, and asset overrides are
  // deep-walked so internal indicators become tokens (the same value -> same token, since one
  // anonymizer instance is used across all artifacts). The asset/IoC graph is derived from the
  // already-anonymized state so its labels are tokenized too. The on-disk report is never touched.
  // The investigating firm's logo (a base64 data URI) is left intact — it is branding, not victim PII.
  async redactedReportContents(caseId: string, redact: (s: string) => string): Promise<RedactedReportContents> {
    const state = applyAnonDeep(await this.loadFilteredState(caseId), redact);
    const rawMeta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    const meta: ReportMeta = { ...applyAnonDeep(rawMeta, redact), companyLogo: rawMeta.companyLogo };
    const exposure = applyAnonDeep(await this.loadExposure(caseId), redact);
    const notebookEntries = applyAnonDeep(await this.loadNotebook(caseId), redact);
    const playbookTasks = applyAnonDeep(await this.loadPlaybook(caseId), redact);
    const overrides = applyAnonDeep(
      this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides(),
      redact,
    );
    const graph = applyAssetOverrides(buildAssetGraph(state), overrides);
    // The redacted export honors the per-case report template too (branding/section layout).
    const template = await this.loadTemplate(caseId);
    return this.renderContents(state, meta, exposure, graph, notebookEntries, playbookTasks, template);
  }
}
