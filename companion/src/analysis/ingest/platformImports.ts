import { type ExternalImporter } from "../declarativeImporter.js";
import { parseEmail, type EmailImportOptions } from "../emailImport.js";
import { parseEvtxXmlProgress } from "../evtxXmlImport.js";
import { parseIrisCase, type IrisCaseData, type IrisImportOptions } from "../irisImport.js";
import { intactTruncationNote, parseMemoryOrIntact, type MemoryImportOptions } from "../intactImport.js";
import { deltaSchema } from "../responseSchema.js";
import { parseSandboxReport, type SandboxImportOptions } from "../sandboxImport.js";
import { applySeverityFloor } from "../severityFloor.js";
import {
  parseSiemExport,
  resolveExtractedFrom,
  type SiemImportOptions,
  type SiemParseResult,
} from "../siemImport.js";
import { parseSocrates, type SocratesImportOptions } from "../socratesImport.js";

import { type InvestigationState, type Severity } from "../stateTypes.js";
import { parseTheHive, type TheHiveImportOptions } from "../theHiveImport.js";
import { detectTool } from "../toolDetect.js";
import { parseWazuhAlerts, type WazuhImportOptions } from "../wazuhImport.js";
import { YARA_SOURCE, parseYaraOutput, type YaraImportOptions } from "../yaraImport.js";
import { commitDelta, noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * Security platforms, case trackers and analysis tooling that already produced findings.
 *
 * Moved from AnalysisPipeline (#384). Each of these was a method; each is now a free function
 * taking an ImportContext, which is the small set of collaborators an importer is allowed to use.
 * The pipeline keeps a one-line delegation per importer, so callers are unchanged.
 */

// Import a SIEM / EDR JSON export (Elastic/Kibana, Splunk, an EDR console, a raw
// winlogbeat dump…). Like THOR, the mapping is DETERMINISTIC (no AI call): the
// container is unwrapped, Windows/Sysmon events get a per-EID mapping, other records
// fall back to field auto-detection, and repetitive events are aggregated. The
// detected tool name (from the filename / source) tags each event's `sources`.
export async function importSiem(
  ctx: ImportContext,
  caseId: string,
  jsonText: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "s3") so ids never collide
    importedAt: string;
    siem?: SiemImportOptions; // filtering overrides (aggregate, minSeverity, maxEvents…)
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseSiemExport(jsonText, opts.siem);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "SIEM", parsed.total);

  const source = detectTool(opts.label) ?? detectTool(parsed.format) ?? "SIEM import";
  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : [source] };
  });
  const raw = {
    findings: [],
    iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
      ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
    })),
    mitreTechniques: [],
    forensicEvents,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `SIEM import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Run a USER-authored declarative importer (the external plugin path). Mirrors the built-in
// deterministic wrappers exactly: parse -> severity floor -> standard delta (findings/MITRE empty,
// MITRE rides inside each event) -> mergeDelta -> save -> notify. Does NOT depend on any shared-runner
// refactor of the built-ins.
export async function importDeclarative(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    importer: ExternalImporter;
    label: string;
    idPrefix: string;
    importedAt: string;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
    // Per-importer health (#84): fired with the raw parse stats (total/kept/dropped/format) right
    // after parsing, BEFORE the zero-events early return, so a run that legitimately produced
    // nothing still counts as a completed (not failed) run in the diagnostics table.
    onParsed?: (result: SiemParseResult) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = opts.importer.parse(text, { minSeverity: opts.minSeverity });
  opts.onParsed?.(parsedRaw);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, opts.importer.label, parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [opts.importer.label],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `${opts.importer.label} import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import a malware-sandbox detonation report (CAPEv2 or CrowdStrike Falcon Sandbox).
// Deterministic (no AI call): the sample verdict + each behavioural signature map to events
// (severity from the report's own score/verdict, MITRE from its ATT&CK), and every
// dropped/extracted file hash + network host/domain/URL is harvested as an IOC.
export async function importSandbox(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "sb3") so ids never collide
    importedAt: string;
    sandbox?: SandboxImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseSandboxReport(text, opts.sandbox);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "Sandbox", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Sandbox"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Sandbox import (${parsed.format}): ${parsed.kept} event(s)` +
      (parsed.signatures > 0 ? `, ${parsed.signatures} signature(s)` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import memory-forensics tool output (Volatility 3 or Rekall). Deterministic (no AI call): each
// plugin table is identified by its columns and mapped — pslist/psscan/pstree → process-tree
// events (with parent→child links), netscan/netstat → network-connection events (+ foreign IP/
// port IOCs), malfind → High injected-code events (ATT&CK T1055), cmdline → command-line events
// (bumped on LOLBin/encoded tradecraft), svcscan/modules → service/driver evidence. Tagged
// "Volatility" / "Rekall" for cross-source correlation; reads the artifact's own time.
export async function importMemory(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "mem3") so ids never collide
    importedAt: string;
    memory?: MemoryImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseMemoryOrIntact(text, { ...opts.memory, filename: opts.label });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Memory", parsed.total);

  const tool = parsed.tool || "Volatility";
  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    // A parser may mint its OWN id: the Intact adapter derives one from the (Offset, Rule) a YARA hit
    // matched at, so the same hit arriving in both of Intact's files lands on ONE timeline row
    // instead of being double-counted (#776). Everyone else leaves it empty and gets numbered here.
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: e.id || `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [tool],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Memory import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s) across ${parsed.tables} plugin(s)` +
      (parsed.injected > 0 ? `, ${parsed.injected} injected-code hit(s)` : "") +
      (parsed.connections > 0 ? `, ${parsed.connections} connection(s)` : "") +
      (parsed.yaraHits ? `, ${parsed.yaraHits} YARA hit(s)` : "") +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)` +
      (parsed.truncated?.length ? ` — ${intactTruncationNote(parsed.truncated)}` : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import an email artifact (.eml RFC 2822, or best-effort .msg). Deterministic (no AI call):
// ONE forensic event dated at the message's own Date: header, severity DERIVED from the email's
// SPF/DKIM/DMARC verdict + sender heuristics; URLs, sender/reply-to domains, originating IP and
// attachment names/hashes become IOCs. Covers ATT&CK T1566 (Phishing). Tagged "Email".
export async function importEmail(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "em3") so ids never collide
    importedAt: string;
    email?: EmailImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseEmail(text, opts.email);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Email", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Email"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Email import (${parsed.format}): ${parsed.kept} event(s)` +
      (parsed.subject ? ` — "${parsed.subject.slice(0, 80)}"` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import a TheHive 5 case, alert, or observable export. Deterministic (no AI call):
// case/alert records → forensic events (severity from TheHive's own 1–4 scale, MITRE from
// ATT&CK-tagged tags, TLP/PAP labels prepended); observable records → IOCs by dataType.
export async function importTheHive(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "th3") so ids never collide
    importedAt: string;
    thehive?: TheHiveImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseTheHive(text, opts.thehive);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "TheHive", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["TheHive"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `TheHive import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.observables > 0 ? `, ${parsed.observables} observable(s)` : "") +
      `, ${parsed.iocCount} IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import an existing DFIR-IRIS case (issue #88) — the reverse of the IRIS push. Takes the raw
// case rows already fetched from the IRIS API (analysis/irisImport.ts parses them deterministically,
// NO AI call): timeline → forensic events, IOCs → IOCs, assets → evidence events. All feed the
// same forensic timeline via mergeDelta, exactly like the other importers.
export async function importIris(
  ctx: ImportContext,
  caseId: string,
  data: IrisCaseData,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "iris3") so ids never collide
    importedAt: string;
    iris?: IrisImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseIrisCase(data, opts.iris);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "DFIR-IRIS", parsed.timelineCount);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["DFIR-IRIS"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `DFIR-IRIS import (${parsed.caseName ?? `case #${parsed.irisCaseId ?? "?"}`}): ` +
      `${parsed.kept} event(s) from ${parsed.timelineCount} timeline + ${parsed.assetCount} asset(s)` +
      `, ${parsed.iocCount} IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import Wazuh SIEM/EDR alert exports (alerts.json / NDJSON / API export). Deterministic
// (no AI call): rule.level drives severity (≥13 Critical, ≥10 High, ≥7 Medium, else Info),
// rule.mitre.technique → MITRE, agent.name → asset, data.srcip/dstip/md5/sha256/url → IOCs.
export async function importWazuh(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "w3") so ids never collide
    importedAt: string;
    wazuh?: WazuhImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseWazuhAlerts(text, opts.wazuh);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) return noteEmptyImport(ctx, caseId, opts, "Wazuh", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Wazuh"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Wazuh import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)` +
      (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import YARA CLI scan output (`yara -s -m <rules> <target>`). Deterministic (no AI): each rule
// match becomes a file-match event (default Medium, bumped only on an explicit rule-meta signal),
// matched file + hash meta become IOCs. YARA output is undated, so mergeDelta stamps events at import
// time. Used by the external-tools run path (#211). See yaraImport.ts.
export async function importYara(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    yara?: YaraImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseYaraOutput(text, { ...opts.yara });
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "YARA", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [YARA_SOURCE],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `YARA import: ${parsed.kept} match event(s) from ${parsed.total} match(es)` +
      `, ${parsed.iocs.length} IOC(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import SO-CRATES (dougburks/so-crates) verdicts — Suricata IDS alerts, YARA file matches, and
// Sigma log detections — as the browser extension pushes them (or a raw export). Deterministic
// (no AI). Events are tagged "SO-CRATES" (+ the underlying engine) for cross-source correlation.
export async function importSocrates(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "s4") so ids never collide
    importedAt: string;
    socrates?: SocratesImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button)
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseSocrates(text, opts.socrates);
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "SO-CRATES", parsed.total);

  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["SO-CRATES"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `SO-CRATES import (${parsed.format}): ${parsed.kept} detection event(s) from ${parsed.total} record(s)` +
      ` — ${parsed.alerts} Suricata alert(s), ${parsed.yara} YARA, ${parsed.sigma} Sigma, ${parsed.iocs.length} IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return commitDelta(ctx, caseId, delta, opts);
}

// Import Windows Event XML through the shared deterministic SIEM/EVTX mapping.
export async function importEvtxXml(
  ctx: ImportContext,
  caseId: string,
  xmlText: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "s3") so ids never collide
    importedAt: string;
    siem?: SiemImportOptions; // filtering overrides (aggregate, minSeverity, maxEvents…)
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void | Promise<void>;
    onParseProgress?: (done: number, total: number, detail?: string) => void | Promise<void>;
    signal?: AbortSignal;
    startBatch?: number;
  },
): Promise<InvestigationState> {
  if ((opts.startBatch ?? 0) >= 1) {
    await opts.onProgress?.(1, 1);
    return ctx.opts.stateStore.load(caseId);
  }
  let parseTotal = 0;
  const parsedRaw = await parseEvtxXmlProgress(
    xmlText,
    opts.siem,
    (done, total) => {
      parseTotal = total;
      return opts.onParseProgress?.(done, total * 2, "reading Windows events");
    },
    (done, total) =>
      opts.onParseProgress?.(parseTotal + done, parseTotal + total, "processing Windows events"),
    opts.signal,
  );
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Windows Event Log (XML)", parsed.total);

  const source = detectTool(opts.label) ?? "Windows Event Log";
  const raw = {
    findings: [],
    iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [source],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Windows Event Log (XML) import: ${parsed.kept} event(s) from ${parsed.total} record(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  // awaitProgress: this importer's callback checkpoints the job, and the import is not finished
  // until that lands — it is the one wrapper whose tail awaited it before the tails were shared.
  return commitDelta(ctx, caseId, delta, { ...opts, awaitProgress: true });
}
