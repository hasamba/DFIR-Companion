// oletools' `olevba -j` VBA/OLE macro static-analysis results document (#932 items 10-11,
// "932.10"): structural facts an external document-analysis tool found in an Office document —
// an auto-run macro entry point, a risky API keyword, a decoded obfuscated string, or a VBA
// source/compiled-P-code mismatch (stomping). Never a claim a macro ran, and never a proven
// entry-point-to-capability chain — see RECOMMENDATION-7.md for the guardrails this enforces and
// why endpoint/YARA correlation and raw macro-source import are deliberately out of scope.
//
// Schema verified live against olevba's own JSON-building code, its SUSPICIOUS_KEYWORDS
// dictionary, and a real serialized 0.60.2 report — not invented.

import { createHash } from "node:crypto";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  MAX_CITATIONS,
  MAX_DESCRIPTION_LEN,
  MAX_FIELD_LEN,
  MAX_MAPPINGS,
  OLEVBA_COMPOUND_LEAD_BASIS,
  OLEVBA_FINDING_BASIS,
  OLEVBA_STOMPING_LEAD_BASIS,
  olevbaFindingTypes,
  type OlevbaCapabilityClass,
  type OlevbaFindingType,
} from "./canonicalOlevbaFinding.js";
import { MAX_PRODUCER_VERSION_LEN } from "./canonicalMalwareSample.js";
import { extractIocsFromText } from "./deobfuscate.js";
import {
  addIoc,
  isObject,
  mergeRowIocs,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_RESULT_ENTRIES = 500;
export const MAX_ANALYSIS_ENTRIES_SCANNED = 50_000; // report-wide
export const MAX_DISTINCT_FINDINGS = 2000; // per result entry
export const MAX_TOOL_WARNINGS_KEPT = 20;

// Exact-string capability mapping (Codex code review finding: substring matching on olevba's own
// free-text description matched benign entries too — "May read or write registry keys" and "May
// save the current workbook" both contain "write"/"save" but name no file-write/launch
// capability). Fetched live from SUSPICIOUS_KEYWORDS; an unrecognized description — even one that
// superficially resembles a known one — is never matched. Fail closed.
const DOWNLOAD_DESCRIPTIONS = new Set([
  "May download files from the Internet",
  "May download files from the Internet using PowerShell",
]);
const LAUNCH_DESCRIPTIONS = new Set([
  "May run an executable file or a system command",
  "May run a dll",
  "May execute file or a system command through WMI",
  "May run an executable file or a system command on a Mac",
  "May run PowerShell commands",
  "May run an executable file or a system command using PowerShell",
  "May run an Excel 4 Macro (aka XLM/XLF) from VBA",
]);
const FILE_WRITE_DESCRIPTIONS = new Set([
  "May write to a file (if combined with Open)",
  "May read or write a binary file (if combined with Open)",
  "May create a text file",
]);

// olevba's own confirmed IOC category labels (its `description` field for an IOC-type entry).
const IOC_CATEGORY_MAP: Record<string, SiemIoc["type"]> = {
  URL: "url",
  "IPv4 address": "ip",
  "Executable file name": "file",
};

const RELEVANT_WARNING_RE = /stomping|unsupported|cannot|error|fail/i;

export interface OlevbaResultOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface OlevbaResultResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedFindings: number;
  notCitedFindings: number;
  errorEntries: number;
  analysisTruncated: boolean;
  resultsTruncated: boolean;
  toolWarnings: string[];
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function clip(text: string, max: number): { text: string; truncated: boolean } {
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max), truncated: true };
}

/** A genuine per-file result entry, positively distinguished from `MetaInformation`/`msg`/
 * `error` entries by shape — `analysis` is legitimately `null` for a macro-free document (Codex
 * code review finding: requiring it to be an array would reject that common, valid case). */
function isResultEntry(entry: unknown): entry is Record<string, unknown> {
  return (
    isObject(entry) &&
    typeof entry.file === "string" &&
    entry.file.length > 0 &&
    Array.isArray(entry.macros) &&
    typeof entry.json_conversion_successful === "boolean"
  );
}

/** Both anchors required: a `MetaInformation` entry naming olevba itself, AND at least one
 * genuine result entry — the same "two anchors, never one" rule every prior item's detector
 * used. */
export function isOlevbaResult(root: unknown): boolean {
  if (!Array.isArray(root)) return false;
  const hasMeta = root.some((e) => isObject(e) && e.type === "MetaInformation" && e.script_name === "olevba");
  const hasResult = root.some(isResultEntry);
  return hasMeta && hasResult;
}

// Report-wide, threaded by reference into every mapResult() call so one oversized result entry
// cannot exhaust the whole cap in one shot before the budget is ever consulted again.
interface ScanBudget {
  scanned: number;
  truncated: boolean;
}

interface FindingGroup {
  findingType: OlevbaFindingType;
  keyword: string;
  descriptions: string[]; // distinct, bounded
  notCitedDescriptions: number;
  occurrences: number;
}

/** One result entry's own identity — the FULL, unclipped container/document path plus its type
 * and array index, so two archive members reporting the same `file` with different `container`
 * (or two entries that otherwise coincide) never collide (Codex code review finding). Built via
 * chained `.update()` calls, never a literal separator character in a template string, per this
 * session's own standing lesson about the Write tool mangling control-byte escapes. */
function resultIdentity(
  containerPath: string | undefined,
  documentPath: string,
  resultType: string,
  index: number,
): string {
  return createHash("sha256")
    .update(JSON.stringify([containerPath ?? null, documentPath, resultType, index]))
    .digest("hex");
}

function capabilityClassesFor(description: string): OlevbaCapabilityClass[] {
  const classes: OlevbaCapabilityClass[] = [];
  if (DOWNLOAD_DESCRIPTIONS.has(description)) classes.push("download");
  if (LAUNCH_DESCRIPTIONS.has(description)) classes.push("launch");
  if (FILE_WRITE_DESCRIPTIONS.has(description)) classes.push("file-write");
  return classes;
}

function mapResult(
  containerPath: string | undefined,
  documentPath: string,
  entry: Record<string, unknown>,
  index: number,
  reportFingerprint: string,
  producerVersion: string,
  sink: Map<string, SiemIoc>,
  budget: ScanBudget,
): { mapped: MappedEvent[]; malformedFindings: number; notCitedFindings: number } {
  const analysis = entry.analysis;
  const mapped: MappedEvent[] = [];
  let malformedFindings = 0;
  let notCitedFindings = 0;

  if (!Array.isArray(analysis)) {
    return { mapped, malformedFindings, notCitedFindings };
  }

  const resultType = str(entry.type) ?? "unknown";
  const resultId = resultIdentity(containerPath, documentPath, resultType, index);
  const groups = new Map<string, FindingGroup>();
  for (const raw of analysis) {
    // Report-wide bound checked HERE, inside the innermost loop, via a shared-by-reference
    // counter — checking it only between result entries (as a first pass did) let one oversized
    // entry's own `analysis` array bypass the cap entirely (Codex code review finding).
    if (budget.scanned >= MAX_ANALYSIS_ENTRIES_SCANNED) {
      budget.truncated = true;
      break;
    }
    budget.scanned += 1;
    if (!isObject(raw)) {
      malformedFindings += 1;
      continue;
    }
    const findingType = str(raw.type);
    const keyword = str(raw.keyword);
    const description = str(raw.description) ?? "";
    if (!findingType || !keyword || !(olevbaFindingTypes as readonly string[]).includes(findingType)) {
      malformedFindings += 1;
      continue;
    }
    const groupKey = `${findingType}|${keyword}`;
    let group = groups.get(groupKey);
    if (!group) {
      if (groups.size >= MAX_DISTINCT_FINDINGS) {
        notCitedFindings += 1;
        continue;
      }
      group = {
        findingType: findingType as OlevbaFindingType,
        keyword,
        descriptions: [],
        notCitedDescriptions: 0,
        occurrences: 0,
      };
      groups.set(groupKey, group);
    }
    group.occurrences += 1;
    if (!group.descriptions.includes(description)) {
      if (group.descriptions.length < MAX_CITATIONS) group.descriptions.push(description);
      else group.notCitedDescriptions += 1;
    }
  }

  const autoExecKeywords: string[] = [];
  const capabilityKeywords: string[] = [];
  const capabilityClassSet = new Set<OlevbaCapabilityClass>();
  let hasStomping = false;

  for (const group of groups.values()) {
    if (group.findingType === "AutoExec") autoExecKeywords.push(group.keyword);
    if (group.findingType === "Suspicious") {
      if (group.keyword === "VBA Stomping") hasStomping = true;
      for (const d of group.descriptions) {
        const classes = capabilityClassesFor(d);
        if (classes.length > 0) {
          capabilityKeywords.push(group.keyword);
          for (const c of classes) capabilityClassSet.add(c);
        }
      }
    }
    let rowSink: Map<string, SiemIoc> | undefined;
    if (group.findingType === "IOC") {
      rowSink = new Map<string, SiemIoc>();
      // Check every citation, not just the first — a controlled category variant seen later
      // must still be found (Codex code review finding: descriptions[0] was order-dependent).
      const mappedDescription = group.descriptions.find((d) => IOC_CATEGORY_MAP[d]);
      const mappedType = mappedDescription ? IOC_CATEGORY_MAP[mappedDescription] : undefined;
      const boundedKeyword = clip(group.keyword, MAX_FIELD_LEN).text;
      if (mappedType) addIoc(rowSink, mappedType, boundedKeyword);
      else for (const raw of extractIocsFromText(boundedKeyword)) addIoc(rowSink, raw.type, raw.value);
    }
    mapped.push(
      mapFinding(
        group,
        rowSink,
        containerPath,
        documentPath,
        resultId,
        reportFingerprint,
        producerVersion,
        sink,
      ),
    );
  }

  if (autoExecKeywords.length > 0 && capabilityKeywords.length > 0) {
    mapped.push(
      mapCompoundLead(
        containerPath,
        documentPath,
        resultId,
        reportFingerprint,
        producerVersion,
        [...new Set(autoExecKeywords)],
        [...new Set(capabilityKeywords)],
        [...capabilityClassSet],
      ),
    );
  }
  if (hasStomping) {
    mapped.push(mapStompingLead(containerPath, documentPath, resultId, reportFingerprint, producerVersion));
  }

  return { mapped, malformedFindings, notCitedFindings };
}

function mapFinding(
  group: FindingGroup,
  rowSink: Map<string, SiemIoc> | undefined,
  containerPath: string | undefined,
  documentPath: string,
  resultId: string,
  reportFingerprint: string,
  producerVersion: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const findingHash = createHash("sha256").update(`${group.findingType}\n${group.keyword}`).digest("hex");
  const aggKey = boundedAggKey(`olevba|${reportFingerprint}|${resultId}|finding|${findingHash}`);
  if (rowSink) mergeRowIocs(sink, rowSink, aggKey);

  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const body = boundedTextTo(
    `olevba ${group.findingType} finding: ${group.keyword} — ${group.occurrences} analysis entry(ies) reporting ` +
      `this pattern in this document; a structural fact, never a claim the macro ran; [undated: olevba's report ` +
      `carries no event time]`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  return {
    timestamp: "",
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["olevba"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "document-analysis-finding", action: "found" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "olevba-result", locator: `finding:${findingHash}` }] },
      producer: { importer: "olevba-result", parserVersion: "1", mappingVersion: "olevba-finding-v1" },
      olevbaFinding: {
        tool: "olevba",
        findingType: group.findingType,
        keyword: clip(group.keyword, MAX_FIELD_LEN).text,
        keywordTruncated: clip(group.keyword, MAX_FIELD_LEN).truncated,
        descriptions: group.descriptions.map((d) => clip(d, MAX_DESCRIPTION_LEN).text),
        notCitedDescriptions: group.notCitedDescriptions,
        documentPath: clip(documentPath, MAX_FIELD_LEN).text,
        ...(containerPath ? { containerPath: clip(containerPath, MAX_FIELD_LEN).text } : {}),
        reportFingerprint,
        producerVersion: clip(producerVersion, MAX_PRODUCER_VERSION_LEN).text,
        mappingVersion: "olevba-finding-v1",
        occurrences: group.occurrences,
        basis: OLEVBA_FINDING_BASIS,
      },
    }),
  };
}

function mapStompingLead(
  containerPath: string | undefined,
  documentPath: string,
  resultId: string,
  reportFingerprint: string,
  producerVersion: string,
): MappedEvent {
  const aggKey = boundedAggKey(`olevba|${reportFingerprint}|${resultId}|lead|stomping`);
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const body = boundedTextTo(
    `olevba VBA stomping lead: source code and compiled P-code differ — an investigation lead, ` +
      `not automatically malicious; [undated: olevba's report carries no event time]`,
    600 - reportTag.length,
  );
  return {
    timestamp: "",
    description: `${body}${reportTag}`,
    severity: "Low",
    mitre: [],
    aggKey,
    sources: ["olevba"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "vba-stomping-lead", action: "flagged" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "olevba-result", locator: `stomping:${resultId.slice(0, 16)}` }] },
      producer: { importer: "olevba-result", parserVersion: "1", mappingVersion: "olevba-finding-v1" },
      olevbaStompingLead: {
        tool: "olevba",
        reportFingerprint,
        documentPath: clip(documentPath, MAX_FIELD_LEN).text,
        ...(containerPath ? { containerPath: clip(containerPath, MAX_FIELD_LEN).text } : {}),
        producerVersion: clip(producerVersion, MAX_PRODUCER_VERSION_LEN).text,
        mappingVersion: "olevba-finding-v1",
        basis: OLEVBA_STOMPING_LEAD_BASIS,
      },
    }),
  };
}

// Neither lead carries its own IOCs (all IOC promotion happens per-finding, in mapFinding) — no
// sink parameter needed here.
function mapCompoundLead(
  containerPath: string | undefined,
  documentPath: string,
  resultId: string,
  reportFingerprint: string,
  producerVersion: string,
  autoExecKeywords: readonly string[],
  capabilityKeywords: readonly string[],
  capabilityClasses: readonly OlevbaCapabilityClass[],
): MappedEvent {
  const boundedAutoExec = autoExecKeywords.slice(0, MAX_MAPPINGS).map((k) => clip(k, MAX_FIELD_LEN).text);
  const notCitedAutoExecKeywords = Math.max(0, autoExecKeywords.length - boundedAutoExec.length);
  const boundedCapability = capabilityKeywords.slice(0, MAX_MAPPINGS).map((k) => clip(k, MAX_FIELD_LEN).text);
  const notCitedCapabilityKeywords = Math.max(0, capabilityKeywords.length - boundedCapability.length);

  const aggKey = boundedAggKey(`olevba|${reportFingerprint}|${resultId}|lead|compound`);
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const body = boundedTextTo(
    `olevba compound static-capability lead: ${boundedAutoExec.join(", ")} + ${boundedCapability.join(", ")} ` +
      `(${capabilityClasses.join("/")}) — co-occurrence in this document's static analysis, not a proven ` +
      `entry-point-to-capability chain; [undated: olevba's report carries no event time]`,
    600 - reportTag.length,
  );
  return {
    timestamp: "",
    description: `${body}${reportTag}`,
    severity: "Low",
    mitre: [],
    aggKey,
    sources: ["olevba"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "compound-capability-lead", action: "flagged" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "olevba-result", locator: `compound:${resultId.slice(0, 16)}` }] },
      producer: { importer: "olevba-result", parserVersion: "1", mappingVersion: "olevba-finding-v1" },
      olevbaCompoundLead: {
        tool: "olevba",
        reportFingerprint,
        documentPath: clip(documentPath, MAX_FIELD_LEN).text,
        ...(containerPath ? { containerPath: clip(containerPath, MAX_FIELD_LEN).text } : {}),
        producerVersion: clip(producerVersion, MAX_PRODUCER_VERSION_LEN).text,
        mappingVersion: "olevba-finding-v1",
        autoExecKeywords: boundedAutoExec,
        notCitedAutoExecKeywords,
        capabilityClasses: [...capabilityClasses],
        capabilityKeywords: boundedCapability,
        notCitedCapabilityKeywords,
        basis: OLEVBA_COMPOUND_LEAD_BASIS,
      },
    }),
  };
}

export function parseOlevbaResult(text: string, opts: OlevbaResultOptions = {}): OlevbaResultResult | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isOlevbaResult(root)) return null;
  const arr = root as unknown[];
  const reportFingerprint = createHash("sha256").update(text).digest("hex");
  const metaEntry = arr.find((e) => isObject(e) && e.type === "MetaInformation") as
    Record<string, unknown> | undefined;
  const producerVersion = str(metaEntry?.version) ?? "";

  const toolWarnings: string[] = [];
  let errorEntries = 0;
  for (const e of arr) {
    if (!isObject(e)) continue;
    if (e.type === "error") {
      errorEntries += 1;
      continue;
    }
    if (e.type === "msg") {
      const msg = str(e.msg);
      if (msg && RELEVANT_WARNING_RE.test(msg) && toolWarnings.length < MAX_TOOL_WARNINGS_KEPT) {
        toolWarnings.push(clip(msg, MAX_DESCRIPTION_LEN).text);
      }
    }
  }

  const resultEntries = arr.filter(isResultEntry);
  const resultsTruncated = resultEntries.length > MAX_RESULT_ENTRIES;
  const boundedResults = resultEntries.slice(0, MAX_RESULT_ENTRIES);

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let malformedFindings = 0;
  let notCitedFindings = 0;
  const budget: ScanBudget = { scanned: 0, truncated: false };
  let total = 0;
  boundedResults.forEach((entry, index) => {
    total += 1;
    const documentPath = str(entry.file) ?? "";
    const containerPath = str(entry.container);
    const result = mapResult(
      containerPath,
      documentPath,
      entry,
      index,
      reportFingerprint,
      producerVersion,
      sink,
      budget,
    );
    mapped.push(...result.mapped);
    malformedFindings += result.malformedFindings;
    notCitedFindings += result.notCitedFindings;
  });

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_DISTINCT_FINDINGS * MAX_RESULT_ENTRIES,
  });

  return {
    events,
    iocs: [...sink.values()],
    total,
    kept: events.length,
    dropped: malformedFindings,
    groups,
    format: "OlevbaResultDocument",
    malformedFindings,
    notCitedFindings,
    errorEntries,
    analysisTruncated: budget.truncated,
    resultsTruncated,
    toolWarnings,
  };
}
