// AI Agent Forensics (#2690): the run report as Markdown and CSV, and (#2722) the rule-by-endpoint
// Sigma coverage table as its own CSV. The Markdown body is shared with the case report's section
// (#2721, aiAgentSection.ts). Matched snippets, file paths, host names, MCP names and commands are
// attacker-controlled, so every one goes through the shared escapers: a table-safe code span
// (evidenceCellMd) in Markdown tables, codeSpanMd in list lines, csv.row (formula-injection guard +
// quoting) for CSV. The snippet is already redacted and length-capped by the report builder.

import type { AiAgentRun } from "../analysis/aiAgentRunStore.js";
import type {
  AiAgentReport,
  AiAgentReportEndpoint,
  AiAgentReportHit,
  AiAgentRunView,
} from "../analysis/aiAgentReportTypes.js";
import { AI_AGENT_HASH_CAVEAT, hashCheckLabel } from "../analysis/aiAgentHashCheck.js";
import { cellCodeMd, cellMd, codeSpanMd, oneLineMd } from "./mdText.js";
import { row } from "./csv.js";

const SENSITIVE_NOTE =
  "Sensitive run: preservation may have copied credential files into Velociraptor's file store. " +
  "The Companion never read the collected files; it keeps a manifest only.";
const PROVISIONAL_NOTE =
  "Severity grades are a first estimate: they have not yet been checked against real developer machines, so some may change.";

/**
 * A table cell of attacker-reachable text (#2721): a code span, so link, image, emphasis and raw-HTML
 * syntax stay literal (html.ts renders explicit http(s) links and images), with the pipe and newline
 * escaped so the cell stays one cell.
 */
export function evidenceCellMd(value: string): string {
  return cellCodeMd(codeSpanMd(value));
}
const ev = evidenceCellMd;

function completenessLines(run: AiAgentRunView): string[] {
  return [
    ...run.failedEndpoints.map(
      (e) => `- Hunt not started on ${codeSpanMd(e.clientId)}: ${codeSpanMd(e.error)}`,
    ),
    ...run.skippedEndpoints.map(
      (e) => `- Skipped ${codeSpanMd(e.hostname || e.clientId)}: ${codeSpanMd(e.reason)}`,
    ),
    ...(run.readIncomplete ?? []).map(
      (x) =>
        `- Results incomplete: ${codeSpanMd(x.artifact)} — only the first ${x.rowsRead} row(s) were read`,
    ),
    ...(run.reportError ? [`- The last results read reported: ${codeSpanMd(run.reportError)}`] : []),
  ];
}

function summaryLines(run: AiAgentRunView): string[] {
  return [
    `- Rule set: ${codeSpanMd(run.report?.ruleSetVersion ?? run.ruleSetVersion)}`,
    `- Launched: ${oneLineMd(run.launchedAt)} · hunt ${codeSpanMd(run.huntId)}${run.guiUrl ? ` · ${codeSpanMd(run.guiUrl)}` : ""}`,
    ...(run.report ? [`- Results read: ${oneLineMd(run.report.builtAt)}`] : []),
    `- Scopes: ${run.scopes.map(codeSpanMd).join(", ")}`,
    `- Copies of the AI-agent files saved in Velociraptor: ${run.preserved ? "yes" : "no"}`,
    ...(run.manifest
      ? [
          `- Preserved files in Velociraptor: ${run.manifest.total} (${run.manifest.totalBytes} bytes, manifest only)`,
        ]
      : []),
    ...completenessLines(run),
    ...run.warnings.map((w) => `- Note: ${codeSpanMd(w)}`),
    `- ${SENSITIVE_NOTE}`,
    `- ${PROVISIONAL_NOTE}`,
  ];
}

/** A report stored before #2722 has no hash check: it was never recorded. */
function hashCheckOf(h: AiAgentReportHit): string {
  return hashCheckLabel(h.hashCheck ?? "not recorded");
}

/** The caveat travels with every check that compares two hashes. */
function hashNoteOf(h: AiAgentReportHit): string {
  return h.hashCheck === "same" || h.hashCheck === "differs" ? AI_AGENT_HASH_CAVEAT : "";
}

/** The text of one rule-by-endpoint cell; a rule with no row from that endpoint was not recorded. */
export function sigmaCellText(ep: AiAgentReportEndpoint, rule: string, sep = ", "): string {
  const cell = (ep.sigma ?? []).find((c) => c.rule === rule);
  return cell ? `${cell.status}${sep}${cell.hits} hit(s)` : "not recorded";
}

/** The rule-by-endpoint Sigma table (#2722): one row per rule of the rule set, one column per endpoint. */
function sigmaMarkdown(r: AiAgentReport, h: string): string[] {
  const rules = r.sigmaRules ?? [];
  if (!rules.length) return [];
  const head = ["", `${h} Sigma coverage per rule and endpoint`, ""];
  // No endpoint, no column: a table would have a header wider than its delimiter row (#2799).
  if (!r.endpoints.length)
    return [...head, "No endpoint reported results, so there is no Sigma coverage to show."];
  const out = [
    ...head,
    `| Rule | Basis | ${r.endpoints.map((e) => ev(e.host)).join(" | ")} |`,
    `|---|---|${r.endpoints.map(() => "---|").join("")}`,
  ];
  for (const rule of rules)
    out.push(
      `| ${ev(rule.rule)} | ${ev(rule.basis)} | ${r.endpoints.map((e) => ev(sigmaCellText(e, rule.rule))).join(" | ")} |`,
    );
  return out;
}

/** The rule-by-endpoint Sigma table as CSV: rule, basis, then one column per endpoint (#2722). */
export function aiAgentSigmaCoverageCsv(run: AiAgentRun): string {
  const r = run.report;
  const endpoints = r?.endpoints ?? [];
  const header = row(["rule", "basis", ...endpoints.map((e) => e.host)]);
  const lines = (r?.sigmaRules ?? []).map((rule) =>
    row([rule.rule, rule.basis, ...endpoints.map((e) => sigmaCellText(e, rule.rule, " - "))]),
  );
  return [header, ...lines].join("\r\n") + "\r\n";
}

function endpointsMarkdown(r: AiAgentReport, h: string): string[] {
  const lines = [
    `${h} Endpoints`,
    "",
    "| Endpoint | AI tools | MCP servers | Hits | Credential stores | Coverage |",
    "|---|---|---|---|---|---|",
  ];
  for (const e of r.endpoints) {
    const mcp = e.mcpServers.map((m) => `${m.name} (${m.command}, ${m.tool})`).join("; ") || "none";
    const cov = e.coverage
      .map((c) => `${c.source}: ${c.status}${c.detail ? ` — ${c.detail}` : ""}`)
      .join("; ");
    lines.push(
      `| ${ev(e.host)} | ${ev(e.tools.join(", ") || "none found")} | ${ev(mcp)} | ${e.hits} | ${e.credentialStores ? "credential store present" : "none"} | ${ev(cov)} |`,
    );
  }
  return lines;
}

const HITS_HEADER =
  "| Grade | Endpoint | Rule | File | Latest time the content could have been planted | Matched text | File SHA-256 (hashed after the scan) | Preserved SHA-256 | Hash check | Rule author |";

function hitLine(h: AiAgentReportHit): string {
  return `| ${h.severity}${h.selfScan ? " (self-scan)" : ""} | ${ev(h.host)} | ${ev(h.rule)} | ${ev(h.path)} | ${ev(`${h.time} (${h.timeBasis})`)} | ${ev(h.snippet)} | ${ev(h.sha256 || "none")} | ${ev(h.preservedSha256 || "none")} | ${cellMd(hashCheckOf(h))} | ${ev(h.author)} ${ev(h.link)} |`;
}

function hitsMarkdown(run: AiAgentRunView, r: AiAgentReport, h: string, maxHits: number): string[] {
  const lines = [`${h} Hits`, ""];
  if (!r.hits.length) {
    const partial = run.readIncomplete?.length || run.reportError || r.unreadableRows > 0;
    lines.push(
      partial
        ? "No rule matched in the results that were read, but the results are incomplete (see above), so this is not a clean result."
        : "No rule matched on the endpoints and scopes above.",
    );
    return lines;
  }
  lines.push(AI_AGENT_HASH_CAVEAT, "", HITS_HEADER, "|---|---|---|---|---|---|---|---|---|---|");
  lines.push(...r.hits.slice(0, maxHits).map(hitLine));
  const more = r.hits.length - maxHits;
  if (more > 0)
    lines.push(
      "",
      `${more} more hit(s) are not shown here; the run's own report download in the AI Agent Forensics panel lists every hit.`,
    );
  return lines;
}

/**
 * The body of one run's report (#2721): the per-run download and the case report section share it,
 * so both show the same columns, hash caveat and Sigma table. `level` is the heading depth of its
 * subsections; `maxHits` caps the hits table (the download shows every hit).
 */
export function aiAgentRunBodyMarkdown(
  run: AiAgentRunView,
  opts: { level: number; maxHits?: number },
): string[] {
  const h = "#".repeat(opts.level);
  const r = run.report;
  const lines = [...summaryLines(run), ""];
  if (!r) return [...lines, "Results have not been read yet."];
  lines.push(...endpointsMarkdown(r, h), "");
  lines.push(...hitsMarkdown(run, r, h, opts.maxHits ?? Infinity));
  lines.push(...sigmaMarkdown(r, h));
  lines.push("", `${h} Rules not run, and why`, "");
  for (const g of r.notRun)
    lines.push(`- ${codeSpanMd(g.reason)} (${g.rules.length}): ${g.rules.map(codeSpanMd).join(", ")}`);
  if (r.unreadableRows) lines.push("", `${r.unreadableRows} result row(s) could not be read.`);
  return lines;
}

/** The run report as Markdown. */
export function aiAgentReportMarkdown(run: AiAgentRun): string {
  return ["# AI Agent Forensics report", "", ...aiAgentRunBodyMarkdown(run, { level: 2 }), ""].join("\n");
}

/** The run's hits as CSV, one row per hit. */
export function aiAgentReportCsv(run: AiAgentRun): string {
  const header = row([
    "grade",
    "self_scan",
    "endpoint",
    "rule",
    "family",
    "rule_file",
    "rule_author",
    "rule_link",
    "atlas",
    "scope",
    "file",
    "file_sha256_after_scan",
    "preserved_sha256",
    "hash_check",
    "hash_note",
    "event_time",
    "event_time_basis",
    "scan_time",
    "matched_text",
    "preserved",
    "rule_set",
  ]);
  const lines = (run.report?.hits ?? []).map((h) =>
    row([
      h.severity,
      h.selfScan ? "yes" : "no",
      h.host,
      h.rule,
      h.family,
      h.ruleFile,
      h.author,
      h.link,
      h.atlas,
      h.scope,
      h.path,
      h.sha256,
      h.preservedSha256 ?? "",
      hashCheckOf(h),
      hashNoteOf(h),
      h.time,
      h.timeBasis,
      h.scanTime,
      h.snippet,
      h.preserved,
      run.report?.ruleSetVersion ?? run.ruleSetVersion,
    ]),
  );
  return [header, ...lines].join("\r\n") + "\r\n";
}
