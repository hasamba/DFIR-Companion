// AI Agent Forensics (#2690): the run report as Markdown and CSV, and (#2722) the rule-by-endpoint
// Sigma coverage table as its own CSV. Matched snippets, file paths, MCP
// names and commands are attacker-controlled, so every one goes through the shared escapers: cellMd /
// codeSpanMd for Markdown tables, csv.row (formula-injection guard + quoting) for CSV. The snippet is
// already redacted and length-capped by the report builder.

import type { AiAgentRun } from "../analysis/aiAgentRunStore.js";
import type { AiAgentReport, AiAgentReportEndpoint, AiAgentReportHit } from "../analysis/aiAgentReport.js";
import { AI_AGENT_HASH_CAVEAT, hashCheckLabel } from "../analysis/aiAgentHashCheck.js";
import { cellMd, codeSpanMd } from "./mdText.js";
import { row } from "./csv.js";

const SENSITIVE_NOTE =
  "Sensitive run: preservation may have copied credential files into Velociraptor's file store. " +
  "The Companion never read the collected files; it keeps a manifest only.";
const PROVISIONAL_NOTE = "Grades are provisional until measured on real developer profiles.";

function summaryLines(run: AiAgentRun): string[] {
  return [
    `- Rule set: ${cellMd(run.report?.ruleSetVersion ?? run.ruleSetVersion)}`,
    `- Launched: ${run.launchedAt} · hunt ${cellMd(run.huntId)}${run.guiUrl ? ` · ${cellMd(run.guiUrl)}` : ""}`,
    `- Scopes: ${run.scopes.map(cellMd).join(", ")}`,
    `- Preserved with Windows.Triage.Targets / AICodingAgents: ${run.preserved ? "yes" : "no — artifacts not preserved"}`,
    ...(run.manifest
      ? [
          `- Preserved files in Velociraptor: ${run.manifest.total} (${run.manifest.totalBytes} bytes, manifest only)`,
        ]
      : []),
    ...run.warnings.map((w) => `- Note: ${cellMd(w)}`),
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
function sigmaMarkdown(r: AiAgentReport): string[] {
  const rules = r.sigmaRules ?? [];
  if (!rules.length) return [];
  const out = [
    "",
    "## Sigma coverage per rule and endpoint",
    "",
    `| Rule | Basis | ${r.endpoints.map((e) => cellMd(e.host)).join(" | ")} |`,
    `|---|---|${r.endpoints.map(() => "---|").join("")}`,
  ];
  for (const rule of rules)
    out.push(
      `| ${cellMd(rule.rule)} | ${cellMd(rule.basis)} | ${r.endpoints.map((e) => cellMd(sigmaCellText(e, rule.rule))).join(" | ")} |`,
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

/** The run report as Markdown. */
export function aiAgentReportMarkdown(run: AiAgentRun): string {
  const r = run.report;
  const lines = ["# AI Agent Forensics report", "", ...summaryLines(run), ""];
  if (!r) return [...lines, "Results have not been read yet.", ""].join("\n");
  lines.push(
    "## Endpoints",
    "",
    "| Endpoint | AI tools | MCP servers | Hits | Credential stores | Coverage |",
  );
  lines.push("|---|---|---|---|---|---|");
  for (const e of r.endpoints) {
    const mcp = e.mcpServers.map((m) => `${m.name} (${m.command}, ${m.tool})`).join("; ") || "none";
    const cov = e.coverage
      .map((c) => `${c.source}: ${c.status}${c.detail ? ` — ${c.detail}` : ""}`)
      .join("; ");
    lines.push(
      `| ${cellMd(e.host)} | ${cellMd(e.tools.join(", ") || "none found")} | ${cellMd(mcp)} | ${e.hits} | ${e.credentialStores ? "credential store present" : "none"} | ${cellMd(cov)} |`,
    );
  }
  lines.push("", "## Hits", "");
  if (!r.hits.length) lines.push("No rule matched on the endpoints and scopes above.");
  else {
    lines.push(
      AI_AGENT_HASH_CAVEAT,
      "",
      "| Grade | Endpoint | Rule | File | Latest time the content could have been planted | Matched text | File SHA-256 (hashed after the scan) | Preserved SHA-256 | Hash check | Rule author |",
    );
    lines.push("|---|---|---|---|---|---|---|---|---|---|");
    for (const h of r.hits)
      lines.push(
        `| ${h.severity}${h.selfScan ? " (self-scan)" : ""} | ${cellMd(h.host)} | ${cellMd(h.rule)} | ${cellMd(h.path)} | ${h.time} (${cellMd(h.timeBasis)}) | ${codeSpanMd(h.snippet)} | ${cellMd(h.sha256 || "none")} | ${cellMd(h.preservedSha256 || "none")} | ${cellMd(hashCheckOf(h))} | ${cellMd(h.author)} ${cellMd(h.link)} |`,
      );
  }
  lines.push(...sigmaMarkdown(r));
  lines.push("", "## Rules not run, and why", "");
  for (const g of r.notRun)
    lines.push(`- ${cellMd(g.reason)} (${g.rules.length}): ${g.rules.map(cellMd).join(", ")}`);
  if (r.unreadableRows) lines.push("", `${r.unreadableRows} result row(s) could not be read.`);
  return [...lines, ""].join("\n");
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
