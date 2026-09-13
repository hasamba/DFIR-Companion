// The last check at the door of a human-readable export (#1006).
//
// A report is assembled by a model from evidence the adversary wrote, and it travels further than
// anything else the tool produces — to counsel, to a regulator, to the subject organisation. Two
// things can go wrong on the way out, and both have gone wrong before: an indicator the case
// itself recorded reaches the reader live instead of defanged (#883, #892, #901), or a piece of
// evidence reaches the markup unescaped (#521, #820). Each was a bug in one exporter that the
// others did not share, found by a reader rather than a test.
//
// This module asks the finished output two questions the case's own data can answer:
//
//   1. Does a URL, domain, IP or email the case recorded as an IOC appear verbatim? Defanging
//      rewrites the scheme and the dots (`hxxp://evil[.]example`), so the literal value is absent
//      from a correctly defanged document. Hashes are not clickable and are not asked about.
//   2. Does a script tag, an `on*=` handler or a `javascript:` URL that sits inside a piece of case
//      text appear verbatim? Escaping turns `<` into `&lt;` and a JSON embed into `\u003c`, so the
//      raw fragment is absent from a correctly escaped document.
//
// Deliberately NOT a scanner for anything URL-shaped: the templates carry their own legitimate
// links (the report-template credit, the SVG namespace), and a generic pattern would need an
// allowlist and still guess. Checking the case's recorded values guesses nothing. The check
// warns and the export still ships (the analyst's call): the warning is stamped INTO the document
// so the file that travels carries it, logged to the case activity, and returned to the dashboard.
//
// Machine exports — CSV, STIX, JSON, the IOC blocklist, the .dfircase archive — are out of scope
// on purpose: the tools that ingest them match on the live value (see defang.ts).

import type { InvestigationState } from "../analysis/stateTypes.js";
import { escapeHtml } from "./escapeHtml.js";
import { defangIndicators } from "./defang.js";
import { CSP_NONCE_PLACEHOLDER } from "../http/securityHeaders.js";

export type EvidenceSafetyKind = "live-indicator" | "unescaped-evidence";

export interface EvidenceSafetyFinding {
  kind: EvidenceSafetyKind;
  /** The live indicator value, or the raw markup fragment, exactly as it appears in the output. */
  value: string;
}

/** The human-readable exports the check applies to. Named so the activity line says which. */
export type EvidenceSafetyFormat = "markdown" | "html" | "docx" | "interactive-html" | "presentation";

/** How many offending values a banner names before it says "and N more". */
export const EVIDENCE_SAFETY_BANNER_MAX = 5;

const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
// The defang pass rewrites IPv4 only (defang.ts), so an IPv6 IOC is not a value it promised to hide.
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

// A live-indicator check that does not match INSIDE a longer token. `10.0.0.1` must not fire on
// `10.0.0.10`, and `evil.example` must not fire on `notevil.example` or `evil.example.net`. A dot
// after the value is a sentence end unless a word character follows it.
function boundedPattern(value: string): RegExp {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![\\w.@-])${escaped}(?![\\w-]|\\.\\w)`);
}

function liveIndicatorFindings(state: InvestigationState, output: string): EvidenceSafetyFinding[] {
  const out: EvidenceSafetyFinding[] = [];
  for (const ioc of state.iocs) {
    const value = ioc.value.trim();
    if (!value) continue;
    let live = false;
    if (ioc.type === "url") live = output.includes(value);
    else if (ioc.type === "domain" || (ioc.type === "ip" && IPV4_RE.test(value)))
      live = boundedPattern(value).test(output);
    else if (ioc.type === "other" && EMAIL_RE.test(value)) live = output.includes(value);
    if (live) out.push({ kind: "live-indicator", value });
  }
  return out;
}

// The dangerous shapes, each carrying enough of the evidence's own payload to be unique against
// the template's markup: an opening script tag WITH the text that follows it (`<script>alert(1)`
// — a bare `</script>` matches every exporter's own closing tag and says nothing), or any tag
// with an `on*=` handler or a `javascript:` URL inside it. A tag is the unit because a handler
// or a `javascript:` URL is inert without one — and a JSON embed (the interactive report, the
// deck) legitimately keeps `onerror="…"` raw inside a string while escaping every `<`, so a
// check on the bare handler would flag a correctly escaped file.
const TAG_RE = /<[a-z][^<>]{0,160}>?[^<]{0,40}/gi;
const DANGEROUS_TAG_RE = /^<script\b|\bon[a-z]+\s*=|javascript:/i;

function evidenceStrings(state: InvestigationState): string[] {
  const out: string[] = [];
  for (const e of state.forensicTimeline) {
    out.push(e.description);
    if (e.asset) out.push(e.asset);
  }
  for (const f of state.findings) out.push(f.title, f.description);
  for (const i of state.iocs) out.push(i.value);
  return out;
}

function unescapedEvidenceFindings(state: InvestigationState, output: string): EvidenceSafetyFinding[] {
  const out: EvidenceSafetyFinding[] = [];
  for (const text of evidenceStrings(state)) {
    if (!text || !text.includes("<")) continue;
    for (const fragment of text.match(TAG_RE) ?? []) {
      const tag = fragment.slice(0, fragment.indexOf(">") + 1 || undefined);
      if (DANGEROUS_TAG_RE.test(tag) && output.includes(fragment.trimEnd())) {
        out.push({ kind: "unescaped-evidence", value: fragment.trimEnd() });
      }
    }
  }
  return out;
}

/** One entry per (kind, value) — also what joins the findings of two renderings of one report. */
export function dedupeEvidenceSafety(findings: EvidenceSafetyFinding[]): EvidenceSafetyFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.kind}\u0000${f.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Every live case indicator and every raw markup fragment from case text that the finished
 * `output` still contains. Empty means the export passed. Pure; `unescaped` is off for a format
 * that is plain text by nature (Markdown), where `<script>` is inert and expected to be literal.
 */
export function checkEvidenceSafety(
  state: InvestigationState,
  output: string,
  opts: { unescaped?: boolean } = {},
): EvidenceSafetyFinding[] {
  const unescaped = opts.unescaped ?? true;
  return dedupeEvidenceSafety([
    ...liveIndicatorFindings(state, output),
    ...(unescaped ? unescapedEvidenceFindings(state, output) : []),
  ]);
}

// The banner must not itself be the leak it reports: a live value is defanged before it is named.
function summarise(findings: EvidenceSafetyFinding[], kind: EvidenceSafetyKind): string | null {
  const values = findings.filter((f) => f.kind === kind).map((f) => f.value);
  if (values.length === 0) return null;
  const shown = values
    .slice(0, EVIDENCE_SAFETY_BANNER_MAX)
    .map((v) => (kind === "live-indicator" ? defangIndicators(v) : v));
  const more = values.length - shown.length;
  const label =
    kind === "live-indicator"
      ? `${values.length} live indicator(s) not defanged`
      : `${values.length} piece(s) of evidence reached the markup unescaped`;
  return `${label}: ${shown.join(", ")}${more > 0 ? `, and ${more} more` : ""}`;
}

/** The warning as plain lines — one per kind present — for the activity log and the dashboard. */
export function evidenceSafetyLines(findings: EvidenceSafetyFinding[]): string[] {
  return [summarise(findings, "live-indicator"), summarise(findings, "unescaped-evidence")].filter(
    (line): line is string => line !== null,
  );
}

const BANNER_TITLE = "Evidence-safety warning";
const BANNER_ADVICE =
  "This is an exporter defect, not something the analyst did. Regenerate after it is fixed before this document leaves the team.";

/** The activity-log entry for an export that shipped with findings, from the warning lines. */
export function evidenceSafetyActivity(
  format: EvidenceSafetyFormat,
  lines: readonly string[],
): { category: "export"; action: string; detail: string } {
  return {
    category: "export",
    action: "evidence-safety-warning",
    detail: `${format} export produced with a warning — ${lines.join("; ")}`,
  };
}

const BANNER_STYLE =
  ".evidence-safety{background:#fff3cd;border:2px solid #b45309;border-radius:6px;color:#3b1d00;margin:0 0 16px;padding:12px 16px;font:14px/1.5 system-ui,sans-serif}" +
  ".evidence-safety strong{display:block;font-size:15px;margin-bottom:4px}" +
  ".evidence-safety ul{margin:4px 0 8px 20px;padding:0}";

/**
 * The HTML report with the warning stamped in as the first thing under `<body>`. Untouched when
 * there is nothing to warn about. The `<style>` carries the CSP nonce placeholder because the
 * served policy blocks inline `style=` attributes (securityHeaders.ts).
 */
export function withEvidenceSafetyHtmlBanner(html: string, findings: EvidenceSafetyFinding[]): string {
  if (findings.length === 0) return html;
  const items = evidenceSafetyLines(findings)
    .map((line) => `<li>${escapeHtml(line)}</li>`)
    .join("");
  const banner =
    `<style nonce="${CSP_NONCE_PLACEHOLDER}">${BANNER_STYLE}</style>` +
    `<div class="evidence-safety" role="alert"><strong>\u26A0 ${BANNER_TITLE}</strong>` +
    `<ul>${items}</ul>${escapeHtml(BANNER_ADVICE)}</div>`;
  const body = /<body(?:\s[^>]*)?>/i.exec(html);
  if (!body) return `${banner}\n${html}`;
  const at = body.index + body[0].length;
  return `${html.slice(0, at)}\n${banner}${html.slice(at)}`;
}

/**
 * The Markdown (and, through the Markdown renderer, the DOCX) with the warning as a leading
 * blockquote. Each line sits in inline code so a raw markup fragment it names stays literal text
 * for the renderer instead of becoming the tag it warns about.
 */
export function withEvidenceSafetyMarkdownBanner(
  markdown: string,
  findings: EvidenceSafetyFinding[],
): string {
  if (findings.length === 0) return markdown;
  const lines = evidenceSafetyLines(findings).map((line) => `> - \`${line.replace(/`/g, "'")}\``);
  return [`> **\u26A0 ${BANNER_TITLE}**`, `>`, ...lines, `>`, `> ${BANNER_ADVICE}`, "", markdown].join("\n");
}
