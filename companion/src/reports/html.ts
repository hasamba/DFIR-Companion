import { Marked } from "marked";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { renderMarkdownReport } from "./markdown.js";
import { emptyReportMeta, type ReportMeta } from "./reportMeta.js";

// Standalone HTML export of the incident report. We render the canonical Markdown report
// (single source of truth) and convert it to HTML with `marked` (GFM tables), then wrap it
// in a self-contained, print-friendly document. Raw HTML in the Markdown source is escaped
// rather than passed through: DFIR data (filenames, IOC values, AI/analyst text) is
// untrusted and must never become live markup in the exported file.

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Self-contained, dependency-free stylesheet. Tuned for on-screen reading and for
// "Print → Save as PDF" from the browser (A4 margins, avoids breaking rows across pages).
const STYLE = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #f5f6f8; color: #1b1f24;
    font: 15px/1.6 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  main.report { max-width: 900px; margin: 0 auto; padding: 48px 56px; background: #fff;
    box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  h1 { font-size: 28px; margin: 0 0 24px; padding-bottom: 12px; border-bottom: 3px solid #2d6cdf; }
  h2 { font-size: 20px; margin: 32px 0 10px; padding-top: 8px; border-top: 1px solid #e6e8ec; color: #16213a; }
  h3 { font-size: 16px; margin: 22px 0 8px; color: #2a3550; }
  h4 { font-size: 14px; margin: 16px 0 6px; color: #44506a; }
  p { margin: 8px 0; }
  a { color: #2d6cdf; }
  code { background: #eef1f5; padding: 1px 5px; border-radius: 4px; font-size: 90%;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
  blockquote { margin: 10px 0; padding: 8px 14px; border-left: 4px solid #c7ccd4;
    background: #f7f8fa; color: #5a6675; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13.5px; }
  th, td { border: 1px solid #d7dbe0; padding: 6px 10px; text-align: left; vertical-align: top; }
  th { background: #f0f3f7; font-weight: 600; }
  tr:nth-child(even) td { background: #fafbfc; }
  ul { margin: 8px 0; padding-left: 22px; }
  @media print {
    body { background: #fff; }
    main.report { box-shadow: none; max-width: none; padding: 0; }
    tr, table, blockquote { break-inside: avoid; }
    @page { margin: 18mm; }
  }
`;

function reportTitle(state: InvestigationState, meta: ReportMeta): string {
  const id = meta.incidentId.trim();
  return id.length > 0 ? `Incident Report — ${id}` : `Incident Report — ${state.caseId}`;
}

export function renderHtmlReport(state: InvestigationState, meta: ReportMeta = emptyReportMeta()): string {
  const markdown = renderMarkdownReport(state, meta);

  const marked = new Marked({ gfm: true });
  // Escape any raw HTML tokens in the source instead of emitting them verbatim.
  marked.use({
    renderer: {
      html(token: string | { text?: string }): string {
        return escapeHtml(typeof token === "string" ? token : token.text ?? "");
      },
    },
  });
  const body = marked.parse(markdown, { async: false }) as string;

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeHtml(reportTitle(state, meta))}</title>`,
    `<style>${STYLE}</style>`,
    "</head>",
    "<body>",
    '<main class="report">',
    body.trim(),
    "</main>",
    "</body>",
    "</html>",
    "",
  ].join("\n");
}
