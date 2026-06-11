import { Marked } from "marked";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { CustomerExposureSummary } from "../analysis/customerExposure.js";
import { buildAssetGraph } from "../analysis/assetGraph.js";
import { renderMarkdownReport } from "./markdown.js";
import { emptyReportMeta, type ReportMeta } from "./reportMeta.js";
import type { NotebookEntry } from "../analysis/notebookStore.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import { renderAssetGraphSvg } from "./assetGraphSvg.js";
import type { AssetGraph } from "../analysis/assetGraph.js";

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

function attr(name: string, value: string | null | undefined): string {
  return value ? ` ${name}="${escapeHtml(value)}"` : "";
}

function safeLinkUrl(href: string): boolean {
  try {
    const u = new URL(href, "https://dfir-companion.local");
    return u.protocol === "http:" || u.protocol === "https:" || u.protocol === "mailto:";
  } catch {
    return false;
  }
}

function safeImageUrl(href: string): boolean {
  if (/^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i.test(href)) return true;
  return safeLinkUrl(href);
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
  img { max-width: 280px; max-height: 96px; object-fit: contain; margin: 0 0 8px; }
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
  .asset-graph { margin: 12px 0; overflow-x: auto; }
  .asset-graph svg { display: block; max-width: 100%; }
  @media print {
    body { background: #fff; }
    main.report { box-shadow: none; max-width: none; padding: 0; }
    tr, table, blockquote { break-inside: avoid; }
    .asset-graph { break-inside: avoid; }
    @page { margin: 18mm; }
  }
`;

function reportTitle(state: InvestigationState, meta: ReportMeta): string {
  const id = meta.incidentId.trim();
  return id.length > 0 ? `Incident Report — ${id}` : `Incident Report — ${state.caseId}`;
}

// PDF export, zero-dependency / offline-safe: rather than bundle a headless browser, we reuse
// the report's existing print stylesheet and let the analyst's own browser render the PDF. This
// fragment opens the print dialog on load (where the destination is set to "Save as PDF") and
// shows an on-screen hint with a manual re-print button. Both the banner and the script are
// screen-only (`@media print` hides them), so the saved PDF stays clean. It is injected on the
// fly only when the report is opened with `?print=1`; the on-disk `report.html` is never altered.
const PRINT_TRIGGER = `
<div class="print-hint" role="note">
  Use your browser's print dialog → set the destination to <b>Save as PDF</b>.
  <button type="button" onclick="window.print()">Print again</button>
</div>
<style>
  .print-hint { position: fixed; top: 0; left: 0; right: 0; z-index: 9999; margin: 0;
    padding: 10px 16px; background: #16213a; color: #fff; text-align: center;
    font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    box-shadow: 0 1px 4px rgba(0,0,0,.25); }
  .print-hint button { margin-left: 12px; padding: 2px 10px; cursor: pointer; color: #fff;
    background: #24314f; border: 1px solid #4a587a; border-radius: 4px; }
  body { padding-top: 48px; }
  @media print { .print-hint { display: none !important; } body { padding-top: 0 !important; } }
</style>
<script>window.addEventListener("load", function () { setTimeout(function () { window.print(); }, 350); });</script>
`;

// Inject the print trigger into an already-rendered report HTML (before </body>). Pure string
// transform — the caller applies it only for the in-browser "Save as PDF" view, never for the
// downloadable file. Falls back to appending if the document has no </body>.
export function injectPrintTrigger(html: string): string {
  const idx = html.lastIndexOf("</body>");
  return idx === -1 ? html + PRINT_TRIGGER : html.slice(0, idx) + PRINT_TRIGGER + html.slice(idx);
}

export function renderHtmlReport(state: InvestigationState, meta: ReportMeta = emptyReportMeta(), exposure?: CustomerExposureSummary, assetGraph?: AssetGraph, notebookEntries?: NotebookEntry[], playbookTasks?: PlaybookTask[]): string {
  const markdown = renderMarkdownReport(state, meta, exposure, assetGraph, notebookEntries, playbookTasks);

  const marked = new Marked({ gfm: true });
  // Escape any raw HTML tokens in the source instead of emitting them verbatim.
  marked.use({
    renderer: {
      html(token: string | { text?: string }): string {
        return escapeHtml(typeof token === "string" ? token : token.text ?? "");
      },
      link(token: { href?: string; title?: string | null; text?: string }): string {
        const href = token.href ?? "";
        const text = token.text ?? href;
        if (!safeLinkUrl(href)) return escapeHtml(`[${text}]`);
        return `<a href="${escapeHtml(href)}"${attr("title", token.title)}>${escapeHtml(text)}</a>`;
      },
      image(token: { href?: string; title?: string | null; text?: string }): string {
        const href = token.href ?? "";
        const text = token.text ?? "";
        if (!safeImageUrl(href)) return escapeHtml(`![${text}]`);
        return `<img src="${escapeHtml(href)}" alt="${escapeHtml(text)}"${attr("title", token.title)}>`;
      },
    },
  });
  const body = marked.parse(markdown, { async: false }) as string;

  const graphSvg = renderAssetGraphSvg(buildAssetGraph(state));
  const graphSection = graphSvg
    ? `\n<h2>Asset–IoC Graph</h2>\n<div class="asset-graph">\n${graphSvg}\n</div>`
    : "";

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
    body.trim() + graphSection,
    "</main>",
    "</body>",
    "</html>",
    "",
  ].join("\n");
}
