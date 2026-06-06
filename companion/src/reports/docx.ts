import {
  AlignmentType,
  BorderStyle,
  Document,
  ExternalHyperlink,
  HeadingLevel,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from "docx";
import { Marked } from "marked";
import type { Tokens, TokensList } from "marked";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { renderMarkdownReport } from "./markdown.js";
import { emptyReportMeta, type ReportMeta } from "./reportMeta.js";

// Render the canonical Markdown report as a Word (.docx) document. The Markdown produced
// by `renderMarkdownReport` is the single source of truth — this file walks its tokens and
// maps each one to the equivalent docx element. DFIR text (filenames, IOC values, AI prose)
// enters as plain TextRun strings, so the docx model has no markup-injection surface.

export type DocxChild = Paragraph | Table;

const HEADING_LEVELS: Record<number, (typeof HeadingLevel)[keyof typeof HeadingLevel]> = {
  1: HeadingLevel.HEADING_1,
  2: HeadingLevel.HEADING_2,
  3: HeadingLevel.HEADING_3,
  4: HeadingLevel.HEADING_4,
  5: HeadingLevel.HEADING_5,
  6: HeadingLevel.HEADING_6,
};

const TABLE_BORDER = { style: BorderStyle.SINGLE, size: 4, color: "BFBFBF" };
const ALL_TABLE_BORDERS = {
  top: TABLE_BORDER, bottom: TABLE_BORDER, left: TABLE_BORDER, right: TABLE_BORDER,
  insideHorizontal: TABLE_BORDER, insideVertical: TABLE_BORDER,
};

// Inline tokens (strong/em/codespan/link/text) → docx run primitives. We accept the parent
// formatting context (bold/italic) so nested marks compose, e.g. **_both_**. Code spans
// carry monospace font; links emit ExternalHyperlink wrapping a styled run.
function inlineRuns(
  tokens: Tokens.Generic[],
  ctx: { bold?: boolean; italic?: boolean } = {},
): (TextRun | ExternalHyperlink)[] {
  const out: (TextRun | ExternalHyperlink)[] = [];
  for (const t of tokens) {
    switch (t.type) {
      case "text": {
        const text = (t as Tokens.Text).text;
        if ((t as Tokens.Text).tokens && (t as Tokens.Text).tokens!.length > 0) {
          out.push(...inlineRuns((t as Tokens.Text).tokens as Tokens.Generic[], ctx));
        } else {
          out.push(new TextRun({ text, bold: ctx.bold, italics: ctx.italic }));
        }
        break;
      }
      case "strong": {
        out.push(...inlineRuns((t as Tokens.Strong).tokens as Tokens.Generic[], { ...ctx, bold: true }));
        break;
      }
      case "em": {
        out.push(...inlineRuns((t as Tokens.Em).tokens as Tokens.Generic[], { ...ctx, italic: true }));
        break;
      }
      case "codespan": {
        out.push(new TextRun({
          text: (t as Tokens.Codespan).text,
          font: "Consolas",
          bold: ctx.bold, italics: ctx.italic,
          shading: { type: ShadingType.CLEAR, color: "auto", fill: "EEF1F5" },
        }));
        break;
      }
      case "link": {
        const link = t as Tokens.Link;
        out.push(new ExternalHyperlink({
          link: link.href,
          children: [new TextRun({
            text: link.text || link.href,
            style: "Hyperlink",
            bold: ctx.bold, italics: ctx.italic,
          })],
        }));
        break;
      }
      case "br": {
        out.push(new TextRun({ break: 1 }));
        break;
      }
      case "html": {
        out.push(new TextRun({ text: (t as Tokens.HTML).text, bold: ctx.bold, italics: ctx.italic }));
        break;
      }
      case "escape": {
        out.push(new TextRun({ text: (t as Tokens.Escape).text, bold: ctx.bold, italics: ctx.italic }));
        break;
      }
      default: {
        // Unknown inline token: fall back to its raw text so nothing is silently dropped.
        const raw = (t as { text?: string; raw?: string }).text ?? (t as { raw?: string }).raw ?? "";
        if (raw) out.push(new TextRun({ text: raw, bold: ctx.bold, italics: ctx.italic }));
      }
    }
  }
  return out;
}

function tableCellsFor(row: Tokens.TableCell[], header: boolean): TableCell[] {
  return row.map((c) => new TableCell({
    children: [new Paragraph({
      children: inlineRuns((c.tokens ?? []) as Tokens.Generic[], { bold: header }),
    })],
    shading: header ? { type: ShadingType.CLEAR, color: "auto", fill: "F0F3F7" } : undefined,
  }));
}

function listItemParagraphs(
  items: Tokens.ListItem[],
  ordered: boolean,
  level: number,
): Paragraph[] {
  const out: Paragraph[] = [];
  for (const item of items) {
    const para: Tokens.Generic[] = [];
    const nested: Tokens.List[] = [];
    for (const child of item.tokens) {
      if (child.type === "list") nested.push(child as Tokens.List);
      else para.push(child as Tokens.Generic);
    }
    out.push(new Paragraph({
      children: inlineRuns(para),
      numbering: ordered
        ? { reference: "ordered-list", level }
        : { reference: "bullet-list", level },
    }));
    for (const n of nested) {
      out.push(...listItemParagraphs(n.items, !!n.ordered, level + 1));
    }
  }
  return out;
}

// Map a flat token list to docx children. Returns Paragraph and Table elements in document
// order. Pure — no I/O, no async, easy to unit-test against document.xml.
export function tokensToDocxChildren(tokens: TokensList): DocxChild[] {
  const out: DocxChild[] = [];
  for (const tok of tokens) {
    switch (tok.type) {
      case "heading": {
        const h = tok as Tokens.Heading;
        out.push(new Paragraph({
          heading: HEADING_LEVELS[h.depth] ?? HeadingLevel.HEADING_6,
          children: inlineRuns(h.tokens as Tokens.Generic[]),
        }));
        break;
      }
      case "paragraph": {
        out.push(new Paragraph({
          children: inlineRuns((tok as Tokens.Paragraph).tokens as Tokens.Generic[]),
        }));
        break;
      }
      case "blockquote": {
        const bq = tok as Tokens.Blockquote;
        for (const inner of bq.tokens) {
          if (inner.type === "paragraph") {
            out.push(new Paragraph({
              children: inlineRuns((inner as Tokens.Paragraph).tokens as Tokens.Generic[], { italic: true }),
              indent: { left: 360 },
              border: { left: { style: BorderStyle.SINGLE, size: 12, color: "C7CCD4", space: 8 } },
            }));
          } else if (inner.type === "text") {
            out.push(new Paragraph({
              children: [new TextRun({ text: (inner as Tokens.Text).text, italics: true })],
              indent: { left: 360 },
              border: { left: { style: BorderStyle.SINGLE, size: 12, color: "C7CCD4", space: 8 } },
            }));
          }
        }
        break;
      }
      case "list": {
        const l = tok as Tokens.List;
        out.push(...listItemParagraphs(l.items, !!l.ordered, 0));
        break;
      }
      case "table": {
        const t = tok as Tokens.Table;
        const rows: TableRow[] = [];
        rows.push(new TableRow({ tableHeader: true, children: tableCellsFor(t.header, true) }));
        for (const r of t.rows) rows.push(new TableRow({ children: tableCellsFor(r, false) }));
        out.push(new Table({
          rows,
          width: { size: 100, type: WidthType.PERCENTAGE },
          borders: ALL_TABLE_BORDERS,
        }));
        break;
      }
      case "code": {
        out.push(new Paragraph({
          children: [new TextRun({ text: (tok as Tokens.Code).text, font: "Consolas" })],
          shading: { type: ShadingType.CLEAR, color: "auto", fill: "F4F6F8" },
        }));
        break;
      }
      case "hr": {
        // A thin bottom border on an empty paragraph — same look as the HTML export's <hr>.
        out.push(new Paragraph({
          children: [],
          border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "BFBFBF", space: 1 } },
        }));
        break;
      }
      case "space":
        // Skip — Markdown blank lines have no docx analog; paragraph spacing handles it.
        break;
      case "html": {
        // HTML in the source is escaped by the Markdown renderer's invariant (the HTML
        // export also escapes it). Treat any leaked HTML token as plain text.
        const text = (tok as { text?: string; raw?: string }).text ?? (tok as { raw?: string }).raw ?? "";
        if (text) out.push(new Paragraph({ children: [new TextRun({ text })] }));
        break;
      }
      default: {
        const raw = (tok as { raw?: string }).raw ?? "";
        if (raw) out.push(new Paragraph({ children: [new TextRun({ text: raw })] }));
      }
    }
  }
  return out;
}

// Top-level renderer. Builds the canonical Markdown, lexes it, maps tokens to docx
// elements, and packs the resulting Document to a Buffer.
export async function renderDocxReport(
  state: InvestigationState,
  meta: ReportMeta = emptyReportMeta(),
): Promise<Buffer> {
  const md = renderMarkdownReport(state, meta);
  const marked = new Marked({ gfm: true });
  const tokens = marked.lexer(md);
  const children = tokensToDocxChildren(tokens);
  const doc = new Document({
    creator: "DFIR Companion",
    title: meta.incidentId.trim() || state.caseId,
    // Numbering definitions referenced by listItemParagraphs above.
    numbering: {
      config: [
        {
          reference: "bullet-list",
          levels: [
            { level: 0, format: "bullet", text: "•", alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 360, hanging: 260 } } } },
            { level: 1, format: "bullet", text: "◦", alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 720, hanging: 260 } } } },
            { level: 2, format: "bullet", text: "▪", alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 1080, hanging: 260 } } } },
          ],
        },
        {
          reference: "ordered-list",
          levels: [
            { level: 0, format: "decimal", text: "%1.", alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 360, hanging: 260 } } } },
            { level: 1, format: "decimal", text: "%2.", alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: 720, hanging: 260 } } } },
          ],
        },
      ],
    },
    sections: [{ children }],
  });
  return Packer.toBuffer(doc);
}
