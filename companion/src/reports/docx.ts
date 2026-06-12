import {
  AlignmentType,
  BorderStyle,
  Document,
  ExternalHyperlink,
  HeadingLevel,
  ImageRun,
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
import type { CustomerExposureSummary } from "../analysis/customerExposure.js";
import { renderMarkdownReport } from "./markdown.js";
import { emptyReportMeta, type ReportMeta } from "./reportMeta.js";
import { DEFAULT_ACCENT, defaultReportTemplate, type ReportTemplate } from "./reportTemplate.js";

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

// Twips (twentieths of a point) — Word's native unit. 240 twips = 12pt, ~one blank line
// at body font size, which gives every non-major heading visible breathing room.
const HEADING_SPACING_BEFORE = 240;

// Max display dimension (in pixels) for an embedded raster like the company logo on the
// title page. Keeps a high-resolution upload from dominating the page — the analyst can
// still resize the image manually in Word after export.
const IMAGE_MAX_PX = 150;

// Parse a `data:image/<mime>[;base64],<payload>` URI into its mime and decoded bytes.
// Returns `null` if the URI is not a recognized data URI or the payload can't be decoded.
// Used to embed the company logo (a base64 data URI in report-meta.json) into the docx.
function parseDataUri(uri: string): { mime: string; buffer: Buffer } | null {
  const match = /^data:([^;,]+)(;base64)?,(.*)$/i.exec(uri);
  if (!match) return null;
  const mime = match[1].toLowerCase();
  const isBase64 = !!match[2];
  try {
    if (isBase64) {
      // Buffer.from accepts whitespace but not stray characters; validate by re-encoding
      // and matching the original payload (case-insensitively, ignoring padding).
      const cleaned = match[3].replace(/\s+/g, "");
      const buffer = Buffer.from(cleaned, "base64");
      if (buffer.length === 0) return null;
      const reencoded = buffer.toString("base64").replace(/=+$/, "");
      if (reencoded !== cleaned.replace(/=+$/, "")) return null;
      return { mime, buffer };
    }
    return { mime, buffer: Buffer.from(decodeURIComponent(match[3]), "binary") };
  } catch {
    return null;
  }
}

// Map a mime type to a docx ImageRun type tag. docx@9 supports png/jpg/gif/bmp/svg;
// WebP and other formats degrade to the image's alt text at the caller.
function mimeToDocxImageType(mime: string): "png" | "jpg" | "gif" | "bmp" | null {
  if (mime === "image/png") return "png";
  if (mime === "image/jpeg" || mime === "image/jpg") return "jpg";
  if (mime === "image/gif") return "gif";
  if (mime === "image/bmp") return "bmp";
  return null;
}

// Read the intrinsic dimensions out of a raster's header so the embedded image is sized
// proportionally instead of stretching to a default square. Returns `null` if the header
// can't be parsed — callers fall back to the alt text in that case.
function imageDimensions(buf: Buffer, mime: string): { width: number; height: number } | null {
  if (mime === "image/png" && buf.length >= 24 &&
      buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
    return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  }
  if ((mime === "image/jpeg" || mime === "image/jpg") && buf.length >= 4 &&
      buf[0] === 0xff && buf[1] === 0xd8) {
    // Walk JPEG segments looking for an SOFn marker (frame header), which carries the
    // image's height and width. Skip standalone markers (no payload) and unwanted SOFs
    // (DHT=0xC4, DAC=0xCC, RST=0xC8).
    let i = 2;
    while (i + 9 < buf.length) {
      if (buf[i] !== 0xff) { i++; continue; }
      const marker = buf[i + 1];
      if (marker === 0xd8 || marker === 0xd9 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
        i += 2;
        continue;
      }
      const segLen = buf.readUInt16BE(i + 2);
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
      }
      i += 2 + segLen;
    }
  }
  if (mime === "image/gif" && buf.length >= 10 &&
      buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) {
    return { width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) };
  }
  if (mime === "image/bmp" && buf.length >= 26 && buf[0] === 0x42 && buf[1] === 0x4d) {
    return { width: buf.readUInt32LE(18), height: Math.abs(buf.readInt32LE(22)) };
  }
  return null;
}

// Convert a Markdown image token to a docx ImageRun when the data URI is a raster format
// Word can embed natively; otherwise degrade to a TextRun carrying the alt text so the
// report still renders (the company name surrounding the logo on the title page stays
// intact even when an unsupported logo is uploaded).
function imageRunFor(
  token: Tokens.Image,
  ctx: { bold?: boolean; italic?: boolean },
): (ImageRun | TextRun)[] {
  const fallback = (): TextRun[] => [new TextRun({
    text: token.text || token.title || "",
    bold: ctx.bold, italics: ctx.italic,
  })];

  const parsed = parseDataUri(token.href);
  if (!parsed) return fallback();
  const docxType = mimeToDocxImageType(parsed.mime);
  if (!docxType) return fallback();
  const dims = imageDimensions(parsed.buffer, parsed.mime);
  if (!dims || dims.width <= 0 || dims.height <= 0) return fallback();

  // Cap the long edge at IMAGE_MAX_PX so a high-res raster doesn't blow out the page.
  const scale = Math.min(1, IMAGE_MAX_PX / Math.max(dims.width, dims.height));
  return [new ImageRun({
    data: parsed.buffer,
    transformation: {
      width: Math.max(1, Math.round(dims.width * scale)),
      height: Math.max(1, Math.round(dims.height * scale)),
    },
    type: docxType,
  })];
}

// Classify a Markdown heading by its TEXT, not just its depth, so the docx outline matches
// what an analyst expects:
//  - the report title (h1) stays Heading 1.
//  - a top-level numbered heading like "## 2 Executive summary" becomes Heading 2 and
//    starts a new page in the printed report, so majors break cleanly between sections.
//  - a numbered subsection ("## 1.1 …", "### 3.1 …") collapses to Heading 3 regardless
//    of its Markdown depth — the Word outline groups every "N.M" under its "N" parent.
//  - a deeper numbered subsection ("### 1.3.1 …") collapses to Heading 4 — every "N.M.K"
//    groups under its "N.M" parent. Check this BEFORE the two-level pattern so "1.3.1"
//    isn't matched as if it were just "1.3".
//  - unnumbered subsections (e.g. "### Recommendations", per-finding h4) keep their
//    Markdown depth.
// Pure — no I/O, easy to unit-test by inspecting `word/document.xml`.
function classifyHeading(depth: number, text: string): {
  level: (typeof HeadingLevel)[keyof typeof HeadingLevel];
  pageBreakBefore: boolean;
  spacingBefore: number;
} {
  if (depth === 1) {
    return { level: HeadingLevel.HEADING_1, pageBreakBefore: false, spacingBefore: 0 };
  }
  if (/^\d+\s/.test(text)) {
    // Page break already separates the section — extra leading space would just push the
    // heading down on the new page.
    return { level: HeadingLevel.HEADING_2, pageBreakBefore: true, spacingBefore: 0 };
  }
  if (/^\d+\.\d+\.\d+/.test(text)) {
    return { level: HeadingLevel.HEADING_4, pageBreakBefore: false, spacingBefore: HEADING_SPACING_BEFORE };
  }
  if (/^\d+\.\d+/.test(text)) {
    return { level: HeadingLevel.HEADING_3, pageBreakBefore: false, spacingBefore: HEADING_SPACING_BEFORE };
  }
  return {
    level: HEADING_LEVELS[depth] ?? HeadingLevel.HEADING_6,
    pageBreakBefore: false,
    spacingBefore: HEADING_SPACING_BEFORE,
  };
}

// Inline tokens (strong/em/codespan/link/text) → docx run primitives. We accept the parent
// formatting context (bold/italic) so nested marks compose, e.g. **_both_**. Code spans
// carry monospace font; links emit ExternalHyperlink wrapping a styled run.
function inlineRuns(
  tokens: Tokens.Generic[],
  ctx: { bold?: boolean; italic?: boolean } = {},
): (TextRun | ExternalHyperlink | ImageRun)[] {
  const out: (TextRun | ExternalHyperlink | ImageRun)[] = [];
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
      case "image": {
        out.push(...imageRunFor(t as Tokens.Image, ctx));
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
        const cls = classifyHeading(h.depth, h.text);
        out.push(new Paragraph({
          heading: cls.level,
          pageBreakBefore: cls.pageBreakBefore,
          spacing: cls.spacingBefore > 0 ? { before: cls.spacingBefore } : undefined,
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
  exposure?: CustomerExposureSummary,
  template: ReportTemplate = defaultReportTemplate(),
): Promise<Buffer> {
  const md = renderMarkdownReport(state, meta, exposure, undefined, undefined, undefined, template);
  const marked = new Marked({ gfm: true });
  const tokens = marked.lexer(md);
  const children = tokensToDocxChildren(tokens);
  // Brand the headings with the template's accent colour (a validated #rrggbb). The default
  // template keeps the historical theme colour (no override) so an un-templated .docx is unchanged.
  const accent = template.accentColor.replace(/^#/, "");
  const brandStyles =
    template.accentColor.toLowerCase() !== DEFAULT_ACCENT
      ? { default: { heading1: { run: { color: accent } }, heading2: { run: { color: accent } } } }
      : undefined;
  const doc = new Document({
    creator: "DFIR Companion",
    title: meta.incidentId.trim() || state.caseId,
    styles: brandStyles,
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
