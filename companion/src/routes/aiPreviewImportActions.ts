import { noteAiPreview } from "../analysis/ai/aiPreviewScope.js";
import { parseCsv } from "../analysis/csvImport.js";
import { parseLogLines } from "../analysis/logImport.js";
import type { CaptureMetadata } from "../types.js";
import { storedImportName } from "./importCommit.js";
import type { RouteAiPreviewAction } from "./aiPreviewRouteAction.js";
import type { RouteContext } from "./context.js";

/**
 * "Preview what the AI will see" for the import-time AI reads (#2515): the CSV, log and screenshot
 * extraction. The file is not in the case yet, so the analyst chooses it in the preview dialog and it
 * travels in the request body.
 *
 * Each runs the REAL extraction (`analyzeCsv` / `analyzeLog` / `analyzeWindow`) and stops it at the
 * AI-call gate. What the import ROUTE does around it is not run: no evidence is stored, no import
 * record or audit line is written, no job starts — and the read-only scope refuses any write. The CSV
 * and log source label is the stored name the file would get if imported now (peeked, not reserved).
 */
type Pipeline = NonNullable<RouteContext["options"]["pipeline"]>;

const IMAGE_TYPES: ReadonlySet<string> = new Set(["image/png", "image/jpeg", "image/webp"]);
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
const fileText = (v: unknown): string => (typeof v === "string" ? v : "");

const MULTI_BATCH =
  "A large file is read in several batches, one request each. This is the first batch; the later ones " +
  "carry the next rows and the case as it stands after the earlier batches, so they are not previewed.";
const NOT_IMPORTED = "Nothing was imported or saved — the file exists only in this preview.";

/** The name the file would be stored under if it were imported now, reserving nothing. */
async function sourceLabel(ctx: RouteContext, caseId: string, name: string, fallback: string) {
  const seq = await ctx.store.peekNextImportSeq(caseId);
  return { seq, label: storedImportName(seq, name, fallback) };
}

function textImport(
  kind: "csv" | "log",
  label: string,
  check: (text: string) => string | null,
  run: (
    p: Pipeline,
    caseId: string,
    text: string,
    opts: { label: string; idPrefix: string; importedAt: string },
  ) => Promise<unknown>,
): RouteAiPreviewAction {
  const fallback = `import.${kind}`;
  return {
    label,
    multiRequest: MULTI_BATCH,
    needs: "ai",
    prepare: async (ctx, caseId, params) => {
      const text = fileText(params.text);
      if (!text.trim()) return `choose a ${kind === "csv" ? "CSV" : "log"} file first`;
      const refused = check(text);
      if (refused) return refused;
      const name = str(params.fileName) || fallback;
      return async () => {
        const { seq, label: source } = await sourceLabel(ctx, caseId, name, fallback);
        noteAiPreview(
          `The source label "${source}" is the name the file would be stored under if you imported it now.`,
        );
        noteAiPreview(
          kind === "csv"
            ? "This is the AI CSV read. The main Import button sends a file here only when no built-in importer recognises its format."
            : "This is the AI log read. The main Import button sends a file here only when no built-in importer recognises its format.",
        );
        noteAiPreview(NOT_IMPORTED);
        return run(ctx.options.pipeline!, caseId, text, {
          label: source,
          idPrefix: `${kind === "csv" ? "m" : "l"}${seq}`,
          importedAt: new Date().toISOString(),
        });
      };
    },
  };
}

/** The chosen image as the vision model receives it, or a sentence saying what is wrong with it. */
function chosenImage(params: Record<string, unknown>): { base64: string; mimeType: string } | string {
  const raw = str(params.imageBase64).replace(/^data:[^,]*,/, "");
  const mimeType = str(params.mimeType).toLowerCase();
  if (!raw) return "choose a screenshot first";
  if (!IMAGE_TYPES.has(mimeType)) return "the screenshot must be a PNG, JPEG or WebP image";
  if (!BASE64.test(raw)) return "the screenshot could not be read";
  return { base64: raw, mimeType };
}

const screenshot: RouteAiPreviewAction = {
  label: "Screenshot read (AI extraction, one image)",
  needs: "ai",
  prepare: async (ctx, caseId, params) => {
    if (!ctx.options.pipeline?.hasAiProvider())
      return "the screenshot (vision) model is not configured — screenshots are not read by the AI";
    const image = chosenImage(params);
    if (typeof image === "string") return image;
    const capture: CaptureMetadata = {
      caseId,
      sequenceNumber: 0,
      timestamp: new Date().toISOString(),
      url: str(params.url),
      tabTitle: str(params.tabTitle),
      triggerType: "manual",
      contentHash: "",
      isDuplicate: false,
      screenshotFile: str(params.fileName) || "screenshot",
    };
    return async () => {
      noteAiPreview(
        "Single-image preview: a real capture window can hold several screenshots, all sent in one request. " +
          "The screenshot name, tab title and address are the ones entered here; a real capture uses its stored " +
          "file name and the captured tab.",
      );
      noteAiPreview(NOT_IMPORTED);
      return ctx.options.pipeline!.analyzeWindow(caseId, [capture], async () => image);
    };
  },
};

export const IMPORT_PREVIEW_ACTIONS: Readonly<Record<string, RouteAiPreviewAction>> = {
  "extract-csv": textImport(
    "csv",
    "CSV read (AI extraction of a file you choose)",
    (text) => (parseCsv(text).rows.length ? null : "the CSV has no data rows"),
    (p, caseId, text, opts) => p.analyzeCsv(caseId, text, opts),
  ),
  "extract-log": textImport(
    "log",
    "Log read (AI extraction of a file you choose)",
    (text) => (parseLogLines(text).lines.length ? null : "the log file has no non-empty lines"),
    (p, caseId, text, opts) => p.analyzeLog(caseId, text, opts),
  ),
  "extract-screenshot": screenshot,
};
