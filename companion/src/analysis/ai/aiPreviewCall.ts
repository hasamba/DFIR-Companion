import type { AIProvider, AnalyzeRequest } from "../../providers/provider.js";
import { PresidioScanError } from "../presidio.js";
import { AnonymizationChangedError, anonRevision } from "../anonRevision.js";
import type { InvestigationState } from "../stateTypes.js";
import { maskRequest, type MaskedRequest } from "./maskRequest.js";
import { authoredFor } from "./presidioAuthoredText.js";
import { presidioEnabledFor, presidioHeldValues } from "./presidioScan.js";
import type { ProviderCallContext } from "./providerCallContext.js";
import {
  activeAiPreview,
  AiPreviewCaptured,
  type AiPreviewCapture,
  type AiPreviewPresidio,
} from "./aiPreviewScope.js";

/**
 * The AI-call gate's preview branch (#2491). `analyzeRestored` calls this instead of preparing and
 * sending when an AI preview is active (aiPreviewScope.ts).
 *
 * It builds the request through `maskRequest` — the function the real send uses — and asks the
 * Presidio question through `presidioHeldValues` — the function the real gate uses. What it leaves
 * out are the real path's side effects: no OCR (which persists what it reads), no pending approvals
 * saved, no gate-probe report, no provider call, no cost, no metrics. It always ends by throwing
 * AiPreviewCaptured, so the action stops here.
 */

// The live path's rule (#1840, providerCall.ts): a change to the anonymization while the request is
// being prepared masks it again from fresh lists, and after this many changes nothing is sent.
const MAX_ANON_ATTEMPTS = 3;

export async function previewCall(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  req: AnalyzeRequest,
  label: string,
  presidioCovered: (revision: number) => boolean,
): Promise<never> {
  const preview = activeAiPreview();
  if (!preview) throw new Error("previewCall outside an AI preview");
  preview.calls++;
  if (!preview.capture && preview.failure === undefined) {
    try {
      preview.capture = await captureOnce(ctx, caseId, state, provider, req, label, presidioCovered);
    } catch (err) {
      preview.failure = err;
    }
  }
  throw new AiPreviewCaptured();
}

async function captureOnce(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  req: AnalyzeRequest,
  label: string,
  presidioCovered: (revision: number) => boolean,
): Promise<AiPreviewCapture> {
  for (let attempt = 1; attempt <= MAX_ANON_ATTEMPTS; attempt++) {
    const revision = anonRevision(caseId);
    const masked = await maskRequest(ctx, caseId, state, req);
    const presidio = await presidioPreview(ctx, caseId, masked, presidioCovered(revision));
    if (anonRevision(caseId) !== revision) continue;
    return {
      kind: label,
      provider: provider.name,
      model: provider.model,
      systemPrompt: req.systemPrompt,
      clearPrompt: masked.plainPrompt,
      maskedPrompt: masked.maskedPrompt,
      anonymized: masked.anon !== null,
      images: req.images.map((img, index) => ({
        index,
        mimeType: img.mimeType,
        handling: masked.anon && ctx.opts.ocrRunner ? "ocr-required" : "sent-as-is",
      })),
      presidio,
    };
  }
  throw new AnonymizationChangedError(
    `The anonymization settings or hidden values kept changing while the preview was being built. ` +
      `Run the preview again.`,
  );
}

/** What the real gate would do with this masked prompt — without saving or holding anything. */
async function presidioPreview(
  ctx: ProviderCallContext,
  caseId: string,
  m: MaskedRequest,
  covered: boolean,
): Promise<AiPreviewPresidio> {
  // The real gate only ever runs on masked text: with anonymization off it does not run at all.
  if (!m.known || !ctx.opts.presidio || !presidioEnabledFor(m.control)) return { state: "off", held: [] };
  if (covered) return { state: "not-gated", held: [] };
  try {
    const authored = await authoredFor(ctx.opts.aiAuthoredStore, ctx.log, caseId, { spans: m.spans });
    const held = await presidioHeldValues(ctx, caseId, m.maskedPrompt, m.known, m.control, authored);
    return held.length
      ? { state: "would-hold", held: held.map((e) => ({ category: e.category, value: e.value })) }
      : { state: "clear", held: [] };
  } catch (err) {
    if (err instanceof PresidioScanError) return { state: "scan-failed", held: [], message: err.message };
    throw err;
  }
}
