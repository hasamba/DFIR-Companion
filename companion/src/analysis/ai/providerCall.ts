import { mkdir, writeFile } from "node:fs/promises";
import { join as joinPath } from "node:path";

import {
  ProviderError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../providers/provider.js";
import {
  isMaskableIpv4,
  isInternalIp,
  type Anonymizer,
  type CustomEntity,
  type KnownEntities,
} from "../anonymize.js";
import { toAnonPolicy, type AnonControl } from "../anonControl.js";
import { bucketForLabel } from "../aiCost.js";
import { parseJsonLoose } from "../extractJson.js";
import { OcrRedactionError, ocrRedactImage, type OcrRunner } from "../ocrRedact.js";
import { safeAiErrorKind, safeAiPhase } from "../operationalMetrics.js";
import { mapFindings, PresidioApprovalRequired, type PresidioFinding } from "../presidio.js";
import { authoredFor, reportAnswer, reportGate, type AuthoredText } from "./presidioAuthoredText.js";
import type { InvestigationState } from "../stateTypes.js";
import { servedModels } from "../servedModels.js";
import { noteAiCallStarted } from "../../http/rateLimiter.js";
import { AnonymizationChangedError, anonRevision } from "../anonRevision.js";
import { captureIfSafetyStop } from "./safetyStopCapture.js";
import type { ProviderCallContext } from "./providerCallContext.js";
import { maskRequest } from "./maskRequest.js";
import {
  alreadyApproved,
  capScanLength,
  presidioEnabledFor,
  presidioHeldValues,
  presidioScanFailed,
  PRESIDIO_SCAN_CHUNK_CHARS,
  PRESIDIO_SCAN_MAX_CHARS,
  PRESIDIO_SCAN_OVERLAP_CHARS,
  splitOnLineBoundaries,
} from "./presidioScan.js";
import { activeAiPreview } from "./aiPreviewScope.js";
import { previewCall } from "./aiPreviewCall.js";

export type { ProviderCallContext } from "./providerCallContext.js";

/**
 * The AI-call gate (#418).
 *
 * Every model call in the companion goes through `analyzeRestored`, and this module is why that
 * matters: it is not a wrapper around `provider.analyze` but a fixed chain — derive the case's known
 * entities, mask the prompt, OCR-redact the images, hand the already-masked text to Presidio for
 * approval, call the provider, record the cost and usage, and restore the real values into the
 * parsed response before any schema sees it.
 *
 * Extracted as ONE unit rather than split across the callers, because the ordering IS the contract.
 * Presidio must see masked text and only masked text; the response must be restored before parsing
 * so a real value containing JSON metacharacters cannot corrupt it; a cost-recording failure must
 * never fail the call it was accounting for. Those are the kind of invariants that survive being
 * written down in one place and quietly rot when each call site re-implements them.
 */

// Write a redacted screenshot copy to DFIR_OCR_DEBUG_DIR for visual inspection. The redacted
// buffer keeps the source image format (sharp infers it from the input), so the extension is
// derived from the source mime type. Best-effort: a dump failure must never break analysis, and
// caseId is sanitized so it can't escape the debug dir. This never touches the evidence files.
async function dumpRedactedImage(
  dir: string,
  caseId: string,
  index: number,
  mimeType: string,
  buffer: Buffer,
): Promise<void> {
  try {
    const ext = (mimeType.split("/")[1] ?? "png").replace(/[^a-z0-9]/gi, "") || "png";
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const safeCase = caseId.replace(/[^a-z0-9_-]/gi, "_");
    const outDir = joinPath(dir, safeCase);
    await mkdir(outDir, { recursive: true });
    await writeFile(joinPath(outDir, `${stamp}-img${index + 1}.${ext}`), buffer);
  } catch (err) {
    console.warn(`[OCR dump] ${(err as Error).message}`);
  }
}

/** The provider call itself, wrapped in the operational-metrics record for both outcomes. */
async function analyzeProvider(
  ctx: ProviderCallContext,
  provider: AIProvider,
  req: AnalyzeRequest,
  label: string,
): Promise<AnalyzeResult> {
  const startedAt = Date.now();
  noteAiCallStarted(); // the request that caused this call keeps its AI-budget slot (#1825)
  try {
    const result = await provider.analyze(req);
    const usage = result.usage;
    // #1601: which concrete model served this call — for the job row and the run manifest.
    servedModels.record({
      provider: provider.name,
      alias: provider.model,
      resolvedModel: usage?.resolvedModel,
      ...(req.signal ? { signal: req.signal } : {}),
    });
    void ctx.opts.operationalMetrics?.record({
      type: "ai",
      phase: safeAiPhase(label),
      durationMs: Date.now() - startedAt,
      success: true,
      inputTokens: usage?.inputTokens ?? 0,
      outputTokens: usage?.outputTokens ?? 0,
      costUsd: usage?.costUSD ?? 0,
      errorKind: "none",
    });
    return result;
  } catch (error) {
    void ctx.opts.operationalMetrics?.record({
      type: "ai",
      phase: safeAiPhase(label),
      durationMs: Date.now() - startedAt,
      success: false,
      inputTokens: 0,
      outputTokens: 0,
      costUsd: 0,
      errorKind: safeAiErrorKind(error instanceof ProviderError ? error.kind : "other"),
    });
    throw error;
  }
}

// Accumulate this call's tokens/cost into the case's running AI-cost totals (Settings →
// Diagnostics). Best-effort: a write failure here must never fail the underlying AI call.
async function recordAiCost(
  ctx: ProviderCallContext,
  caseId: string,
  label: string,
  provider: AIProvider,
  result: AnalyzeResult,
): Promise<void> {
  if (!ctx.opts.aiCostStore) return;
  try {
    await ctx.opts.aiCostStore.record(
      caseId,
      bucketForLabel(label),
      provider.name,
      provider.model,
      result.usage,
    );
  } catch (err) {
    ctx.log.warn(`[ai-cost] could not record: ${(err as Error).message}`, { caseId });
  }
}

// Log token usage at DEBUG after a provider call (surfaced with DFIR_LOG_LEVEL=debug).
function logAiUsage(
  ctx: ProviderCallContext,
  caseId: string,
  label: string,
  provider: AIProvider,
  result: AnalyzeResult,
): void {
  const u = result.usage;
  if (!u) {
    ctx.log.debug(`AI call [${label}] done provider=${provider.name} (no usage reported)`, { caseId });
    return;
  }
  const cache =
    (u.cacheReadTokens ? ` cacheRead=${u.cacheReadTokens}` : "") +
    (u.cacheCreationTokens ? ` cacheWrite=${u.cacheCreationTokens}` : "");
  // resolvedModel: the concrete model id actually served, when the provider reports one — e.g.
  // claude-code's --model alias ("sonnet") resolves to "claude-sonnet-4-6" server-side; surfacing
  // it here means DFIR_AI_SYNTH_MODEL=sonnet doesn't leave the exact version silently ambiguous.
  const resolved =
    u.resolvedModel && u.resolvedModel !== provider.model ? ` resolvedModel=${u.resolvedModel}` : "";
  ctx.log.debug(
    `AI call [${label}] done provider=${provider.name} model=${provider.model}${resolved} in=${u.inputTokens ?? "?"} out=${u.outputTokens ?? "?"}${cache}`,
    { caseId },
  );
}

/** Scan already-masked text with Presidio; fail closed on a scan error or unapproved value. */
export async function presidioGate(
  ctx: ProviderCallContext,
  caseId: string,
  maskedText: string,
  known: KnownEntities,
  control: AnonControl | null,
  authored?: AuthoredText,
): Promise<void> {
  const fresh = await presidioHeldValues(ctx, caseId, maskedText, known, control, authored);
  if (fresh.length === 0) return;
  ctx.log.warn(`[presidio] ${fresh.length} new PII value(s) need approval before this case can call the AI`, {
    caseId,
  });
  await ctx.opts.presidioPendingStore?.save(caseId, fresh);
  throw new PresidioApprovalRequired(fresh);
}

/** Scan one complete masked import up front so batched CSV/log analysis needs one approval round. */
export async function presidioPreScan(
  ctx: ProviderCallContext,
  caseId: string,
  text: string,
  known: KnownEntities,
  anon: Anonymizer,
  control: AnonControl | null,
): Promise<void> {
  const fresh = await presidioPreScanHeld(ctx, caseId, text, known, anon, control);
  if (fresh.length === 0) return;
  ctx.log.warn(`[presidio] import pre-scan found ${fresh.length} new PII value(s) needing approval`, {
    caseId,
  });
  await ctx.opts.presidioPendingStore?.save(caseId, fresh);
  throw new PresidioApprovalRequired(fresh);
}

/**
 * The import pre-scan's question without its side effects: the values it WOULD hold. Saves nothing;
 * throws only the scan-failure error. `presidioPreScan` and the AI preview (#2515) both ask it.
 */
export async function presidioPreScanHeld(
  ctx: ProviderCallContext,
  caseId: string,
  text: string,
  known: KnownEntities,
  anon: Anonymizer,
  control: AnonControl | null,
): Promise<CustomEntity[]> {
  const presidio = ctx.opts.presidio;
  if (!presidio || !presidioEnabledFor(control)) return [];

  // TEST-ONLY seam (see PipelineOptions.presidioScanCapsOverride) so a test can force the
  // truncation path with a tiny budget instead of generating megabytes of synthetic text.
  // Production never sets this; the caps default to the real module constants.
  const chunkChars = ctx.opts.presidioScanCapsOverride?.chunkChars ?? PRESIDIO_SCAN_CHUNK_CHARS;
  const maxChars = ctx.opts.presidioScanCapsOverride?.maxChars ?? PRESIDIO_SCAN_MAX_CHARS;

  // Mask FIRST, same as analyzeRestored — Presidio only ever sees already-scrubbed text.
  const scanned = capScanLength(ctx, caseId, anon.apply(text), maxChars);

  const all: PresidioFinding[] = [];
  for (const chunk of splitOnLineBoundaries(scanned, chunkChars, PRESIDIO_SCAN_OVERLAP_CHARS)) {
    try {
      all.push(...(await presidio.client.analyze(chunk)));
    } catch (err) {
      throw presidioScanFailed(presidio.url, err);
    }
  }

  const found = mapFindings(all, presidio.minScore);
  const alreadyKnown = alreadyApproved(known);
  return found.filter((e) => !alreadyKnown.has(e.value.toLowerCase()));
}

/** OCR-redact the image buffers when an external-provider runner is configured. */
async function redactImages(
  ctx: ProviderCallContext,
  caseId: string,
  images: AnalyzeRequest["images"],
  policy: ReturnType<typeof toAnonPolicy>,
  known: KnownEntities,
  runner: OcrRunner,
): Promise<AnalyzeRequest["images"]> {
  const tally: RedactionTally = { totalRedactions: 0, redactedImages: 0, publicIpsBoxed: 0, failures: [] };
  // OCR-discovered entities to persist into the case's auto-discovery list after this pass.
  const discovered: CustomEntity[] = [];
  const out = await Promise.all(
    images.map((img, i) =>
      redactOneImage(ctx, caseId, img, i, images.length, { policy, known, runner, tally, discovered }),
    ),
  );
  await persistOcrDiscoveries(ctx, caseId, discovered);
  // Fail closed (#1952): one unreadable screenshot stops the whole call, so no image leaves raw.
  if (tally.failures.length > 0) {
    ctx.log.warn(
      `[OCR] ${tally.failures.length} of ${images.length} screenshot(s) could not be read by OCR — ` +
        `nothing was sent to the model`,
      { caseId },
    );
    throw new OcrRedactionError(tally.failures.length, tally.failures[0]);
  }
  logRedactionTally(ctx, caseId, images.length, tally);
  return out;
}

/** Mutable counters accumulated across the per-image passes, reported once at the end. */
interface RedactionTally {
  totalRedactions: number;
  redactedImages: number;
  publicIpsBoxed: number;
  /** One message per screenshot OCR could not read. Any entry stops the call. */
  failures: string[];
}

interface RedactOneOptions {
  policy: ReturnType<typeof toAnonPolicy>;
  known: KnownEntities;
  runner: OcrRunner;
  tally: RedactionTally;
  discovered: CustomEntity[];
}

/**
 * OCR-redact one screenshot. An OCR failure is recorded in the tally, and `redactImages` then
 * fails the whole call closed (#1952): forwarding the original would send an UNREDACTED image while
 * the case says anonymisation is on. The capture stays on disk; only its AI read stops. The
 * analyst's exits are a local vision model or anonymisation off for the case.
 */
async function redactOneImage(
  ctx: ProviderCallContext,
  caseId: string,
  img: NonNullable<AnalyzeRequest["images"]>[number],
  index: number,
  count: number,
  o: RedactOneOptions,
): Promise<NonNullable<AnalyzeRequest["images"]>[number]> {
  // DFIR_OCR_DEBUG forces the per-image detail to INFO (always shown); otherwise it is a DEBUG
  // line, surfaced when DFIR_LOG_LEVEL=debug or the dashboard's Logging toggle is on.
  const forceInfo = !!process.env.DFIR_OCR_DEBUG;
  try {
    const res = await ocrRedactImage(Buffer.from(img.base64, "base64"), o.policy, o.known, o.runner);
    if (res.discovered.length) o.discovered.push(...res.discovered);
    if (res.changed) {
      o.tally.redactedImages++;
      o.tally.totalRedactions += res.redactions.length;
      o.tally.publicIpsBoxed += res.redactions.filter(
        (w) => isMaskableIpv4(w.text.trim()) && !isInternalIp(w.text.trim()),
      ).length;
      const dumpDir = process.env.DFIR_OCR_DEBUG_DIR; // write the redacted copy for inspection
      if (dumpDir) await dumpRedactedImage(dumpDir, caseId, index, img.mimeType, res.buffer);
    }
    const matched = res.redactions.map((w) => w.text).join(", ");
    const line =
      `[OCR] image ${index + 1}/${count}: read ${res.wordCount} word(s), ` +
      `redacted ${res.redactions.length}${matched ? ` [${matched}]` : ""}`;
    if (forceInfo) ctx.log.info(line, { caseId });
    else ctx.log.debug(line, { caseId });
    return res.changed ? { ...img, base64: res.buffer.toString("base64") } : img;
  } catch (err) {
    const message = (err as Error).message;
    ctx.log.warn(`[OCR redact] image ${index + 1}/${count}: ${message}`, { caseId });
    o.tally.failures.push(message);
    return img; // never sent: redactImages throws once every image has settled
  }
}

/**
 * Always-on confirmation that the OCR pre-pass ran — as opposed to images going to the model
 * unredacted because anon is off or the provider is local. One line per analyze call.
 */
function logRedactionTally(
  ctx: ProviderCallContext,
  caseId: string,
  count: number,
  tally: RedactionTally,
): void {
  ctx.log.info(
    `[OCR] redaction ran on ${count} screenshot(s) — scrubbed ` +
      `${tally.totalRedactions} word(s) across ${tally.redactedImages} image(s) before sending to the model`,
    { caseId },
  );
  if (tally.publicIpsBoxed > 0) {
    ctx.log.warn(
      `[OCR] ${tally.publicIpsBoxed} public IP(s) were blacked out of the screenshot(s). Image ` +
        `redaction is one-way, so these will NOT be extracted as IOCs from this capture.`,
      { caseId },
    );
  }
}

/**
 * Feed what OCR tokenized back into the case's auto-discovery list (dedupe/suppress handled by the
 * store). Best-effort — a write failure must not fail the analysis.
 */
async function persistOcrDiscoveries(
  ctx: ProviderCallContext,
  caseId: string,
  discovered: CustomEntity[],
): Promise<void> {
  if (!ctx.opts.discoveredStore || discovered.length === 0) return;
  try {
    const added = await ctx.opts.discoveredStore.addDiscovered(caseId, discovered);
    ctx.log.debug(`[OCR] auto-discovery now holds ${added.discovered.length} entit(y/ies)`, { caseId });
  } catch (err) {
    ctx.log.warn(`[OCR] could not persist discovered entities: ${(err as Error).message}`, { caseId });
  }
}

/** A request ready to send, and the anonymizer (null when masking is off) that restores its answer. */
interface PreparedCall {
  readonly req: AnalyzeRequest;
  readonly anon: Anonymizer | null;
}

// How many times a call masks again because the anonymization changed under it (#1840) before it
// holds instead. Three changes inside one call's preparation is an analyst mid-edit or a loop; the
// fail-closed answer is to send nothing.
const MAX_ANON_ATTEMPTS = 3;

/**
 * Presidio coverage an import pre-scan already gave this call (#1840): `true` for a caller that
 * never re-checks, or the anonymization revision the pre-scan masked with. A revision only skips
 * the gate while it is still current — an entity change after the pre-scan can expose text the
 * scan never saw, so the call is then gated itself.
 */
export type PresidioCoverage = boolean | number;

function presidioCovered(skip: PresidioCoverage, revision: number): boolean {
  return typeof skip === "number" ? skip === revision : skip;
}

/** Everything before the send: control, entities, anonymizer, OCR, mask, Presidio gate. */
async function prepareCall(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  req: AnalyzeRequest,
  label: string,
  skipPresidioGate: boolean,
): Promise<PreparedCall> {
  // The text the provider receives comes from maskRequest — the one function the AI preview also
  // uses (#2491), so the preview can never show a safer prompt than this send.
  const m = await maskRequest(ctx, caseId, state, req);
  ctx.log.debug(
    `AI call [${label}] provider=${provider.name} images=${req.images.length} promptChars=${m.plainPrompt.length} ` +
      `anonymize=${m.policy.enabled ? "on" : "off"}`,
    { caseId },
  );
  if (!m.anon || !m.known) {
    reportGate(false); // the model sees clear text: its answer may not be recorded as AI text
    return { req: { ...req, userPrompt: m.plainPrompt }, anon: null };
  }
  ctx.log.debug(`anonymized prompt before [${label}] AI call`, { caseId });

  const images =
    ctx.opts.ocrRunner && req.images.length > 0
      ? await redactImages(ctx, caseId, req.images, m.policy, m.known, ctx.opts.ocrRunner)
      : req.images;

  // Import call sites (analyzeCsv/analyzeLog) pre-scan the WHOLE payload once, up front, and
  // pass their coverage so the loop that calls this per-chunk doesn't re-gate (and re-approve)
  // the same import one chunk at a time.
  if (!skipPresidioGate)
    await presidioGate(
      ctx,
      caseId,
      m.maskedPrompt,
      m.known,
      m.control,
      await authoredFor(ctx.opts.aiAuthoredStore, ctx.log, caseId, { spans: m.spans }),
    );
  // Protected only when the gate ran on THIS call: an import pre-scan's coverage is not a synthesis.
  reportGate(!skipPresidioGate && Boolean(ctx.opts.presidio) && presidioEnabledFor(m.control));
  return { req: { ...req, userPrompt: m.maskedPrompt, images }, anon: m.anon };
}

// Apply per-case prompt/image anonymization in memory, then restore parsed JSON before schema
// validation so real values containing JSON metacharacters cannot corrupt parsing.
//
// #1840: preparing a call takes time (OCR, a Presidio scan over the network), and a "Hide from AI"
// can land inside it. The call reads the case's anonymization revision BEFORE it loads anything and
// compares it right before the send — synchronously, with no await between the check and the
// provider call. A change masks the request again from fresh lists (and re-runs the Presidio gate);
// after MAX_ANON_ATTEMPTS changes the call holds and sends nothing. See anonRevision.ts.
export async function analyzeRestored(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  req: AnalyzeRequest,
  label = "ai",
  skipPresidioGate: PresidioCoverage = false,
): Promise<unknown> {
  // "Preview what the AI will see" (#2491): build the as-sent request through the same masking
  // function, record it, and stop — nothing is sent. Every real call is outside that scope.
  if (activeAiPreview())
    return previewCall(ctx, caseId, state, provider, req, label, (revision) =>
      presidioCovered(skipPresidioGate, revision),
    );
  for (let attempt = 1; attempt <= MAX_ANON_ATTEMPTS; attempt++) {
    const revision = anonRevision(caseId);
    const prepared = await prepareCall(
      ctx,
      caseId,
      state,
      provider,
      req,
      label,
      presidioCovered(skipPresidioGate, revision),
    );
    if (anonRevision(caseId) === revision) return sendPrepared(ctx, caseId, provider, prepared, label);
    ctx.log.warn(
      `[anon] anonymization changed while [${label}] was being prepared — masking again before sending`,
      { caseId },
    );
  }
  throw new AnonymizationChangedError(
    `The anonymization settings or hidden values kept changing while this AI call was being ` +
      `prepared, so nothing was sent. Run it again.`,
  );
}

/** The send and its bookkeeping. Starts the provider call before its first await. */
async function sendPrepared(
  ctx: ProviderCallContext,
  caseId: string,
  provider: AIProvider,
  prepared: PreparedCall,
  label: string,
): Promise<unknown> {
  let result: AnalyzeResult;
  try {
    result = await analyzeProvider(ctx, provider, prepared.req, label);
  } catch (err) {
    // #2083: opt-in, best-effort save of the exact (as-sent) prompt a safety filter refused.
    const sent = { req: prepared.req, anonymized: prepared.anon !== null };
    await captureIfSafetyStop(ctx.opts.safetyStopCapture, ctx.log, caseId, provider, sent, label, err);
    throw err;
  }
  logAiUsage(ctx, caseId, label, provider, result);
  await recordAiCost(ctx, caseId, label, provider, result);
  const anon = prepared.anon;
  if (!anon) return parseAnswer(result.rawText, (t) => t);
  const masked = parseAnswer(result.rawText, (t) => anon.restore(t));
  reportAnswer(masked); // the model's own words, placeholders kept (presidioAuthoredText.ts)
  return anon.restoreDeep(masked);
}

/**
 * A model answer that is not parseable JSON (#1602). Carries the raw text — restored to real values
 * when anonymization is on, the same as a parsed answer — so a caller can keep it for the analyst.
 * The message is the parser's own, so every existing log line and error reads as before.
 */
export class AiAnswerParseError extends Error {
  constructor(
    readonly rawText: string,
    cause: unknown,
  ) {
    super(cause instanceof Error ? cause.message : String(cause), { cause });
    this.name = "AiAnswerParseError";
  }
}

// Wraps ONLY the JSON parse, so a provider, Presidio or accounting error is never mistaken for a bad answer.
function parseAnswer(rawText: string, restore: (text: string) => string): unknown {
  try {
    return parseJsonLoose(rawText);
  } catch (err) {
    throw new AiAnswerParseError(restore(rawText), err);
  }
}
