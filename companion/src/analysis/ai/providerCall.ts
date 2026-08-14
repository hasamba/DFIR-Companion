import { mkdir, writeFile } from "node:fs/promises";
import { join as joinPath } from "node:path";

import {
  ProviderError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../providers/provider.js";
import type { Logger } from "../../logging/logger.js";
import {
  createAnonymizer,
  deriveKnownEntities,
  isMaskableIpv4,
  isInternalIp,
  type Anonymizer,
  type CustomEntity,
  type KnownEntities,
} from "../anonymize.js";
import { toAnonPolicy, type AnonControl, type AnonControlStore } from "../anonControl.js";
import type { CustomEntitiesStore } from "../anonEntities.js";
import type { DiscoveredEntitiesStore } from "../anonDiscovered.js";
import { AiCostStore, bucketForLabel } from "../aiCost.js";
import { parseJsonLoose } from "../extractJson.js";
import { ocrRedactImage, type OcrRunner } from "../ocrRedact.js";
import { safeAiErrorKind, safeAiPhase, type OperationalMetricsStore } from "../operationalMetrics.js";
import {
  mapFindings,
  PresidioApprovalRequired,
  PresidioScanError,
  PresidioTimeoutError,
  type PresidioClient,
  type PresidioFinding,
} from "../presidio.js";
import type { PresidioPendingStore } from "../presidioPending.js";
import type { InvestigationState } from "../stateTypes.js";

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

/** What the gate needs. Deliberately no state store, no providers list, no synthesis knobs. */
export interface ProviderCallContext {
  readonly log: Logger;
  readonly opts: {
    anonStore?: AnonControlStore;
    customEntitiesStore?: CustomEntitiesStore;
    discoveredStore?: DiscoveredEntitiesStore;
    ocrRunner?: OcrRunner;
    presidio?: { client: PresidioClient; url: string; minScore: number };
    presidioPendingStore?: PresidioPendingStore;
    presidioScanCapsOverride?: { chunkChars: number; maxChars: number };
    aiCostStore?: AiCostStore;
    operationalMetrics?: OperationalMetricsStore;
  };
}

// Presidio's /analyze cannot take an arbitrarily large body, and a big CSV would be many
// requests. These bound it. They are module constants rather than env vars to keep the
// settings surface small — the truncation is logged, so hitting the cap is visible.
//
// NAMED "_CHARS", NOT "_BYTES": both are compared against JS string .length, which counts
// UTF-16 code units, not UTF-8 bytes. For non-ASCII PII (Hebrew, Cyrillic, accented names —
// all plausible in a DFIR case) that undercounts real UTF-8 size by up to ~3-4x, so the
// effective request-size cap is larger than a "_BYTES" name would imply. Left as a rough
// request-size bound rather than switched to a real byte measure (e.g. Buffer.byteLength)
// because the cap only needs to keep /analyze requests reasonably sized, not hit an exact
// number — and the split/truncate arithmetic below is unit-tested against character counts.
const PRESIDIO_SCAN_CHUNK_CHARS = 50_000;
const PRESIDIO_SCAN_MAX_CHARS = 5_000_000;
// How far the next chunk rewinds when a chunk had to be cut mid-line (see splitOnLineBoundaries).
// It only has to exceed the longest value Presidio's ENTITY_MAP can produce — names, IBANs, card
// and phone numbers, national IDs are all far under 256 characters — so this buys the guarantee
// cheaply: at the 50,000-char chunk size it re-scans at most 0.5% of the text.
const PRESIDIO_SCAN_OVERLAP_CHARS = 256;

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
  try {
    const result = await provider.analyze(req);
    const usage = result.usage;
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

/** The masked-text/known-entities pair the anonymised path is built from. */
async function knownEntitiesFor(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
): Promise<KnownEntities> {
  const known = deriveKnownEntities(state);
  const custom = ctx.opts.customEntitiesStore ? await ctx.opts.customEntitiesStore.load(caseId) : [];
  // Auto-discovered screenshot entities are tokenized too; suppressed ones are never tokenized.
  const disc = ctx.opts.discoveredStore
    ? await ctx.opts.discoveredStore.load(caseId)
    : { discovered: [], suppressed: [] };
  known.custom = [...custom, ...disc.discovered];
  known.suppressed = disc.suppressed;
  return known;
}

/** Values the analyst has already vetted or vetoed, case-folded on both sides. */
function alreadyApproved(known: KnownEntities): Set<string> {
  // known.suppressed is DOCUMENTED as pre-lowercased (anonDiscovered.ts) and both writers
  // enforce it today, but that invariant is easy to violate at a distance and this is the
  // load-bearing case: a suppressed value is deliberately left UNMASKED, so Presidio sees it
  // raw on every single call. A case-fold mismatch here would re-trigger the approval gate
  // forever on a value the analyst already vetoed. Lower-case defensively rather than trust it.
  return new Set<string>([
    ...(known.custom ?? []).map((e) => e.value.toLowerCase()),
    ...(known.suppressed ?? []).map((s) => s.toLowerCase()),
  ]);
}

/**
 * Whether the per-case Presidio switch is on. A null control means the store is not wired, which
 * everywhere else in this module means "no per-case opinion" — so it leaves the configured layer
 * running rather than silently standing the gate down.
 */
function presidioEnabledFor(control: AnonControl | null): boolean {
  return control?.presidio !== false;
}

/** The one message shape for a Presidio scan that could not run — the analyst's next action. */
function presidioScanFailed(url: string, err: unknown): PresidioScanError {
  // A silent request and a refused connection need opposite advice, and getting that wrong is
  // expensive: telling someone to start a container that is already running sends them to look in
  // the one place the problem is not. Branch on the typed error, never on message wording.
  if (err instanceof PresidioTimeoutError)
    return new PresidioScanError(
      `Presidio is enabled but the scan at ${url} did not finish: ${err.message} ` +
        `(budget ${err.timeoutMs}ms). The analyzer may be busy — it serializes requests when run ` +
        `with a single worker — or the connection may be hanging without being refused. Raise ` +
        `DFIR_PRESIDIO_TIMEOUT_MS, give the analyzer more workers, check the URL and network path, ` +
        `or untick Presidio in the case's Anonymization panel to proceed without name detection.`,
      true,
    );
  return new PresidioScanError(
    `Presidio is enabled but the scan at ${url} failed (not reachable, or returned an ` +
      `unusable response): ${(err as Error).message}. Start the container or clear ` +
      `DFIR_PRESIDIO_URL to disable the layer.`,
    false,
  );
}

/** Scan already-masked text with Presidio; fail closed on a scan error or unapproved value. */
async function presidioGate(
  ctx: ProviderCallContext,
  caseId: string,
  maskedText: string,
  known: KnownEntities,
  control: AnonControl | null,
): Promise<void> {
  const presidio = ctx.opts.presidio;
  if (!presidio || !presidioEnabledFor(control)) return;

  // CHUNKED, on the same line-boundary split and the same chunk size as presidioPreScan. This used
  // to hand Presidio the whole prompt in one request, which made the unit of work as large as the
  // case: a 104k-char synthesis prompt was one indivisible request, so any timeout had to be sized
  // against however large this case happened to have grown. Chunking is what lets ONE fixed budget
  // be correct for every case, and it also bounds the damage of a timeout — an abandoned request
  // keeps running server-side (see DEFAULT_PRESIDIO_TIMEOUT_MS), so a smaller unit of work means
  // less of the single worker is left occupied by a scan nobody is waiting for any more.
  //
  // No maxChars cap here, unlike the pre-scan: capping would silently leave the tail of a prompt
  // unscanned on the way to the model, and this gate's whole contract is to fail closed.
  const chunkChars = ctx.opts.presidioScanCapsOverride?.chunkChars ?? PRESIDIO_SCAN_CHUNK_CHARS;
  const raw: PresidioFinding[] = [];
  for (const chunk of splitOnLineBoundaries(maskedText, chunkChars, PRESIDIO_SCAN_OVERLAP_CHARS)) {
    try {
      raw.push(...(await presidio.client.analyze(chunk)));
    } catch (err) {
      throw presidioScanFailed(presidio.url, err);
    }
  }

  const found = mapFindings(raw, presidio.minScore);
  if (found.length === 0) return;

  const alreadyKnown = alreadyApproved(known);
  const fresh = found.filter((e) => !alreadyKnown.has(e.value.toLowerCase()));
  if (fresh.length === 0) return;

  ctx.log.warn(`[presidio] ${fresh.length} new PII value(s) need approval before this case can call the AI`, {
    caseId,
  });
  await ctx.opts.presidioPendingStore?.save(caseId, fresh);
  throw new PresidioApprovalRequired(fresh);
}

/**
 * Cap what gets scanned, and SAY SO when the cap bites.
 *
 * A silent partial scan is worse than no scan: an analyst who sees "import scanned, no PII found"
 * must be able to trust that claim. Naming the unscanned character count is what stops a truncated
 * scan being mistaken for a complete one.
 */
function capScanLength(ctx: ProviderCallContext, caseId: string, masked: string, maxChars: number): string {
  if (masked.length <= maxChars) return masked;
  ctx.log.warn(
    `[presidio] import pre-scan truncated — ${masked.length - maxChars} character(s) of this ` +
      `import were NOT scanned for PII (cap is ${maxChars} characters)`,
    { caseId },
  );
  return masked.slice(0, maxChars);
}

/**
 * Split on line boundaries so an entity is never cut in half across two /analyze requests — a
 * half an email address on each side of a chunk edge is two values Presidio recognises as neither.
 *
 * A line boundary is not always available. A prompt can carry a single line longer than the chunk
 * size — one enormous JSON object, a base64 blob, a log line with no newline for 60k characters —
 * and there the split falls back to a hard cut at the limit, which is exactly the mid-entity slice
 * the line search exists to avoid. That is a fail-OPEN in a fail-closed gate: the halves match
 * nothing, the scan reports clean, and the intact value goes to the model anyway.
 *
 * So a hard cut REWINDS the next chunk by `overlapChars`, making the two chunks share a window
 * wide enough to contain any entity Presidio maps. A value straddling the cut is therefore whole in
 * the second chunk even though it was severed in the first. Duplicates that overlap creates cost
 * nothing: mapFindings already dedupes on category + case-folded value.
 */
function splitOnLineBoundaries(text: string, chunkChars: number, overlapChars = 0): string[] {
  // Never let the rewind consume more than a quarter of a chunk: `start` must advance, and a
  // pathological overlap >= chunkChars would rewind as far as it stepped and loop forever.
  const overlap = Math.max(0, Math.min(overlapChars, Math.floor(chunkChars / 4)));
  const chunks: string[] = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + chunkChars, text.length);
    let cutMidLine = false;
    if (end < text.length) {
      const nl = text.lastIndexOf("\n", end);
      if (nl > start) end = nl + 1;
      else cutMidLine = true;
    }
    chunks.push(text.slice(start, end));
    start = cutMidLine ? end - overlap : end;
  }
  return chunks;
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
  const presidio = ctx.opts.presidio;
  if (!presidio || !presidioEnabledFor(control)) return;

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
  if (found.length === 0) return;

  const alreadyKnown = alreadyApproved(known);
  const fresh = found.filter((e) => !alreadyKnown.has(e.value.toLowerCase()));
  if (fresh.length === 0) return;

  ctx.log.warn(`[presidio] import pre-scan found ${fresh.length} new PII value(s) needing approval`, {
    caseId,
  });
  await ctx.opts.presidioPendingStore?.save(caseId, fresh);
  throw new PresidioApprovalRequired(fresh);
}

/**
 * Build the same (known entities, anonymizer) pair analyzeRestored derives per call, so an
 * import's pre-scan sees exactly the masked text the chunk loop would later produce. Returns
 * null when anonymization is off case-wide (mirrors analyzeRestored's own early return for
 * `!policy.enabled`) — with anonymization off there is no masked text for Presidio to see.
 */
export async function buildImportAnonContext(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
): Promise<{ known: KnownEntities; anon: Anonymizer; control: AnonControl | null } | null> {
  const control = ctx.opts.anonStore ? await ctx.opts.anonStore.load(caseId) : null;
  const policy = toAnonPolicy(control);
  if (!policy.enabled) return null;
  const known = await knownEntitiesFor(ctx, caseId, state);
  // Hands back the control it already loaded so the pre-scan can read the per-case Presidio switch
  // off the SAME snapshot the anonymizer was built from, rather than re-reading it from disk and
  // risking a mid-import flip masking one batch under different rules than the scan covered.
  return { known, anon: createAnonymizer(policy, known), control };
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
  const tally: RedactionTally = { totalRedactions: 0, redactedImages: 0, publicIpsBoxed: 0 };
  // OCR-discovered entities to persist into the case's auto-discovery list after this pass.
  const discovered: CustomEntity[] = [];
  const out = await Promise.all(
    images.map((img, i) =>
      redactOneImage(ctx, caseId, img, i, images.length, { policy, known, runner, tally, discovered }),
    ),
  );
  logRedactionTally(ctx, caseId, images.length, tally);
  await persistOcrDiscoveries(ctx, caseId, discovered);
  return out;
}

/** Mutable counters accumulated across the per-image passes, reported once at the end. */
interface RedactionTally {
  totalRedactions: number;
  redactedImages: number;
  publicIpsBoxed: number;
}

interface RedactOneOptions {
  policy: ReturnType<typeof toAnonPolicy>;
  known: KnownEntities;
  runner: OcrRunner;
  tally: RedactionTally;
  discovered: CustomEntity[];
}

/**
 * OCR-redact one screenshot. OCR failure is deliberately NON-FATAL: the original image is forwarded
 * and the analysis continues, because a Tesseract crash must not block an investigation.
 *
 * Note what that means — a failure here forwards the UNREDACTED image. That is the accepted
 * trade-off for this layer (the text path's Presidio gate is the fail-closed one); the warning line
 * is what makes it visible rather than silent.
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
    ctx.log.warn(`[OCR redact] ${(err as Error).message}`, { caseId });
    return img;
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

// Apply per-case prompt/image anonymization in memory, then restore parsed JSON before schema
// validation so real values containing JSON metacharacters cannot corrupt parsing.
export async function analyzeRestored(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  req: AnalyzeRequest,
  label = "ai",
  skipPresidioGate = false,
): Promise<unknown> {
  const control = ctx.opts.anonStore ? await ctx.opts.anonStore.load(caseId) : null;
  const policy = toAnonPolicy(control);
  ctx.log.debug(
    `AI call [${label}] provider=${provider.name} images=${req.images.length} ` +
      `promptChars=${req.userPrompt.length} anonymize=${policy.enabled ? "on" : "off"}`,
    { caseId },
  );
  if (!policy.enabled) {
    const result = await analyzeProvider(ctx, provider, req, label);
    logAiUsage(ctx, caseId, label, provider, result);
    await recordAiCost(ctx, caseId, label, provider, result);
    return parseJsonLoose(result.rawText);
  }
  const known = await knownEntitiesFor(ctx, caseId, state);
  const anon = createAnonymizer(policy, known);
  ctx.log.debug(`anonymized prompt before [${label}] AI call`, { caseId });

  const images =
    ctx.opts.ocrRunner && req.images.length > 0
      ? await redactImages(ctx, caseId, req.images, policy, known, ctx.opts.ocrRunner)
      : req.images;

  // Mask FIRST, then let Presidio look at the result. It never sees a real hostname, IP,
  // username, email, SID or secret — only what our own detectors could not find.
  const maskedPrompt = anon.apply(req.userPrompt);
  // Import call sites (analyzeCsv/analyzeLog) pre-scan the WHOLE payload once, up front, and
  // pass skipPresidioGate=true so the loop that calls this per-chunk doesn't re-gate (and
  // re-approve) the same import one chunk at a time.
  if (!skipPresidioGate) await presidioGate(ctx, caseId, maskedPrompt, known, control);

  const result = await analyzeProvider(ctx, provider, { ...req, userPrompt: maskedPrompt, images }, label);
  logAiUsage(ctx, caseId, label, provider, result);
  await recordAiCost(ctx, caseId, label, provider, result);
  return anon.restoreDeep(parseJsonLoose(result.rawText));
}
