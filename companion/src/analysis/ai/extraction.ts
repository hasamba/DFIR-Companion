import type { AIProvider, AnalyzeImage } from "../../providers/provider.js";
import type { CaptureMetadata } from "../../types.js";
import { chunkToCsvText, parseCsv } from "../csvImport.js";
import { lastImportEventSequence } from "../importResume.js";
import { aggregateLogLines, type AggregateStats } from "../logAggregate.js";
import { parseLogLines } from "../logImport.js";
import { batchByBudget, estimateTokens, inputTokenBudget } from "../promptBudget.js";
import { deltaSchema, stripAiExtractedFrom } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { mergeDelta, type WindowContext } from "../stateMerge.js";
import type { InvestigationState, Severity } from "../stateTypes.js";
import { tagNaiveAsUtc } from "../naiveTimestamp.js";
import { buildStateSummary } from "../summary.js";
import { detectTool } from "../toolDetect.js";
import { getCsvPrompt, getLogPrompt, getSystemPrompt } from "./prompts/index.js";
import { type AiCallContext } from "./aiContext.js";
import { buildImportAnonContext, presidioPreScan, type ProviderCallContext } from "./providerCall.js";

/**
 * The three AI EXTRACTION calls (#418): screenshots, CSV rows, log lines → forensic events.
 *
 * Moved from AnalysisPipeline (see ai/caseReports.ts for the pattern). These are the other half of
 * ingest: `analysis/ingest/` holds the ~36 DETERMINISTIC importers, which parse a known format and
 * need no model at all. These three are what is left when the format is not known in advance — a
 * screenshot of someone else's console, an arbitrary CSV export, a log nobody wrote a parser for.
 * They produce the SAME delta the deterministic importers do, and like them they produce only
 * events and IOCs: findings, techniques and the attacker path come afterwards from synthesize().
 *
 * All three hold the state lock across their whole batch loop, and all three pre-scan the entire
 * payload for Presidio once up front rather than per batch — one approval round trip per import.
 */

/** What an extraction call needs: the AI-call seam, the gate's own context, and the merge path. */
export interface ExtractionContext extends AiCallContext, ProviderCallContext {
  readonly opts: AiCallContext["opts"] &
    ProviderCallContext["opts"] & {
      provider?: AIProvider;
      imageLoader: (caseId: string, screenshotFile: string) => Promise<AnalyzeImage>;
      onState?: (state: InvestigationState) => void;
    };
  /** Serialise the load→merge→save critical section per case. Never nest for the same caseId. */
  withStateLock<T>(caseId: string, fn: () => Promise<T>): Promise<T>;
  /** mergeDelta plus the case's analyst IOC-merge aliases (#82). */
  mergeWithAliases(
    state: InvestigationState,
    delta: Parameters<typeof mergeDelta>[1],
    ctx: WindowContext,
  ): Promise<InvestigationState>;
  /** Side channel for analyzeLog's distinct-template cap; null clears a previous run's warning. */
  recordImportTruncation(caseId: string, stats: AggregateStats | null): void;
}

/** Options common to the two file-import extractions; each adds its own batch-size knob. */
interface ImportExtractionOptions {
  label: string; // evidence label shown as the event source (stored filename)
  idPrefix: string; // unique per import (e.g. "m3") so event ids never collide
  importedAt: string; // ISO time used for timeline/firstSeen context
  minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
  onProgress?: (done: number, total: number) => void | Promise<void>;
  signal?: AbortSignal; // #225: analyst cancel — aborts the in-flight AI call + stops between batches
  startBatch?: number;
}

export async function analyzeWindow(
  ctx: ExtractionContext,
  caseId: string,
  captures: CaptureMetadata[],
): Promise<InvestigationState> {
  const provider = ctx.requireProvider("screenshot analysis");
  const analyzable = captures.filter((c) => !c.isDuplicate);
  if (analyzable.length === 0) return ctx.opts.stateStore.load(caseId);

  return ctx.withStateLock(caseId, async () => {
    const state = await ctx.opts.stateStore.load(caseId);
    const images = await Promise.all(analyzable.map((c) => ctx.opts.imageLoader(caseId, c.screenshotFile)));
    const userPrompt = buildScreenshotPrompt(state, analyzable);

    const delta = await ctx.withRetry(
      caseId,
      "extract",
      async () => {
        const parsed = await ctx.analyzeRestored(
          caseId,
          state,
          provider,
          { systemPrompt: getSystemPrompt(), userPrompt, images },
          "extract",
        );
        return stripAiExtractedFrom(deltaSchema.parse(parsed));
      },
      ctx.opts.retries ?? 3,
      ctx.opts.backoffMs ?? 500,
    );

    const last = analyzable[analyzable.length - 1];
    const next = await ctx.mergeWithAliases(state, tagScreenshotSources(delta, analyzable), {
      windowSequence: last.sequenceNumber,
      timestamp: last.timestamp,
      sourceScreenshots: analyzable.map((c) => c.screenshotFile),
    });
    await ctx.opts.stateStore.save(next);
    ctx.opts.onState?.(next);
    return next;
  });
}

/**
 * The screenshot batch, as prompt text.
 *
 * The capture time is deliberately NOT put on these lines — the model would otherwise copy it into
 * forensicEvents instead of reading the artifact's own timestamp column shown in the image.
 */
function buildScreenshotPrompt(state: InvestigationState, analyzable: CaptureMetadata[]): string {
  const contextLines = analyzable
    .map((c) => `Screenshot ${c.screenshotFile} — ${c.tabTitle} (${c.url})`)
    .join("\n");
  return (
    `${buildStateSummary(state)}\n\nNEW SCREENSHOTS (read each artifact's OWN timestamp column ` +
    `for event times — do not use any capture/current time):\n${contextLines}\n\nReturn the JSON delta.`
  );
}

/**
 * Tag each event's source for correlation/corroboration: detect the real tool from the captured tab
 * titles (e.g. "Velociraptor", "CrowdStrike Falcon"), else the generic "screenshot".
 */
function tagScreenshotSources<D extends { forensicEvents?: { sources?: string[] }[] }>(
  delta: D,
  analyzable: CaptureMetadata[],
): D {
  const winSource = detectTool(analyzable.map((c) => c.tabTitle).join(" ")) ?? "screenshot";
  return {
    ...delta,
    forensicEvents: (delta.forensicEvents ?? []).map((e) => ({
      ...e,
      sources: e.sources?.length ? e.sources : [winSource],
    })),
  };
}

/**
 * What differs between the CSV and log imports (#453). Everything NOT here is shared, and lives in
 * `runBatchedImport` below.
 *
 * The two used to be 100+ lines each and ~85% identical, which is how they drifted: the log path
 * reserves 96 tokens of prompt overhead and the CSV path 64 plus a header row, for no reason anyone
 * recorded. Making the difference a parameter means the next divergence has to be typed out here,
 * where it is visible, rather than appearing as a diff between two long functions nobody diffs.
 */
interface ImportExtractionSpec<T> {
  /** The retry/telemetry kind AND the analyzeRestored call kind — always the same string. */
  kind: "csv" | "log";
  /**
   * A RESOLVER, not a string. `DFIR_AI_{CSV,LOG}_PROMPT_FILE` is documented as "re-read on each AI
   * call", and this loop makes one call per batch per attempt — so resolving once up front would
   * pin a whole multi-batch import to whatever the file said when it started.
   */
  resolveSystemPrompt: () => string;
  /** Fallback event source when `detectTool(label)` finds nothing. */
  defaultSource: string;
  /** The raw payload, pre-scanned once alongside the state summary. */
  payloadText: string;
  /** Split the items into batches. Takes the loaded state because the summary is prompt overhead. */
  planBatches(state: InvestigationState): T[][];
  buildPrompt(state: InvestigationState, batch: T[], index: number, total: number): string;
}

/**
 * Scan the WHOLE import once, up front, instead of letting the per-batch loop hit presidioGate
 * repeatedly (which would stall-approve-restart on a large CSV with names scattered through it).
 * One approval round trip per import, not one per batch.
 *
 * The scan covers the STATE SUMMARY as well as the payload, because every batch prompt is
 * `buildStateSummary(state) + chunk` and every batch passes skipPresidioGate=true. Scanning the
 * payload alone left the summary — finding titles and descriptions, open threads, the last 12
 * forensic events and every known IOC value, all RESTORED to real values — reaching the provider
 * having never been seen by Presidio: a fail-OPEN in a layer whose contract is fail-closed.
 */
async function preScanWholeImport(
  ctx: ExtractionContext,
  caseId: string,
  state: InvestigationState,
  payloadText: string,
): Promise<void> {
  if (!ctx.opts.presidio) return;
  const importAnonCtx = await buildImportAnonContext(ctx, caseId, state);
  if (!importAnonCtx) return;
  await presidioPreScan(
    ctx,
    caseId,
    `${buildStateSummary(state)}\n${payloadText}`,
    importAnonCtx.known,
    importAnonCtx.anon,
    importAnonCtx.control,
  );
}

/**
 * One batch's model call. `skipPresidioGate=true` because `preScanWholeImport` already covered this
 * whole payload — that flag and the pre-scan are a pair, and neither is safe without the other.
 */
async function extractBatch<T>(
  ctx: ExtractionContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  opts: ImportExtractionOptions,
  spec: ImportExtractionSpec<T>,
  userPrompt: string,
): Promise<ReturnType<typeof stripAiExtractedFrom>> {
  const parsed = await ctx.analyzeRestored(
    caseId,
    state,
    provider,
    {
      systemPrompt: spec.resolveSystemPrompt(),
      userPrompt,
      images: [],
      ...(opts.signal ? { signal: opts.signal } : {}),
    },
    spec.kind,
    true,
  );
  return stripAiExtractedFrom(deltaSchema.parse(parsed));
}

/**
 * Every 4-digit year that literally appears in an import's raw text.
 *
 * This is how an AI-extracted event's year is judged RECORDED or GUESSED (#739). The model must emit
 * a full timestamp whichever kind of source it read, so its output alone says nothing; the source
 * does. A year the file never mentions cannot have been read out of it — a BSD syslog line or a bare
 * `12:00:48` CSV cell dated by the model is exactly that case, and it is the one the year-clamp
 * exists for.
 *
 * The test is deliberately ASYMMETRIC. A year present in the file is treated as recorded even if the
 * match was really a port number or an id, so the failure mode is a stray the clamp declines to fix —
 * never a real timestamp the clamp silently rewrites. Under-clamping is recoverable; overwriting
 * evidence is not.
 */
function yearsPresentIn(text: string): Set<string> {
  return new Set(text.match(/\b(?:19|20)\d{2}\b/g) ?? []);
}

/**
 * The UTC year of an ISO timestamp as a bare string, or "" when it does not parse.
 *
 * deltaSchema already tagged a naive model stamp as UTC (#757), so the parse below is
 * zone-independent for every caller in this file. Tagging again costs nothing and keeps the function
 * correct on its own terms: judging a year through a zone-aware parse is what let a UTC+2 server read
 * "2026-01-01T00:30:00" as 2025 and mark a RECORDED year as guessed.
 */
function yearStringOf(timestamp: string): string {
  const ms = Date.parse(tagNaiveAsUtc(timestamp));
  return Number.isNaN(ms) ? "" : String(new Date(ms).getUTCFullYear());
}

/**
 * The shared import shape: hold the state lock across the whole batch loop, pre-scan once, then for
 * each batch call the model, renumber the events it returned, merge and persist.
 *
 * The lock spans every batch deliberately — a concurrent import merging into the same case between
 * two batches would renumber against a timeline this loop has already read.
 */
async function runBatchedImport<T>(
  ctx: ExtractionContext,
  caseId: string,
  provider: AIProvider,
  opts: ImportExtractionOptions,
  spec: ImportExtractionSpec<T>,
): Promise<InvestigationState> {
  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    let evSeq = lastImportEventSequence(state.forensicTimeline, opts.idPrefix);
    // Scanned once for the whole payload, not per batch: the question is whether the SOURCE names a
    // year anywhere, and a batch boundary is an artifact of the token budget, not of the evidence.
    const sourceYears = yearsPresentIn(spec.payloadText);
    await preScanWholeImport(ctx, caseId, state, spec.payloadText);
    const batches = spec.planBatches(state);

    for (let b = opts.startBatch ?? 0; b < batches.length; b++) {
      if (opts.signal?.aborted) break; // #225: cancelled — stop before the next batch, keep prior batches
      const userPrompt = spec.buildPrompt(state, batches[b], b, batches.length);

      const delta = await ctx.withRetry(
        caseId,
        spec.kind,
        () => extractBatch(ctx, caseId, state, provider, opts, spec, userPrompt),
        ctx.opts.retries ?? 3,
        ctx.opts.backoffMs ?? 500,
      );

      // Renumber event ids so chunked imports don't overwrite each other (merge dedupes forensic
      // events by id, and each batch independently emits e1, e2…).
      const renumbered = {
        ...delta,
        forensicEvents: applySeverityFloor(delta.forensicEvents ?? [], opts.minSeverity).map((e) => ({
          ...e,
          id: `${opts.idPrefix}e${++evSeq}`,
          sources: e.sources?.length ? e.sources : [detectTool(opts.label) ?? spec.defaultSource],
          // Per EVENT, not per import: a CSV of RFC 3339 rows is recorded evidence and marking the
          // whole file would let the merge's year-clamp rewrite a real minority year — the #739
          // defect itself. Only a year the source never mentions was invented here (#739).
          ...(sourceYears.has(yearStringOf(e.timestamp)) ? {} : { yearInferred: true }),
        })),
      };

      state = await ctx.mergeWithAliases(state, renumbered, {
        windowSequence: -(b + 1), // negative: distinguishes import batches from capture windows
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label], // evidence traceability: the uploaded file
      });
      await ctx.opts.stateStore.save(state);
      ctx.opts.onState?.(state);
      await opts.onProgress?.(b + 1, batches.length);
    }
    return state;
  });
}

/**
 * Import an uploaded CSV (e.g. a Velociraptor result export) as evidence: extract dated forensic
 * events + IOCs from the rows, batch by batch, into the timeline — the same delta the screenshot
 * path produces. Findings/TTPs/attacker-path come afterwards from synthesize() (call it after this
 * resolves), exactly like capture.
 */
export async function analyzeCsv(
  ctx: ExtractionContext,
  caseId: string,
  csvText: string,
  opts: ImportExtractionOptions & { rowsPerBatch?: number },
): Promise<InvestigationState> {
  // Text model (same idiom as ask/explain/synthesis): CSV extraction is text reasoning, not OCR.
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("CSV analysis");
  const { headers, rows } = parseCsv(csvText);
  if (rows.length === 0) return ctx.opts.stateStore.load(caseId);

  return runBatchedImport(ctx, caseId, provider, opts, {
    kind: "csv",
    resolveSystemPrompt: getCsvPrompt,
    defaultSource: "CSV import",
    payloadText: csvText,
    // Batch by BOTH the row cap and a token budget: wide rows (long EDR/SIEM command-lines) could
    // otherwise pack 50 rows into a prompt that overflows the model context. Reserve room for the
    // system prompt, the state summary prepended to every batch, and the repeated header row.
    planBatches: (state) => {
      const overhead =
        estimateTokens(getCsvPrompt()) +
        estimateTokens(buildStateSummary(state)) +
        estimateTokens(chunkToCsvText(headers, [])) +
        64;
      const budget = Math.max(0, inputTokenBudget() - overhead);
      return batchByBudget(rows, opts.rowsPerBatch ?? 50, (r) => r.join(","), budget);
    },
    buildPrompt: (state, batch, index, total) =>
      `${buildStateSummary(state)}\n\nCSV ARTIFACT ROWS (source: ${opts.label}; batch ${index + 1}/${total}). ` +
      `Read each row's OWN time column for event times — do not use the current time:\n\n` +
      `${chunkToCsvText(headers, batch)}\n\nReturn the JSON delta.`,
  });
}

// Import an uploaded generic log file (firewall logs, syslog, sshd, IIS, etc.)
// as evidence. Logs are mostly repetition, so we DEDUPLICATE deterministically
// first (aggregateLogLines collapses near-identical lines into counted patterns),
// then ask the model to triage the PATTERNS — emitting one aggregated forensic
// event only for the security-relevant ones and skipping routine noise. This
// keeps the timeline signal-rich and cuts the analysis to ~one AI call.
// Findings/TTPs/attacker-path come afterwards from synthesize().
export async function analyzeLog(
  ctx: ExtractionContext,
  caseId: string,
  logText: string,
  opts: ImportExtractionOptions & { patternsPerBatch?: number },
): Promise<InvestigationState> {
  // Text model (same idiom as ask/explain/synthesis): log triage is text reasoning, not OCR.
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("log analysis");
  const { lines } = parseLogLines(logText);
  if (lines.length === 0) return ctx.opts.stateStore.load(caseId);

  // Collapse the raw lines into distinct, counted patterns (most frequent first). Capture the
  // aggregation stats so a cap-hit (more distinct patterns than the AI could be shown) is flagged
  // as a coverage blind spot by the import route (#10 trigger b).
  const aggStats: AggregateStats = { distinctTemplates: 0, keptTemplates: 0 };
  const maxTemplates = Number(process.env.DFIR_LOG_MAX_TEMPLATES) || undefined; // else the built-in default
  const templates = aggregateLogLines(lines, { maxTemplates }, aggStats);
  ctx.recordImportTruncation(caseId, aggStats.distinctTemplates > aggStats.keptTemplates ? aggStats : null);

  return runBatchedImport(ctx, caseId, provider, opts, {
    kind: "log",
    resolveSystemPrompt: getLogPrompt,
    defaultSource: "Log import",
    payloadText: logText,
    // Batch by BOTH the pattern cap and a token budget — a few patterns with very long examples
    // shouldn't form a prompt that overflows the model context.
    planBatches: (state) => {
      const render = (t: (typeof templates)[number]) =>
        `×${t.count} ${t.firstTimestamp ?? ""} ${t.lastTimestamp ?? ""} ${t.example}`;
      const overhead = estimateTokens(getLogPrompt()) + estimateTokens(buildStateSummary(state)) + 96;
      const budget = Math.max(0, inputTokenBudget() - overhead);
      return batchByBudget(templates, opts.patternsPerBatch ?? 120, render, budget);
    },
    buildPrompt: (state, batch, index, total) =>
      `${buildStateSummary(state)}\n\nDEDUPLICATED LOG PATTERNS (source: ${opts.label}; ` +
      `batch ${index + 1}/${total}; ${lines.length} raw line(s) → ${templates.length} pattern(s)). ` +
      `Emit an aggregated event ONLY for security-relevant patterns; skip routine noise:\n\n` +
      `${renderPatternBatch(batch)}\n\nReturn the JSON delta.`,
  });
}

/** Present each pattern with its occurrence count, time span, and an example. */
function renderPatternBatch(batch: ReturnType<typeof aggregateLogLines>): string {
  return batch
    .map(
      (t, i) =>
        `[p${i + 1}] ×${t.count}` +
        (t.firstTimestamp ? ` first=${t.firstTimestamp}` : "") +
        (t.lastTimestamp && t.lastTimestamp !== t.firstTimestamp ? ` last=${t.lastTimestamp}` : "") +
        `\n     e.g. ${t.example}`,
    )
    .join("\n");
}
