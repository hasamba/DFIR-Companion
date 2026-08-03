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
    // Note: we deliberately do NOT put the capture time on these lines — the model
    // would otherwise copy it into forensicEvents instead of reading the artifact's
    // own timestamp column shown in the image.
    const contextLines = analyzable
      .map((c) => `Screenshot ${c.screenshotFile} — ${c.tabTitle} (${c.url})`)
      .join("\n");
    const userPrompt =
      `${buildStateSummary(state)}\n\nNEW SCREENSHOTS (read each artifact's OWN timestamp column ` +
      `for event times — do not use any capture/current time):\n${contextLines}\n\nReturn the JSON delta.`;

    const retries = ctx.opts.retries ?? 3;
    const backoffMs = ctx.opts.backoffMs ?? 500;

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
      retries,
      backoffMs,
    );

    const windowSequence = analyzable[analyzable.length - 1].sequenceNumber;
    // Tag each event's source for correlation/corroboration: detect the real tool from the
    // captured tab titles (e.g. "Velociraptor", "CrowdStrike Falcon"), else generic "screenshot".
    const winSource = detectTool(analyzable.map((c) => c.tabTitle).join(" ")) ?? "screenshot";
    const tagged = {
      ...delta,
      forensicEvents: (delta.forensicEvents ?? []).map((e) => ({
        ...e,
        sources: e.sources?.length ? e.sources : [winSource],
      })),
    };
    const next = await ctx.mergeWithAliases(state, tagged, {
      windowSequence,
      timestamp: analyzable[analyzable.length - 1].timestamp,
      sourceScreenshots: analyzable.map((c) => c.screenshotFile),
    });
    await ctx.opts.stateStore.save(next);
    ctx.opts.onState?.(next);
    return next;
  });
}

// Import an uploaded CSV (e.g. a Velociraptor result export) as evidence: extract
// dated forensic events + IOCs from the rows, batch by batch, into the timeline —
// the same delta the screenshot path produces. Findings/TTPs/attacker-path come
// afterwards from synthesize() (call it after this resolves), exactly like capture.
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

  const retries = ctx.opts.retries ?? 3;
  const backoffMs = ctx.opts.backoffMs ?? 500;

  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    let evSeq = lastImportEventSequence(state.forensicTimeline, opts.idPrefix);

    // Scan the WHOLE import once, up front, instead of letting the per-chunk batches below hit
    // presidioGate repeatedly (which would stall-approve-restart on a large CSV with names
    // scattered through it). One approval round trip per import, not one per chunk.
    //
    // The scan covers the STATE SUMMARY as well as the payload, because every batch prompt
    // below is `buildStateSummary(state) + csvChunk`, and every batch passes
    // skipPresidioGate=true. Scanning csvText alone left the summary — finding titles and
    // descriptions, open threads, the last 12 forensic events and every known IOC value, all
    // RESTORED to real values — reaching the provider having never been seen by Presidio: a
    // fail-OPEN in a layer whose contract is fail-closed.
    if (ctx.opts.presidio) {
      const importAnonCtx = await buildImportAnonContext(ctx, caseId, state);
      if (importAnonCtx)
        await presidioPreScan(
          ctx,
          caseId,
          `${buildStateSummary(state)}\n${csvText}`,
          importAnonCtx.known,
          importAnonCtx.anon,
        );
    }

    // Batch by BOTH the row cap and a token budget: wide rows (long EDR/SIEM command-lines)
    // could otherwise pack 50 rows into a prompt that overflows the model context. Reserve
    // room for the system prompt + the state-summary that's prepended to every batch.
    const csvOverhead =
      estimateTokens(getCsvPrompt()) +
      estimateTokens(buildStateSummary(state)) +
      estimateTokens(chunkToCsvText(headers, [])) +
      64;
    const rowBudget = Math.max(0, inputTokenBudget() - csvOverhead);
    const batches = batchByBudget(rows, opts.rowsPerBatch ?? 50, (r) => r.join(","), rowBudget);

    for (let b = opts.startBatch ?? 0; b < batches.length; b++) {
      if (opts.signal?.aborted) break; // #225: cancelled — stop before the next batch, keep prior batches
      const csvChunk = chunkToCsvText(headers, batches[b]);
      const userPrompt =
        `${buildStateSummary(state)}\n\nCSV ARTIFACT ROWS (source: ${opts.label}; batch ${b + 1}/${batches.length}). ` +
        `Read each row's OWN time column for event times — do not use the current time:\n\n${csvChunk}\n\n` +
        `Return the JSON delta.`;

      const delta = await ctx.withRetry(
        caseId,
        "csv",
        async () => {
          // skipPresidioGate=true: the pre-scan above already covered this whole import.
          const parsed = await ctx.analyzeRestored(
            caseId,
            state,
            provider,
            {
              systemPrompt: getCsvPrompt(),
              userPrompt,
              images: [],
              ...(opts.signal ? { signal: opts.signal } : {}),
            },
            "csv",
            true,
          );
          return stripAiExtractedFrom(deltaSchema.parse(parsed));
        },
        retries,
        backoffMs,
      );

      // Renumber event ids so chunked imports don't overwrite each other (merge
      // dedupes forensic events by id, and each batch independently emits e1, e2…).
      const renumbered = {
        ...delta,
        forensicEvents: applySeverityFloor(delta.forensicEvents ?? [], opts.minSeverity).map((e) => ({
          ...e,
          id: `${opts.idPrefix}e${++evSeq}`,
          sources: e.sources?.length ? e.sources : [detectTool(opts.label) ?? "CSV import"],
        })),
      };

      state = await ctx.mergeWithAliases(state, renumbered, {
        windowSequence: -(b + 1), // negative: distinguishes import batches from capture windows
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label], // evidence traceability: the CSV file
      });
      await ctx.opts.stateStore.save(state);
      ctx.opts.onState?.(state);
      await opts.onProgress?.(b + 1, batches.length);
    }
    return state;
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
  const retries = ctx.opts.retries ?? 3;
  const backoffMs = ctx.opts.backoffMs ?? 500;

  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    let evSeq = lastImportEventSequence(state.forensicTimeline, opts.idPrefix);

    // Scan the WHOLE import once, up front — see analyzeCsv for why this must precede the
    // per-pattern batch loop below rather than living inside it, and why the state summary is
    // scanned alongside the payload (every batch prompt below prepends it and skips the gate).
    if (ctx.opts.presidio) {
      const importAnonCtx = await buildImportAnonContext(ctx, caseId, state);
      if (importAnonCtx)
        await presidioPreScan(
          ctx,
          caseId,
          `${buildStateSummary(state)}\n${logText}`,
          importAnonCtx.known,
          importAnonCtx.anon,
        );
    }

    // Batch by BOTH the pattern cap and a token budget — a few patterns with very long
    // examples shouldn't form a prompt that overflows the model context.
    const renderPattern = (t: (typeof templates)[number]) =>
      `×${t.count} ${t.firstTimestamp ?? ""} ${t.lastTimestamp ?? ""} ${t.example}`;
    const logOverhead = estimateTokens(getLogPrompt()) + estimateTokens(buildStateSummary(state)) + 96;
    const patternBudget = Math.max(0, inputTokenBudget() - logOverhead);
    const batches = batchByBudget(templates, opts.patternsPerBatch ?? 120, renderPattern, patternBudget);

    for (let b = opts.startBatch ?? 0; b < batches.length; b++) {
      if (opts.signal?.aborted) break; // #225: cancelled — stop before the next batch, keep prior batches
      // Present each pattern with its occurrence count, time span, and an example.
      const patternText = batches[b]
        .map(
          (t, i) =>
            `[p${i + 1}] ×${t.count}` +
            (t.firstTimestamp ? ` first=${t.firstTimestamp}` : "") +
            (t.lastTimestamp && t.lastTimestamp !== t.firstTimestamp ? ` last=${t.lastTimestamp}` : "") +
            `\n     e.g. ${t.example}`,
        )
        .join("\n");
      const userPrompt =
        `${buildStateSummary(state)}\n\nDEDUPLICATED LOG PATTERNS (source: ${opts.label}; ` +
        `batch ${b + 1}/${batches.length}; ${lines.length} raw line(s) → ${templates.length} pattern(s)). ` +
        `Emit an aggregated event ONLY for security-relevant patterns; skip routine noise:\n\n${patternText}\n\n` +
        `Return the JSON delta.`;

      const delta = await ctx.withRetry(
        caseId,
        "log",
        async () => {
          // skipPresidioGate=true: the pre-scan above already covered this whole import.
          const parsed = await ctx.analyzeRestored(
            caseId,
            state,
            provider,
            {
              systemPrompt: getLogPrompt(),
              userPrompt,
              images: [],
              ...(opts.signal ? { signal: opts.signal } : {}),
            },
            "log",
            true,
          );
          return stripAiExtractedFrom(deltaSchema.parse(parsed));
        },
        retries,
        backoffMs,
      );

      const renumbered = {
        ...delta,
        forensicEvents: applySeverityFloor(delta.forensicEvents ?? [], opts.minSeverity).map((e) => ({
          ...e,
          id: `${opts.idPrefix}e${++evSeq}`,
          sources: e.sources?.length ? e.sources : [detectTool(opts.label) ?? "Log import"],
        })),
      };

      state = await ctx.mergeWithAliases(state, renumbered, {
        windowSequence: -(b + 1),
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await ctx.opts.stateStore.save(state);
      ctx.opts.onState?.(state);
      await opts.onProgress?.(b + 1, batches.length);
    }
    return state;
  });
}
