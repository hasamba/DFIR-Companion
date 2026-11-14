import {
  buildMarkerKind,
  buildTimeWindows,
  hardAttackerSignal,
  type BuildTimeWindow,
} from "../analysis/buildTimeWindow.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import { hostBuildMarkers } from "../analysis/gapHostHistory.js";
import { labSetupPaths } from "../analysis/labSetupTransfer.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { finalizeHeld, heldContentTagger } from "../analysis/ai/watson/heldTagger.js";
import type { WatsonPasteIngest } from "../analysis/ai/watson/pasteIngestChat.js";
import type { WatsonPaste } from "../analysis/ai/watson/types.js";
import type { RouteContext } from "./context.js";
import { beginImportSection } from "./importSection.js";
import { settleForensicImport } from "./importSettle.js";
import { importTagger, routeSettleDeps } from "./routeSettleDeps.js";

export type { WatsonPasteIngest } from "../analysis/ai/watson/pasteIngestChat.js";

/**
 * Parse a Watson chat paste into rows when it is in a format a deterministic importer reads (spec
 * §14). It follows the import replay (routes/analysisRuns.ts): the case's import section, the
 * importer, then the same settle seam as every import — merge-all → super-timeline dual-write →
 * tagger → caps → demote (CLAUDE.md §7) — with ONE change: the content tagger's promotions are held
 * (analysis/ai/watson/heldTagger.ts). The rows it would raise out of Info stay Info, so demote moves
 * them to the super-timeline, and their raised copies come back for Watson to propose; they pass the
 * settle's post-tagger corrections first, so a proposal never carries a grade the settle would not.
 *
 * A generic CSV or log (which only the AI could extract) and an unknown format stay searchable
 * text: no model call here. A chat ingest starts no synthesis (#1599), sends no import-meta ping,
 * and pushes no undo checkpoint; it marks the conclusions out of date. It never throws: the paste is
 * already stored as evidence, so a failure leaves it as text with the reason.
 */
const AI_ONLY_KINDS: ReadonlySet<string> = new Set(["csv", "log", "unknown"]);

const PASTE_REFUSAL_WORDING = {
  saved: "The pasted text is saved in the case",
  retry: "paste it again",
};

export async function ingestWatsonPaste(
  ctx: RouteContext,
  caseId: string,
  paste: WatsonPaste,
  text: string,
): Promise<WatsonPasteIngest> {
  let kind: string;
  try {
    kind = ctx.resolveImportKind()(paste.filename, text);
  } catch (err) {
    return { kind: "text", reason: `the format could not be detected: ${message(err)}` };
  }
  if (AI_ONLY_KINDS.has(kind)) {
    return { kind: "text", reason: "no built-in importer reads this format; it stays searchable text" };
  }
  let imported = false;
  try {
    const parsed = await parseInSection(ctx, caseId, paste, text, kind, () => {
      imported = true;
    });
    if (!("reason" in parsed)) await ctx.markConclusionsOutOfDate(caseId, "Watson paste parsed");
    return parsed;
  } catch (err) {
    ctx.serverLogger.warn(`[watson] ${caseId}: paste ${paste.storedName} was not parsed — ${message(err)}`);
    if (imported) {
      // The importer merged its rows; a later step failed. Say so rather than calling it unparsed.
      await ctx.markConclusionsOutOfDate(caseId, "Watson paste parsed").catch(() => undefined);
      return {
        kind: "text",
        reason: `the ${kind} rows were imported, but grading them failed: ${message(err)}`,
      };
    }
    return { kind: "text", reason: `the ${kind} importer could not parse it: ${message(err)}` };
  }
}

async function parseInSection(
  ctx: RouteContext,
  caseId: string,
  paste: WatsonPaste,
  text: string,
  kind: string,
  onImported: () => void,
): Promise<WatsonPasteIngest> {
  const { options } = ctx;
  const settleDeps = routeSettleDeps(ctx);
  if (!settleDeps || !options.stateStore) return { kind: "text", reason: "the case has no state store" };
  const logLine = (m: string): void => ctx.serverLogger.info(m);
  const held = heldContentTagger({
    taggerStore: options.taggerStore,
    tagsStore: options.tagsStore,
    onTags: options.onTags,
    logLine,
  });
  const deps = {
    ...settleDeps,
    autoTagImported: importTagger(
      { options, store: ctx.store, runStateExclusive: ctx.runStateExclusive, logLine },
      held.tag,
    ),
  };
  const section = await beginImportSection(ctx.importLock, caseId, options.stateStore, {
    incomingBytes: paste.bytes,
    wording: PASTE_REFUSAL_WORDING,
  });
  try {
    if (!section.baseline) return { kind: "text", reason: "the case could not be snapshotted" };
    await ctx.dispatchImport(kind, caseId, text, {
      label: paste.storedName,
      idPrefix: `watson-${paste.id}`,
      importedAt: new Date().toISOString(),
    });
    onImported();
    const settled = await settleForensicImport(deps, caseId, section.baseline, paste.storedName);
    const offered = held.offered();
    const candidates = held.held();
    const windows = candidates.length ? await heldBuildWindows(settleDeps.stateStore, caseId, offered) : [];
    const finalized = finalizeHeld(candidates, { windows, labPaths: labSetupPaths(), offered });
    const added = settled.timelineDiff.added.length; // rows that landed in the forensic timeline
    return { kind, rows: offered.length || added, held: finalized, added };
  } finally {
    section.release();
  }
}

/**
 * The build-time windows the settle's cap used (importSettleCap.ts). Demote has since removed this
 * import's Info rows from the forensic timeline, so its own rows are read from what the tagger saw.
 */
async function heldBuildWindows(
  store: ForensicRowStore,
  caseId: string,
  offered: readonly ForensicEvent[],
): Promise<BuildTimeWindow[]> {
  const ledger = store.loadOverviewWithoutIocs
    ? await store.loadOverviewWithoutIocs(caseId)
    : await store.loadOverview(caseId);
  const renames = ledger.hostRenames ?? [];
  const chains = hostBuildMarkers(renames);
  if (!chains.length) return [];
  const signals = (e: ForensicEvent): boolean => !!(buildMarkerKind(e) || hardAttackerSignal(e));
  const discovery = offered.filter(signals);
  const seen = new Set(discovery.map((e) => e.id));
  const names = new Set(chains.flatMap((c) => c.names));
  const hosts = (await store.forensicHosts(caseId)).filter((h) =>
    names.has(h.trim().split(".")[0].toUpperCase()),
  );
  for (const host of hosts) {
    for await (const batch of store.forensicTimelineBatches(caseId, { host, limit: SCAN_PAGE_ROWS })) {
      for (const e of batch) if (signals(e) && !seen.has(e.id)) discovery.push(e);
    }
  }
  return buildTimeWindows(discovery, renames);
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
