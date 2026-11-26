import { labSetupPaths } from "../analysis/labSetupTransfer.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { finalizeHeld, heldContentTagger } from "../analysis/ai/watson/heldTagger.js";
import { heldBuildWindows } from "../analysis/ai/watson/heldWindows.js";
import type { WatsonPasteIngest } from "../analysis/ai/watson/pasteIngestChat.js";
import type { WatsonPaste } from "../analysis/ai/watson/types.js";
import type { RouteContext } from "./context.js";
import { beginImportSection } from "./importSection.js";
import { settleImportOrRecoverThenThrow } from "./importRowRecovery.js";
import { gradeArmOf, type SettledImport } from "./importSettle.js";
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
    return { kind: "text", reason: `Watson could not find the format: ${message(err)}` };
  }
  if (AI_ONLY_KINDS.has(kind)) {
    return {
      kind: "text",
      reason: "no built-in importer reads this format. It stays as text that Watson can search",
    };
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
        reason: `Watson imported the ${kind} rows, but it could not grade them: ${message(err)}`,
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
  // #2909: the paste's rows are marked "held" (at insert and with the stamp), so only a held tagger ever
  // grades them — this one now, a tags-only one in a later re-grade — never a plain one that would apply a
  // raise the analyst did not accept. Rows another import left marked true keep the plain tagger.
  const deps = {
    ...settleDeps,
    markGradePending: "held" as const,
    tagHeld: importTagger(
      { options, store: ctx.store, runStateExclusive: ctx.runStateExclusive, logLine },
      held.tag,
    ),
  };
  const section = await beginImportSection(
    ctx.importLock,
    caseId,
    options.stateStore,
    { incomingBytes: paste.bytes, wording: PASTE_REFUSAL_WORDING },
    gradeArmOf(deps),
  );
  try {
    if (!section.baseline) return { kind: "text", reason: "Watson could not make a snapshot of the case" };
    await ctx.dispatchImport(kind, caseId, text, {
      label: paste.storedName,
      idPrefix: `watson-${paste.id}`,
      importedAt: new Date().toISOString(),
    });
    onImported();
    // A settle failure settles the paste's rows first (#2891) — with the HELD tagger, so a recovery
    // never applies a promotion the analyst has not accepted. #2909: when the held tagger did read the
    // rows (the settle's own pass or the recovery's), its proposals are still offered rather than lost.
    const target = { caseId, storedNames: [paste.storedName], tag: "watson" };
    let settled: SettledImport | null = null;
    try {
      settled = await settleImportOrRecoverThenThrow(deps, target, section.baseline, paste.storedName);
    } catch (err) {
      if (!held.offered().length) throw err;
      ctx.serverLogger.warn(
        `[watson] ${caseId}: paste ${paste.storedName}: grading failed (${message(err)}); its rows were ` +
          "recovered and the rows the tagger would raise are still offered for approval",
      );
    }
    const offered = lastById(held.offered()); // a failed settle and its recovery offer the rows twice
    const candidates = lastById(held.held());
    const windows = candidates.length ? await heldBuildWindows(settleDeps.stateStore, caseId, offered) : [];
    const finalized = finalizeHeld(candidates, { windows, labPaths: labSetupPaths(), offered });
    const added = settled?.timelineDiff.added.length; // rows that landed in the forensic timeline
    return {
      kind,
      rows: offered.length || (added ?? 0),
      held: finalized,
      ...(added === undefined ? {} : { added }),
    };
  } finally {
    section.release();
  }
}

/** One row per id, the latest copy (the recovery's read is after the failed settle's). */
function lastById(rows: readonly ForensicEvent[]): ForensicEvent[] {
  return [...new Map(rows.map((e) => [e.id, e] as const)).values()];
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
