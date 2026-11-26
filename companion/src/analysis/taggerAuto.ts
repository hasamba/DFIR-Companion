// The AUTOMATIC post-import tagger hook. Every import path dual-writes its newly-added events into
// the super-timeline; immediately after that append, this runs the ruleset over just those NEW
// events (so cost is O(new × rules), not the whole 100k-event store) and applies the result:
//   • tags   — written for every match (tags are keyed by event id, so they light up BOTH the
//              forensic timeline and the super-timeline filters);
//   • forensic severity/MITRE — raised/unioned on the forensic timeline, UNLESS scope is super-only.
//
// Best-effort for the IMPORT: a missing store, TAGGER_AUTO=false, an empty ruleset or an error never
// fails an import. But it is not silent about it (#2891): it reports the rows it did NOT finish on, so
// the settle leaves them marked (analysis/gradeMark.ts) and the demote holds them for a later re-grade
// instead of moving them out untagged. A deliberate skip (no tagger wired, TAGGER_AUTO off, an empty
// ruleset, TAGGER_SCOPE=super) is finished; an internal failure — an invalid hand-edited ruleset
// included — leaves every row it was handed unfinished and logs a WARN. Gated by the TAGGER_AUTO /
// TAGGER_SCOPE settings (analysis/taggerRun.ts).

import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import type { TagsStore } from "./tags.js";
import type { TaggerStore } from "./taggerStore.js";
import type { StateStore } from "./stateStore.js";
import { runAndApplyTagger, readTaggerSettings } from "./taggerRun.js";
import { applyToForensicEvent, runTaggerYielding, type EventTagResult } from "./tagger.js";
import { rewriteRows } from "./forensicRowRewrite.js";
import type { AnalysisRunStore } from "./analysisRunStore.js";
import { hashManifestValue } from "./analysisRunHash.js";
import type { OperationalMetricsStore } from "./operationalMetrics.js";
import type { ForensicRow } from "./forensicRows.js";
import { getServerLogger } from "../logging/serverLogger.js";

export interface AutoTagDeps {
  taggerStore?: TaggerStore;
  tagsStore?: TagsStore;
  stateStore?: StateStore;
  analysisRunStore?: AnalysisRunStore;
  operationalMetrics?: OperationalMetricsStore;
  onTags?: (caseId: string) => void;
  onState?: (state: InvestigationState) => void;
  /** The case's state lock: the read → apply → write of the tagged rows runs inside it (#1874). */
  runStateExclusive?: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  logLine?: (msg: string) => void;
}

/**
 * Tag the just-imported events. `added` is the set newly appended to the super-timeline. Safe to call
 * from any import site; never throws. Returns the ids it did not finish on (#2891).
 */
export async function autoTagNewEvents(
  deps: AutoTagDeps,
  caseId: string,
  added: readonly ForensicEvent[],
): Promise<{ ungraded: string[] }> {
  const { taggerStore, tagsStore, stateStore } = deps;
  const finished = { ungraded: [] as string[] };
  if (!taggerStore || !tagsStore || !added.length) return finished;
  const settings = readTaggerSettings();
  if (!settings.auto) return finished;
  let graded: GradeWrite;
  const startedAt = new Date().toISOString();
  let active: { text: string };
  let ruleSource: Awaited<ReturnType<TaggerStore["provenance"]>>;
  let applied: Awaited<ReturnType<typeof runAndApplyTagger>>;
  try {
    active = await taggerStore.readActive();
    ruleSource = await taggerStore.provenance(); // named in the run ledger and the report (#2349)
    const ruleset = await taggerStore.load(); // throws on an invalid hand-edited file
    if (!ruleset.rules.length) return finished;
    // Tags first, from the rows handed in; the forensic grade/MITRE change after, below.
    // The rules run in slices (#2716): over a large import this was minutes of blocked event loop.
    applied = await runAndApplyTagger({
      caseId,
      result: await runTaggerYielding(added, ruleset),
      ruleset,
      forensicTimeline: [],
      tagsStore,
      mutateForensic: false,
    });
    const mutateForensic = settings.scope !== "super" && !!stateStore;
    graded = mutateForensic
      ? await writeGrades(deps, stateStore, caseId, applied.result.perEvent)
      : { written: [], refused: [] };
  } catch (err) {
    const message = (err as Error)?.message ?? String(err);
    const line = `[tagger] ${caseId} auto-tag failed: ${message} — ${added.length} row(s) left for a re-grade`;
    deps.logLine?.(line);
    getServerLogger().warn(line, { caseId });
    return { ungraded: added.map((e) => e.id) };
  }
  // The grades are written: nothing below can unmark a row (#2891).
  try {
    await reportTagging(deps, caseId, added, graded.written, applied, {
      startedAt,
      active,
      ruleSource,
      settings,
    });
  } catch (err) {
    deps.logLine?.(`[tagger] ${caseId} auto-tag reporting failed: ${(err as Error)?.message ?? String(err)}`);
  }
  return { ungraded: graded.refused };
}

interface GradeWrite {
  written: ForensicRow[];
  /** Rows whose grade change was computed but could not be written (a version conflict, for good). */
  refused: string[];
}

// #1874: only the rows a rule matched can change, so only they are read and written — by row id
// and version, inside the state lock — never the whole case.
async function writeGrades(
  deps: AutoTagDeps,
  stateStore: StateStore,
  caseId: string,
  perEvent: readonly EventTagResult[],
): Promise<GradeWrite> {
  const matched = new Map(perEvent.map((r) => [r.eventId, r]));
  if (!matched.size) return { written: [], refused: [] };
  const lock = deps.runStateExclusive ?? (<T>(_: string, fn: () => Promise<T>) => fn());
  return lock(caseId, async () => {
    const rows = await stateStore.forensicRowsById(caseId, [...matched.keys()]);
    const apply = (e: ForensicEvent): ForensicEvent => {
      const r = matched.get(e.id);
      return r ? applyToForensicEvent(e, r) : e;
    };
    // Matched but unchanged (already at that grade) is finished; a change not written is not.
    const changing = rows.filter((r) => apply(r.event) !== r.event).map((r) => r.rowId);
    const written = await rewriteRows(stateStore, caseId, rows, apply);
    if (written.length) await stateStore.patchStateMeta(caseId, { updatedAt: new Date().toISOString() });
    const done = new Set(written.map((r) => r.rowId));
    const refused = rows
      .filter((r) => changing.includes(r.rowId) && !done.has(r.rowId))
      .map((r) => r.event.id);
    return { written, refused };
  });
}

async function reportTagging(
  deps: AutoTagDeps,
  caseId: string,
  added: readonly ForensicEvent[],
  written: readonly ForensicRow[],
  applied: Awaited<ReturnType<typeof runAndApplyTagger>>,
  run: {
    startedAt: string;
    active: { text: string };
    ruleSource: Awaited<ReturnType<TaggerStore["provenance"]>>;
    settings: ReturnType<typeof readTaggerSettings>;
  },
): Promise<void> {
  const { stateStore } = deps;
  const byId = new Map(written.map((r) => [r.event.id, r.event]));
  const promoted = added.filter(
    (event) => event.severity === "Info" && (byId.get(event.id)?.severity ?? "Info") !== "Info",
  ).length;
  if (promoted > 0) await deps.operationalMetrics?.record({ type: "import_promotion", promoted });
  if (written.length && deps.onState) {
    deps.onState(await stateStore!.load(caseId)); // a caller that asked for a state broadcast
  }
  if (applied.tagsWritten > 0) deps.onTags?.(caseId);
  if (applied.result.totalMatched > 0) {
    deps.logLine?.(
      `[tagger] ${caseId} auto-tagged ${applied.result.totalMatched} event(s), +${applied.tagsWritten} tag(s), ${written.length} severity/MITRE update(s)`,
    );
  }
  await deps.analysisRunStore?.record(caseId, {
    kind: "deterministic",
    startedAt: run.startedAt,
    finishedAt: new Date().toISOString(),
    versions: {
      schema: "tagger/v1",
      rules: hashManifestValue(run.active.text),
    },
    input: {
      artifacts: [],
      eventIds: added.map((event) => event.id),
      entityIds: [],
      selectionHash: hashManifestValue(added.map((event) => event.id)),
    },
    configuration: {
      parameters: { analyzer: "tagger", mode: "automatic", rulePack: run.ruleSource },
      filteringPolicy: { scope: run.settings.scope },
    },
    output: {
      entityIds: applied.result.perEvent.map((event) => event.eventId),
      hashes: [
        {
          id: "tagger-result",
          sha256: hashManifestValue(applied.result),
        },
      ],
      claims: [],
    },
  });
}
