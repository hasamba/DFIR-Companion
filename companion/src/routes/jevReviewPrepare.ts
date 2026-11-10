import type { SuperQuery } from "../analysis/superTimeline.js";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { stateEventResolver } from "../analysis/eventAliasLookup.js";
import { buildAnalystContext } from "../analysis/ai/jev/jevDecomposed.js";
import type { JevGradeShape } from "../analysis/ai/jev/jevGrader.js";
import type { JevSettings } from "../analysis/ai/jev/jevConfig.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import type { CaseStore } from "../storage/caseStore.js";
import { rowsInBuildWindow } from "./jevBuildWindow.js";
import type { RouteContext } from "./context.js";

/**
 * What the missed-evidence review reads before it asks Jev anything (#1540), split out of the route
 * (#2515) so "Preview what the AI will see" selects EXACTLY the rows a real review would send: the
 * route and the preview both call `selectReviewRows`.
 *
 * It reads the raw record under the documented bounds (ARCHITECTURE.md, "The forensic /
 * super-timeline boundary"): analyst-pressed, capped with the truncation disclosed, writes nothing.
 */

/**
 * A single super-timeline query is ceilinged by the store, so reading more than one page means
 * paging. Stops at `cap` rows, or when the matched total is in hand, or when a page comes back
 * empty — that last guard is what keeps a filter whose total disagrees with its rows from looping.
 */
const SUPER_PAGE_ROWS = 2000;

async function readMatchingRows(
  store: NonNullable<RouteContext["options"]["superTimelineStore"]>,
  caseId: string,
  filters: SuperQuery,
  cap: number,
): Promise<{ events: ForensicEvent[]; total: number }> {
  const events: ForensicEvent[] = [];
  let total = 0;
  for (;;) {
    const want = Math.min(SUPER_PAGE_ROWS, cap - events.length);
    if (want <= 0) break;
    const page = await store.query(caseId, { ...filters, offset: events.length, limit: want });
    total = page.total;
    if (!page.events.length) break;
    events.push(...page.events);
    if (events.length >= total) break;
  }
  return { events, total };
}

/** The review's coverage, as facts — see the route for why `capped` is the only one that blames the cap. */
export interface ReviewCoverage {
  readonly matched: number;
  readonly read: number;
  readonly alreadyAnalyzed: number;
  readonly buildWindow: number;
  readonly buildWindows: Awaited<ReturnType<typeof rowsInBuildWindow>>["windows"];
  readonly collectorFootprint: number;
  readonly graded: number;
  readonly capped: boolean;
  readonly cap: number;
  readonly readAll: boolean;
}

export interface ReviewRows {
  readonly state: InvestigationState;
  readonly candidates: ForensicEvent[];
  readonly coverage: ReviewCoverage;
}

/** The request body's choices: `all`, `limit`, `filters`. */
export interface ReviewRequest {
  readonly all?: unknown;
  readonly limit?: unknown;
  readonly filters?: unknown;
}

export async function selectReviewRows(
  options: RouteContext["options"],
  caseId: string,
  settings: JevSettings,
  body: ReviewRequest,
): Promise<ReviewRows> {
  const superStore = options.superTimelineStore!;
  const stateStore = options.stateStore!;

  // `all` is the analyst saying "read every row, never mind the cap". Everything else caps at
  // the configured default. One query cannot answer either: the store ceilings a single page, so
  // a full read pages until the matched total is in hand.
  const readAll = body.all === true;
  const requested = Number(body.limit);
  const cap = readAll
    ? Number.POSITIVE_INFINITY
    : Math.min(
        settings.maxRows,
        Number.isFinite(requested) && requested > 0 ? Math.floor(requested) : Number.POSITIVE_INFINITY,
      );
  const capForWire = Number.isFinite(cap) ? cap : settings.maxRows;
  const filters: SuperQuery = { ...((body.filters as SuperQuery | undefined) ?? {}) };

  const state = await stateStore.load(caseId);
  const { events: read, total } = await readMatchingRows(superStore, caseId, filters, cap);

  // Rows already in the forensic timeline are the ones synthesis can ALREADY see. Reviewing them
  // would spend the analyst's money re-grading what is not missing. That includes a row the case
  // holds under ANOTHER id: a second tool's copy of an event, folded into the first tool's (#1761).
  // The lineage resolves it to that event while the event is live; once the event is gone, the row
  // resolves to itself and is missing evidence again.
  const analyzed = new Set(state.forensicTimeline.map((e) => e.id));
  const canonical = stateEventResolver(state);
  const unanalyzed = read.filter((e) => !analyzed.has(canonical(e.id)));
  // Rows inside the host's own build window are the machine being built (#1529). The grader is not
  // told that, so it grades a Chocolatey firewall change Medium and a provisioning log clear Critical
  // (#1700). They are set aside here, before anything is spent, and counted so the sum still closes.
  const setAside = await rowsInBuildWindow(superStore, caseId, state, unanalyzed);
  const inBuild = setAside.ids;
  const outsideBuild = unanalyzed.filter((e) => !inBuild.has(e.id));
  // The collector's own footprint (#1949): rows the importer proved were the investigator's tooling
  // at work. Graded blind, PersistenceSniper's Add-Type reads as the intruder's. Keyed on the
  // structured origin, never the note: a Critical keeps the note but no origin, and stays graded.
  const candidates = outsideBuild.filter((e) => e.origin !== "collector");
  const collectorFootprint = outsideBuild.length - candidates.length;

  // Coverage, as four facts rather than one flag. `capped` is the ONLY one that may blame the
  // cap, and it is true only when the cap actually held rows back: an earlier version inferred
  // truncation from "graded < matched" and told an analyst the cap had stopped a read of 1,344
  // rows against a 2,000 cap, when the shortfall was 366 rows already in the forensic timeline.
  const coverage: ReviewCoverage = {
    matched: total,
    read: read.length,
    alreadyAnalyzed: read.length - unanalyzed.length,
    buildWindow: inBuild.size,
    buildWindows: setAside.windows,
    collectorFootprint,
    graded: candidates.length,
    capped: read.length < total,
    cap: capForWire,
    readAll,
  };
  return { state, candidates, coverage };
}

/**
 * The analyst's own authorized/known-good records (#1924), masked like the rows. Read only when the
 * decomposed shape will ask about them. The caller reads it inside its error handling: a damaged
 * marker file must not break a single-shape review that never reads it.
 */
export async function reviewCaseContext(
  store: CaseStore,
  caseId: string,
  shape: JevGradeShape,
  mask: (text: string) => string,
): Promise<string> {
  return shape === "decomposed"
    ? buildAnalystContext(await new FalsePositiveStore(store).load(caseId), mask)
    : "";
}
