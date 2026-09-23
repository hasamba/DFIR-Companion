import { filterFalsePositiveEvents } from "../falsePositive.js";
import type { HostAliasIndex } from "../hostAlias.js";
import { loadHostAliasIndex } from "../hostScopeLoad.js";
import { rankConnectiveIocs } from "../iocAnchors.js";
import { isPendingLabRow } from "../labIntel.js";
import { filterEventsByScope, hasScope, NO_SCOPE, type ScopeWindow } from "../scope.js";
import {
  buildSecondLookPlan,
  buildSecondLookRequests,
  deriveWindow,
  resolveSecondLookRequests,
  summarizeSecondLook,
  type SecondLookPlan,
  type SecondLookRequest,
} from "../secondLook.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { SecondLookMeta } from "../synthMeta.js";
import { synthesize, type SynthesisContext } from "./synthesis.js";

/**
 * The second look (investigation-guidance #11), as an analyst-pressed button (#1554).
 *
 * It re-queries the COMPLETE raw record — the super-timeline plus the scoped events the synthesis
 * sampler omitted — for the terms the case's OPEN questions imply, promotes the matches into the
 * forensic timeline with provenance tags, and re-synthesises so the conclusions fold them in. A
 * request that matches nothing anywhere is recorded as a collection lead: a blind spot the analyst
 * can task around.
 *
 * WHY IT IS NO LONGER AUTOMATIC. This sweep is the only path that WRITES to the forensic record
 * without anybody asking for it, and it used to run at the tail of every synthesis. An automatic
 * writer to the evidence record is the one thing a forensic tool should not have: the analyst could
 * not see what it was about to promote, could not decline it, and could not tell an import's rows
 * from a sweep's. Now they press it, after a preview that counts exactly what it would do.
 *
 * It sits in its own module rather than inside ai/synthesis.ts for the reason deepPassRun.ts gives,
 * and for the same shape of dependency: the second look calls synthesis, synthesis knows nothing
 * about the second look. Filing it here keeps that direction visible and the import graph acyclic —
 * and synthesis.ts, at 780-odd of its 800 lines, has no room for it in any case.
 *
 * THE SWEEP ITSELF MAKES ZERO AI CALLS. It is a deterministic keyword search over the raw record.
 * Only the optional re-synthesis costs anything.
 */

/** Connective IOCs mined into requests — the same bound the automatic sweep used. */
const MAX_CONNECTIVE_IOCS = 5;

/** Collection leads carried on the synth-meta card and into the report. */
const MAX_LEADS = 10;

/** Second look needs everything synthesis needs: it ends by calling it. */
export type SecondLookContext = SynthesisContext;

/** What a sweep WOULD do, counted without writing anything. */
export interface SecondLookPreview {
  /** False when the case has no super-timeline — there is no raw record to re-query. */
  configured: boolean;
  hypotheses: number; // open hypotheses that became a search
  questions: number; // unknown/partial key questions with a collect target
  iocs: number; // top connective indicators
  modelRequests: number; // the model's own persisted evidence requests
  requests: number; // total searches, after dedupe
  wouldPromote: number; // rows this sweep would put on the forensic timeline
  leads: string[]; // reasons of the searches that matched nothing anywhere
  truncated: boolean; // the sweep cap would hold promotable rows back
  shapeHeld: number; // rows the per-shape cap would hold back as near-duplicates
}

/** What a sweep DID. */
export interface SecondLookRunResult {
  promoted: number;
  leads: string[];
  summary: string;
  resynthesized: boolean;
  shapeCapped: number;
  truncated: boolean;
}

/**
 * The explicit scope when the analyst set one, else the span of the dated in-scope events. Bounds
 * the raw re-query so a huge super-timeline is searched only over the incident window.
 */
function activeWindow(scope: ScopeWindow, scopedEvents: ForensicEvent[]): { from?: string; to?: string } {
  return hasScope(scope)
    ? { from: scope.start ?? undefined, to: scope.end ?? undefined }
    : deriveWindow(scopedEvents);
}

/**
 * The pool the second look searches: the scoped events the sampler OMITTED from the prompt, plus the
 * super-timeline rows inside the active window, deduped by id.
 *
 * A super row that is a copy of a forensic event shares its id, so the caller's `forensicEventIds`
 * check correctly marks it non-promotable — only genuinely-new raw rows are ever promoted.
 */
async function collectSecondLookCandidates(
  superStore: NonNullable<SecondLookContext["opts"]["superTimelineStore"]>,
  caseId: string,
  window: { from?: string; to?: string },
  input: { scopedEvents: ForensicEvent[]; promptEvents: ForensicEvent[] },
): Promise<ForensicEvent[]> {
  const shownIds = new Set(input.promptEvents.map((e) => e.id));
  const omitted = input.scopedEvents.filter((e) => !shownIds.has(e.id));
  const superRows = (await superStore.query(caseId, { from: window.from, to: window.to })).events;
  const byId = new Map<string, ForensicEvent>();
  // A pending lab row (sandbox behaviour nobody promoted) is out of the pool ENTIRELY — not just
  // out of the promotable subset. It may not be promoted, and it may not satisfy a request either:
  // a request whose only match is hidden lab evidence still needs a collection lead. A lab row the
  // analyst promoted is in the forensic timeline by their choice and may match (#932 item 5 part B).
  for (const e of [...omitted, ...superRows]) if (!byId.has(e.id) && !isPendingLabRow(e)) byId.set(e.id, e);
  return [...byId.values()];
}

interface SweptCase {
  state: InvestigationState;
  requests: SecondLookRequest[];
  plan: SecondLookPlan;
}

/**
 * Build the requests, resolve them against the raw record and plan the promotions — and stop there.
 * Nothing here writes: both entry points share it, and the preview is only a preview because this
 * function is where the sweep ends.
 *
 * Returns null when the case has no super-timeline, which is "there is nothing to re-query", not an
 * error. `promptEvents` is empty on purpose: decoupled from a synthesis run there is no prompt to
 * subtract, so every in-scope event joins the pool. None of them is promotable — they are already in
 * the forensic timeline — but they can SATISFY a request, and a request whose evidence is already in
 * hand must not be reported to the analyst as a blind spot.
 */
async function sweepCase(ctx: SecondLookContext, caseId: string): Promise<SweptCase | null> {
  const superStore = ctx.opts.superTimelineStore;
  if (!superStore) return null;

  const state = await ctx.opts.stateStore.load(caseId);
  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(state.forensicTimeline, scope), markers);
  const aliasIndex: HostAliasIndex = await loadHostAliasIndex(
    {
      ...(ctx.opts.assetOverridesStore ? { assetOverrides: ctx.opts.assetOverridesStore } : {}),
      ...(ctx.opts.velociraptorClientStore ? { fleet: ctx.opts.velociraptorClientStore } : {}),
    },
    caseId,
  );
  const window = activeWindow(scope, scopedEvents);
  const meta = await ctx.opts.synthMetaStore?.load(caseId);

  const requests = buildSecondLookRequests({
    hypotheses: ctx.opts.hypothesisStore ? await ctx.opts.hypothesisStore.load(caseId) : [],
    iocValueById: new Map(state.iocs.map((i) => [i.id, i.value] as const)),
    keyQuestions: state.keyQuestions,
    connectiveIocs: rankConnectiveIocs(state, scopedEvents, { max: MAX_CONNECTIVE_IOCS, aliasIndex }),
    // Persisted by the last synthesis (#1554). Before that it was a closure value on the synthesis
    // call, so the button — running in a different request, minutes later — would have seen nothing.
    ...(meta?.modelEvidenceRequests ? { modelRequests: meta.modelEvidenceRequests } : {}),
    window,
  });
  // Nothing to search for. Skip the super-timeline read entirely rather than scan it for no terms.
  if (!requests.length) return { state, requests, plan: buildSecondLookPlan([]) };

  const candidates = await collectSecondLookCandidates(superStore, caseId, window, {
    scopedEvents,
    promptEvents: [],
  });
  const forensicEventIds = new Set(state.forensicTimeline.map((e) => e.id));
  const resolutions = resolveSecondLookRequests(requests, candidates, forensicEventIds);
  return { state, requests, plan: buildSecondLookPlan(resolutions) };
}

const leadReasons = (plan: SecondLookPlan): string[] => plan.leads.map((l) => l.reason).slice(0, MAX_LEADS);

const countBy = (requests: readonly SecondLookRequest[], source: SecondLookRequest["source"]): number =>
  requests.filter((r) => r.source === source).length;

/**
 * A TRUE dry run: what pressing the button would promote, and what it would leave as a lead. One
 * bounded super-timeline read, no AI call, and `promoteSuperTimeline` is never reached — so the
 * forensic record is exactly as it was when this returns.
 */
export async function secondLookPreview(ctx: SecondLookContext, caseId: string): Promise<SecondLookPreview> {
  const swept = await sweepCase(ctx, caseId);
  if (!swept) {
    return {
      configured: false,
      hypotheses: 0,
      questions: 0,
      iocs: 0,
      modelRequests: 0,
      requests: 0,
      wouldPromote: 0,
      leads: [],
      truncated: false,
      shapeHeld: 0,
    };
  }
  const { requests, plan } = swept;
  return {
    configured: true,
    hypotheses: countBy(requests, "hypothesis"),
    questions: countBy(requests, "question"),
    iocs: countBy(requests, "connective-ioc"),
    modelRequests: countBy(requests, "model"),
    requests: requests.length,
    wouldPromote: plan.promotions.length,
    leads: leadReasons(plan),
    truncated: plan.truncated,
    shapeHeld: plan.shapeCapped,
  };
}

/**
 * Run the sweep: promote what the plan selected, then re-synthesise so the conclusions account for
 * it. Returns null when the case has no super-timeline.
 *
 * `resynthesize` DEFAULTS TO TRUE, and the default is the point. Promoting evidence and leaving the
 * findings written before it arrived is a case whose conclusions silently disagree with its own
 * timeline; that must never be what happens by accident. The opt-out exists for the analyst who
 * wants to read the promoted rows first, or who does not want to spend the call right now.
 *
 * A sweep that promoted nothing never re-synthesises: there is no new evidence to fold in, and a
 * forced call would spend the analyst's money to reproduce the conclusions they already have.
 */
export async function secondLookRun(
  ctx: SecondLookContext,
  caseId: string,
  opts: { resynthesize?: boolean; signal?: AbortSignal } = {},
): Promise<SecondLookRunResult | null> {
  const swept = await sweepCase(ctx, caseId);
  if (!swept) return null;
  const { requests, plan } = swept;

  if (plan.promotions.length) {
    await ctx.promoteSuperTimeline(caseId, plan.promotions, {
      intent: "second-look",
      importedAt: new Date().toISOString(),
      tagById: plan.tagById,
      note: `Second look: promoted ${plan.promotions.length} raw event(s) matching open questions`,
    });
  }

  // Promotion changed the in-scope timeline → the synthHash differs → this re-synthesis really runs
  // rather than being skipped as unchanged. It sweeps nothing of its own: synthesis no longer has a
  // sweep, which is what makes one press mean exactly one sweep.
  const wantsResynthesis = opts.resynthesize !== false && plan.promotions.length > 0;
  if (wantsResynthesis) {
    await synthesize(ctx, caseId, { force: true, ...(opts.signal ? { signal: opts.signal } : {}) });
  }

  // AFTER the re-synthesis, which rewrites the synth-meta document wholesale. Recording the sweep
  // first would hand the re-synthesis a card to overwrite, and reportWriter.ts reads these leads
  // straight out of that file — a lost merge drops them from the REPORT, not just from a card.
  const meta: SecondLookMeta = {
    promoted: plan.promotions.length,
    requests: requests.length,
    matched: plan.resolutions.filter((r) => r.matchedEventIds.length > 0).length,
    leads: leadReasons(plan),
    summary: summarizeSecondLook(plan),
    at: new Date().toISOString(),
  };
  await ctx.opts.synthMetaStore?.recordSecondLook(caseId, meta);

  return {
    promoted: meta.promoted,
    leads: meta.leads,
    summary: meta.summary,
    resynthesized: wantsResynthesis,
    shapeCapped: plan.shapeCapped,
    truncated: plan.truncated,
  };
}
