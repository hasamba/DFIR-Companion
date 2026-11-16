import type { WatsonRoundDeps } from "../analysis/ai/watson/pipelineRound.js";
import { matchClient } from "../integrations/velociraptor/clientInventory.js";
import { blockMd } from "../reports/mdText.js";
import type { WatsonAutoDeps } from "../analysis/ai/watson/autoApply.js";
import type { WriterDeps } from "../analysis/ai/watson/proposals.js";
import type { WatsonRawSearchDeps } from "../analysis/ai/watson/superTimelineSearch.js";
import type { RouteContext } from "./context.js";
import { caseVeloConnected, watsonVeloLaunchDeps } from "./watsonVeloLaunch.js";
import { isFrozenCase } from "./importCaseGuard.js";
import { WATSON_MAX_TOOL_CALLS_CEILING } from "../analysis/ai/watson/toolMode.js";
import { watsonRuns } from "../analysis/ai/watson/runRegistry.js";

/** A positive finite number from a setting, else undefined: blank, junk, zero and negatives mean "no limit". */
export function positiveLimit(raw: string | undefined): number | undefined {
  const text = raw?.trim();
  const n = Number(text);
  return text && Number.isFinite(n) && n > 0 ? n : undefined;
}

export { caseVeloConnected };

const DEFAULT_MAX_TOOL_CALLS = 4;

/**
 * "Watson lookups per question" (D13): blank, junk or negative → 4; 0 → the one-step hop; decimals
 * are floored; above the ceiling → the ceiling.
 */
export function watsonMaxToolCalls(env: NodeJS.ProcessEnv): number {
  const text = env.DFIR_AI_WATSON_MAX_TOOL_CALLS?.trim();
  const n = Number(text);
  if (!text || !Number.isFinite(n) || n < 0) return DEFAULT_MAX_TOOL_CALLS;
  return Math.min(Math.floor(n), WATSON_MAX_TOOL_CALLS_CEILING);
}

/** AI off, a closed or archived case, or null: the same expression as rawSearch.writable (D5). */
const canContinueOf =
  (ctx: RouteContext) =>
  async (id: string): Promise<"off" | "frozen" | null> => {
    if (!(await ctx.getControl(id)).enabled) return "off";
    return (await isFrozenCase(ctx.store, id)) ? "frozen" : null;
  };

type Pipeline = NonNullable<RouteContext["options"]["pipeline"]>;
const promoteVia =
  (pipeline: Pipeline): NonNullable<WriterDeps["promoteEvents"]> =>
  (caseId, events, opts) =>
    pipeline.promoteSuperTimelineWithOutcome(caseId, events, opts);

/**
 * What applying a Watson proposal needs — an analyst's click and Auto mode alike, so both launch
 * through the same Velociraptor seam. Undefined when not wired.
 */
export function watsonProposalDeps(ctx: RouteContext): WriterDeps | undefined {
  const { options, store } = ctx;
  if (!options.watsonChatStore || !options.stateStore || !options.stateLock || !options.activityLogStore) {
    return undefined;
  }
  return {
    stateStore: options.stateStore,
    stateLock: options.stateLock,
    chatStore: options.watsonChatStore,
    activity: options.activityLogStore,
    cases: store,
    markConclusionsOutOfDate: ctx.markConclusionsOutOfDate,
    reportText: options.reportMetaStore,
    ...(options.pipeline ? { promoteEvents: promoteVia(options.pipeline) } : {}),
    veloLaunch: watsonVeloLaunchDeps(ctx),
  };
}

/**
 * The app's reaction scheduler, bound per route context once it exists (server.ts creates it after the
 * routes). Auto's "keep going" notes a case event on it, so Watson's own next round runs after the
 * usual quiet window and shows as due in the panel.
 */
const reactors = new WeakMap<
  RouteContext,
  { note(caseId: string, e: { kind: "continue"; text: string }): void }
>();
export function bindWatsonReactor(
  ctx: RouteContext,
  reactor: { note(caseId: string, e: { kind: "continue"; text: string }): void },
): void {
  reactors.set(ctx, reactor);
}

/** Auto mode's seams for a round; undefined when proposals cannot be applied on this server. */
function watsonAutoDeps(ctx: RouteContext): WatsonAutoDeps | undefined {
  const writer = watsonProposalDeps(ctx);
  if (!writer) return undefined;
  return {
    // A case closed or archived mid-round stops Auto like a switch to Approve (final review G4).
    control: async (id) => ({ ...(await ctx.getControl(id)), frozen: await isFrozenCase(ctx.store, id) }),
    writer,
    onStateChanged: (id) => ctx.options.onStateChanged?.(id),
    continueLater: (id, text) => reactors.get(ctx)?.note(id, { kind: "continue", text }),
  };
}

/**
 * Watson's one door to the raw record (D12): the super-timeline reader, the writer its promotion uses,
 * and the guard Auto uses too (AI on, case neither closed nor archived). Undefined when either is
 * missing: a super-timeline search is then skipped with a note.
 */
export function watsonRawSearchDeps(ctx: RouteContext): WatsonRawSearchDeps | undefined {
  const reader = ctx.options.superTimelineStore;
  const writer = watsonProposalDeps(ctx);
  if (!reader || !writer) return undefined;
  return {
    reader,
    writer,
    writable: async (id) => (await ctx.getControl(id)).enabled && !(await isFrozenCase(ctx.store, id)),
  };
}

/**
 * What a Watson round needs from the server: the shared chat store, the model and the limits. Read per
 * call so a Settings change applies at once. One builder for every caller — the Watson routes, the
 * `/dfir ask` slash command and the AI preview — so each runs the round on the same terms.
 * Undefined when Watson has no chat store or no model.
 */
export function watsonRoundDeps(ctx: RouteContext): WatsonRoundDeps | undefined {
  const { options, store } = ctx;
  const provider = options.watsonProvider?.();
  if (!options.watsonChatStore || !provider) return undefined;
  const auto = watsonAutoDeps(ctx);
  const rawSearch = watsonRawSearchDeps(ctx);
  return {
    chatStore: options.watsonChatStore,
    cases: store,
    provider,
    isAiEnabled: async (id) => (await ctx.getControl(id)).enabled,
    maxToolCalls: watsonMaxToolCalls(process.env),
    canContinue: canContinueOf(ctx),
    costLimitUSD: positiveLimit(process.env.DFIR_AI_WATSON_COST_LIMIT_USD),
    tokenLimit: positiveLimit(process.env.DFIR_AI_WATSON_TOKEN_LIMIT),
    reportText: options.reportMetaStore,
    reportBlockText: blockMd,
    onStateChanged: options.onStateChanged,
    veloConnected: (id) => caseVeloConnected(ctx, id),
    matchClient,
    ...(auto ? { auto } : {}),
    ...(rawSearch ? { rawSearch } : {}),
    runs: watsonRuns, // the stop and "Watson is working" (routes/watsonMessage.ts)
    onRunChange: (id) => options.onWatson?.(id),
  };
}
