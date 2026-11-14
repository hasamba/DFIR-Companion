import { WatsonReactor } from "../analysis/ai/watson/reactor.js";
import { frozenCaseRefusal } from "../routes/importCaseGuard.js";
import type { RouteContext } from "../routes/context.js";
import { watsonRoundDeps } from "../routes/watsonDeps.js";
import { warnLine } from "../logging/serverLogger.js";

/** D4: reactions on by default, after a 60-second quiet window. */
export const WATSON_REACT_DELAY_DEFAULT_SEC = 60;

/** DFIR_AI_WATSON_REACT_DELAY_SEC in milliseconds: 0 = off; blank, junk or negative = the default. */
export function watsonReactDelayMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.DFIR_AI_WATSON_REACT_DELAY_SEC?.trim();
  const n = Number(raw);
  const sec = raw && Number.isFinite(n) && n >= 0 ? n : WATSON_REACT_DELAY_DEFAULT_SEC;
  return Math.round(sec * 1000);
}

/**
 * The ONE Watson reaction scheduler of an app (spec §4.6). It writes through the same chat store the
 * Watson routes use and runs the round on the same terms (watsonRoundDeps, read per fire so a
 * Settings change applies at once). Undefined when the app has no Watson chat store.
 */
export function createAppWatsonReactor(
  ctx: RouteContext,
  isSynthesisBusy: (caseId: string) => boolean,
): WatsonReactor | undefined {
  const { options, store } = ctx;
  const chatStore = options.watsonChatStore;
  if (!chatStore) return undefined;
  return new WatsonReactor({
    chatStore,
    // No model or no pipeline counts as "AI off" for a reaction: it skips without a word.
    isAiEnabled: async (caseId) => {
      const deps = watsonRoundDeps(ctx);
      return Boolean(deps && options.pipeline) && (await deps!.isAiEnabled(caseId));
    },
    runRound: async (caseId, input) => {
      const deps = watsonRoundDeps(ctx);
      if (!deps || !options.pipeline) throw new Error("Watson has no model");
      return options.pipeline.watsonRound(caseId, input, deps);
    },
    isSynthesisBusy,
    isFrozen: async (caseId) => (await frozenCaseRefusal(store, caseId)) !== null,
    delayMs: () => watsonReactDelayMs(process.env),
    onChanged: (caseId) => options.onWatson?.(caseId),
    log: warnLine,
  });
}
