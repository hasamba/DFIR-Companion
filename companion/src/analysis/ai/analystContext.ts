import type { AiControlStore } from "../aiControl.js";
import type { AskTurn } from "../askHistory.js";
import type { CommentsStore } from "../comments.js";
import type { DwellWindowStore } from "../dwellWindowStore.js";
import { withResolvedTargets, type EventResolver } from "../eventAliasLookup.js";
import { DEFAULT_MAX_GRAPH_EDGES } from "../graphContext.js";
import type { HostScopeStore } from "../hostScopeStore.js";
import { renderPriorHuntsBlock } from "../huntOutcomes.js";
import type { HuntOutcomeStore } from "../huntOutcomeStore.js";
import { resolveHypothesisLinks } from "../hypothesisLineage.js";
import type { HypothesisStore } from "../hypothesisStore.js";
import type { NotebookStore } from "../notebookStore.js";
import type { TagsStore } from "../tags.js";
import {
  renderAnalystMarksBlock,
  renderAskHistoryBlock,
  renderAskHypothesesBlock,
  renderAskNotebookBlock,
  renderDwellWindowsBlock,
  renderHostScopeBlock,
} from "./askContext.js";

/**
 * The analyst's own work on the case, as prompt blocks, shared by every chat-shaped AI call (Ask,
 * Watson). Reads side files only — never the super-timeline.
 */

/**
 * The four analyst-decision stores the chat calls read that the pipeline's AI context did not
 * already carry (#1411). Getters, not a snapshot, like the rest of the pipeline's `aiCtx.opts`
 * literal: a store wired after construction is still seen. Spread into that literal so pipeline.ts
 * grows by one line.
 */
export interface AnalystDecisionStores {
  tagsStore?: TagsStore;
  commentsStore?: CommentsStore;
  hostScopeStore?: HostScopeStore;
  dwellWindowStore?: DwellWindowStore;
}

export function analystDecisionOpts(opts: AnalystDecisionStores): AnalystDecisionStores {
  return {
    get tagsStore() {
      return opts.tagsStore;
    },
    get commentsStore() {
      return opts.commentsStore;
    },
    get hostScopeStore() {
      return opts.hostScopeStore;
    },
    get dwellWindowStore() {
      return opts.dwellWindowStore;
    },
  };
}

/** Everything analystDecisionBlocks reads: the four decision stores plus hypotheses, hunts, notebook. */
export interface AnalystContextHost {
  readonly opts: AnalystDecisionStores & {
    hypothesisStore?: HypothesisStore;
    huntOutcomeStore?: HuntOutcomeStore;
    notebookStore?: NotebookStore;
    aiControlStore?: AiControlStore;
  };
}

/**
 * Every store is optional and every block is "" when empty; the notebook honours the same opt-in
 * synthesis does (ai-control.json `includeNotebook`), so a private note never reaches a model the
 * analyst did not point at it.
 */
export async function analystDecisionBlocks(
  ctx: AnalystContextHost,
  caseId: string,
  history: readonly AskTurn[],
  resolve: EventResolver,
): Promise<string> {
  const o = ctx.opts;
  const [hypotheses, decisions, windows, outcomes, tags, comments, notebook] = await Promise.all([
    o.hypothesisStore?.load(caseId) ?? [],
    o.hostScopeStore?.load(caseId) ?? [],
    o.dwellWindowStore?.list(caseId) ?? [],
    o.huntOutcomeStore?.load(caseId) ?? [],
    o.tagsStore?.load(caseId) ?? [],
    o.commentsStore?.load(caseId) ?? [],
    loadNotebookIfOptedIn(ctx, caseId),
  ]);
  // The model is told to cite these ids, so each one names the event it lives on today (#1715).
  const onLiveEvent = <T extends { targetType: string; targetId: string }>(list: readonly T[]) =>
    withResolvedTargets(list, resolve).map((r) => ({ ...r, targetId: r.resolvedTargetId ?? r.targetId }));
  return (
    renderAskHypothesesBlock(hypotheses.map((h) => resolveHypothesisLinks(h, resolve))) +
    renderHostScopeBlock(decisions) +
    renderDwellWindowsBlock(windows) +
    renderPriorHuntsBlock(outcomes) +
    renderAnalystMarksBlock(onLiveEvent(tags), onLiveEvent(comments)) +
    renderAskNotebookBlock(notebook) +
    renderAskHistoryBlock(history)
  );
}

export async function loadNotebookIfOptedIn(ctx: AnalystContextHost, caseId: string) {
  if (!ctx.opts.notebookStore || !ctx.opts.aiControlStore) return [];
  const control = await ctx.opts.aiControlStore.load(caseId);
  return control.includeNotebook ? ctx.opts.notebookStore.load(caseId) : [];
}

/**
 * Max causal edges of the evidence-chain graph a chat call carries (GraphRAG, #98):
 * `DFIR_AI_WATSON_GRAPH_MAX_EDGES`, else the old `DFIR_ASK_GRAPH_MAX_EDGES`, else the default.
 */
export function graphMaxEdges(env: NodeJS.ProcessEnv = process.env): number {
  return (
    Number(env.DFIR_AI_WATSON_GRAPH_MAX_EDGES) ||
    Number(env.DFIR_ASK_GRAPH_MAX_EDGES) ||
    DEFAULT_MAX_GRAPH_EDGES
  );
}
