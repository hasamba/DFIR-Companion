import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type { AIProvider } from "../../../providers/provider.js";
import type { CaseStore } from "../../../storage/caseStore.js";
import type { AiCostStore } from "../../aiCost.js";
import type { AssetOverridesStore } from "../../assetOverrides.js";
import type { CaseFleetInventory } from "../../velociraptorClientStore.js";
import { computeMainSource, type SourceFamily } from "../../caseMainSource.js";
import type { CaseMainSourceStore } from "../../caseMainSourceStore.js";
import { enabledHuntPlatforms, huntLanguageFor } from "../../huntLanguage.js";
import type { StateLock } from "../../stateLock.js";
import type { StateStore } from "../../stateStore.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { buildSynthesisContext, selectSynthesisEvents } from "../../synthSelect.js";
import { loadCtxAliasIndex, loadScopedEvents, type AiCallContext } from "../aiContext.js";
import { promptDescription } from "../promptDescription.js";
import { analystDecisionBlocks, graphMaxEdges, type AnalystDecisionStores } from "../analystContext.js";
import { stateEventResolver } from "../../eventAliasLookup.js";
import { buildGraphContext } from "../../graphContext.js";
import type { HuntOutcomeStore } from "../../huntOutcomeStore.js";
import type { HypothesisStore } from "../../hypothesisStore.js";
import type { NotebookStore } from "../../notebookStore.js";
import type { AiControlStore } from "../../aiControl.js";
import type { WatsonChatStore } from "./chatStore.js";
import { WATSON_PASTE_MAX_BYTES } from "./pasteSearch.js";
import { WATSON_CASE_CONTEXT_PROMPT_MAX } from "./promptBuilder.js";
import { ensureStandardQuestions } from "./standardQuestions.js";
import type { WatsonPaste } from "./types.js";

// What a Watson round needs besides the AI-call seam, and the read-only helpers that build its
// prompt inputs. Watson reads the forensic timeline only — never the super-timeline (spec, §7).

export type WatsonRoundContext = AiCallContext & {
  /** The analyst's own decisions Watson reads, as Ask did (carried by the pipeline's AI context). */
  opts: AnalystDecisionStores & {
    hypothesisStore?: HypothesisStore;
    huntOutcomeStore?: HuntOutcomeStore;
    notebookStore?: NotebookStore;
    aiControlStore?: AiControlStore;
  };
  chatStore: WatsonChatStore;
  stateStore: StateStore;
  stateLock: StateLock;
  cases: CaseStore;
  costStore: AiCostStore;
  provider: AIProvider;
  costLimitUSD?: number;
  /** Input + output tokens; the limit that still works when the provider reports no dollar cost. */
  tokenLimit?: number;
  /** The case's AI on/off switch (the route passes getControl(caseId).enabled). */
  isAiEnabled(caseId: string): Promise<boolean>;
  mainSourceStore?: CaseMainSourceStore;
  /** Host-identity sources, so Watson names hosts the way synthesis does. */
  assetOverridesStore?: AssetOverridesStore;
  velociraptorClientStore?: CaseFleetInventory;
  /** Tells the dashboard the case state changed (the standard questions were seeded). */
  onStateChanged?(caseId: string): void;
};

/** Thrown before anything is saved when the case's AI switch is off. The route answers 409. */
export class WatsonAiOff extends Error {
  constructor() {
    super("AI is off for this case. Turn it on to talk to Watson.");
    this.name = "WatsonAiOff";
  }
}

/** Thrown before anything is saved when Watson's spend reached a case limit. The route answers 409. */
export class WatsonCostLimitReached extends Error {
  constructor(reason: string) {
    super(`Watson reached this case's ${reason}. Raise the limit in Settings to continue.`);
    this.name = "WatsonCostLimitReached";
  }
}

/** What Watson has used on a case: dollars, and tokens for providers that report no dollar cost. */
export interface WatsonSpend {
  usd: number;
  tokens: number;
}

export const NO_SPEND: WatsonSpend = { usd: 0, tokens: 0 };

/** Which limit `spent` reached, in words, or null when Watson may still call the model. */
export function limitReached(ctx: WatsonRoundContext, spent: WatsonSpend): string | null {
  if (ctx.costLimitUSD !== undefined && spent.usd >= ctx.costLimitUSD) {
    return `cost limit ($${spent.usd.toFixed(2)} of $${ctx.costLimitUSD.toFixed(2)})`;
  }
  if (ctx.tokenLimit !== undefined && spent.tokens >= ctx.tokenLimit) {
    return `token limit (${spent.tokens.toLocaleString("en-US")} of ${ctx.tokenLimit.toLocaleString("en-US")} tokens)`;
  }
  return null;
}

/** The case's running Watson spend in the cost store (the `watson` bucket). */
export async function watsonSpend(ctx: WatsonRoundContext, caseId: string): Promise<WatsonSpend> {
  const b = (await ctx.costStore.load(caseId)).watson;
  return { usd: b.totalCostUSD, tokens: b.totalInputTokens + b.totalOutputTokens };
}

/** What a round used: `after` minus `before`, never negative. */
export function spendDelta(before: WatsonSpend, after: WatsonSpend): WatsonSpend {
  return { usd: Math.max(0, after.usd - before.usd), tokens: Math.max(0, after.tokens - before.tokens) };
}

const hasStandard = (s: InvestigationState): boolean =>
  s.keyQuestions.some((q) => q.id.startsWith("wq-std-"));

/**
 * Add the six standard questions when the case has none of them. A deleted one stays deleted. The
 * cheap check runs first, so the state lock is taken only on the round that actually seeds. True
 * when this call saved them.
 */
export async function seedStandardQuestions(ctx: WatsonRoundContext, caseId: string): Promise<boolean> {
  if (hasStandard(await ctx.stateStore.loadOverview(caseId))) return false;
  return ctx.stateLock.runExclusive(caseId, async () => {
    const state = await ctx.stateStore.loadOverview(caseId);
    if (hasStandard(state)) return false;
    await ctx.stateStore.saveOverview({
      ...state,
      keyQuestions: ensureStandardQuestions(state.keyQuestions),
    });
    return true;
  });
}

/** The hunt languages the case's main evidence source calls for (all of them on a mixed case). */
export async function mainLanguages(
  ctx: WatsonRoundContext,
  caseId: string,
  state: InvestigationState,
): Promise<string[]> {
  const override = await (ctx.mainSourceStore?.load(caseId) ?? Promise.resolve(null)).catch(() => null);
  const main = computeMainSource(state.forensicTimeline, override);
  const families: SourceFamily[] =
    main.effective === "mixed" ? main.counts.map((c) => c.family) : main.effective ? [main.effective] : [];
  const enabled = enabledHuntPlatforms();
  // Watson's reply schema speaks one "kql"; the hunt planner splits it by platform.
  const languages = families.map((f) => huntLanguageFor(f, enabled).language?.replace(/^kql-.*/, "kql"));
  return [...new Set(languages.filter((l): l is string => typeof l === "string"))];
}

const MAX_FINDINGS = 150;

/** The case block of Watson's prompt, and how much of the in-scope timeline it carries. */
export interface WatsonCaseContext {
  text: string;
  usedEvents: number;
  eventCount: number;
}

/**
 * The case block of Watson's prompt — what Ask carried: synthesis context, the evidence-chain graph,
 * path, findings and the analyst's own decisions — then forensic-timeline rows to fit the budget.
 * The chat is Watson's own, so no Q&A history block.
 */
export async function buildWatsonCaseContext(
  ctx: WatsonRoundContext,
  caseId: string,
  state: InvestigationState,
): Promise<WatsonCaseContext> {
  const { scoped } = await loadScopedEvents(ctx, caseId, state);
  const aliasIndex = await loadCtxAliasIndex(ctx, caseId);
  const head =
    buildSynthesisContext(state, scoped, await ctx.getKevCatalog(), aliasIndex) +
    buildGraphContext({ ...state, forensicTimeline: scoped }, { maxEdges: graphMaxEdges() }) +
    `ATTACKER PATH: ${state.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${
      state.findings
        .slice(0, MAX_FINDINGS)
        .map((f) => `[${f.id}] [${f.severity}] ${f.title}`)
        .join("\n") || "(none)"
    }\n\n` +
    (await analystDecisionBlocks(ctx, caseId, [], stateEventResolver(state)));
  const timeline = timelineBlock(scoped, WATSON_CASE_CONTEXT_PROMPT_MAX - head.length);
  return { text: head + timeline.text, usedEvents: timeline.used, eventCount: scoped.length };
}

function timelineBlock(scoped: ForensicEvent[], budget: number): { text: string; used: number } {
  const title = `FORENSIC TIMELINE (${scoped.length} in-scope events, most significant first):\n`;
  const rows: string[] = [];
  let used = title.length;
  for (const e of selectSynthesisEvents(scoped, 400)) {
    const row = `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${promptDescription(e.description)}`;
    if (used + row.length + 1 > budget) break;
    rows.push(row);
    used += row.length + 1;
  }
  return { text: title + (rows.join("\n") || "(no events shown)"), used: rows.length };
}

/**
 * The text of a stored paste. `storedName` comes from a chat file that travels with an exported
 * case, so it must be a bare file name inside the case's imports folder, and the size is checked
 * before anything is read.
 */
export async function readPasteText(cases: CaseStore, caseId: string, paste: WatsonPaste): Promise<string> {
  const name = paste.storedName;
  if (!name || name !== basename(name) || name.startsWith(".") || /[\\/:]/.test(name)) {
    throw new Error("The pasted text cannot be read: its stored file name is not valid.");
  }
  const path = join(cases.importsDir(caseId), name);
  const info = await stat(path);
  if (info.size > WATSON_PASTE_MAX_BYTES) throw new Error("The pasted text is too large to read.");
  return readFile(path, "utf8");
}
