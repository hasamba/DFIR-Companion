import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type { AIProvider } from "../../../providers/provider.js";
import type { CaseStore } from "../../../storage/caseStore.js";
import type { AiCostStore } from "../../aiCost.js";
import type { AnonControlStore } from "../../anonControl.js";
import type { AssetOverridesStore } from "../../assetOverrides.js";
import type { CaseFleetInventory } from "../../velociraptorClientStore.js";
import { computeMainSource, type SourceFamily } from "../../caseMainSource.js";
import type { CaseMainSourceStore } from "../../caseMainSourceStore.js";
import { enabledHuntPlatforms, huntLanguageFor } from "../../huntLanguage.js";
import type { StateLock } from "../../stateLock.js";
import { SendStopped } from "../sendStop.js";
import type { StateStore } from "../../stateStore.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { buildSynthesisContext } from "../../synthSelect.js";
import { loadCtxAliasIndex, loadScopedEvents, type AiCallContext } from "../aiContext.js";
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
import type { WatsonCoverage, WatsonPaste } from "./types.js";
import type { LaunchContext } from "./velo/launchCheck.js";
import type { WatsonAutoDeps } from "./autoApply.js";
import type { WatsonRunRegistry } from "./runRegistry.js";
import type { WatsonRawSearchDeps } from "./superTimelineSearch.js";
import type { WatsonReportText } from "./writers/writerTypes.js";

// What a Watson round needs besides the AI-call seam, and the read-only helpers that build its
// prompt inputs. Watson's packet and its lookups read the forensic timeline only. It reads the raw
// record only through the `rawSearch` seam: one bounded, targeted search per analyst round, never in
// a reaction round, and only through superTimelineSearch.ts (CLAUDE.md §7, phase 4).

export type WatsonRoundContext = AiCallContext & {
  /** The analyst's own decisions Watson reads, as Ask did (carried by the pipeline's AI context). */
  opts: AnalystDecisionStores & {
    hypothesisStore?: HypothesisStore;
    huntOutcomeStore?: HuntOutcomeStore;
    notebookStore?: NotebookStore;
    aiControlStore?: AiControlStore;
    /** The case's anonymization switch (the AI-call gate reads the same store). */
    anonStore?: AnonControlStore;
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
  /** Tool calls per analyst question (DFIR_AI_WATSON_MAX_TOOL_CALLS, phase 5). Absent or 0: the one-step hop. */
  maxToolCalls?: number;
  /** Checked before every model call (D5): AI off, a closed or archived case, or null. Absent: isAiEnabled. */
  canContinue?(caseId: string): Promise<"off" | "frozen" | null>;
  mainSourceStore?: CaseMainSourceStore;
  /** Host-identity sources, so Watson names hosts the way synthesis does. */
  assetOverridesStore?: AssetOverridesStore;
  velociraptorClientStore?: CaseFleetInventory;
  /** Whether the case has a Velociraptor server (the route knows; the pipeline does not). Absent: no. */
  veloConnected?(caseId: string): boolean;
  /** The inventory host matcher for launch checks, injected (analysis/ai may not import integrations). */
  matchClient?: LaunchContext["matchClient"];
  /** The report details, for the text a report-text proposal would replace. Absent: none proposed. */
  reportText?: WatsonReportText;
  /** Report text made safe for report.md (reports' blockMd, injected). Absent: none proposed. */
  reportBlockText?(text: string): string;
  /** Tells the dashboard the case state changed (the standard questions were seeded). */
  onStateChanged?(caseId: string): void;
  /** Auto mode's seams (route-built); absent: Watson only proposes, whatever the case's mode. */
  auto?: WatsonAutoDeps;
  /** Watson's ONE door to the raw record (route-built, D12). Absent: a super-timeline search is skipped. */
  rawSearch?: WatsonRawSearchDeps;
  /** The round's stop signal (runWatsonRound sets it from the run registry). Aborted: Watson stops. */
  signal?: AbortSignal;
  /** The per-case registry of running rounds (memory only). Absent: a round cannot be stopped. */
  runs?: WatsonRunRegistry;
  /** Tells the dashboard a round started or ended on the case. */
  onRunChange?(caseId: string): void;
};

/** The stop note. No class name in it: system turns may reach later prompts. */
export const WATSON_CANCELLED_TEXT =
  "Watson stopped this answer because an analyst selected Stop. Watson did not propose changes after the stop.";

/** An analyst stopped the round (run registry cancel). Never retried: it extends SendStopped. */
export class WatsonCancelled extends SendStopped {
  constructor(text: string = WATSON_CANCELLED_TEXT) {
    super(text);
    this.name = "WatsonCancelled";
  }
}

/**
 * #2639: a round has a wall-clock limit, so a provider that accepts the connection and never answers
 * cannot hold the round, its Idempotency-Key entry and every resend forever. The limit is
 * WATSON_ROUND_TIMEOUT_FACTOR times the AI request timeout (DFIR_AI_TIMEOUT_MS, default 15 minutes),
 * so it follows the setting the analyst already has. It is cooperative: it aborts the round's signal,
 * which every provider request and every Watson check observes. It is a stop like an analyst's
 * (before the commit point the reply is dropped; after it the saved work stays), but it counts as a
 * failed reaction, so repeated hangs pause the automatic reactions.
 */
export const WATSON_ROUND_TIMEOUT_FACTOR = 2;
const AI_TIMEOUT_DEFAULT_MS = 900_000;
/** setTimeout fires at once for a delay above 2^31-1 ms. */
const TIMER_MAX_MS = 2_147_483_647;

export function watsonRoundMaxMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.DFIR_AI_TIMEOUT_MS);
  const request = Number.isFinite(raw) && raw > 0 ? raw : AI_TIMEOUT_DEFAULT_MS;
  return Math.min(TIMER_MAX_MS, Math.round(request * WATSON_ROUND_TIMEOUT_FACTOR));
}

export class WatsonRoundTimedOut extends WatsonCancelled {
  constructor(maxMs: number) {
    const minutes = Math.max(1, Math.round(maxMs / 60_000));
    super(
      `Watson stopped this answer after ${minutes} minute${minutes === 1 ? "" : "s"}, because the round did not finish in time. ` +
        "The AI provider may not answer. Check the provider in Settings, then send your message again.",
    );
    this.name = "WatsonRoundTimedOut";
  }
}

/** Thrown before anything is saved when the case's AI switch is off. The route answers 409. */
export class WatsonAiOff extends SendStopped {
  constructor() {
    super("AI is off for this case. Turn it on to talk to Watson.");
    this.name = "WatsonAiOff";
  }
}

/** Thrown before a model call when the case was closed or archived during the round (D5). */
export class WatsonCaseFrozen extends SendStopped {
  constructor() {
    super("The case was closed or archived, so Watson stopped.");
    this.name = "WatsonCaseFrozen";
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

/** True when the case already has at least one of the six standard questions. */
export const hasStandardQuestions = (s: Pick<InvestigationState, "keyQuestions">): boolean =>
  s.keyQuestions.some((q) => q.id.startsWith("wq-std-"));

/**
 * Add the six standard questions when the case has none of them. A deleted one stays deleted. The
 * cheap check runs first, so the state lock is taken only on the round that actually seeds. True
 * when this call saved them.
 */
export async function seedStandardQuestions(ctx: WatsonRoundContext, caseId: string): Promise<boolean> {
  if (hasStandardQuestions(await ctx.stateStore.loadOverview(caseId))) return false;
  return ctx.stateLock.runExclusive(caseId, async () => {
    const state = await ctx.stateStore.loadOverview(caseId);
    if (hasStandardQuestions(state)) return false;
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

/** The case block of Watson's prompt (everything but the timeline), and what the timeline is built from. */
export interface WatsonCaseHead {
  text: string;
  /** The analyst-decision section was cut to its share of the budget. */
  decisionsTrimmed: boolean;
  /** The synthesis/graph/findings head was cut to fit. */
  headTrimmed: boolean;
  /** The in-scope forensic timeline (scope and false-positive marks applied). */
  scoped: ForensicEvent[];
  aliasIndex: Awaited<ReturnType<typeof loadCtxAliasIndex>>;
}

/** The decision section may take at most this share of the case-context budget. */
export const WATSON_DECISION_SHARE = 0.4;
const trimNote = (what: string): string => `\n(${what} trimmed to fit the prompt)\n\n`;

// Cut at a line boundary so no half-line survives, and say so in the text the model reads.
function clipTo(text: string, max: number, what: string): { text: string; trimmed: boolean } {
  if (text.length <= max) return { text, trimmed: false };
  const note = trimNote(what);
  const cut = text.slice(0, Math.max(0, max - note.length));
  return { text: cut.slice(0, Math.max(cut.lastIndexOf("\n"), 0)) + note, trimmed: true };
}

/** What the turn stores so the panel can disclose a trim: null when nothing was trimmed. */
export function coverageOf(head: WatsonCaseHead, timeline: { used: number }): WatsonCoverage | undefined {
  const eventCount = head.scoped.length;
  if (timeline.used >= eventCount && !head.decisionsTrimmed && !head.headTrimmed) return undefined;
  return {
    usedEvents: timeline.used,
    eventCount,
    ...(head.decisionsTrimmed ? { decisionsTrimmed: true } : {}),
    ...(head.headTrimmed ? { headTrimmed: true } : {}),
  };
}

/**
 * The CASE CONTEXT block of Watson's prompt — what Ask carried: synthesis context, the evidence-chain
 * graph, path, findings and the analyst's own decisions — at most WATSON_CASE_CONTEXT_PROMPT_MAX, so the
 * prompt builder's own clip never cuts anything. The forensic timeline is its own block (#2658), sized
 * from the model's window once the rest of the prompt is measured (requestBuild.ts).
 */
export async function buildWatsonCaseHead(
  ctx: WatsonRoundContext,
  caseId: string,
  state: InvestigationState,
): Promise<WatsonCaseHead> {
  const { scoped } = await loadScopedEvents(ctx, caseId, state);
  const aliasIndex = await loadCtxAliasIndex(ctx, caseId);
  const rawHead =
    buildSynthesisContext(state, scoped, await ctx.getKevCatalog(), aliasIndex) +
    buildGraphContext({ ...state, forensicTimeline: scoped }, { maxEdges: graphMaxEdges() }) +
    `ATTACKER PATH: ${state.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${
      state.findings
        .slice(0, MAX_FINDINGS)
        .map((f) => `[${f.id}] [${f.severity}]${f.status === "dismissed" ? " (dismissed)" : ""} ${f.title}`)
        .join("\n") || "(none)"
    }\n\n`;
  const max = WATSON_CASE_CONTEXT_PROMPT_MAX;
  const decisions = clipTo(
    await analystDecisionBlocks(ctx, caseId, stateEventResolver(state)),
    Math.floor(max * WATSON_DECISION_SHARE),
    "analyst decisions",
  );
  const head = clipTo(rawHead, max - decisions.text.length, "case context");
  return {
    text: head.text + decisions.text,
    decisionsTrimmed: decisions.trimmed,
    headTrimmed: head.trimmed,
    scoped,
    aliasIndex,
  };
}

/**
 * The text of a stored paste. `storedName` comes from a chat file that travels with an exported
 * case, so it must be a bare file name inside the case's imports folder, and the size is checked
 * before anything is read.
 */
export async function readPasteText(cases: CaseStore, caseId: string, paste: WatsonPaste): Promise<string> {
  const name = paste.storedName;
  if (!name || name !== basename(name) || name.startsWith(".") || /[\\/:]/.test(name)) {
    throw new Error("Watson cannot read the pasted text. Its stored file name is not valid.");
  }
  const path = join(cases.importsDir(caseId), name);
  const info = await stat(path);
  if (info.size > WATSON_PASTE_MAX_BYTES)
    throw new Error("The pasted text is too large. Watson cannot read it.");
  return readFile(path, "utf8");
}
