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
import type { WatsonChatStore } from "./chatStore.js";
import { WATSON_PASTE_MAX_BYTES } from "./pasteSearch.js";
import { WATSON_CASE_CONTEXT_PROMPT_MAX } from "./promptBuilder.js";
import { ensureStandardQuestions } from "./standardQuestions.js";
import type { WatsonPaste } from "./types.js";

// What a Watson round needs besides the AI-call seam, and the read-only helpers that build its
// prompt inputs. Watson reads the forensic timeline only — never the super-timeline (spec, §7).

export type WatsonRoundContext = AiCallContext & {
  chatStore: WatsonChatStore;
  stateStore: StateStore;
  stateLock: StateLock;
  cases: CaseStore;
  costStore: AiCostStore;
  provider: AIProvider;
  costLimitUSD?: number;
  /** The case's AI on/off switch (the route passes getControl(caseId).enabled). */
  isAiEnabled(caseId: string): Promise<boolean>;
  mainSourceStore?: CaseMainSourceStore;
  /** Host-identity sources, so Watson names hosts the way synthesis does. */
  assetOverridesStore?: AssetOverridesStore;
  velociraptorClientStore?: CaseFleetInventory;
};

/** Thrown before anything is saved when the case's AI switch is off. The route answers 409. */
export class WatsonAiOff extends Error {
  constructor() {
    super("AI is off for this case. Turn it on to talk to Watson.");
    this.name = "WatsonAiOff";
  }
}

/** Thrown before anything is saved when Watson's spend reached the case limit. The route answers 409. */
export class WatsonCostLimitReached extends Error {
  constructor(spentUSD: number, limitUSD: number) {
    super(
      `Watson reached this case's cost limit ($${spentUSD.toFixed(2)} of $${limitUSD.toFixed(2)}). ` +
        `Raise DFIR_AI_WATSON_COST_LIMIT_USD to continue.`,
    );
    this.name = "WatsonCostLimitReached";
  }
}

export function costLimitReached(ctx: WatsonRoundContext, spentUSD: number): boolean {
  return ctx.costLimitUSD !== undefined && spentUSD >= ctx.costLimitUSD;
}

/** The case's running Watson spend in the cost store (the `watson` bucket). */
export async function watsonSpend(ctx: WatsonRoundContext, caseId: string): Promise<number> {
  return (await ctx.costStore.load(caseId)).watson.totalCostUSD;
}

/** Add the six standard questions when the case has none of them. A deleted one stays deleted. */
export async function seedStandardQuestions(ctx: WatsonRoundContext, caseId: string): Promise<void> {
  await ctx.stateLock.runExclusive(caseId, async () => {
    const state = await ctx.stateStore.loadOverview(caseId);
    if (state.keyQuestions.some((q) => q.id.startsWith("wq-std-"))) return;
    await ctx.stateStore.saveOverview({
      ...state,
      keyQuestions: ensureStandardQuestions(state.keyQuestions),
    });
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
  const languages = families.map((f) => huntLanguageFor(f, enabled).language);
  return [...new Set(languages.filter((l): l is NonNullable<typeof l> => l !== null))];
}

const MAX_FINDINGS = 150;

/** The case block of Watson's prompt: synthesis context, path, findings, then timeline rows to fit. */
export async function buildWatsonCaseContext(
  ctx: WatsonRoundContext,
  caseId: string,
  state: InvestigationState,
): Promise<string> {
  const { scoped } = await loadScopedEvents(ctx, caseId, state);
  const aliasIndex = await loadCtxAliasIndex(ctx, caseId);
  const head =
    buildSynthesisContext(state, scoped, await ctx.getKevCatalog(), aliasIndex) +
    `ATTACKER PATH: ${state.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${
      state.findings
        .slice(0, MAX_FINDINGS)
        .map((f) => `[${f.id}] [${f.severity}] ${f.title}`)
        .join("\n") || "(none)"
    }\n\n`;
  return head + timelineBlock(scoped, WATSON_CASE_CONTEXT_PROMPT_MAX - head.length);
}

function timelineBlock(scoped: ForensicEvent[], budget: number): string {
  const title = `FORENSIC TIMELINE (${scoped.length} in-scope events, most significant first):\n`;
  const rows: string[] = [];
  let used = title.length;
  for (const e of selectSynthesisEvents(scoped, 400)) {
    const row = `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${promptDescription(e.description)}`;
    if (used + row.length + 1 > budget) break;
    rows.push(row);
    used += row.length + 1;
  }
  return title + (rows.join("\n") || "(no events shown)");
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
