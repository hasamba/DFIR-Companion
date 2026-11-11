import type { AIProvider } from "../../providers/provider.js";
import { withEventTechniques } from "../eventTechniques.js";
import { buildGraphContext, DEFAULT_MAX_GRAPH_EDGES } from "../graphContext.js";
import { LANGUAGE_LABELS, LANGUAGE_SCHEMA_HINTS, type CopyHuntLanguage } from "../huntLanguage.js";
import { HUNT_SUGGEST_MAX_DEFAULT, renderHuntFindings, renderHuntIocs } from "../huntSuggest.js";
import {
  languageHuntResponseSchema,
  sanitizeLanguageHunts,
  sanitizePlaybookLanguageHunts,
  type LanguageHuntSuggestion,
  type PlaybookLanguageHunt,
} from "../languageHuntSuggest.js";
import type { PlaybookTask } from "../playbook.js";
import {
  buildTaskEndpointsMap,
  PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT,
  renderPlaybookHuntTasks,
} from "../playbookHunt.js";
import { estimateTokens, fitItemsToBudget, remainingBudget } from "../promptBudget.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { selectSynthesisEvents } from "../synthSelect.js";
import { maxPromptEvents } from "../synthGroup.js";
import { callAiJson, loadScopedEvents } from "./aiContext.js";
import type { HuntContext } from "./hunts.js";
import { LANGUAGE_HUNT_PROMPT, PLAYBOOK_LANGUAGE_HUNT_PROMPT } from "./prompts/languageHunt.js";
import { promptDescription } from "./promptDescription.js";

/**
 * AI-written behaviour hunts in a non-VQL language (#2559): the sibling of suggestHunts /
 * suggestPlaybookHunts in hunts.ts, which stay the VQL path, untouched.
 *
 * Deliberately different from the VQL calls:
 * - the broad synthesis model, as translateQuery uses — the VQL-tuned velociraptorProvider is the
 *   wrong model for KQL/SPL/ES|QL/CQL;
 * - no PRIOR HUNTS ledger blocks, no deployed-VQL exclusion, no artifact list, no targetHost/mode:
 *   all of that describes Velociraptor deploys, and these hunts are copy-ready only;
 * - the timeline is the case's FORENSIC timeline in scope (loadScopedEvents) — never the
 *   super-timeline (§7).
 * EPHEMERAL like the VQL calls — nothing here mutates the case.
 */

const providerOf = (ctx: HuntContext, label: string): AIProvider =>
  ctx.opts.synthesisProvider ?? ctx.requireProvider(label);

const HUNT_OVERHEAD_SLACK_TOKENS = 300;

/** The sanitizer drops answers silently by design; say how many, so a model writing the wrong language shows up. */
function noteDropped<T>(
  ctx: HuntContext,
  caseId: string,
  language: CopyHuntLanguage,
  answered: number,
  kept: T[],
): T[] {
  const dropped = answered - kept.length;
  if (dropped > 0)
    ctx.log?.warn(
      `[hunts] dropped ${dropped} of ${answered} ${language} hunt answer(s): empty, over the cap, a repeat, or not ${LANGUAGE_LABELS[language]}`,
      { caseId },
    );
  return kept;
}

function languageBlock(language: CopyHuntLanguage): string {
  return `TARGET LANGUAGE: ${language} — ${LANGUAGE_LABELS[language]}\nSCHEMA:\n${LANGUAGE_SCHEMA_HINTS[language]}\n\n`;
}

const excludeNote = (exclude?: string): string =>
  exclude
    ? `ALREADY SUGGESTED (this query was already shown to the analyst — write something DIFFERENT that investigates from another angle):\n${exclude}\n\n`
    : "";

function renderTimeline(
  scoped: ForensicEvent[],
  max: number,
  systemPrompt: string,
  overhead: string,
): string {
  const render = (e: ForensicEvent): string =>
    `[${e.timestamp || "(undated)"}] [${e.severity}]${e.asset ? ` <${e.asset}>` : ""} ${promptDescription(e.description)}`;
  let events = selectSynthesisEvents(scoped, max);
  const used = estimateTokens(systemPrompt) + estimateTokens(overhead) + HUNT_OVERHEAD_SLACK_TOKENS;
  const fit = fitItemsToBudget(events, render, remainingBudget(used));
  if (fit < events.length) events = selectSynthesisEvents(scoped, fit);
  return events.map(render).join("\n") || "(no events yet)";
}

function fleetPrompt(
  loaded: InvestigationState,
  scoped: ForensicEvent[],
  language: CopyHuntLanguage,
  findingIds: ReadonlySet<string> | undefined,
  exclude?: string,
): string {
  const findings = findingIds ? loaded.findings.filter((f) => findingIds.has(f.id)) : loaded.findings;
  const findingsText = renderHuntFindings(findings);
  const iocText = renderHuntIocs(loaded.iocs);
  const techText =
    withEventTechniques({ ...loaded, forensicTimeline: scoped })
      .mitreTechniques.map((t) => `${t.id} ${t.name}`)
      .join(", ") || "(none)";
  const graph = buildGraphContext(
    { ...loaded, forensicTimeline: scoped },
    { maxEdges: DEFAULT_MAX_GRAPH_EDGES },
  );
  const leading = languageBlock(language) + graph;
  const timeline = renderTimeline(
    scoped,
    maxPromptEvents(),
    LANGUAGE_HUNT_PROMPT,
    leading + findingsText + iocText + techText + (loaded.attackerPath || ""),
  );
  return (
    leading +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `ATT&CK TECHNIQUES: ${techText}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `PIVOTABLE INDICATORS:\n${iocText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timeline}\n\n` +
    excludeNote(exclude) +
    `Propose the ${LANGUAGE_LABELS[language]} hunts as JSON.`
  );
}

/** Behaviour hunts in `language` for the given findings (all live findings when omitted). */
export async function suggestLanguageHunts(
  ctx: HuntContext,
  caseId: string,
  language: CopyHuntLanguage,
  opts: { findingIds?: readonly string[]; exclude?: string } = {},
): Promise<LanguageHuntSuggestion[]> {
  const provider = providerOf(ctx, "hunt suggestions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);
  const ids = opts.findingIds ? new Set(opts.findingIds) : undefined;
  const userPrompt = fleetPrompt(loaded, scoped, language, ids, opts.exclude);
  const allowed = ids ?? new Set(loaded.findings.map((f) => f.id));
  const max = Number(process.env.DFIR_HUNT_SUGGEST_MAX) || HUNT_SUGGEST_MAX_DEFAULT;
  return callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "suggest-language-hunts",
    LANGUAGE_HUNT_PROMPT,
    userPrompt,
    (raw) => {
      const answers = languageHuntResponseSchema.parse(raw).suggestions;
      const kept = sanitizeLanguageHunts(answers, language, {
        allowedFindingIds: allowed,
        exclude: opts.exclude,
        max,
      });
      return noteDropped(ctx, caseId, language, answers.length, kept);
    },
  );
}

/** One query in `language` per playbook task the model judges a query can serve. */
export async function suggestPlaybookLanguageHunts(
  ctx: HuntContext,
  caseId: string,
  tasks: PlaybookTask[],
  language: CopyHuntLanguage,
  opts: { exclude?: string } = {},
): Promise<PlaybookLanguageHunt[]> {
  if (!tasks.length) return [];
  const provider = providerOf(ctx, "playbook hunt suggestions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);
  const tasksText = renderPlaybookHuntTasks(tasks, buildTaskEndpointsMap(loaded, tasks));
  const findingsText = renderHuntFindings(loaded.findings);
  const iocText = renderHuntIocs(loaded.iocs);
  const leading = languageBlock(language);
  const timeline = renderTimeline(
    scoped,
    Number(process.env.DFIR_PBHUNT_MAX_EVENTS) || 120,
    PLAYBOOK_LANGUAGE_HUNT_PROMPT,
    leading + tasksText + findingsText + iocText,
  );
  const userPrompt =
    leading +
    `PLAYBOOK TASKS:\n${tasksText}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `PIVOTABLE INDICATORS:\n${iocText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timeline}\n\n` +
    excludeNote(opts.exclude) +
    `Propose the per-task ${LANGUAGE_LABELS[language]} queries as JSON.`;
  const taskIds = new Set(tasks.map((t) => t.id));
  const max = Number(process.env.DFIR_PBHUNT_SUGGEST_MAX) || PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT;
  return callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "suggest-playbook-language-hunts",
    PLAYBOOK_LANGUAGE_HUNT_PROMPT,
    userPrompt,
    (raw) => {
      const answers = languageHuntResponseSchema.parse(raw).suggestions;
      const kept = sanitizePlaybookLanguageHunts(answers, language, taskIds, { exclude: opts.exclude, max });
      return noteDropped(ctx, caseId, language, answers.length, kept);
    },
  );
}
