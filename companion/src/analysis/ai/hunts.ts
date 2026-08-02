import type { AIProvider } from "../../providers/provider.js";
import { buildGraphContext, DEFAULT_MAX_GRAPH_EDGES } from "../graphContext.js";
import {
  deployedFingerprints,
  renderPriorHuntsBlock,
  renderHuntProductivityBlock,
  vqlFingerprint,
  type HuntOutcome,
} from "../huntOutcomes.js";
import type { HuntOutcomeStore } from "../huntOutcomeStore.js";
import { HUNT_PLATFORMS, type HuntPlatform } from "../huntPlatforms.js";
import {
  huntSuggestionsResponseSchema,
  sanitizeHuntSuggestions,
  renderHuntFindings,
  renderHuntIocs,
  hasHuntMaterial,
  HUNT_SUGGEST_MAX_DEFAULT,
  type HuntSuggestion,
} from "../huntSuggest.js";
import type { PlaybookTask } from "../playbook.js";
import {
  playbookHuntResponseSchema,
  sanitizePlaybookHuntSuggestions,
  buildTaskEndpointsMap,
  knownEndpoints,
  renderPlaybookHuntTasks,
  renderKnownEndpoints,
  renderAvailableArtifacts,
  hasPlaybookHuntMaterial,
  PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT,
  type PlaybookHuntSuggestion,
} from "../playbookHunt.js";
import { estimateTokens, inputTokenBudget, fitItemsToBudget } from "../promptBudget.js";
import {
  queryTranslationResponseSchema,
  sanitizeQueryTranslations,
  sanitizeInterpretation,
  renderPlatformGuide,
  renderCaseDataSources,
  type QueryTranslationResult,
} from "../queryTranslate.js";
import type { ForensicEvent } from "../stateTypes.js";
import { buildSynthesisContext, selectSynthesisEvents } from "../synthSelect.js";
import { maxPromptEvents } from "../synthGroup.js";
import { getHuntSuggestPrompt, getPlaybookHuntPrompt, getQueryTranslatePrompt } from "./prompts/index.js";
import { loadScopedEvents, retryPolicy } from "./aiContext.js";
import { knownUnknownsBlock, type PromptBlockContext } from "./promptBlocks.js";

/**
 * The four AI calls that produce something the analyst RUNS (#418).
 *
 * Moved from AnalysisPipeline (see ai/caseReports.ts for the pattern). Three of them write
 * Velociraptor VQL and the fourth translates plain English into a SIEM query, but what actually
 * groups them is the feedback loop underneath: every VQL suggestion is filtered against the hunts
 * this case has already deployed, and every VQL prompt carries the hit/miss ledger so the model
 * pivots on what worked. All four are EPHEMERAL — nothing here mutates the case.
 */

/** What a hunt generator needs beyond the shared AI-call seam and the derived prompt blocks. */
export interface HuntContext extends PromptBlockContext {
  readonly opts: PromptBlockContext["opts"] & {
    velociraptorProvider?: AIProvider;
    huntOutcomeStore?: HuntOutcomeStore;
  };
}

// The hunting feedback loop's prior-hunt outcomes for a case (#157) — [] when no store is wired
// (scripts/*) or the file is absent/corrupt, so the loop simply stays off without ever throwing.
export async function loadHuntOutcomes(ctx: HuntContext, caseId: string): Promise<HuntOutcome[]> {
  if (!ctx.opts.huntOutcomeStore) return [];
  try {
    return await ctx.opts.huntOutcomeStore.load(caseId);
  } catch {
    return [];
  }
}

// Drop any suggestion whose VQL was already deployed in this case (#157) — the deterministic guarantee
// that a hunt the analyst already ran is never re-proposed (the "PRIOR HUNTS" prompt block is the soft
// signal; this is the hard one). Bundles contribute no fingerprint, so they never exclude a suggestion.
function excludeDeployedHunts<T extends { vql: string }>(
  suggestions: T[],
  outcomes: readonly HuntOutcome[],
): T[] {
  const fps = deployedFingerprints(outcomes);
  if (!fps.size) return suggestions;
  return suggestions.filter((s) => !fps.has(vqlFingerprint(s.vql)));
}

/** The regenerate hook shared by the two hunt calls the analyst can ask for a different take on. */
const excludeNote = (excludeVql?: string): string =>
  excludeVql
    ? `ALREADY SUGGESTED (this VQL was already shown to the analyst — generate something DIFFERENT that investigates from a different angle or uses different VQL plugins):\n${excludeVql}\n\n`
    : "";

// Propose proactive Velociraptor VQL fleet-hunts from the synthesized findings (issue #57).
// Single text-only AI call; EPHEMERAL like ask()/executiveSummary() — it does NOT mutate state.
// The analyst reviews each hunt's VQL + rationale, then one-click deploys it through the existing
// launchHunt flow (POST /velociraptor/hunt). Returns [] without an AI call on an empty case.
export async function suggestHunts(
  ctx: HuntContext,
  caseId: string,
  opts?: { excludeVql?: string },
): Promise<HuntSuggestion[]> {
  const provider =
    ctx.opts.velociraptorProvider ?? ctx.opts.synthesisProvider ?? ctx.requireProvider("hunt suggestions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (!hasHuntMaterial(loaded)) return []; // nothing to pivot on — don't spend a call

  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);

  const max = maxPromptEvents();
  let events = selectSynthesisEvents(scoped, max);
  const renderEvent = (e: ForensicEvent) =>
    `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;
  const findingsText = renderHuntFindings(loaded.findings);
  const iocText = renderHuntIocs(loaded.iocs);
  const techText = loaded.mitreTechniques.map((t) => `${t.id} ${t.name}`).join(", ") || "(none)";
  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog());
  // Causal grounding (#124): serialize the deterministic evidence-chain graph — process spawn
  // chains, file lineage, lateral-movement edges — so the model hunts the RELATIONSHIP (the
  // parent→child chain, the binary/account that moved between hosts) fleet-wide, not just the leaf
  // indicator. The flat timeline drops processName/parentName; the graph carries them. Built from
  // the SAME scoped+legitimate-filtered events as the rest of the prompt; "" when there are no edges.
  // Capped at the shared default (the timeline trim below absorbs the block into the prompt budget).
  const graphBlock = buildGraphContext(
    { ...loaded, forensicTimeline: scoped },
    { maxEdges: DEFAULT_MAX_GRAPH_EDGES },
  );

  // Feedback loop (#157): the prior hunts already run in this case (what hit / what missed), so the
  // model proposes follow-ups that pivot on productive hunts and avoids repeating dead ones. "" when
  // there are no recorded outcomes (or no store wired). Also drives the deterministic exclusion below.
  const outcomes = await loadHuntOutcomes(ctx, caseId);
  const priorHuntsBlock = renderPriorHuntsBlock(outcomes);
  // Productivity tuning (#72): the aggregate hit-rate by pivot class (hash/process/path/network/
  // registry) across this case's hunt history, so the model biases toward classes that have found
  // evidence rather than only avoiding exact repeats (priorHuntsBlock is the per-hunt signal; this
  // is the aggregate one). "" until there's collected history to bias on.
  const productivityBlock = renderHuntProductivityBlock(outcomes);
  // Known unknowns (#165): the gaps in the story (silent windows, uncovered ATT&CK phases, likely-
  // next techniques) so suggested hunts target what's MISSING, not just re-confirm what's known.
  const unknownsBlock = await knownUnknownsBlock(ctx, loaded, scoped, caseId);

  // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
  const overhead =
    estimateTokens(getHuntSuggestPrompt()) +
    estimateTokens(
      priorHuntsBlock +
        productivityBlock +
        contextBlock +
        unknownsBlock +
        graphBlock +
        findingsText +
        iocText +
        techText +
        (loaded.attackerPath || ""),
    ) +
    300;
  const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
  if (fit < events.length) events = selectSynthesisEvents(scoped, fit);
  const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

  const userPrompt =
    priorHuntsBlock +
    productivityBlock +
    contextBlock +
    unknownsBlock +
    graphBlock +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `ATT&CK TECHNIQUES: ${techText}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `PIVOTABLE INDICATORS:\n${iocText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timelineText}\n\n` +
    excludeNote(opts?.excludeVql) +
    `Propose the fleet-hunts as JSON.`;

  const limit = Number(process.env.DFIR_HUNT_SUGGEST_MAX) || HUNT_SUGGEST_MAX_DEFAULT;
  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "suggest-hunts",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getHuntSuggestPrompt(), userPrompt, images: [] },
        "suggest-hunts",
      );
      const { suggestions } = huntSuggestionsResponseSchema.parse(parsed);
      return excludeDeployedHunts(sanitizeHuntSuggestions(suggestions, limit), outcomes);
    },
    retries,
    backoffMs,
  );
}

// Targeted hunt for ONE ATT&CK technique the adversary-emulation panel flagged as a likely next
// move (issue #121). Unlike suggestHunts (findings-driven), this is technique-DRIVEN: the technique
// has NOT been observed yet — the analyst wants VQL to detect it proactively if a lookalike actor
// brings it here. Reuses the fleet-hunt system prompt + schema + sanitizer + deploy flow, with a
// technique-focused user prompt grounded in the case's pivotable IOCs. EPHEMERAL like suggestHunts()
// — no state change. Works on ANY case (the technique is by definition not in the timeline).
export async function suggestTechniqueHunts(
  ctx: HuntContext,
  caseId: string,
  techniqueId: string,
  techniqueName?: string,
): Promise<HuntSuggestion[]> {
  const provider =
    ctx.opts.velociraptorProvider ?? ctx.opts.synthesisProvider ?? ctx.requireProvider("technique hunt");
  const id = String(techniqueId || "")
    .trim()
    .toUpperCase();
  if (!/^T\d{4}(?:\.\d{3})?$/.test(id)) return []; // not a technique id — nothing to hunt
  const loaded = await ctx.opts.stateStore.load(caseId);
  const iocText = renderHuntIocs(loaded.iocs);
  const label = techniqueName ? `${id} (${techniqueName})` : id;
  const outcomes = await loadHuntOutcomes(ctx, caseId); // #157 feedback loop (exclude + prior-hunts context)
  const priorHuntsBlock = renderPriorHuntsBlock(outcomes);
  const productivityBlock = renderHuntProductivityBlock(outcomes); // #72: aggregate hit-rate by pivot class
  const userPrompt =
    priorHuntsBlock +
    productivityBlock +
    `Focus EXCLUSIVELY on ONE ATT&CK technique the analyst wants to hunt for proactively across the fleet:\n` +
    `  ${label}\n\n` +
    `This technique has NOT yet been observed in this case. A group whose tradecraft resembles this case is known ` +
    `to use it, so the goal is to DETECT it on any enrolled endpoint if it is being used here but missed.\n\n` +
    `Propose 1–3 CLIENT-side Velociraptor VQL hunts that surface this technique's tradecraft generally (not tied to ` +
    `one host). Where relevant, pivot on these case indicators, but do not depend on them:\n` +
    `PIVOTABLE INDICATORS:\n${iocText}\n\n` +
    `Set every suggestion's mitreTechniques to ["${id}"]. Propose the hunt(s) as JSON.`;
  const limit = Number(process.env.DFIR_HUNT_SUGGEST_MAX) || HUNT_SUGGEST_MAX_DEFAULT;
  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "hunt-technique",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getHuntSuggestPrompt(), userPrompt, images: [] },
        "hunt-technique",
      );
      const { suggestions } = huntSuggestionsResponseSchema.parse(parsed);
      return excludeDeployedHunts(sanitizeHuntSuggestions(suggestions, limit), outcomes);
    },
    retries,
    backoffMs,
  );
}

// Propose a Velociraptor hunt for each ENDPOINT-related PLAYBOOK task (issue #70). Single text-only
// AI call; EPHEMERAL like suggestHunts() — it does NOT mutate state. The deploy MODE is decided here
// deterministically from the case's observed endpoints: a task tied to exactly one host → a single
// client COLLECTION on it; otherwise → a fleet HUNT. The playbook `tasks` are passed in by the route
// (the pipeline has no PlaybookStore). Returns [] without an AI call when there's no endpoint task.
export async function suggestPlaybookHunts(
  ctx: HuntContext,
  caseId: string,
  tasks: PlaybookTask[],
  availableArtifacts: string[] = [],
  opts?: { excludeVql?: string },
): Promise<PlaybookHuntSuggestion[]> {
  const provider =
    ctx.opts.velociraptorProvider ??
    ctx.opts.synthesisProvider ??
    ctx.requireProvider("playbook hunt suggestions");
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (!hasPlaybookHuntMaterial(loaded, tasks)) return []; // empty/closed playbook → don't spend a call

  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);

  const endpointsByTaskId = buildTaskEndpointsMap(loaded, tasks);
  const endpoints = knownEndpoints(loaded);
  const tasksText = renderPlaybookHuntTasks(tasks, endpointsByTaskId);
  const endpointsText = renderKnownEndpoints(endpoints);
  // The server's REAL CLIENT artifacts (passed in by the route) — the model may reference an
  // Artifact.<Name> only from this list (otherwise it hallucinates a name that won't compile).
  const artifactsText = renderAvailableArtifacts(
    availableArtifacts,
    Number(process.env.DFIR_PBHUNT_MAX_ARTIFACTS) || 150,
  );

  // This call hunts PER TASK (grounded by the tasks + findings + IOCs + endpoints), so it does NOT
  // need the full synthesis timeline — a smaller stratified event sample keeps the signal while
  // cutting the prompt (the timeline dominates it). A leaner prompt is faster + cheaper and shrinks
  // the window for a transient provider transport failure on a long generation. Tune via
  // DFIR_PBHUNT_MAX_EVENTS (default 120, well below synthesis's 300).
  const max = Number(process.env.DFIR_PBHUNT_MAX_EVENTS) || 120;
  let events = selectSynthesisEvents(scoped, max);
  const renderEvent = (e: ForensicEvent) =>
    `[${e.timestamp || "(undated)"}] [${e.severity}]${e.asset ? ` <${e.asset}>` : ""} ${e.description.slice(0, 240)}`;
  const findingsText = renderHuntFindings(loaded.findings);
  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog());
  const outcomes = await loadHuntOutcomes(ctx, caseId); // #157 feedback loop (exclude + prior-hunts context)
  const priorHuntsBlock = renderPriorHuntsBlock(outcomes);
  const productivityBlock = renderHuntProductivityBlock(outcomes); // #72: aggregate hit-rate by pivot class

  // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
  const overhead =
    estimateTokens(getPlaybookHuntPrompt()) +
    estimateTokens(
      priorHuntsBlock +
        productivityBlock +
        contextBlock +
        tasksText +
        endpointsText +
        artifactsText +
        findingsText +
        (loaded.attackerPath || ""),
    ) +
    300;
  const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
  if (fit < events.length) events = selectSynthesisEvents(scoped, fit);
  const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

  const userPrompt =
    priorHuntsBlock +
    productivityBlock +
    contextBlock +
    `KNOWN ENDPOINTS (hosts — pick a targetHost ONLY from these): ${endpointsText}\n\n` +
    `AVAILABLE VELOCIRAPTOR ARTIFACTS (reference Artifact.<Name> ONLY if <Name> is in this list — else use a raw plugin):\n${artifactsText}\n\n` +
    `PLAYBOOK TASKS:\n${tasksText}\n\n` +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timelineText}\n\n` +
    excludeNote(opts?.excludeVql) +
    `Propose the per-task hunts as JSON.`;

  const limit = Number(process.env.DFIR_PBHUNT_SUGGEST_MAX) || PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT;
  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "suggest-playbook-hunts",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getPlaybookHuntPrompt(), userPrompt, images: [] },
        "suggest-playbook-hunts",
      );
      const { suggestions } = playbookHuntResponseSchema.parse(parsed);
      return excludeDeployedHunts(
        sanitizePlaybookHuntSuggestions(suggestions, endpointsByTaskId, endpoints, limit),
        outcomes,
      );
    },
    retries,
    backoffMs,
  );
}

// Translate a free-text analyst request into a runnable hunting query per platform (issue #100).
// Unlike suggestHunts (findings-driven proposals), this is analyst-DRIVEN: the request is plain
// English ("PowerShell downloading a file and executing it") and the model maps that intent onto
// each requested platform's real schema. EPHEMERAL like ask()/suggestHunts() — no state change.
// Works on an empty case (the analyst may translate before any evidence is imported); the case's
// known data sources + pivotable IOCs are passed only as light grounding. Uses the strong
// synthesisProvider like ask()/executiveSummary() — this spans MANY query languages (KQL/SPL/ES|QL/
// Sigma/…) in one call, so the broad general model follows the multi-platform instruction far better
// than the narrow VQL-tuned velociraptorProvider (which biases toward VQL and ignores the rest).
export async function translateQuery(
  ctx: HuntContext,
  caseId: string,
  request: string,
  platforms?: readonly HuntPlatform[],
): Promise<QueryTranslationResult> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("query translation");
  const loaded = await ctx.opts.stateStore.load(caseId);

  // The caller's requested subset, intersected with the canonical platform set; empty → all.
  const requested = (platforms ?? []).filter((p): p is HuntPlatform =>
    (HUNT_PLATFORMS as readonly string[]).includes(p),
  );
  const targets: HuntPlatform[] = requested.length ? [...new Set(requested)] : [...HUNT_PLATFORMS];

  const sourcesText = renderCaseDataSources(loaded);
  const iocText = renderHuntIocs(loaded.iocs);
  const guide = renderPlatformGuide(targets);

  const userPrompt =
    `KNOWN CASE DATA SOURCES (the tools/log sources this investigation already has data from):\n${sourcesText}\n\n` +
    `PIVOTABLE INDICATORS observed in this case (use these exact values when the request refers to "this" host/IP/hash/etc.):\n${iocText}\n\n` +
    `TARGET PLATFORMS (emit one query per key, grounded in the schema shown):\n${guide}\n\n` +
    `ANALYST REQUEST: ${request.trim()}\n\nTranslate it as JSON.`;

  const { retries, backoffMs } = retryPolicy(ctx);
  return ctx.withRetry(
    caseId,
    "translate-query",
    async () => {
      const parsed = await ctx.analyzeRestored(
        caseId,
        loaded,
        provider,
        { systemPrompt: getQueryTranslatePrompt(), userPrompt, images: [] },
        "translate-query",
      );
      const { interpretation, queries } = queryTranslationResponseSchema.parse(parsed);
      return {
        interpretation: sanitizeInterpretation(interpretation),
        queries: sanitizeQueryTranslations(queries, targets),
      };
    },
    retries,
    backoffMs,
  );
}
