import { parseAskRequest } from "../analysis/askHistory.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import {
  loadEventTagLabelMap,
  loadStarredEventIds,
  parseSimilarKind,
  parseTechniqueHuntBody,
  parseViewSummaryFilters,
  resolveTranslatePlatforms,
  similarCandidates,
  similarLabel,
} from "./aiActionArgs.js";
import type { RouteContext } from "./context.js";

/**
 * Every AI action "Preview what the AI will see" covers (#2491), keyed as the dashboard names them.
 *
 * Each entry calls the SAME pipeline method the real button's route calls, with the arguments built
 * by the SAME helper (aiActionArgs.ts) — the preview's job is to run the real action and stop it at
 * the AI-call gate, so the prompt it shows is built by the action's own code from the forensic
 * timeline. An entry never builds a prompt itself.
 *
 * The other covered AI requests need the route's own context and live beside these (#2515):
 * import-time extraction (aiPreviewImportActions.ts — the analyst chooses the file), playbook hunts
 * (aiPreviewPlaybookAction.ts — built from the stored fleet inventory, no refresh) and the Jev review
 * and containment check (aiPreviewJevActions.ts). The ONLY AI calls not previewed are the provider
 * "test connection" calls in Settings: they carry no case data.
 */
type Options = RouteContext["options"];
type Pipeline = NonNullable<Options["pipeline"]>;
type Params = Record<string, unknown>;

export interface AiPreviewAction {
  readonly label: string;
  /** Shown with the result when the action asks the model more than once. */
  readonly multiRequest?: string;
  /** The action as the real route would run it, or a sentence naming the missing parameter. */
  prepare(pipeline: Pipeline, options: Options, caseId: string, params: Params): Promise<Run | string>;
}
type Run = () => Promise<unknown>;

const str = (v: unknown): string => (typeof v === "string" ? v.trim() : "");
const caseOnly = (
  label: string,
  run: (p: Pipeline, caseId: string) => Promise<unknown>,
): AiPreviewAction => ({
  label,
  prepare: async (pipeline, _options, caseId) => () => run(pipeline, caseId),
});

const MULTI_BATCH =
  "The deep pass asks the model once per batch of events, then once more to synthesize. This is the " +
  "first batch; the later requests carry other events and the model's earlier answers, so they are not previewed.";
const MULTI_SECOND_OPINION =
  "A second opinion asks several times: it first refreshes the primary synthesis when it is out of date, " +
  "then runs the second model, then the referee. This is the first of those requests; the later ones are not previewed.";
const MULTI_SECOND_LOOK =
  "A second look promotes matching raw rows, then re-synthesizes. This is the re-synthesis request as it would " +
  "be sent after the promotion (the promotion itself was only simulated — nothing was promoted).";

export const AI_PREVIEW_ACTIONS: Readonly<Record<string, AiPreviewAction>> = {
  synthesis: {
    label: "Synthesis",
    prepare: async (pipeline, _o, caseId, params) => () =>
      pipeline.synthesize(caseId, { force: true, deepReasoning: params.deepReasoning === true }),
  },
  "deep-pass": {
    label: "Deep pass",
    multiRequest: MULTI_BATCH,
    prepare: async (pipeline, _o, caseId, params) => {
      const minSeverity = parseMinSeverity(params.minSeverity ?? "Medium");
      if (!minSeverity || minSeverity === "Info")
        return "minSeverity must be one of Critical, High, Medium, Low";
      return () => pipeline.deepPass(caseId, { minSeverity });
    },
  },
  "second-look": {
    label: "Second look",
    multiRequest: MULTI_SECOND_LOOK,
    prepare: async (pipeline, _o, caseId) => () => pipeline.secondLook(caseId, { resynthesize: true }),
  },
  "second-opinion": {
    label: "Second opinion",
    multiRequest: MULTI_SECOND_OPINION,
    prepare: async (pipeline, options, caseId, params) =>
      options.secondOpinionEnabled
        ? () => pipeline.secondOpinion(caseId, { deepReasoning: params.deepReasoning === true })
        : "the second-opinion model is not configured — set DFIR_AI_SECOND_OPINION_MODEL",
  },
  "second-opinion-referee": caseOnly("Second opinion — re-run the referee", (p, c) =>
    p.rerunSecondOpinionReferee(c),
  ),
  narrative: caseOnly("Narrative timeline", (p, c) => p.generateNarrative(c)),
  "executive-summary": caseOnly("Executive summary", (p, c) => p.executiveSummary(c)),
  "remediation-plan": caseOnly("Remediation plan", (p, c) => p.remediationPlan(c)),
  "hypothesis-review": caseOnly("Hypothesis review", (p, c) => p.hypothesisReview(c)),
  "explain-event": {
    label: "Explain event",
    prepare: async (pipeline, _o, caseId, params) => {
      const eventId = str(params.eventId);
      return eventId ? () => pipeline.explainEvent(caseId, eventId) : "eventId is required";
    },
  },
  "starred-report": {
    label: "Starred events report",
    prepare: async (pipeline, options, caseId) => {
      const ids = await loadStarredEventIds(options, caseId);
      return ids.length ? () => pipeline.starredReport(caseId, ids) : "no starred events — star rows first";
    },
  },
  "view-summary": {
    label: "Summarize the current super-timeline view",
    prepare: async (pipeline, options, caseId, params) => {
      if (!options.superTimelineStore) return "the super-timeline is not configured";
      const filters = parseViewSummaryFilters(params);
      const labels = await loadEventTagLabelMap(options, caseId);
      return () => pipeline.viewSummary(caseId, filters, labels);
    },
  },
  "session-summary": {
    label: "Session summary",
    prepare: async (pipeline, _o, caseId, params) => {
      const sessionId = str(params.sessionId);
      return sessionId ? () => pipeline.sessionSummary(caseId, sessionId) : "sessionId is required";
    },
  },
  ask: {
    label: "Ask the case",
    prepare: async (pipeline, _o, caseId, params) => {
      const { question, history } = parseAskRequest(params);
      return question ? () => pipeline.ask(caseId, question, { history }) : "question is required";
    },
  },
  // #2559: the same routing as the real press — VQL unchanged, else the main-source language.
  "velociraptor-hunts": caseOnly("Velociraptor hunt suggestions", (p, c) => p.caseHunts.suggest(c)),
  "technique-hunt": {
    label: "Hunt for one ATT&CK technique",
    prepare: async (pipeline, _o, caseId, params) => {
      const t = parseTechniqueHuntBody(params);
      return t
        ? () => pipeline.suggestTechniqueHunts(caseId, t.techniqueId, t.techniqueName)
        : "valid ATT&CK techniqueId required";
    },
  },
  "memory-next-steps": caseOnly("Memory forensics next steps", (p, c) => p.suggestMemoryNextSteps(c)),
  "gap-hypotheses": caseOnly("Timeline gap hypotheses", (p, c) => p.hypothesizeGaps(c)),
  "translate-query": {
    label: "Translate a query",
    prepare: async (pipeline, options, caseId, params) => {
      const request = str(params.request);
      if (!request) return "request is required";
      const platforms = resolveTranslatePlatforms(options, params);
      return () => pipeline.translateQuery(caseId, request, platforms);
    },
  },
  "tagger-rule": {
    label: "Suggest a tagger rule",
    prepare: async (pipeline, _o, caseId, params) => {
      const description = str(params.description);
      return description ? () => pipeline.suggestTaggerRule(caseId, description) : "description is required";
    },
  },
  "fp-similar": {
    label: "Find similar false positives (AI pass)",
    prepare: async (pipeline, options, caseId, params) => {
      const kind = parseSimilarKind(params);
      const ref = str(params.ref);
      if (!kind || !ref) return "kind ('event'|'finding') and ref are required";
      if (!options.stateStore) return "state store not configured";
      const similar = similarCandidates(await options.stateStore.load(caseId), kind, ref);
      if (!similar) return `${kind} ${ref} not found`;
      const { anchorLabel, rest } = similar;
      return () =>
        pipeline.suggestFalsePositiveSimilarAi(
          caseId,
          ref,
          anchorLabel,
          rest.map((r) => r.id),
          rest.map((r) => similarLabel(kind, r)),
        );
    },
  },
};
