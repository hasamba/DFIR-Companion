import type { AnalyzeRequest } from "../../providers/provider.js";
import { createAnonymizer, deriveKnownEntities, type Anonymizer, type KnownEntities } from "../anonymize.js";
import { toAnonPolicy, type AnonControl } from "../anonControl.js";
import type { InvestigationState } from "../stateTypes.js";
import { splitAiSpans } from "./aiSpan.js";
import { maskSegments, type AuthoredSpan } from "./presidioAuthoredText.js";
import type { ProviderCallContext } from "./providerCallContext.js";

/**
 * The masking half of the AI-call gate (#418), split out for #2491.
 *
 * The real call (providerCall.ts `prepareCall`) and "Preview what the AI will see" both build the
 * prompt text the provider receives through THIS function. That is the whole guarantee the preview
 * gives: a copy of the masking could show a safer result than the real send and give false
 * assurance, so there is no copy — one function, two callers.
 *
 * What it does, in order: strip the AI-field markers (aiSpan.ts — they never leave the process),
 * load the case's control and policy, and — when anonymization is on — derive the known entities and
 * mask the prompt with the case's anonymizer. Image OCR redaction and the Presidio gate are NOT here:
 * the real path runs them after this, and the preview reports them without running their side
 * effects. Text masking never depends on OCR output: `known` and the anonymizer are built before any
 * image is read, so masking before or after OCR gives the same text.
 */
export interface MaskedRequest {
  readonly control: AnonControl | null;
  readonly policy: ReturnType<typeof toAnonPolicy>;
  /** The prompt with the AI-field markers removed: the clear text. */
  readonly plainPrompt: string;
  /** The text the provider receives. Equal to plainPrompt when anonymization is off. */
  readonly maskedPrompt: string;
  /** Where the AI-written text sits inside maskedPrompt, for the Presidio gate. */
  readonly spans: AuthoredSpan[];
  /** null when anonymization is off for the case. */
  readonly known: KnownEntities | null;
  readonly anon: Anonymizer | null;
}

/**
 * Entities found in THIS request's own text that the case state does not know yet (Watson pastes).
 * They are masked for this call only: never saved, never added to auto-discovery. They join the
 * state-derived hosts and usernames, not `custom`, so an analyst's "leave visible" still wins.
 */
export interface PromptEntities {
  readonly hosts: readonly string[];
  readonly usernames: readonly string[];
}

/**
 * An AnalyzeRequest as the AI-call gate accepts it. `promptEntities` rides on the request (not a new
 * positional argument) so every binding of `analyzeRestored` forwards it unchanged; prepareCall
 * strips it before the provider sees the request.
 */
export type GatedAnalyzeRequest = AnalyzeRequest & { promptEntities?: PromptEntities };

const byLenDesc = (a: string, b: string): number => b.length - a.length || a.localeCompare(b);

function withPromptEntities(known: KnownEntities, extra: PromptEntities | undefined): KnownEntities {
  if (!extra || (extra.hosts.length === 0 && extra.usernames.length === 0)) return known;
  return {
    ...known,
    hosts: [...new Set([...known.hosts, ...extra.hosts])].sort(byLenDesc),
    usernames: [...new Set([...(known.usernames ?? []), ...extra.usernames])].sort(byLenDesc),
  };
}

/** The case's known entities: derived from the state, plus custom and auto-discovered ones. */
export async function knownEntitiesFor(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  extra?: PromptEntities,
): Promise<KnownEntities> {
  const known = withPromptEntities(deriveKnownEntities(state), extra);
  const custom = ctx.opts.customEntitiesStore ? await ctx.opts.customEntitiesStore.load(caseId) : [];
  // Auto-discovered screenshot entities are tokenized too; suppressed ones are never tokenized.
  const disc = ctx.opts.discoveredStore
    ? await ctx.opts.discoveredStore.load(caseId)
    : { discovered: [], suppressed: [] };
  known.custom = [...custom, ...disc.discovered];
  known.suppressed = disc.suppressed;
  return known;
}

/**
 * The case's masker: its control and policy and — when anonymization is on — its known entities and
 * anonymizer. THE one place that builds them (#2515): `maskRequest` (every gated AI call and the
 * preview), the import pre-scan and the Jev routes all come here. `mask` is the anonymizer's own
 * `apply`, or the identity function when anonymization is off for the case. Writes nothing.
 */
export interface CaseMasker {
  readonly control: AnonControl | null;
  readonly policy: ReturnType<typeof toAnonPolicy>;
  /** null when anonymization is off for the case. */
  readonly known: KnownEntities | null;
  readonly anon: Anonymizer | null;
  readonly mask: (text: string) => string;
}

export async function caseMasker(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  extra?: PromptEntities,
): Promise<CaseMasker> {
  const control = ctx.opts.anonStore ? await ctx.opts.anonStore.load(caseId) : null;
  const policy = toAnonPolicy(control);
  // Off: no entity list is read at all, and Presidio (which needs `known`) does not run either.
  if (!policy.enabled) return { control, policy, known: null, anon: null, mask: (t) => t };
  const known = await knownEntitiesFor(ctx, caseId, state, extra);
  const anon = createAnonymizer(policy, known);
  return { control, policy, known, anon, mask: (t) => anon.apply(t) };
}

/** Mask one request's user prompt exactly as the provider will receive it. Writes nothing. */
export async function maskRequest(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  req: Pick<GatedAnalyzeRequest, "userPrompt" | "promptEntities">,
): Promise<MaskedRequest> {
  const { control, policy, known, anon, mask } = await caseMasker(ctx, caseId, state, req.promptEntities);
  // The AI-field markers (aiSpan.ts) come out first, whatever happens next: nothing is sent with them.
  const segments = splitAiSpans(req.userPrompt);
  const plainPrompt = segments.map((sg) => sg.text).join("");
  if (!known || !anon)
    return { control, policy, plainPrompt, maskedPrompt: plainPrompt, spans: [], known: null, anon: null };
  // Mask FIRST, then let Presidio look at the result. It never sees a real hostname, IP,
  // username, email, SID or secret — only what our own detectors could not find.
  const { masked, spans } = maskSegments(segments, mask);
  return { control, policy, plainPrompt, maskedPrompt: masked, spans, known, anon };
}
