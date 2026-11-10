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

/** The case's known entities: derived from the state, plus custom and auto-discovered ones. */
export async function knownEntitiesFor(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
): Promise<KnownEntities> {
  const known = deriveKnownEntities(state);
  const custom = ctx.opts.customEntitiesStore ? await ctx.opts.customEntitiesStore.load(caseId) : [];
  // Auto-discovered screenshot entities are tokenized too; suppressed ones are never tokenized.
  const disc = ctx.opts.discoveredStore
    ? await ctx.opts.discoveredStore.load(caseId)
    : { discovered: [], suppressed: [] };
  known.custom = [...custom, ...disc.discovered];
  known.suppressed = disc.suppressed;
  return known;
}

/** Mask one request's user prompt exactly as the provider will receive it. Writes nothing. */
export async function maskRequest(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  req: Pick<AnalyzeRequest, "userPrompt">,
): Promise<MaskedRequest> {
  const control = ctx.opts.anonStore ? await ctx.opts.anonStore.load(caseId) : null;
  const policy = toAnonPolicy(control);
  // The AI-field markers (aiSpan.ts) come out first, whatever happens next: nothing is sent with them.
  const segments = splitAiSpans(req.userPrompt);
  const plainPrompt = segments.map((sg) => sg.text).join("");
  if (!policy.enabled)
    return { control, policy, plainPrompt, maskedPrompt: plainPrompt, spans: [], known: null, anon: null };
  const known = await knownEntitiesFor(ctx, caseId, state);
  const anon = createAnonymizer(policy, known);
  // Mask FIRST, then let Presidio look at the result. It never sees a real hostname, IP,
  // username, email, SID or secret — only what our own detectors could not find.
  const { masked, spans } = maskSegments(segments, (t) => anon.apply(t));
  return { control, policy, plainPrompt, maskedPrompt: masked, spans, known, anon };
}
