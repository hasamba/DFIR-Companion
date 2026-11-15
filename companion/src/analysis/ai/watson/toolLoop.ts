import type { InvestigationState } from "../../stateTypes.js";
import { toReadableAiError } from "../aiReplyUnreadable.js";
import { getWatsonPrompt } from "../prompts/index.js";
import { buildWatsonUserPrompt, type WatsonPromptInput } from "./promptBuilder.js";
import { sanitizeWatsonReply, type WatsonReply } from "./replySchema.js";
import { secondHop, type HopInput } from "./roundHop.js";
import type { WatsonRoundContext, WatsonSpend } from "./roundContext.js";
import type { Outcome } from "./roundOutcome.js";
import type { WatsonCitationSets as CitationSets } from "./replySchema.js";
import { WATSON_MAX_SUPER_SEARCHES, WATSON_TRANSCRIPT_BUDGET_CHARS } from "./toolMode.js";
import { watsonToolsAddendum } from "./toolPrompt.js";
import { watsonTools } from "./toolSpecs.js";
import { emptyLoop, hopFallback, runBatch, sendStep, type LoopState, type StepEnv } from "./toolStep.js";
import { fitTranscript } from "./transcriptBudget.js";
import type { WatsonChat } from "./types.js";

// Watson's tool loop (phase 5): native tool calls replace the one-step hop for an analyst question.
// Each send goes through guardedCall, so the limits, the AI switch and a closed case are checked
// before every provider attempt (D5), and at most cap + 1 attempts are made, retries and the
// finalization send included (R1). The tools only read. A throw on the FIRST send propagates to
// round.ts (D7b); after a send, a failure keeps what was read: the lookups and the roster.

export interface ToolLoopInput {
  ctx: WatsonRoundContext;
  caseId: string;
  chat: WatsonChat;
  state: InvestigationState;
  base: WatsonPromptInput;
  head: WatsonPromptInput["pasteExcerpt"];
  cap: number;
  reaction: boolean;
  known: { questions: Set<string>; pastes: Set<string>; events: Set<string>; citations: CitationSets };
  counter: { calls: number };
  spent(): Promise<WatsonSpend>;
  rest: Omit<Outcome, "reply">;
  /** The hop's guarded call: a final reply that asks for a hop with no tool run goes to secondHop (D7). */
  ask: HopInput["ask"];
  /** The counter value at which no provider call starts (R1). Absent: counter.calls + cap + 1. */
  ceiling?: number;
  /** Tool-result characters per question (D4c). Absent: WATSON_TRANSCRIPT_BUDGET_CHARS. */
  budget?: number;
}

/** Tool mode ends for this question; round.ts runs the one-step hop with what was already read. */
export class ToolModeFallback extends Error {
  constructor(
    readonly reason: unknown,
    /** The model cannot call tools: round.ts marks its capability key (D12). */
    readonly remember: boolean,
    /** What the loop read: `superShown` lets the hop's reply cite and promote those rows (F1). */
    readonly carried: Pick<Outcome, "lookups" | "superRoster" | "readPasteIds" | "superShown">,
    /** Super-timeline searches the question may still run: the hop respects it (R2). */
    readonly superLeft: number,
    /** Lookups the question may still run (cap minus those that ran): the hop respects it (F2). */
    readonly lookupsLeft: number,
  ) {
    super(reason instanceof Error ? reason.message : String(reason));
    this.name = "ToolModeFallback";
  }
}

/** The system prompt (with the tools addendum), user prompt and tool list of a tool-mode question. */
export function toolRequestParts(
  i: Pick<ToolLoopInput, "base" | "head" | "reaction" | "ctx" | "cap">,
): Pick<StepEnv, "system" | "userPrompt" | "tools"> {
  const tools = watsonTools({
    super: !i.reaction && !!i.ctx.rawSearch,
    history: (i.base.historyTurns ?? 0) > 0,
  });
  const addendum = watsonToolsAddendum(
    i.cap,
    tools.map((t) => t.name),
  );
  return {
    system: `${getWatsonPrompt()}\n\n${addendum}`,
    userPrompt: buildWatsonUserPrompt(i.head ? { ...i.base, pasteExcerpt: i.head } : i.base),
    tools,
  };
}

function envOf(i: ToolLoopInput): StepEnv {
  return {
    ...i,
    ...toolRequestParts(i),
    ceiling: i.ceiling ?? i.counter.calls + i.cap + 1,
  };
}

/** What the question read, on every exit after a send. */
function carried(i: ToolLoopInput, s: LoopState): Partial<Outcome> {
  const read = [...(i.rest.readPasteIds ?? []), ...s.readPasteIds];
  return {
    ...(s.lookups.length ? { lookups: s.lookups } : {}),
    ...(s.roster ? { superRoster: s.roster } : {}),
    ...(read.length ? { readPasteIds: [...new Set(read)] } : {}),
    ...(s.superCapHit ? { superCapHit: true } : {}),
  };
}

/** A failure: the hop fallback, the first send's throw (D7b), or an error outcome that keeps the reads. */
function failure(i: ToolLoopInput, s: LoopState, raw: unknown): Outcome {
  const err = toReadableAiError(raw, i.ctx.log, i.caseId, "watson");
  const fallback = hopFallback(err);
  if (fallback) {
    const keep = carried(i, s);
    const remember = fallback === "remember" && !s.sent;
    throw new ToolModeFallback(
      err,
      remember,
      {
        ...(keep.lookups ? { lookups: keep.lookups } : {}),
        ...(keep.superRoster ? { superRoster: keep.superRoster } : {}),
        ...(s.readPasteIds.length ? { readPasteIds: s.readPasteIds } : {}),
        ...(s.superShown.length ? { superShown: s.superShown } : {}),
      },
      Math.max(0, WATSON_MAX_SUPER_SEARCHES - s.superUsed),
      Math.max(0, i.cap - s.executed),
    );
  }
  if (!s.sent) throw err;
  // The rows were sent, but none were cited: nothing is promoted.
  return { ...i.rest, ...carried(i, s), reply: null, error: err, superShown: [] };
}

/** The final reply (D7): sanitized against every row this question showed; a hop only with no tool run. */
async function finish(i: ToolLoopInput, env: StepEnv, s: LoopState, reply: WatsonReply): Promise<Outcome> {
  const { known } = i;
  const events = new Set([...known.events, ...s.superShown.map((e) => e.id)]);
  const veloOn = i.base.velo !== undefined;
  const clean = sanitizeWatsonReply(reply, known.questions, known.pastes, events, known.citations, veloOn);
  const rest = { ...i.rest, ...carried(i, s), ...(s.superShown.length ? { superShown: s.superShown } : {}) };
  if (s.executed === 0 && (clean.search || clean.lookup)) {
    const spent = i.spent;
    const callsLeft = () => env.ceiling - i.counter.calls;
    return secondHop({ ...i, first: clean, spent, rest, reaction: i.reaction, callsLeft });
  }
  return { ...rest, reply: { ...clean, search: null, lookup: null } };
}

/** Run the question's tool loop and return its outcome. */
export async function runToolLoop(i: ToolLoopInput): Promise<Outcome> {
  const env = envOf(i);
  const budget = i.budget ?? WATSON_TRANSCRIPT_BUDGET_CHARS;
  let s = emptyLoop();
  for (;;) {
    let out;
    try {
      out = await sendStep(env, s);
    } catch (err) {
      return failure(i, s, err);
    }
    s = { ...s, sent: true, session: out.session };
    if (out.kind === "answer") return finish(i, env, s, out.reply);
    if (out.kind === "unparsed") return finalize(i, env, s, out.error);
    const batch = await runBatch(env, s, out.assistant);
    s = { ...batch.state, transcript: fitTranscript(batch.state.transcript, budget) };
    if (batch.stop) return failure(i, s, batch.stop);
  }
}

/** One finalization send after a tool ran and the reply could not be read (D7c, R3). */
async function finalize(i: ToolLoopInput, env: StepEnv, s: LoopState, error: unknown): Promise<Outcome> {
  if (i.counter.calls >= env.ceiling) return failure(i, s, error);
  let out;
  try {
    out = await sendStep(env, s, true);
  } catch (err) {
    return failure(i, s, err);
  }
  const next = { ...s, session: out.session };
  if (out.kind === "answer") return finish(i, env, next, out.reply);
  return failure(i, next, out.kind === "unparsed" ? out.error : error);
}
