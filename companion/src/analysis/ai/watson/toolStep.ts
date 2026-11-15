import { ProviderError } from "../../../providers/provider.js";
import {
  ThinkingBindingError,
  ToolsUnsupportedError,
  TurnBindingError,
  type ToolCall,
  type ToolResult,
  type ToolSpec,
  type ToolTurn,
} from "../../../providers/toolCalling.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { ConverseAnswerParseError, type ConverseSession } from "../converseRestored.js";
import { ZodError } from "zod";
import { AiAnswerParseError, parseAnswer } from "../providerCall.js";
import { assertCanContinue, guardedCall } from "./guardedCall.js";
import { promptEntities } from "./pasteEntities.js";
import type { WatsonPromptInput } from "./promptBuilder.js";
import { watsonReplySchema, type WatsonReply } from "./replySchema.js";
import { veloHostNames, WATSON_LABEL } from "./requestBuild.js";
import type { WatsonRoundContext, WatsonSpend } from "./roundContext.js";
import { mergeMaskRoster, type WatsonMaskRoster } from "./superRoster.js";
import { runWatsonTool, type ToolRun } from "./toolDispatch.js";
import { WATSON_MAX_SUPER_SEARCHES } from "./toolMode.js";
import { WATSON_FINALIZE_LINE } from "./toolPrompt.js";
import { WATSON_TOOL } from "./toolSpecs.js";
import type { WatsonChat, WatsonLookedUp } from "./types.js";

// One step of Watson's tool loop (toolLoop.ts): one guarded send, or one batch of tool calls. The
// transcript is kept in clear text; converseRestored masks all of it again on every send (D6).

/** What the loop has done so far in this question. Each step returns a new one. */
export interface LoopState {
  transcript: ToolTurn[];
  session: ConverseSession;
  lookups: WatsonLookedUp[];
  superShown: ForensicEvent[];
  roster?: WatsonMaskRoster;
  readPasteIds: string[];
  /** Tool calls that ran (D3): the cap counts these. */
  executed: number;
  superUsed: number;
  superCapHit: boolean;
  /** A send succeeded: a later failure keeps what was read (D7b). */
  sent: boolean;
}

export const emptyLoop = (): LoopState => ({
  transcript: [],
  session: { pairs: [] },
  lookups: [],
  superShown: [],
  readPasteIds: [],
  executed: 0,
  superUsed: 0,
  superCapHit: false,
  sent: false,
});

/** What a step needs that does not change during the question. */
export interface StepEnv {
  ctx: WatsonRoundContext;
  caseId: string;
  chat: WatsonChat;
  state: InvestigationState;
  base: WatsonPromptInput;
  cap: number;
  reaction: boolean;
  counter: { calls: number };
  spent(): Promise<WatsonSpend>;
  system: string;
  userPrompt: string;
  tools: ToolSpec[];
  /** No attempt starts once counter.calls reaches this (cap + 1 sends in all, R1). */
  ceiling: number;
}

export const capNotRun = (n: number): string =>
  `Not run: you used all ${n} lookups for this question. Answer now from what you have.`;
export const SUPER_NOT_RUN =
  "Not run: you used both super-timeline searches for this question. Use what you have.";

/** A "none" send that still called tools and gave no text (D3). Never retried. */
export class WatsonNoAnswer extends Error {
  constructor(lookups: number) {
    super(
      lookups > 0
        ? `Watson did not answer after ${lookups} lookups. Send your message again.`
        : "Watson did not answer. Send your message again.",
    );
    this.name = "WatsonNoAnswer";
  }
}

/**
 * How a send's failure falls back to the one-step hop: "remember" (the model cannot call tools),
 * "once" (a thinking, signature or turn-order refusal, or another 4xx that is not about auth, quota
 * or context length), or null (not a fallback).
 */
export function hopFallback(err: unknown): "remember" | "once" | null {
  if (err instanceof ToolsUnsupportedError) return "remember";
  if (err instanceof ThinkingBindingError || err instanceof TurnBindingError) return "once";
  if (!(err instanceof ProviderError) || err.kind !== "other" || err.notAboutTools) return null;
  return /HTTP 4\d\d/.test(err.message) && !/HTTP 408|context too large/i.test(err.message) ? "once" : null;
}

export type SendOutcome =
  | { kind: "calls"; assistant: Extract<ToolTurn, { role: "assistant" }>; session: ConverseSession }
  | { kind: "answer"; reply: WatsonReply; session: ConverseSession }
  | { kind: "unparsed"; error: unknown; session: ConverseSession };

/** Every readable string of the clear transcript, for the masking entities. */
const turnTexts = (t: ToolTurn): string[] =>
  t.role === "assistant"
    ? [t.text, ...t.calls.map((c) => JSON.stringify(c.input))]
    : t.results.map((r) => r.content);

/** The roster and entities of the send: the chat's, the base input's and every row this question showed. */
function entities(env: StepEnv, s: LoopState) {
  const roster = mergeMaskRoster(mergeMaskRoster(env.chat.maskRoster, env.base.rawRoster), s.roster);
  const text = [env.userPrompt, ...s.transcript.flatMap(turnTexts)].join("\n");
  return promptEntities(text, [...veloHostNames(env.base), ...roster.hosts], roster.users);
}

/** The answer of a "none" send that still called tools: its text, else WatsonNoAnswer. */
function textAnswer(text: string, executed: number): unknown {
  if (!text.trim()) throw new WatsonNoAnswer(executed);
  return parseAnswer(text, (t) => t);
}

/** Never retried: a no-answer, a fallback, or a key, quota, size or region refusal (F3). */
const noRetry = (err: unknown): boolean =>
  err instanceof WatsonNoAnswer ||
  hopFallback(err) !== null ||
  (err instanceof ProviderError && err.notAboutTools === true);

/** One guarded send (D4, D5, D7). After a tool ran, a reply that cannot be read is returned, not retried. */
export async function sendStep(env: StepEnv, s: LoopState, finalize = false): Promise<SendOutcome> {
  const start = env.ceiling - env.cap - 1;
  let session = s.session;
  const toolRan = s.executed > 0;
  const attempt = async (one: WatsonRoundContext): Promise<SendOutcome> => {
    const k = env.counter.calls - 1 - start;
    const none = finalize || s.executed >= env.cap || k >= env.cap;
    const req = {
      systemPrompt: finalize ? `${env.system}\n\n${WATSON_FINALIZE_LINE}` : env.system,
      userPrompt: env.userPrompt,
      transcript: s.transcript,
      tools: env.tools,
      toolChoice: none ? ("none" as const) : ("auto" as const),
      // Unique per attempt in the question: a call sent without an id gets a synthetic id that never repeats.
      idSalt: `t${k}`,
      promptEntities: entities(env, s),
      beforeSend: () => assertCanContinue(env.ctx, env.caseId),
      ...(one.signal ? { signal: one.signal } : {}),
    };
    let answer: unknown;
    try {
      const sent = await one.converseRestored!(
        env.caseId,
        env.state,
        one.provider,
        req,
        session,
        WATSON_LABEL,
      );
      session = sent.session;
      const { result } = sent;
      if (result.calls.length > 0 && !none) return { kind: "calls", assistant: result.assistant, session };
      // F6: calls and no text on a "none" send: the loop makes one finalization send if one is left.
      if (result.calls.length > 0 && !result.assistant.text.trim())
        return { kind: "unparsed", error: new WatsonNoAnswer(s.executed), session };
      answer = result.calls.length > 0 ? textAnswer(result.assistant.text, s.executed) : result.answer;
      return { kind: "answer", reply: watsonReplySchema.parse(answer), session };
    } catch (err) {
      if (err instanceof ConverseAnswerParseError) session = err.session;
      if (toolRan && !(err instanceof WatsonNoAnswer) && isUnreadable(err)) {
        return { kind: "unparsed", error: err, session };
      }
      throw err;
    }
  };
  return guardedCall(env.ctx, env.caseId, env.counter, env.spent, attempt, { ceiling: env.ceiling, noRetry });
}

const isUnreadable = (err: unknown): boolean => err instanceof AiAnswerParseError || err instanceof ZodError;

function fold(s: LoopState, run: ToolRun): LoopState {
  const ran = run.lookedUp !== undefined || run.superQueried === true;
  const known = new Set(s.superShown.map((e) => e.id));
  return {
    ...s,
    executed: s.executed + (ran ? 1 : 0),
    superUsed: s.superUsed + (run.superQueried ? 1 : 0),
    lookups: run.lookedUp ? [...s.lookups, run.lookedUp] : s.lookups,
    superShown: [...s.superShown, ...(run.superShown ?? []).filter((e) => !known.has(e.id))],
    ...(run.roster ? { roster: mergeMaskRoster(s.roster, run.roster) } : {}),
    readPasteIds: run.readPasteId ? [...s.readPasteIds, run.readPasteId] : s.readPasteIds,
  };
}

/** The result a call gets without running: past the cap (D3) or past the super-timeline cap (D4b). */
function capped(env: StepEnv, s: LoopState, c: ToolCall): string | null {
  if (s.executed >= env.cap) return capNotRun(env.cap);
  const offered = env.tools.some((t) => t.name === WATSON_TOOL.super);
  if (c.name === WATSON_TOOL.super && offered && s.superUsed >= WATSON_MAX_SUPER_SEARCHES)
    return SUPER_NOT_RUN;
  return null;
}

/**
 * Run one batch of calls in order (D3). AI off and a closed case are checked before each tool (D5; a
 * lookup costs nothing, so the limits are checked before each send): a stop ends the
 * batch at once, and the state so far comes back with it. Each run's roster is folded in before the
 * next call and before the send that carries its result.
 */
export async function runBatch(
  env: StepEnv,
  start: LoopState,
  assistant: Extract<ToolTurn, { role: "assistant" }>,
): Promise<{ state: LoopState; stop?: unknown }> {
  // Ids pass through unchanged: the adapters make a missing id unique per question (idSalt).
  const calls = assistant.calls;
  let s: LoopState = { ...start, transcript: [...start.transcript, assistant] };
  const results: ToolResult[] = [];
  const offered = env.tools.map((t) => t.name);
  for (const c of calls) {
    const refused = capped(env, s, c);
    if (refused) {
      results.push({ id: c.id, name: c.name, content: refused, isError: true });
      if (refused === SUPER_NOT_RUN) s = { ...s, superCapHit: true };
      continue;
    }
    try {
      await assertCanContinue(env.ctx, env.caseId);
    } catch (stop) {
      return { state: s, stop };
    }
    const chat = { ...env.chat, maskRoster: mergeMaskRoster(env.chat.maskRoster, s.roster) };
    const superLeft = WATSON_MAX_SUPER_SEARCHES - s.superUsed;
    const o = { reaction: env.reaction, superLeft, offered };
    const run = await runWatsonTool(env.ctx, env.caseId, chat, env.state, c, o);
    results.push({ id: c.id, name: c.name, ...run.result });
    s = fold(s, run);
  }
  return { state: { ...s, transcript: [...s.transcript, { role: "tool", results }] } };
}
