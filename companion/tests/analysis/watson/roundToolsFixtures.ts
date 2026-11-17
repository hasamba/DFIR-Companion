import { converseRestored } from "../../../src/analysis/ai/converseRestored.js";
import { spentNow } from "../../../src/analysis/ai/watson/guardedCall.js";
import { watsonBaseInput } from "../../../src/analysis/ai/watson/requestBuild.js";
import type { WatsonRoundContext } from "../../../src/analysis/ai/watson/roundContext.js";
import { runWatsonRound, type WatsonRoundInput } from "../../../src/analysis/ai/watson/round.js";
import { citationSets } from "../../../src/analysis/ai/watson/roundWrites.js";
import { runToolLoop, type ToolLoopInput } from "../../../src/analysis/ai/watson/toolLoop.js";
import type { WatsonChat } from "../../../src/analysis/ai/watson/types.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import type { ConverseRequest, ConverseResult, ToolCall } from "../../../src/providers/toolCalling.js";
import { CASE, harness, log, reply, type HarnessOpts } from "./superPromoteFixtures.js";

// Watson phase 5, Task 6: a scripted tool-calling provider on top of the phase-4 promotion harness
// (real chat, state, super-timeline and cost stores in a temp dir).

export { CASE, reply };

export type Step = ConverseResult | Error | ((req: ConverseRequest) => ConverseResult | Error);

let seq = 0;
export const call = (name: string, input: Record<string, unknown>, id?: string): ToolCall => ({
  id: id ?? `c${++seq}`,
  name,
  input,
});
export const forensic = (input: Record<string, unknown>, id?: string) => call("forensic_lookup", input, id);
export const superSearch = (input: Record<string, unknown>, id?: string) =>
  call("supertimeline_search", input, id);
export const calls = (...c: ToolCall[]): ConverseResult => ({ text: "", calls: c });
export const final = (text = reply()): ConverseResult => ({ text, calls: [] });

export interface ScriptOpts {
  /** Input tokens each send reports. */
  tokens?: number;
  /** Cache-read tokens each send reports (#2663). */
  cacheRead?: number;
  model?: string;
  endpoint?: string;
  /** Replies for the hop's analyze() calls. */
  hop?: string[];
  onSend?: (n: number) => void | Promise<void>;
}

/** A provider whose converse() returns queued steps and whose analyze() serves the hop. */
export class Scripted implements AIProvider {
  readonly name = "scripted";
  readonly model: string;
  readonly endpoint?: string;
  readonly supportsTools = true;
  readonly sent: ConverseRequest[] = [];
  readonly analyzed: AnalyzeRequest[] = [];
  constructor(
    private readonly steps: Step[],
    private readonly o: ScriptOpts = {},
  ) {
    this.model = o.model ?? `m-${++seq}`;
    if (o.endpoint) this.endpoint = o.endpoint;
  }
  async converse(req: ConverseRequest): Promise<ConverseResult> {
    const { signal: _s, withhold: _w, ...wire } = req;
    this.sent.push(structuredClone(wire));
    await this.o.onSend?.(this.sent.length);
    const raw = this.steps.shift();
    const next = typeof raw === "function" ? raw(req) : raw;
    if (!next) throw new Error("no scripted reply");
    if (next instanceof Error) throw next;
    const cache = this.o.cacheRead !== undefined ? { cacheReadTokens: this.o.cacheRead } : {};
    return { ...next, usage: { inputTokens: this.o.tokens ?? 10, outputTokens: 0, ...cache } };
  }
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.analyzed.push(req);
    return { rawText: this.o.hop?.shift() ?? reply(), usage: { inputTokens: this.o.tokens ?? 10 } };
  }
}

export interface ToolHarnessOpts extends HarnessOpts {
  maxToolCalls?: number;
  tokenLimit?: number;
  anonymize?: boolean;
  retries?: number;
  ctx?: Partial<WatsonRoundContext>;
}

/** The phase-4 harness with tool mode on: the scripted provider and the real converseRestored gate. */
export async function toolHarness(p: Scripted, o: ToolHarnessOpts = {}) {
  const h = await harness([], o);
  const anonStore = h.ctx.opts.anonStore!;
  if (o.anonymize) await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: true });
  const gate = { log, opts: { anonStore, aiCostStore: h.ctx.costStore } };
  const ctx: WatsonRoundContext = {
    ...h.ctx,
    opts: { ...h.ctx.opts, retries: o.retries ?? 0, backoffMs: 0 },
    provider: p,
    requireProvider: () => p,
    maxToolCalls: o.maxToolCalls ?? 4,
    ...(o.tokenLimit !== undefined ? { tokenLimit: o.tokenLimit } : {}),
    converseRestored: (caseId, state, prov, req, session, label) =>
      converseRestored(gate, caseId, state, prov, req, session, label),
    ...o.ctx,
  };
  const run = (text = "any rclone?", over: Partial<WatsonRoundInput> = {}): Promise<WatsonChat> =>
    runWatsonRound(ctx, CASE, { text, source: "dashboard", ...over });
  return { ...h, ctx, run };
}

/** Call runToolLoop directly (the Outcome is not saved on the turn until Task 7). */
export async function loopOutcome(
  ctx: WatsonRoundContext,
  over: Partial<ToolLoopInput> = {},
  text = "any rclone?",
) {
  const state = await ctx.stateStore.load(CASE);
  const chat = await ctx.chatStore.load(CASE);
  const { base } = await watsonBaseInput(ctx, CASE, state, chat, text, true);
  const counter = { calls: 0 };
  const before = { usd: 0, tokens: 0 };
  const outcome = await runToolLoop({
    ctx,
    caseId: CASE,
    chat,
    state,
    base,
    head: undefined,
    cap: ctx.maxToolCalls ?? 4,
    reaction: false,
    known: {
      questions: new Set(state.keyQuestions.map((q) => q.id)),
      pastes: new Set(chat.pastes.map((x) => x.id)),
      events: new Set(state.forensicTimeline.map((e) => e.id)),
      citations: citationSets(chat.pastes, state.findings),
    },
    counter,
    spent: () => spentNow(ctx, CASE, chat, before),
    rest: { shownEvents: [], questions: [] },
    ask: async () => {
      throw new Error("the hop is not used here");
    },
    ...over,
  });
  return { outcome, counter };
}

/** The tool results the n-th send (0-based) carried, flattened. */
export const resultsIn = (req: ConverseRequest) =>
  req.transcript.flatMap((t) => (t.role === "tool" ? t.results : []));

export const lastTurn = (chat: WatsonChat) => chat.turns.at(-1)!;
