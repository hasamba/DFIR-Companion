import { AnonymizationChangedError } from "../../anonRevision.js";
import { retryPolicy } from "../aiContext.js";
import { isRetryableError } from "../retry.js";
import {
  limitReached,
  spendDelta,
  WatsonAiOff,
  WatsonCaseFrozen,
  WatsonCostLimitReached,
  watsonSpend,
  type WatsonRoundContext,
  type WatsonSpend,
} from "./roundContext.js";
import type { WatsonChat } from "./types.js";

// Watson's guarded model call (moved out of round.ts for the tool loop, phase 5). Before EVERY
// provider attempt — the first send, each retry, each tool-loop send and the hop's call — it checks
// the case's cost and token limits, the AI switch and whether the case was closed (D5). A stop is
// thrown before the attempt, so it is never retried and nothing more is sent.

/** Watson's spend on the case now: the chat's total before this round plus what the round used. */
export async function spentNow(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  before: WatsonSpend,
): Promise<WatsonSpend> {
  const d = spendDelta(before, await watsonSpend(ctx, caseId));
  return { usd: chat.costUSD + d.usd, tokens: chat.tokens + d.tokens };
}

/** AI off, a closed or archived case, or null. Without `canContinue` only the AI switch is read. */
async function continueState(ctx: WatsonRoundContext, caseId: string): Promise<"off" | "frozen" | null> {
  if (ctx.canContinue) return ctx.canContinue(caseId);
  return (await ctx.isAiEnabled(caseId)) ? null : "off";
}

/** Throws the stop that applies now (D5): a limit, AI off or a frozen case. Nothing when none does. */
export async function assertMayContinue(
  ctx: WatsonRoundContext,
  caseId: string,
  spent: () => Promise<WatsonSpend>,
): Promise<void> {
  const limited = ctx.costLimitUSD !== undefined || ctx.tokenLimit !== undefined;
  const reached = limited ? limitReached(ctx, await spent()) : null;
  if (reached) throw new WatsonCostLimitReached(reached);
  await assertCanContinue(ctx, caseId);
}

/** Throws WatsonAiOff or WatsonCaseFrozen. Run before each tool: a lookup costs nothing (D5). */
export async function assertCanContinue(ctx: WatsonRoundContext, caseId: string): Promise<void> {
  const state = await continueState(ctx, caseId);
  if (state === "off") throw new WatsonAiOff();
  if (state === "frozen") throw new WatsonCaseFrozen();
}

/** Tool-loop options: an attempt ceiling on `counter.calls` (R1), and errors that are never retried. */
export interface GuardOptions {
  /** No attempt starts once `counter.calls` has reached this. A retry it blocks rethrows the error. */
  ceiling?: number;
  noRetry?(err: unknown): boolean;
}

/** Thrown when the attempt ceiling stops a first attempt (the loop checks before it asks). */
export class WatsonSendCeiling extends Error {
  constructor() {
    super("Watson reached its lookup limit for this question. Send your message again.");
    this.name = "WatsonSendCeiling";
  }
}

const mayRetry = (err: unknown, o: GuardOptions): boolean =>
  !(err instanceof AnonymizationChangedError) && !o.noRetry?.(err) && isRetryableError(err);

/**
 * One model call with Watson's own retry loop, so every stop is checked before EVERY provider attempt
 * (a retry on a malformed reply included), and `counter` counts attempts, not calls. callAiJson runs
 * with retries off; the same policy and the same retry rules apply out here.
 */
export async function guardedCall<T>(
  ctx: WatsonRoundContext,
  caseId: string,
  counter: { calls: number },
  spent: () => Promise<WatsonSpend>,
  call: (one: WatsonRoundContext) => Promise<T>,
  o: GuardOptions = {},
): Promise<T> {
  const { retries, backoffMs } = retryPolicy(ctx);
  const one: WatsonRoundContext = { ...ctx, opts: { ...ctx.opts, retries: 0 } };
  let last: unknown;
  for (let attempt = 0; ; attempt++) {
    await assertMayContinue(ctx, caseId, spent);
    if (o.ceiling !== undefined && counter.calls >= o.ceiling) {
      throw attempt > 0 ? last : new WatsonSendCeiling();
    }
    counter.calls++;
    try {
      return await call(one);
    } catch (err) {
      if (attempt >= retries || !mayRetry(err, o)) throw err;
      last = err;
      ctx.log?.warn(`Watson call attempt ${attempt + 1} failed; retrying`, { caseId });
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
    }
  }
}
