import { PresidioApprovalRequired } from "../analysis/presidio.js";
import { redactPaths } from "../analysis/redactPaths.js";
import type { SlashCommandResponse } from "../analysis/slashCommand.js";
import { WATSON_TURN_TEXT_MAX } from "../analysis/ai/watson/chatStore.js";
import { WatsonAiOff, WatsonCostLimitReached } from "../analysis/ai/watson/round.js";
import type { WatsonChat, WatsonTurn } from "../analysis/ai/watson/types.js";
import type { RouteContext } from "./context.js";
import { frozenCaseRefusal } from "./importCaseGuard.js";
import { watsonRoundDeps } from "./watsonDeps.js";

/**
 * `/dfir ask <question>` from Slack, Teams or Telegram: one Watson round in the case's shared chat
 * (product decision D2). The team sees the question and the answer in the Watson panel, the round
 * counts toward Watson's limits, and it waits behind a round already running on the case.
 *
 * The bot reply is Watson's message, the free-form answer ("[status] answer") and its "Next:"
 * pointer. A refused round answers with the refusal: a closed or archived case (the same sentence a Watson POST gets from the case-write
 * gate — checked here because chat routes are outside /cases/:id), AI off, a reached limit, a
 * Presidio hold. `ok` is false for every refusal and failure, so the caller can audit the outcome.
 */
export interface WatsonSlashResult {
  reply: SlashCommandResponse;
  ok: boolean;
}

const refusal = (title: string): WatsonSlashResult => ({ reply: { title, lines: [] }, ok: false });

/** The turn this round left: the first Watson reply or error after the analyst's message. */
function roundTurn(chat: WatsonChat, text: string, actor: string): WatsonTurn | undefined {
  for (let i = chat.turns.length - 1; i >= 0; i--) {
    const t = chat.turns[i];
    if (t.role === "analyst" && t.actor === actor && t.text === text) {
      return chat.turns.slice(i + 1).find((r) => r.role === "watson" || r.error);
    }
  }
  return undefined;
}

export async function runWatsonSlash(
  ctx: RouteContext,
  caseId: string,
  question: string,
  actor: string,
): Promise<WatsonSlashResult> {
  const frozen = await frozenCaseRefusal(ctx.store, caseId, "changing it");
  if (frozen) return refusal(frozen);
  const deps = watsonRoundDeps(ctx);
  const pipeline = ctx.options.pipeline;
  if (!deps || !pipeline) return refusal("AI provider not configured for Watson.");
  if (!(await deps.isAiEnabled(caseId))) return refusal(new WatsonAiOff().message);
  const text = question.slice(0, WATSON_TURN_TEXT_MAX); // the round stores at most this much
  try {
    const chat = await pipeline.watsonRound(caseId, { text, actor }, deps);
    const turn = roundTurn(chat, text, actor);
    if (!turn || turn.error) {
      // The stored error turn already reads "Watson could not answer: …"; it goes to chat, so no paths.
      const why = turn?.text ?? "Watson could not answer: no reply was saved.";
      return refusal(redactPaths(why, [ctx.store.casesRoot]));
    }
    const answer = turn.answer;
    const said = answer?.answer ? [`[${answer.status}] ${answer.answer}`] : [];
    return {
      reply: {
        title: `Q: ${question}`,
        lines: [turn.text || "(no answer)", ...said, ...(answer?.pointer ? [`Next: ${answer.pointer}`] : [])],
      },
      ok: true,
    };
  } catch (err) {
    if (err instanceof WatsonAiOff || err instanceof WatsonCostLimitReached) return refusal(err.message);
    if (err instanceof PresidioApprovalRequired) {
      return refusal(`${err.message} — resolve them in the dashboard's Anonymization panel, then ask again.`);
    }
    return refusal(`Watson failed: ${redactPaths((err as Error).message, [ctx.store.casesRoot])}`);
  } finally {
    ctx.options.onWatson?.(caseId); // the round saves the analyst turn (or an error turn) even when it fails
  }
}
