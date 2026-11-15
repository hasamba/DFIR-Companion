import type { Express, Request, Response } from "express";
import { WATSON_TURN_TEXT_MAX } from "../analysis/ai/watson/chatStore.js";
import type { WatsonRoundDeps } from "../analysis/ai/watson/pipelineRound.js";
import { WatsonAiOff, type WatsonDisposition } from "../analysis/ai/watson/round.js";
import { watsonRuns } from "../analysis/ai/watson/runRegistry.js";
import type { WatsonChat } from "../analysis/ai/watson/types.js";
import { withStalledLaunches } from "../analysis/ai/watson/velo/launchResolve.js";
import { requestAuthentication } from "../auth/types.js";
import type { RouteContext } from "./context.js";
import { watsonRoundDeps } from "./watsonDeps.js";
import { IDEMPOTENCY_KEY_RE, WatsonMessageDedupe } from "./watsonIdempotency.js";

/**
 * POST /cases/:id/watson/message (moved from routes/watson.ts) and POST /cases/:id/watson/cancel.
 *
 * A message with an Idempotency-Key header is deduped (routes/watsonIdempotency.ts): a resend after
 * a lost answer attaches to the first round, or gets the current saved chat. A message without the
 * header (slash, MCP, an old client) is not deduped. At most WATSON_MAX_ACTIVE_PER_CASE messages run
 * or wait on a case; a new one beyond that is refused with 429, and a duplicate still attaches.
 *
 * The stop does not check the AI switch or the provider: a stop must always work. A closed case
 * refuses it with 423 before this handler; the round then stops at its next check (WatsonCaseFrozen).
 */

export const WATSON_MAX_ACTIVE_PER_CASE = 3;
const BUSY_TEXT = `Watson already has ${WATSON_MAX_ACTIVE_PER_CASE} messages for this case. Wait for an answer, then send again.`;
const BAD_KEY_TEXT = "The request key is not valid. Send the message again.";
const KEY_CONFLICT_TEXT = "This request key belongs to a different message. Send the message again.";
const NO_PROVIDER_TEXT = "Watson has no AI provider. Set one up in Settings.";

/** A check that refuses a model-calling request before any work, with its HTTP status. */
export class WatsonRouteRefusal extends Error {
  constructor(
    readonly status: 404 | 409 | 429 | 501,
    message: string,
  ) {
    super(message);
    this.name = "WatsonRouteRefusal";
  }
}

/** What a model-calling route needs once its checks pass. */
export interface WatsonRun {
  pipeline: NonNullable<RouteContext["options"]["pipeline"]>;
  deps: WatsonRoundDeps;
}

/** The checks every model-calling route makes before it saves anything; throws WatsonRouteRefusal. */
export async function watsonRunOrRefuse(ctx: RouteContext, caseId: string): Promise<WatsonRun> {
  if ((await ctx.store.getCaseMeta(caseId).catch(() => null)) === null) {
    throw new WatsonRouteRefusal(404, "case not found");
  }
  const deps = watsonRoundDeps(ctx);
  const pipeline = ctx.options.pipeline;
  if (!deps || !pipeline) throw new WatsonRouteRefusal(501, NO_PROVIDER_TEXT);
  if (!(await deps.isAiEnabled(caseId))) throw new WatsonRouteRefusal(409, new WatsonAiOff().message);
  return { pipeline, deps };
}

type SendError = (res: Response, err: unknown) => Response;
type Dedupe = WatsonMessageDedupe<{ disposition: WatsonDisposition }>;

const stringOrEmpty = (v: unknown): string => (typeof v === "string" ? v : "");

/** The message text, or the 400 answer it gets. */
function messageText(body: unknown): { text: string } | { error: string } {
  const text = stringOrEmpty((body as { text?: unknown } | undefined)?.text).trim();
  if (!text) return { error: "text is required" };
  if (text.length > WATSON_TURN_TEXT_MAX) {
    return {
      error: `The message is longer than ${WATSON_TURN_TEXT_MAX} characters. Send long text with the paste button.`,
    };
  }
  return { text };
}

/**
 * Admits new messages per case. A message counts from its admission until its round registers in
 * watsonRuns (the same synchronous step), then watsonRuns counts it. So two concurrent requests
 * cannot both pass a full case during the asynchronous checks.
 */
class WatsonAdmission {
  private readonly admitting = new Map<string, number>();

  enter(caseId: string): () => void {
    const status = watsonRuns.status(caseId);
    const active = (status ? status.queued + 1 : 0) + (this.admitting.get(caseId) ?? 0);
    if (active >= WATSON_MAX_ACTIVE_PER_CASE) throw new WatsonRouteRefusal(429, BUSY_TEXT);
    this.admitting.set(caseId, (this.admitting.get(caseId) ?? 0) + 1);
    let left = false;
    return () => {
      if (left) return;
      left = true;
      const n = (this.admitting.get(caseId) ?? 1) - 1;
      if (n > 0) this.admitting.set(caseId, n);
      else this.admitting.delete(caseId);
    };
  }
}

export function registerWatsonMessageRoutes(
  app: Express,
  ctx: RouteContext,
  sendWatsonError: SendError,
): void {
  const { options } = ctx;
  const dedupe: Dedupe = new WatsonMessageDedupe();
  const admission = new WatsonAdmission();

  /** One admitted round. The admission ends in the same step the round registers in watsonRuns. */
  async function runMessage(caseId: string, text: string, actor: string) {
    const leave = admission.enter(caseId);
    let run: WatsonRun;
    try {
      run = await watsonRunOrRefuse(ctx, caseId); // the mutable checks run only here (Codex #8)
    } finally {
      leave();
    }
    let disposition: WatsonDisposition = "failed";
    const input = {
      text,
      actor,
      source: "dashboard" as const, // may auto-launch (G12)
      onDisposition: (d: WatsonDisposition) => (disposition = d),
    };
    const chat = await run.pipeline.watsonRound(caseId, input, run.deps);
    return { chat, disposition };
  }

  /** The current saved chat: what a keyed request answers, the first one and every replay (Codex #9). */
  async function savedChat(caseId: string): Promise<WatsonChat> {
    if (!options.watsonChatStore) throw new WatsonRouteRefusal(501, NO_PROVIDER_TEXT);
    return withStalledLaunches(caseId, await options.watsonChatStore.load(caseId));
  }

  async function answer(req: Request, res: Response, caseId: string, text: string): Promise<Response> {
    const actor = requestAuthentication(req)?.identity.displayName ?? "analyst";
    const key = req.get("Idempotency-Key");
    if (key === undefined) {
      const { chat } = await runMessage(caseId, text, actor);
      return res.status(200).json(withStalledLaunches(caseId, chat));
    }
    if (!IDEMPOTENCY_KEY_RE.test(key)) return res.status(400).json({ error: BAD_KEY_TEXT });
    const scope = { caseId, identityId: requestAuthentication(req)?.identity.id ?? "local" };
    const claim = dedupe.run(scope, key, text, async () => {
      const { disposition } = await runMessage(caseId, text, actor);
      return { disposition }; // the entry keeps no chat
    });
    if (claim.kind === "conflict") return res.status(409).json({ error: KEY_CONFLICT_TEXT });
    await claim.promise;
    return res.status(200).json(await savedChat(caseId));
  }

  app.post("/cases/:id/watson/message", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const body = messageText(req.body);
    if ("error" in body) return res.status(400).json({ error: body.error });
    try {
      return await answer(req, res, caseId, body.text);
    } catch (err) {
      if (err instanceof WatsonRouteRefusal) return res.status(err.status).json({ error: err.message });
      return sendWatsonError(res, err);
    } finally {
      options.onWatson?.(caseId); // the round saves the analyst turn (or an error turn) even when it fails
    }
  });

  app.post("/cases/:id/watson/cancel", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!options.watsonChatStore) return res.status(501).json({ error: "Watson is not configured" });
    if ((await ctx.store.getCaseMeta(caseId).catch(() => null)) === null) {
      return res.status(404).json({ error: "case not found" });
    }
    return res.status(200).json({ cancelled: watsonRuns.cancel(caseId) });
  });
}
