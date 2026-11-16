import type { Express, Request, Response } from "express";
import { logActivityWithWarning } from "../analysis/activityLog.js";
import {
  chainLimitText,
  parseChainMax,
  WATSON_AUTO_CHAIN_LIMIT_MAX,
  withChainMax,
  withChainStopped,
} from "../analysis/ai/watson/autoChain.js";
import type { WatsonChat } from "../analysis/ai/watson/types.js";
import { withStalledLaunches } from "../analysis/ai/watson/velo/launchResolve.js";
import { requestAuthentication } from "../auth/types.js";
import type { RouteContext } from "./context.js";

/**
 * The Auto chain controls in the Watson panel (user decision of 2026-11-16), no model call:
 *
 *   POST /cases/:id/watson/auto-chain {max}   the case's chain limit, 0..50 (0 = no limit) → the chat
 *   POST /cases/:id/watson/auto-chain/stop    stop the chain until the analyst's next message → the chat
 *
 * Both are case writes (a closed or archived case refuses them, caseWriteAllowlist.ts) and both are
 * audited. Stop chain keeps Auto on: Watson still applies case writes, and a launch already running
 * finishes. Only Watson's own follow-up launches stop.
 */
export function registerWatsonAutoChainRoutes(
  app: Express,
  ctx: RouteContext,
  sendError: (res: Response, err: unknown) => Response,
): void {
  const { options, store } = ctx;
  const caseMissing = async (caseId: string): Promise<boolean> =>
    (await store.getCaseMeta(caseId).catch(() => null)) === null;
  const actor = (req: Request): string => requestAuthentication(req)?.identity.displayName ?? "analyst";

  async function change(
    req: Request,
    res: Response,
    detail: string,
    fn: (chat: WatsonChat) => WatsonChat,
  ): Promise<Response> {
    const caseId = req.params.id;
    const chatStore = options.watsonChatStore;
    if (!chatStore) return res.status(501).json({ error: "Watson is not configured" });
    if (await caseMissing(caseId)) return res.status(404).json({ error: "case not found" });
    try {
      const entry = { actor: actor(req), category: "ai" as const, action: "watson.autoChain", detail };
      const unaudited = await logActivityWithWarning(
        options.activityLogStore,
        options.onActivity,
        caseId,
        entry,
      );
      if (unaudited) return res.status(503).json({ error: `The Auto chain did not change: ${unaudited}` });
      const chat = await chatStore.update(caseId, fn);
      return res.status(200).json(withStalledLaunches(caseId, chat));
    } catch (err) {
      return sendError(res, err);
    } finally {
      options.onWatson?.(caseId);
    }
  }

  app.post("/cases/:id/watson/auto-chain/stop", (req: Request, res: Response) =>
    change(req, res, "Stopped the Auto chain until the next analyst message", withChainStopped),
  );

  app.post("/cases/:id/watson/auto-chain", (req: Request, res: Response) => {
    const max = parseChainMax(req.body?.max);
    if (max === null) {
      return res
        .status(400)
        .json({
          error: `The chain limit must be a whole number from 0 to ${WATSON_AUTO_CHAIN_LIMIT_MAX} (0 = no limit).`,
        });
    }
    return change(req, res, `Set the Auto chain limit to ${chainLimitText(max)}`, (c) =>
      withChainMax(c, max),
    );
  });
}
