import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import type { RouteContext } from "./context.js";
import { mirrorAudit } from "./watsonMirrorSupport.js";

// #2647: the Watson panel's "Mirrored to Telegram" list. It shows which Telegram chats mirror the case
// and can switch each one OFF. There is deliberately no "on" route: turning mirroring on must come
// from inside the chat (`/dfir mirror on`), by a user on the Telegram allowlist.
//
//   GET  /cases/:id/watson/mirrors
//   POST /cases/:id/watson/mirrors/:chatId/off
//
// The demo has no mirror, and the list is empty there: chat ids are never shown to strangers.

/** A Telegram chat id: a number (negative for groups) or an @channel handle. */
const CHAT_ID = /^(-?\d{1,20}|@[A-Za-z0-9_]{1,64})$/;

export function registerWatsonMirrorRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/watson/mirrors", async (req: Request, res: Response) => {
    const store = options.watsonMirrorStore;
    if (options.demoMode || !store) return void res.json({ mirrors: [] });
    try {
      const mirrors = (await store.listCase(req.params.id)).map((m) => ({
        chatId: m.chatId,
        chatType: m.chatType,
        enabledAt: m.enabledAt,
        enabledBy: m.enabledBy,
        held: m.held === true,
        pending: m.pending.length,
      }));
      res.json({ mirrors });
    } catch (err) {
      ctx.serverLogger.warn(`[telegram-mirror] list failed: ${(err as Error).message}`);
      res.status(500).json({ error: "Could not read the Telegram mirror list." });
    }
  });

  app.post("/cases/:id/watson/mirrors/:chatId/off", async (req: Request, res: Response) => {
    const store = options.watsonMirrorStore;
    const { id, chatId } = req.params;
    if (!store) return void res.status(404).json({ error: "Telegram mirroring is not set up." });
    if (!CHAT_ID.test(chatId)) return void res.status(400).json({ error: "invalid chat id" });
    try {
      const entry = await store.get(chatId);
      if (!entry || entry.caseId !== id)
        return void res.status(404).json({ error: "This chat is not mirroring the case." });
      await store.disable(chatId);
      const actor = requestAuthentication(req)?.identity.displayName ?? "analyst";
      mirrorAudit(ctx, actor)(
        id,
        "watson-mirror-off",
        `Telegram chat ${chatId}: mirroring switched off from the dashboard`,
      );
      res.json({ ok: true });
    } catch (err) {
      ctx.serverLogger.warn(`[telegram-mirror] off failed: ${(err as Error).message}`);
      res.status(500).json({ error: "Could not switch the mirror off." });
    }
  });
}
