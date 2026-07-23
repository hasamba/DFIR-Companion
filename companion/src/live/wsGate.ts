import type { Server } from "node:http";
import { WebSocketServer } from "ws";
import type { CaseStore } from "../storage/caseStore.js";
import { parseCookieHeader, unlockCookieName, verifyUnlockToken } from "../analysis/casePassword.js";
import { isOriginAllowed } from "../http/originGuard.js";
import type { LiveHub, SocketLike } from "./hub.js";

/**
 * Authorization for a `/ws` upgrade (issue #212).
 *
 * The live hub broadcasts the COMPLETE investigation state to every socket subscribed to a case, and
 * the upgrade handler used to take `?caseId=` on faith: no origin check, no case-existence check,
 * and — because Express middleware does not run during a WebSocket upgrade — no case-password check
 * either. Anyone who knew a locked case's id received its full contents on the next broadcast.
 *
 * Two things make this different from an HTTP route, and both argue for checking here rather than
 * relying on anything upstream:
 *   - A WebSocket handshake is not subject to the same-origin policy. Any page can open a socket to
 *     any origin, so `Origin` is the only signal available and must be validated explicitly.
 *   - The case-password middleware is mounted on `/cases/:id` and never sees `/ws`.
 */

export type WsUpgradeDecision =
  | { ok: true; caseId: string }
  | { ok: false; reason: string };

export interface WsUpgradeRequest {
  url: string | undefined;
  headers: { host?: string; origin?: string; cookie?: string };
}

export interface WsUpgradeDeps {
  store: CaseStore;
  secret: Buffer;
  allowedOrigins: string[];
}

// Mirrors the id shape CaseStore is willing to create, so a traversal-flavoured id is refused
// before it is used to look anything up.
const SAFE_CASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Decide whether this upgrade may subscribe, and to which case. Never throws. */
export async function authorizeWsUpgrade(req: WsUpgradeRequest, deps: WsUpgradeDeps): Promise<WsUpgradeDecision> {
  const { headers } = req;

  if (!isOriginAllowed(headers.origin, headers.host, deps.allowedOrigins)) {
    return { ok: false, reason: `origin "${headers.origin}" is not allowed` };
  }

  let caseId: string;
  try {
    caseId = new URL(req.url ?? "", "http://localhost").searchParams.get("caseId")?.trim() ?? "";
  } catch {
    return { ok: false, reason: "malformed upgrade url" };
  }
  if (!caseId) return { ok: false, reason: "caseId is required" };
  if (!SAFE_CASE_ID.test(caseId)) return { ok: false, reason: `invalid caseId "${caseId}"` };

  let meta;
  try {
    meta = await deps.store.getCaseMeta(caseId);
  } catch {
    // Fail CLOSED, exactly as the HTTP case-lock gate does: an unexpected read failure must not
    // default to handing out state.
    return { ok: false, reason: `case "${caseId}" could not be read` };
  }
  if (!meta) return { ok: false, reason: `case "${caseId}" not found` };
  if (!meta.password) return { ok: true, caseId };

  const token = parseCookieHeader(headers.cookie)[unlockCookieName(caseId)];
  if (token && verifyUnlockToken(token, caseId, meta.password.salt, deps.secret)) {
    return { ok: true, caseId };
  }
  return { ok: false, reason: `case "${caseId}" is locked` };
}

/**
 * Mount the live-state WebSocket on `server`, admitting only upgrades that pass
 * {@link authorizeWsUpgrade}.
 *
 * Authorization runs during the UPGRADE, not after `connection` — `noServer: true` plus an explicit
 * `handleUpgrade` is what makes that possible. Deciding after the handshake would be wrong twice
 * over: a rejected client would still have completed a connection, and an accepted one would be
 * subscribed only after an async case lookup, leaving a window in which it silently misses the
 * broadcasts it just connected for. Here the handshake completes only for a socket that is already
 * authorized, and the subscribe happens before the socket is handed out.
 */
export function attachLiveSocket(server: Server, hub: LiveHub, deps: WsUpgradeDeps): WebSocketServer {
  const wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", (req, socket, head) => {
    // Only claim our own path; anything else is left for another handler to answer (or to time out).
    const path = new URL(req.url ?? "", "http://localhost").pathname;
    if (path !== "/ws") return;

    void authorizeWsUpgrade({ url: req.url, headers: req.headers }, deps)
      .then((decision) => {
        if (!decision.ok) {
          // Refuse before the handshake: the client gets an HTTP error and never has a socket.
          socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
          socket.destroy();
          return;
        }
        const { caseId } = decision;
        wss.handleUpgrade(req, socket, head, (ws) => {
          hub.subscribe(caseId, ws as unknown as SocketLike);
          ws.on("close", () => hub.unsubscribe(caseId, ws as unknown as SocketLike));
          wss.emit("connection", ws, req);
        });
      })
      .catch(() => socket.destroy());
  });

  return wss;
}
