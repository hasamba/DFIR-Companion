import type { Request, RequestHandler, Response, NextFunction } from "express";

/**
 * Browser-origin gate for the localhost companion API (issue #211).
 *
 * Binding to 127.0.0.1 keeps other MACHINES out; it does nothing about other ORIGINS. A page on
 * any website you visit while the companion is running can issue cross-origin requests to
 * http://127.0.0.1:4773 — and the API previously answered every one of them with
 * `Access-Control-Allow-Origin: *` plus a private-network opt-in. That turned "visited a web page"
 * into custom-tool creation and, from there, local process execution.
 *
 * The gate splits callers into three groups:
 *
 *  1. NO `Origin` header — curl, the push-to-companion scripts, Velociraptor, MCP clients. Allowed.
 *     These are not the threat: a process that can already run on this machine does not need the
 *     companion's help to run more code, and blocking them breaks every documented scripted flow.
 *  2. A TRUSTED browser origin — the capture extension, the dashboard on loopback, the server's own
 *     host (so the hosted demo and reverse-proxy setups work), or an operator-configured origin.
 *     Allowed, and answered with that exact origin echoed back rather than a wildcard.
 *  3. Anything else — a real web page. Rejected with 403 before the route runs, and with no CORS or
 *     private-network headers, so the browser fails the preflight too.
 */

// Browser-extension schemes. An unpacked/dev install gets a randomly generated extension id, so the
// id itself is not something we can pin — the scheme is the durable signal. A hostile extension is
// out of scope here: it would need to be installed, at which point it has its own host permissions.
const EXTENSION_SCHEMES = new Set(["chrome-extension:", "moz-extension:", "safari-web-extension:"]);

// The dashboard is served by this same process, so in a normal install its origin is loopback on
// whatever port the companion picked (DFIR_PORT). Any port is fine; a remote page cannot forge these.
const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Parse `DFIR_ALLOWED_ORIGINS` — a comma-separated origin list — into normalized origins. */
export function parseAllowedOrigins(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, "")) // tolerate a pasted trailing slash
    .filter((s) => s.length > 0);
}

/**
 * Is this browser origin allowed to talk to the companion?
 *
 * `host` is the server's own Host header, which makes same-origin work without configuration no
 * matter where the companion is deployed (loopback, the Railway demo, behind a reverse proxy).
 */
export function isOriginAllowed(origin: string | undefined, host: string | undefined, extra: string[]): boolean {
  if (!origin) return true; // non-browser caller — see group 1 above

  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false; // unparseable, including the literal "null" origin of a sandboxed iframe/data: URL
  }

  if (EXTENSION_SCHEMES.has(url.protocol)) return true;
  // Compare parsed components, never substrings: `https://127.0.0.1.evil.example` contains a
  // trusted host as a prefix but is a completely different origin.
  if (host && url.host.toLowerCase() === host.toLowerCase()) return true;
  if (LOOPBACK_HOSTNAMES.has(url.hostname.toLowerCase())) return true;
  return extra.includes(`${url.protocol}//${url.host}`);
}

/** Express middleware enforcing {@link isOriginAllowed}, and emitting origin-scoped CORS headers. */
export function createOriginGuard(opts: { allowedOrigins?: string[] } = {}): RequestHandler {
  const extra = opts.allowedOrigins ?? [];
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;
    if (!isOriginAllowed(origin, req.headers.host, extra)) {
      // 403 with no CORS headers: the page cannot read this response, and a preflight shaped like
      // this fails, so the browser never sends the real request either.
      res.status(403).json({
        error: `origin "${origin}" is not allowed to reach the DFIR companion` +
          " — add it to DFIR_ALLOWED_ORIGINS if this is your own dashboard",
      });
      return;
    }

    if (origin) {
      res.header("Access-Control-Allow-Origin", origin); // echo the caller, never "*"
      res.header("Vary", "Origin"); // the response varies by origin, so it must not be cached across them
      res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      res.header("Access-Control-Allow-Headers", "Content-Type");
      // Chromium Private Network Access: a request from an extension page to a private address
      // (127.0.0.1) is blocked unless the preflight allows it. Only ever granted to a trusted origin.
      res.header("Access-Control-Allow-Private-Network", "true");
    }

    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  };
}
