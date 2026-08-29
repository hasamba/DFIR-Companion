/**
 * The Express middleware pipeline, in the order every request traverses it. Lifted out of createApp
 * by #416.
 *
 * ORDER IS THE WHOLE POINT of this file, and it is not stylistic. A guard only protects what is
 * registered AFTER it, so moving one line down here silently un-protects everything below it.
 * tests/architecture/routeInventory.test.ts records all ~469 Express layers — routes AND middleware
 * — in one interleaved list, so a guard that slides below the routes it guards shows up as a diff
 * rather than as a vulnerability. That test was mutation-proven on exactly this: moving
 * `caseLockGate` below the import routes reports `10: … caseLockGate/3` → `121: … caseLockGate/3`.
 *
 * The layers, and why each sits where it does:
 *   originGuard          browser origin + DNS-rebinding rejection, before anything reads the body
 *   securityHeaders      CSP/Trusted-Types on every response, including error responses
 *   demoModeReadOnlyGate blocks writes on the public demo before any route can act on them
 *   requestLogger        so even a rejected request is logged
 *   operationalMetrics   counts what the logger logged
 *   preAuthBodyGate      team mode only: 401 before the generous parsers can read a stranger's body
 *   json/text parsers    the body limit; generous because imports arrive as request bodies
 *   bodyParserErrorHandler  4-arg, immediately after the parsers so it catches THEIR errors
 *   errorPathRedactor    wraps res.json ONCE for every route, present and future
 *   teamAuth             its own routes first, then the middleware that guards everything after
 *   caseIdGate           rejects a malformed :id before any handler builds a path from it
 *   caseLockGate         per-case password, mounted before ANY /cases/:id/* route exists
 *   abandonedCaseReadGate  drops GETs whose client already hung up
 *
 * Nothing here reads case state. Everything here can reject a request.
 */
import express, { type Express, type Request, type Response, type NextFunction } from "express";
import type { Buffer } from "node:buffer";
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import { createOriginGuard } from "../http/originGuard.js";
import { createSecurityHeaders } from "../http/securityHeaders.js";
import { createOperationalHttpMetrics } from "../analysis/operationalHttpMetrics.js";
import { createCaseIdGate } from "../analysis/caseIdGate.js";
import { createCaseLockGate } from "../analysis/caseLockGate.js";
import {
  verifyUnlockToken,
  isRememberedUnlockToken,
  unlockCookieName,
  parseCookieHeader,
} from "../analysis/casePassword.js";
import { isTeamAuthRoutePath, registerTeamAuthRoutes } from "../auth/authRoutes.js";
import { resolveRequestPolicy } from "../auth/policy.js";
import { redactPaths } from "../analysis/redactPaths.js";
import { registerStaticAssets } from "../http/staticAssets.js";
import { CaseNotFoundError } from "../ingest/captureIngest.js";
import { ZodError } from "zod";
import { logLine, getServerLogger } from "../logging/serverLogger.js";

/**
 * Ceiling on a body this server reads from a caller it has not authenticated yet, in MB (#681).
 *
 * The generous DFIR_MAX_BODY_MB limit exists for bulk evidence imports, and every import route
 * requires a credential. Count what is left — what a stranger may still POST a body to in team
 * mode — and it is a login form, a user/role edit, and three chat webhooks. None of them is bulk
 * anything; the largest is a Telegram Update. 1 MB is the same cap routes/slashCommand.ts already
 * puts on Slack's own urlencoded parser.
 *
 * Not a separate env knob on purpose: it is a floor under DFIR_MAX_BODY_MB, so lowering that knob
 * lowers this too and the 413 still names the one variable an operator has to change.
 */
const PRE_AUTH_BODY_MB = 1;

/**
 * Set on a request whose body the pre-auth parsers read, so bodyParserErrorHandler can tell which
 * of the two limits rejected it. The two need DIFFERENT advice: "raise DFIR_MAX_BODY_MB" is sound
 * for an import and a dead end for a webhook, because the pre-auth cap is a floor and raising the
 * knob above 1 cannot lift it. An operator who followed that advice would restart and get the same
 * 413. Comparing byte counts instead would be ambiguous the moment the two limits coincide.
 */
type PreAuthBodyRequest = Request & { dfirPreAuthBody?: boolean };

/**
 * Bytes → the MB figure an operator actually typed. `DFIR_MAX_BODY_MB=0.25` is a number Node
 * accepts and body-parser honours, so rounding the reported limit to whole MB would answer a
 * 262,144-byte refusal with "exceeds the 0 MB limit" — a message that reads as a bug in the server
 * rather than a cap on the caller. toFixed(3) then Number() drops the trailing zeros an exact
 * value would otherwise grow (1 → "1", not "1.000").
 */
function megabytes(bytes: number): string {
  return String(Number((bytes / (1024 * 1024)).toFixed(3)));
}

export interface HttpStackDeps {
  store: CaseStore;
  options: AppOptions;
  /** Signs/verifies case-unlock cookies; shared with readUnlockState below. */
  instanceSecret: Buffer;
}

/**
 * Register every layer that runs BEFORE the route families. Call once, before any registerXRoutes.
 */
export function mountRequestPipeline(app: Express, { store, options, instanceSecret }: HttpStackDeps): void {
  // Let the browser extension and the dashboard reach this server, and turn every OTHER browser
  // origin away (issue #211) — plus every request arriving under a hostname we do not answer to
  // (#280), which is what a DNS-rebinding attack looks like from in here. Binding to 127.0.0.1
  // stops other machines, not other origins: without this gate any page you happen to be browsing
  // could POST a custom tool here and have the companion spawn it. Non-browser callers (curl,
  // scripted pushes) are unaffected. See src/http/originGuard.ts for the full threat model.
  app.use(
    createOriginGuard({
      allowedOrigins: options.allowedOrigins,
      allowedHosts: options.allowedHosts,
      allowedHostSuffixes: options.allowedHostSuffixes,
    }),
  );

  // Content-Security-Policy on every response. Scripts and styles are confined to this origin or a
  // per-response nonce, inline attributes are forbidden, and Chromium requires the audited Trusted
  // Types policies installed by safe-dom.js. Egress is pinned to this origin as a second boundary,
  // so a missed rendering escape still cannot beacon case data or API keys out. See
  // http/securityHeaders.ts.
  app.use(createSecurityHeaders());

  // Demo mode guard: allow all GETs and the manual reset route; block everything else.
  // This makes the public Railway demo safe — visitors can browse the pre-seeded case but
  // cannot create new cases, import evidence, trigger AI calls, or change global settings.
  if (options.demoMode) {
    app.use(function demoModeReadOnlyGate(req: Request, res: Response, next: NextFunction) {
      // GET /settings/browse-fs is the one GET that isn't safe to blanket-allow: it walks the
      // server's own filesystem on request, which on the public demo means any visitor could
      // enumerate arbitrary directories the server process can read.
      if (req.path === "/settings/browse-fs") {
        return res
          .status(403)
          .json({ error: "Demo mode: filesystem browsing is disabled on the public demo." });
      }
      if (req.method === "GET" || req.method === "OPTIONS") return next();
      if (req.path === "/cases/seed-demo") return next();
      return res
        .status(403)
        .json({ error: "Demo mode: this action is disabled. The demo case resets every hour." });
    });
  }

  // Log each request and its final status (useful for a local single-user tool).
  app.use(function requestLogger(req: Request, res: Response, next: NextFunction) {
    res.on("finish", () => {
      logLine(`[req] ${req.method} ${req.url} -> ${res.statusCode}`);
    });
    next();
  });
  app.use(createOperationalHttpMetrics(options.operationalMetrics));
  // JSON body limit. Bulk evidence imports (CSV / log / THOR / SIEM-EDR JSON exports) wrap the
  // whole file in the request body, and SIEM/EDR exports in particular are routinely tens to
  // hundreds of MB — so the cap is generous and configurable via DFIR_MAX_BODY_MB (default
  // 256 MB). Files beyond a few hundred MB approach V8's max string length; for those, split the
  // export. WHO may spend that budget is the gate below, not this limit.
  const maxBodyMb = Number(process.env.DFIR_MAX_BODY_MB) || 256;
  // Text types are listed once: the pre-auth parser below has to match exactly the same set, or a
  // body it was supposed to cap would fall through to the generous parser instead.
  const textBodyTypes = ["text/*", "application/x-ndjson", "application/jsonl"];

  // ── Authenticate BEFORE the generous parsers, in team mode (#681) ─────────────────────
  // This limit used to be justified by "localhost-only single-user tool, so a large limit is not a
  // DoS concern". That is true of DFIR_AUTH_MODE=single. It is false of DFIR_AUTH_MODE=team behind
  // a DFIR_HOST that answers the network: the parsers sat ABOVE teamAuth.middleware(), so a
  // stranger's 256 MB body was received, inflated, allocated, decoded and JSON-parsed in full, and
  // only THEN answered 401. A few concurrent requests exhaust the heap or stall the event loop.
  //
  // So resolve the policy — which is a pure function of method and path — and demand a credential
  // first. This layer only ever answers "no credential"; teamAuth.middleware() below still does the
  // whole authorization decision, on the parsed body, exactly as before. A request that gets past
  // here has proven it is someone, and only then is the generous limit its to spend.
  if (options.teamAuth) {
    const teamAuth = options.teamAuth;
    const preAuthLimit = `${Math.min(maxBodyMb, PRE_AUTH_BODY_MB)}mb`;
    const preAuthJson = express.json({ limit: preAuthLimit });
    const preAuthText = express.text({ limit: preAuthLimit, type: textBodyTypes });
    app.use(function preAuthBodyGate(req: Request, res: Response, next: NextFunction) {
      const policy = resolveRequestPolicy(req.method, req.path);
      // Two kinds of request legitimately arrive with no credential. The public routes — /health,
      // the login page, and the slash-command webhooks, which authenticate themselves against a
      // per-platform HMAC or shared secret inside the handler. And the /auth routes, because
      // logging in is HOW a caller gets a credential. Both parse right here, at the small limit;
      // body-parser then marks the request consumed, so the generous parsers below do nothing.
      //
      // POST /captures is NOT in this set even though its policy is decided by the caseId in its
      // body. Read middleware() again: the body picks WHICH case the caller may write to, but a
      // caller with no credential at all is turned away before that, by the same 401 this gate
      // sends. So a capture already had to be somebody, and its body is still parsed at the
      // generous limit — the extension's screenshots are unaffected by this change.
      if (policy.kind === "public" || isTeamAuthRoutePath(req.path)) {
        (req as PreAuthBodyRequest).dfirPreAuthBody = true;
        preAuthJson(req, res, (err) => (err ? next(err) : preAuthText(req, res, next)));
        return;
      }
      // Header- and cookie-only: nothing here touches the body, which is the entire point.
      if (teamAuth.authenticateRequest(req)) {
        next();
        return;
      }
      teamAuth.rejectUnauthenticated(req, res);
    });
  }

  app.use(express.json({ limit: `${maxBodyMb}mb` }));
  // Also accept text/plain + NDJSON bodies so the generic push endpoint (#84) can take a raw blob
  // (a Velociraptor monitor dump, an NDJSON alert stream) without forcing every caller to wrap it in
  // a JSON envelope. JSON bodies still parse via express.json above; this only catches non-JSON types.
  app.use(express.text({ limit: `${maxBodyMb}mb`, type: textBodyTypes }));

  // Turn body-parser failures into actionable JSON (instead of Express's default HTML page):
  // an over-limit upload → 413 with how to raise the cap; malformed JSON → 400. Placed right
  // after the parser so it catches its errors; normal requests skip it (4-arg = error-only).
  app.use(function bodyParserErrorHandler(
    err: Error & { type?: string; status?: number; limit?: number },
    req: Request,
    res: Response,
    next: NextFunction,
  ) {
    if (err?.type === "entity.too.large") {
      // Name the limit that actually fired, and give advice that works on it. Telling a webhook
      // its payload exceeded "the 256 MB limit" would be a puzzle; telling it to raise
      // DFIR_MAX_BODY_MB would be worse, because that knob cannot lift the pre-auth floor.
      const limitMb = megabytes(err.limit ?? maxBodyMb * 1024 * 1024);
      if ((req as PreAuthBodyRequest).dfirPreAuthBody) {
        return res.status(413).json({
          error: `request exceeds the ${limitMb} MB limit that applies before a caller is authenticated — this cap is fixed and DFIR_MAX_BODY_MB does not raise it; send a smaller payload, or authenticate and use an import route`,
        });
      }
      return res.status(413).json({
        error: `upload exceeds the ${limitMb} MB limit — raise DFIR_MAX_BODY_MB and restart the companion, or split the export into smaller files`,
      });
    }
    if (err?.type === "entity.parse.failed") {
      return res.status(400).json({ error: "request body is not valid JSON" });
    }
    return next(err);
  });

  // ── Absolute-path redaction on every error response (#250) ───────────────────────────
  // ~60 route catch blocks end in `res.status(500).json({ error: (err as Error).message })`, and
  // Node's fs errors carry the full path, so each one is a potential cases-root disclosure. Wrapping
  // res.json here is the single choke point that covers all of them — including routes added later
  // and the terminal error handler — with no per-handler opt-in, the same reasoning as the
  // caseIdGate/caseLockGate mounts below.
  //
  // ONLY the `error` field is rewritten. Ordinary fields legitimately carry filesystem paths that
  // the operator asked for: /settings/env round-trips DFIR_CASES_ROOT into the Settings form, and
  // the size report's per-file paths are case-relative, not absolute. Redacting those would break
  // features to no benefit. Request logging is untouched, so the console still shows real paths.
  app.use(function errorPathRedactor(_req: Request, res: Response, next: NextFunction) {
    const sendJson = res.json.bind(res);
    res.json = ((body: unknown) => {
      if (body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string") {
        // Spread rather than mutate: the caller's object literal is not ours to rewrite, and
        // overwriting an existing key preserves its position in the response.
        return sendJson({
          ...body,
          error: redactPaths((body as { error: string }).error, [store.casesRoot]),
        });
      }
      return sendJson(body);
    }) as typeof res.json;
    next();
  });

  if (options.teamAuth) {
    registerTeamAuthRoutes(app, options.teamAuth, store);
    app.use(options.teamAuth.middleware());
  }
  app.use("/cases/:id", createCaseIdGate());
  // Gates every /cases/:id/* route behind that case's password, when one is set. Mounted
  // here, before ANY /cases/:id/* route is registered, so it covers all of them via prefix
  // matching — a route added later is protected with no change to this file. See
  // caseLockGate.ts for the gate itself.
  app.use("/cases/:id", createCaseLockGate(store, instanceSecret));

  // Bail out of read-only case routes whose client already gave up (#174). The dashboard's connect
  // flow fans out ~40 GET requests per case; switching (or dismissing a slow-loading) case aborts the
  // abandoned case's fetches client-side, but Node is single-threaded — a request already queued
  // behind another one's synchronous JSON/graph work still gets dequeued and run to completion unless
  // something checks first. This is that check: skip the (often expensive) handler entirely once the
  // underlying connection is already gone, so the event loop reaches the new case's requests sooner.
  // GET-only: a write whose client disconnected mid-flight should still finish, not leave a partial edit.
  app.use("/cases/:id", function abandonedCaseReadGate(req: Request, res: Response, next: NextFunction) {
    if (req.method === "GET" && req.destroyed) return;
    next();
  });
}

/**
 * Whether a request already carries a valid unlock for `id` (used by /lock-status), and whether that
 * unlock — if present — was signed with "remember on this computer". The dashboard needs the latter
 * to know whether it's safe to explicitly forget the unlock when navigating away from a case it
 * didn't itself just unlock in this page load (e.g. one already unlocked via a remembered cookie
 * from an earlier session).
 */
export function createUnlockStateReader(instanceSecret: Buffer) {
  return function readUnlockState(
    req: Request,
    id: string,
    salt: string,
  ): { unlocked: boolean; remembered: boolean } {
    const cookies = parseCookieHeader(req.headers.cookie);
    const token = cookies[unlockCookieName(id)];
    if (!token) return { unlocked: false, remembered: false };
    const unlocked = verifyUnlockToken(token, id, salt, instanceSecret);
    return { unlocked, remembered: unlocked && isRememberedUnlockToken(token, id, salt, instanceSecret) };
  };
}

/**
 * Register the two layers that must come LAST: the static-asset whitelist and the terminal error
 * handler. Call once, after every route family.
 */
export function mountTerminalHandlers(app: Express): void {
  // Whitelisted static client assets (vendored libraries + first-party browser modules). The map
  // itself lives in src/http/staticAssets.ts — it grows every time a browser module is added, and
  // server.ts may not grow (#385). Registered here so the routes exist in tests too.
  registerStaticAssets(app);

  // Terminal error handler (4-arg, last-registered so it runs after every route). express-async-errors
  // forwards any error thrown or rejected inside an async route here; explicit next(err) calls land here
  // too. Without it, Express 4 would fall through to its default handler and leak an HTML stack-trace page
  // — or, for async routes it never catches, hang the connection. The failure is always logged (never
  // silently swallowed); ZodError/CaseNotFoundError keep their conventional 400/404 for routes that forgot
  // their own try/catch, and everything else becomes a generic JSON 500 so the client always gets a clean,
  // closed response. Per-route try/catch blocks still handle their own errors and never reach this.
  app.use(function terminalErrorHandler(err: unknown, req: Request, res: Response, next: NextFunction) {
    if (res.headersSent) return next(err);
    if (err instanceof ZodError)
      return res.status(400).json({ error: "invalid payload", details: err.issues });
    if (err instanceof CaseNotFoundError) {
      return res
        .status(404)
        .json({ error: `case ${err.caseId} does not exist — create it in the dashboard first` });
    }
    const message = err instanceof Error ? err.message : String(err);
    getServerLogger().error(`unhandled error on ${req.method} ${req.path}: ${message}`);
    return res.status(500).json({ error: "internal server error" });
  });
}
