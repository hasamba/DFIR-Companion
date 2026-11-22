/**
 * Identical heavy reads share one answer (#2846).
 *
 * THE PROBLEM. A second dashboard on the same case (a second tab, a refresh that did not cancel, a
 * second analyst) fires the same 33 whole-case reads as the first. Behind the heavy-read gate those
 * queue up, and each one rebuilds what an identical queued read is about to build — a second round of
 * the most expensive work the server does, for the same answers.
 *
 * THE RULE. A GET that arrives while an identical one is still WAITING in the gate's queue joins it:
 * it takes no slot and no queue place of its own, and gets a copy of that one's answer. Once the first
 * request's handler starts, nothing new joins it. That is what keeps a shared answer fresh: every read
 * the handler makes happens after every follower arrived, so a follower never gets data read before a
 * write that came before it — whoever made the write (an analyst, an import, Watson, a background job),
 * and whatever file it touched. Identical means the same case, the same URL with its query string,
 * the same caller, and the same origin, content-negotiation and conditional headers.
 *
 * Only reads that overlap a queued one are shared. A second open repeats the reads that already ran
 * or are running; on a large case most of the first open is still queued a minute in, so most of a
 * second open is shared.
 *
 * WHAT IS SHARED. Only the case-open panel reads (COALESCED_PATHS), never the downloads and exports
 * (streamed, rare, and an analyst who asks twice expects two files), nor /login-graph and the Sigma
 * re-grade preview (interactive or streamed scans). HEAD is never shared.
 *
 * MEMORY. An answer is kept only for followers: the first request's chunks are held by reference (no
 * copy), joined once at the end only if someone is waiting, and dropped otherwise. Every follower is
 * sent the same buffer, and it stays counted until the last of them has been sent it (a slow client
 * holds it in its socket). Everything kept or being sent stays under COALESCE_MAX_HELD_BYTES, the
 * joining copy included; an answer that would pass it is not kept, and its followers run on their
 * own.
 *
 * WHEN THE FIRST ONE FAILS. A first request that never completes its answer (its client left while it
 * was queued, or its handler stopped early) hands its followers back: each runs as if it had just
 * arrived, so the first of them takes the lead. A completed answer is copied as it is, error statuses
 * included. A follower keeps the headers its own middleware already set (security headers, CSP
 * nonce, CORS for its own origin); from the first answer it takes the representation headers (type,
 * length, encoding, ETag, ...) and any header it does not have yet, never Set-Cookie or a hop-by-hop
 * header. Vary is merged.
 */
import type { NextFunction, Request, Response } from "express";
import { currentIdentity } from "../auth/identityContext.js";
import { requestAbortSignal } from "../http/requestAbort.js";

/** All answers kept for followers at once. /state with its timeline page is about 85 MB at 72k events. */
export const COALESCE_MAX_HELD_BYTES = 256 * 1024 * 1024;

/** The case-open panel reads, relative to /cases/:id. A subset of HEAVY_READ_PATHS (tests pin it). */
export const COALESCED_PATHS: ReadonlySet<string> = new Set([
  "/state",
  "/swimlane",
  "/ioc-sources",
  "/timeline-gaps",
  "/asset-graph",
  "/evidence-graph",
  "/lateral-paths",
  "/phases",
  "/beacon-candidates",
  "/anomalies",
  "/host-ranking",
  "/d3fend-countermeasures",
  "/attack-mitigations",
  "/geo-map",
  "/adversary-hints",
  "/mobile-summary",
  "/timesketch-omitted",
  "/ioc-provenance",
  "/ioc-provenance-chain",
  "/ioc-risk",
  "/customer-exposure",
  "/cockpit",
  "/sessions",
  "/campaign-scope",
  "/served-exposure",
  "/kerberoast-chain",
  "/tls-graph",
  "/sensitive-access",
  "/playbook-match",
  "/hypotheses",
  "/host-scope",
  "/host-duplicates",
  "/second-look/preview",
  "/known-unknowns",
]);

/** Request headers an answer can vary by. */
const KEY_HEADERS = [
  "origin",
  "accept",
  "accept-encoding",
  "if-none-match",
  "if-modified-since",
  "range",
] as const;
/** Response headers never copied to a follower. */
const UNCOPIED_HEADERS = new Set([
  "set-cookie",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "proxy-connection",
  "trailer",
  "te",
  "date",
]);
/** Headers that describe the body: the first answer's always win over what a follower already has. */
const REPRESENTATION_HEADERS = new Set([
  "content-type",
  "content-length",
  "content-encoding",
  "content-disposition",
  "content-range",
  "etag",
  "last-modified",
  "cache-control",
]);

/** Admit a request to the gate; the gate calls `start` when its handler may run. */
export type HeavyReadAdmit = (start: NextFunction) => void;

interface Lead {
  readonly followers: Follower[];
}

interface Follower {
  req: Request;
  res: Response;
  next: NextFunction;
  admit: HeavyReadAdmit;
}

interface Captured {
  status: number;
  headers: Record<string, number | string | string[] | undefined>;
  body: Buffer;
}

/** A written chunk, kept by reference: a string is not converted until a follower needs it. */
type Kept = { data: string; encoding: BufferEncoding } | { data: Uint8Array };

function byteLength(chunk: unknown, encoding: BufferEncoding): number {
  if (typeof chunk === "string") return Buffer.byteLength(chunk, encoding);
  return chunk instanceof Uint8Array ? chunk.byteLength : 0;
}

function joined(kept: Kept[]): Buffer {
  return Buffer.concat(
    kept.map((k) =>
      "encoding" in k
        ? Buffer.from(k.data, k.encoding)
        : Buffer.from(k.data.buffer, k.data.byteOffset, k.data.byteLength),
    ),
  );
}

export class HeavyReadCoalescer {
  /** Leads still waiting in the gate's queue, by request key. A lead leaves when its handler starts. */
  private readonly leads = new Map<string, Lead>();
  /** Followers of every lead, joinable or started. */
  private followers = 0;
  /** Bytes all leads hold for their followers right now. */
  private held = 0;

  /** Bytes kept for followers right now. For tests and diagnostics. */
  get heldBytes(): number {
    return this.held;
  }

  /** Requests waiting on another's answer. For tests and diagnostics. */
  get following(): number {
    return this.followers;
  }

  /**
   * Admit `req` through `admit` (the gate) and then `next` (the handler), or attach it to an identical
   * read still queued. `relPath` is the folded path relative to /cases/:id.
   */
  handle(req: Request, res: Response, relPath: string, next: NextFunction, admit: HeavyReadAdmit): void {
    if (req.method !== "GET" || !COALESCED_PATHS.has(relPath) || !req.params.id) return admit(next);
    const key = this.keyOf(req);
    const lead = this.leads.get(key);
    if (lead) return this.follow(lead, { req, res, next, admit });
    this.lead(key, res, next, admit);
  }

  private keyOf(req: Request): string {
    const headers = KEY_HEADERS.map((name) => String(req.headers[name] ?? ""));
    const caller = currentIdentity()?.id ?? "";
    return [req.params.id, req.originalUrl, caller, ...headers].join("\u0000");
  }

  /**
   * Keep a replayed body counted against the cap until every follower's response has finished or
   * closed: a slow client holds the buffer in its socket long after the first answer is done.
   */
  private chargeUntilSent(bytes: number, followers: Follower[]): void {
    this.held += bytes;
    let pending = followers.length;
    for (const f of followers) {
      let done = false;
      const sent = (): void => {
        if (done) return;
        done = true;
        if (--pending === 0) this.held -= bytes;
      };
      f.res.once("finish", sent);
      f.res.once("close", sent);
    }
  }

  private follow(lead: Lead, follower: Follower): void {
    lead.followers.push(follower);
    this.followers++;
    requestAbortSignal(follower.res).addEventListener(
      "abort",
      () => {
        const at = lead.followers.indexOf(follower);
        if (at < 0) return;
        lead.followers.splice(at, 1);
        this.followers--;
      },
      { once: true },
    );
  }

  private lead(key: string, res: Response, next: NextFunction, admit: HeavyReadAdmit): void {
    const lead: Lead = { followers: [] };
    this.leads.set(key, lead);
    const closeToJoiners = (): void => {
      if (this.leads.get(key) === lead) this.leads.delete(key);
    };
    let kept: Kept[] = [];
    let size = 0;
    let overflow = false;
    const keep = (chunk: unknown, encodingArg?: unknown): void => {
      if (overflow || chunk === undefined || chunk === null || typeof chunk === "function") return;
      const encoding = (typeof encodingArg === "string" ? encodingArg : "utf8") as BufferEncoding;
      const bytes = byteLength(chunk, encoding);
      if (this.held + bytes > COALESCE_MAX_HELD_BYTES) {
        overflow = true; // checked before anything is kept or copied
        this.held -= size;
        size = 0;
        kept = [];
        return;
      }
      size += bytes;
      this.held += bytes;
      if (typeof chunk === "string") kept.push({ data: chunk, encoding });
      else if (chunk instanceof Uint8Array) kept.push({ data: chunk });
    };
    const write = res.write;
    const end = res.end;
    res.write = function (this: Response, ...args: unknown[]) {
      keep(args[0], args[1]);
      return (write as (...a: unknown[]) => boolean).apply(this, args);
    } as Response["write"];
    res.end = function (this: Response, ...args: unknown[]) {
      keep(args[0], args[1]);
      return (end as (...a: unknown[]) => Response).apply(this, args);
    } as Response["end"];
    let settled = false;
    const settle = (finished: boolean): void => {
      if (settled) return;
      settled = true;
      res.write = write;
      res.end = end;
      closeToJoiners();
      const all = lead.followers.splice(0);
      this.followers -= all.length;
      const followers = all.filter((f) => !requestAbortSignal(f.res).aborted);
      // Joining copies the body once: that copy must fit under the cap next to what is kept now.
      const replayable =
        finished && !overflow && followers.length > 0 && this.held + size <= COALESCE_MAX_HELD_BYTES;
      const answer: Captured | null = replayable
        ? { status: res.statusCode, headers: res.getHeaders(), body: joined(kept) }
        : null;
      this.held -= size;
      size = 0;
      kept = [];
      if (answer) this.chargeUntilSent(answer.body.length, followers);
      for (const f of followers) {
        if (answer) replay(f.res, answer);
        else this.handle(f.req, f.res, relPathOf(f.req), f.next, f.admit); // as if just arrived
      }
    };
    res.once("finish", () => settle(true));
    res.once("close", () => settle(false)); // after "finish" this does nothing
    admit((err?: unknown) => {
      closeToJoiners(); // its handler starts now: from here on, a new arrival must read for itself
      next(err);
    });
  }
}

function mergeVary(own: unknown, theirs: unknown): string {
  const names = [own, theirs]
    .flatMap((v) => (Array.isArray(v) ? v : v === undefined ? [] : [String(v)]))
    .flatMap((v) => String(v).split(","))
    .map((v) => v.trim())
    .filter(Boolean);
  const seen = new Map<string, string>();
  for (const n of names) if (!seen.has(n.toLowerCase())) seen.set(n.toLowerCase(), n);
  return [...seen.values()].join(", ");
}

function replay(res: Response, answer: Captured): void {
  if (requestAbortSignal(res).aborted || res.headersSent) return;
  for (const [rawName, value] of Object.entries(answer.headers)) {
    const name = rawName.toLowerCase();
    if (value === undefined || UNCOPIED_HEADERS.has(name)) continue;
    if (name === "vary") res.setHeader("Vary", mergeVary(res.getHeader("Vary"), value));
    else if (REPRESENTATION_HEADERS.has(name) || res.getHeader(name) === undefined)
      res.setHeader(name, value);
  }
  res.status(answer.status).end(answer.body);
}

/** The route suffix after /cases/:id, folded the way Express matches it (case, trailing slash). */
export function relPathOf(req: Request): string {
  return (
    req.path
      .replace(/^\/cases\/[^/]+\//, "/")
      .replace(/\/+$/, "")
      .toLowerCase() || "/"
  );
}
