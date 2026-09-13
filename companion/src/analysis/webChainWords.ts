// The words and the envelope facts of a web request row and a transfer row (#993). Every
// sensor-read text is shown inside its own named span (`[target: …]`, `[mime: …]`, `[filename:
// …]`, `[user: …]`, `[request: …]`, `[next: …]`, `[referrer: …]`, `[ua: …]`) through showToken,
// so no field can spell a tag beside the row's own, and correlate.ts skips the spans when it
// scrapes free text for a hash or a path. A digest is shown by its ends and never as a bare run.

import type {
  CoverageKind,
  RequestFacts,
  TransferFacts,
  WebBlock,
  WebBodyHop,
  TransferBlock,
} from "./canonicalWeb.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { readTarget, type TargetReading } from "./webRecordFields.js";
import type { RequestObservation, TransferObservation } from "./webChainRead.js";
import {
  isFileIdentity,
  WEB_BODIES_MAX,
  type BodyHop,
  type RequestChain,
  type TransferChain,
} from "./webChainJoin.js";

const SHOWN_MAX = 160;
const SHORT_MAX = 80;
const KB = 1024,
  MB = KB * 1024,
  GB = MB * 1024;

export function humanBytes(n: number): string {
  if (n >= GB) return `${(n / GB).toFixed(1)} GB`;
  if (n >= MB) return `${(n / MB).toFixed(1)} MB`;
  if (n >= KB) return `${(n / KB).toFixed(1)} KB`;
  return `${n} B`;
}

const show = (v: string, max = SHOWN_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
export const ends = (hex: string): string => (hex.length > 12 ? `${hex.slice(0, 8)}…${hex.slice(-4)}` : hex);

// ───────────────────────────── the request target ─────────────────────────────

export interface TargetView {
  reading: TargetReading;
  /** The validated destination host: from an absolute target, else from the Host header. */
  host: string;
  /** The Host header's own validation — an invalid header names no host and mints nothing. */
  hostHeaderValid: boolean;
  /** The text shown inside `[target: …]`. */
  shown: string;
}

export function targetView(req: RequestObservation): TargetView {
  const reading = readTarget(req.method, req.target);
  // The Host header is validated by the same whole-authority rule as a request target.
  const header = req.host ? readTarget("GET", `http://${req.host}/`) : undefined;
  const hostHeaderValid = header?.form === "absolute";
  const host = reading.host || (hostHeaderValid ? header.host : "");
  const shown =
    reading.form === "origin" && req.host
      ? `${show(req.host, SHORT_MAX)}${show(req.target)}`
      : reading.form === "authority"
        ? show(req.target, SHORT_MAX)
        : show(req.target);
  return { reading, host, hostHeaderValid, shown };
}

// ───────────────────────────── coverage words ─────────────────────────────

function sizeWords(x: TransferObservation, coverage: CoverageKind): string {
  const seen = x.seenBytes !== undefined ? humanBytes(x.seenBytes) : "";
  const total = x.totalBytes !== undefined ? humanBytes(x.totalBytes) : "";
  switch (coverage) {
    case "whole":
      return `${seen || total} whole`;
    case "unsized":
      return `${seen} seen; object size not recorded`;
    case "partial":
      return total ? `${seen} of ${total} seen` : `${seen} seen (truncated)`;
    case "gapped":
      return `${seen || "?"} seen, ${x.missingBytes !== undefined ? humanBytes(x.missingBytes) : "some"} missing`;
    case "range":
      return `a range (${seen || "size not recorded"}), not the whole object`;
    case "timed-out":
      return `timed out; ${seen || "?"} seen`;
    default:
      return "size not recorded";
  }
}

function digestWords(x: TransferObservation, coverage: CoverageKind): string {
  const d = x.sha256
    ? `sha256 ${ends(x.sha256)}`
    : x.sha1
      ? `sha1 ${ends(x.sha1)}`
      : x.md5
        ? `md5 ${ends(x.md5)}`
        : "";
  if (!d) return "no digest computed by the sensor";
  return isFileIdentity(coverage) ? d : `partial digest ${d} over the bytes seen`;
}

/** `sha256 3a7b…c9e1; 1.2 MB whole` — what moved and what the digest covers. */
export function transferWords(x: TransferObservation, coverage: CoverageKind): string {
  return `${digestWords(x, coverage)}; ${sizeWords(x, coverage)}`;
}

// ───────────────────────────── request row words ─────────────────────────────

// `GET [target: www.example.com/x] → 200` — the target inside its own span, the status after it.
const requestLine = (r: RequestObservation, v: TargetView): string =>
  `${r.method} [target: ${v.reading.form === "invalid" ? "(invalid)" : v.shown}]${r.status !== undefined ? ` → ${r.status}` : " → no response recorded"}`;

function redirectTags(c: RequestChain): string[] {
  const rd = c.redirect;
  if (!rd) return [];
  const tags = [
    rd.target !== undefined
      ? `redirect target (stated by the server): ${show(rd.target)}`
      : "redirect target: not in this record",
  ];
  switch (rd.nextState) {
    case "observed":
      tags.push(
        `next: ${requestLine(rd.next!, targetView(rd.next!))} (transaction ${rd.next!.depth}) — order on the connection, not the redirect target`,
      );
      break;
    case "not in this upload":
      tags.push(`next transaction (${(c.req.depth ?? 0) + 1}) not in this upload`);
      break;
    case "later transaction only":
      tags.push(`later on this connection: transaction ${rd.laterDepth} — not adjacent`);
      break;
    case "not read (HTTP/2 stream)":
      tags.push("next transaction not read: HTTP/2 stream");
      break;
    default:
      tags.push("next transaction not read: no connection identity");
  }
  return tags;
}

function bodyTag(hop: BodyHop, coverage: CoverageKind | undefined): string {
  const side =
    hop.direction === "response"
      ? "body"
      : hop.direction === "request"
        ? "body sent by the client"
        : "body (direction not recorded)";
  if (!hop.transfer || !coverage)
    return `${side}: ${show(hop.id, SHORT_MAX)} — no files record in this upload`;
  const x = hop.transfer;
  const mime = x.mime ? `; mime: ${show(x.mime, SHORT_MAX)}` : "";
  return `${side}: ${transferWords(x, coverage)}${mime}`;
}

export interface RequestTagGroups {
  /** What the status, the target form and the redirect establish — placed before the bodies. */
  before: string[];
  /** One tag per body hop, in the record's order; the row names how many it could not show. */
  bodies: string[];
  bodiesTotal: number;
  /** The client's fields, the addresses, the version — after the bodies. */
  after: string[];
}

/** The tags of a request row, in evidence order; `coverageOf` is passed so words match the key. */
export function requestTags(
  c: RequestChain,
  coverageOf: (hop: BodyHop) => CoverageKind | undefined,
): RequestTagGroups {
  const r = c.req;
  const view = targetView(r);
  const before: string[] = [];
  if (r.status === 304) before.push("not modified — no body");
  if (view.reading.words) before.push(view.reading.words);
  if (r.host && !view.hostHeaderValid) before.push("invalid Host header — no host named");
  before.push(...redirectTags(c));
  const bodies = c.bodies.slice(0, WEB_BODIES_MAX).map((hop) => bodyTag(hop, coverageOf(hop)));
  const after: string[] = [];
  if (r.identifiersDropped) after.push(`+${r.identifiersDropped} identifiers not read`);
  if (r.user) after.push(`user: ${show(r.user, SHORT_MAX)}`);
  if (r.referrer) after.push(`referrer: ${show(r.referrer)}`);
  if (r.userAgent) after.push(`ua: ${show(r.userAgent, SHORT_MAX)}`);
  if (r.proxied?.length) after.push(`proxied: ${r.proxied.map((p) => show(p, SHORT_MAX)).join("; ")}`);
  if (r.src || r.dst) after.push(`${r.src ?? "?"} → ${r.dst ?? "?"}${r.port ? `:${r.port}` : ""}`);
  if (r.version) after.push(`HTTP/${r.version.replace(/^HTTP\//i, "")}`);
  return { before, bodies, bodiesTotal: c.bodiesTotal, after };
}

export const requestHead = (c: RequestChain): string => `HTTP ${requestLine(c.req, targetView(c.req))}`;

// ───────────────────────────── transfer row words ─────────────────────────────

export function transferHead(c: TransferChain): string {
  return `Transfer${c.xfer.over ? ` over ${show(c.xfer.over, 16)}` : ""}: ${transferWords(c.xfer, c.coverage)}`;
}

export function transferTags(c: TransferChain): string[] {
  const x = c.xfer;
  const tags: string[] = [];
  if (x.mime) tags.push(`mime: ${show(x.mime, SHORT_MAX)}`);
  if (x.filename) tags.push(`filename: ${show(x.filename)}`);
  if (x.tx?.length || x.rx?.length)
    tags.push(`from ${x.tx?.join(", ") || "?"} to ${x.rx?.join(", ") || "?"}`);
  else if (x.flowSrc || x.flowDst)
    tags.push(`flow ${x.flowSrc ?? "?"} ↔ ${x.flowDst ?? "?"} — sender not recorded`);
  switch (c.requestState) {
    case "observed":
      for (const r of c.requests) tags.push(`request: ${requestLine(r, targetView(r))}`);
      if (c.requestsTotal > c.requests.length)
        tags.push(`+${c.requestsTotal - c.requests.length} more requests`);
      break;
    case "inline on this record": {
      const i = x.inlineRequest!;
      tags.push(
        `request (inline): ${i.method} ${show(`${i.host}${i.target}`)}${i.status !== undefined ? ` → ${i.status}` : ""}`,
      );
      break;
    }
    case "not in this upload":
      tags.push("request: not in this upload");
      break;
    default:
      break; // a transfer over SMTP/FTP/SMB names no request
  }
  if (x.identifiersDropped) tags.push(`+${x.identifiersDropped} identifiers not read`);
  return tags;
}

// ───────────────────────────── envelope facts ─────────────────────────────

export function requestFacts(r: RequestObservation): RequestFacts {
  const view = targetView(r);
  const locator = {
    ...(r.uid ? { uid: r.uid } : {}),
    ...(r.depth !== undefined ? { depth: r.depth } : {}),
    ...(r.streamId ? { streamId: r.streamId } : {}),
    ...(r.flowId ? { flowId: r.flowId } : {}),
    ...(r.txId ? { txId: r.txId } : {}),
  };
  return {
    method: r.method,
    ...(view.host ? { host: view.host } : {}),
    ...(r.target ? { target: r.target } : {}),
    targetForm: view.reading.form,
    ...(r.version ? { version: r.version } : {}),
    ...(r.status !== undefined ? { statusCode: r.status } : {}),
    ...(Object.keys(locator).length ? { locator } : {}),
  };
}

export function transferFacts(x: TransferObservation, coverage: CoverageKind): TransferFacts {
  const digests = (
    [
      ["sha256", x.sha256],
      ["sha1", x.sha1],
      ["md5", x.md5],
    ] as const
  ).filter((d): d is readonly ["sha256" | "sha1" | "md5", string] => !!d[1]);
  const direction = {
    ...(x.tx?.length ? { tx: x.tx } : {}),
    ...(x.rx?.length ? { rx: x.rx } : {}),
    ...(x.fromOriginator !== undefined ? { fromOriginator: x.fromOriginator } : {}),
  };
  return {
    ...(x.over ? { over: x.over } : {}),
    ...(x.mime ? { mime: x.mime } : {}),
    ...(x.filename ? { filename: x.filename } : {}),
    ...(x.seenBytes !== undefined ? { seenBytes: x.seenBytes } : {}),
    ...(x.totalBytes !== undefined ? { totalBytes: x.totalBytes } : {}),
    ...(x.missingBytes !== undefined ? { missingBytes: x.missingBytes } : {}),
    ...(x.timedOut !== undefined ? { timedOut: x.timedOut } : {}),
    ...(x.sensorState ? { sensorState: x.sensorState } : {}),
    coverage,
    ...(digests.length ? { digests: digests.map(([alg, value]) => ({ alg, value })) } : {}),
    ...(Object.keys(direction).length ? { direction } : {}),
  };
}

export function bodyFacts(hop: BodyHop, coverage: CoverageKind | undefined): WebBodyHop {
  return {
    direction: hop.direction,
    id: hop.id,
    state: hop.transfer && coverage ? "observed" : "no files record in this upload",
    ...(hop.transfer && coverage ? { transfer: transferFacts(hop.transfer, coverage) } : {}),
  };
}

export function webBlock(
  c: RequestChain,
  coverageOf: (hop: BodyHop) => CoverageKind | undefined,
  records: number,
): WebBlock {
  const r = c.req;
  const rd = c.redirect;
  return {
    ...requestFacts(r),
    responseState: r.status !== undefined ? "recorded" : "not recorded",
    ...(r.user ? { user: r.user } : {}),
    ...(r.referrer ? { referrer: r.referrer } : {}),
    ...(r.userAgent ? { userAgent: r.userAgent } : {}),
    ...(r.requestBodyLen !== undefined ? { requestBodyLen: r.requestBodyLen } : {}),
    ...(r.responseBodyLen !== undefined ? { responseBodyLen: r.responseBodyLen } : {}),
    ...(r.proxied?.length ? { proxied: r.proxied } : {}),
    ...(rd
      ? {
          redirect: {
            ...(rd.target !== undefined ? { target: rd.target } : {}),
            targetState: rd.targetState,
            ...(rd.next ? { next: requestFacts(rd.next) } : {}),
            nextState: rd.nextState,
            ...(rd.laterDepth !== undefined ? { laterDepth: rd.laterDepth } : {}),
          },
        }
      : {}),
    bodies: c.bodies.slice(0, WEB_BODIES_MAX).map((hop) => bodyFacts(hop, coverageOf(hop))),
    bodiesTotal: c.bodiesTotal,
    ...(r.identifiersDropped ? { identifiersDropped: r.identifiersDropped } : {}),
    records,
  };
}

export function transferBlock(c: TransferChain, records: number): TransferBlock {
  const x = c.xfer;
  const locator = {
    ...(x.fuid ? { fuid: x.fuid } : {}),
    ...(x.connUids.length === 1 ? { uid: x.connUids[0] } : {}),
    ...(x.flowId ? { flowId: x.flowId } : {}),
    ...(x.txId ? { txId: x.txId } : {}),
  };
  return {
    ...transferFacts(x, c.coverage),
    requests: c.requests.map(requestFacts),
    requestsTotal: c.requestsTotal,
    requestState: c.requestState,
    ...(x.inlineRequest
      ? {
          inlineRequest: {
            method: x.inlineRequest.method,
            ...(x.inlineRequest.host ? { host: x.inlineRequest.host } : {}),
            ...(x.inlineRequest.target ? { target: x.inlineRequest.target } : {}),
            ...(x.inlineRequest.status !== undefined ? { statusCode: x.inlineRequest.status } : {}),
          },
        }
      : {}),
    ...(Object.keys(locator).length ? { locator } : {}),
    ...(x.identifiersDropped ? { identifiersDropped: x.identifiersDropped } : {}),
    records,
  };
}
