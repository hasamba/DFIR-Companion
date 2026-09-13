// The join inside one upload — through identities both records carry, and through nothing else
// (#993). A request names its bodies by `resp_fuids` / `orig_fuids`; a files record names itself
// by `fuid`; a Suricata fileinfo names its request by `flow_id` + `tx_id`. Where the identifier
// is on both sides the hop is OBSERVED; where the partner record is absent the hop says "not in
// this upload"; where the format has no field for it the hop says "not in this record".
//
// Timing and adjacency never join: the one adjacency this module reads — the next transaction on
// the same connection (uid, depth + 1) after a 3xx — is a fact about the connection's order and
// is worded as such. It is never "the redirect target".
//
// Coverage is the sensor's own counters read as what a digest was computed over. Zeek removes its
// hash analyzers on a gap (a gapped file carries no digest) and finalises on EOF (a truncated file
// carries a digest over the bytes seen); Suricata says `state` and `gaps`. Only `whole` and
// `unsized` make the digest a FILE identity; every other coverage keeps it a partial digest that
// identifies nothing on an endpoint.

import type { CoverageKind } from "./canonicalWeb.js";
import type { RequestObservation, TransferObservation } from "./webChainRead.js";

/** Bodies named on a request row; the rest are counted. */
export const WEB_BODIES_MAX = 8;
/** Request records named on a transfer row; the rest are counted. */
export const WEB_REQUESTS_MAX = 4;
/** Observations retained per kind; records past it fold into the kind's overflow row, unjoined. */
export const WEB_OBSERVATIONS_MAX = 65_536;

const REDIRECT = new Set([301, 302, 303, 307, 308]);
const PARTIAL_CONTENT = 206;

export interface BodyHop {
  /** Zeek says which side sent a body (resp_fuids / orig_fuids); a Suricata fileinfo does not. */
  direction: "response" | "request" | "not recorded";
  /** The shared identifier: a Zeek fuid, or Suricata's `flow_id|tx_id`. */
  id: string;
  transfer?: TransferObservation;
}

export interface RedirectHop {
  target?: string;
  targetState: "stated by the server" | "not in this record";
  next?: RequestObservation;
  nextState:
    | "observed"
    | "not in this upload"
    | "later transaction only"
    | "not read (HTTP/2 stream)"
    | "no transaction identity";
  laterDepth?: number;
}

export interface RequestChain {
  req: RequestObservation;
  /** Every body hop (bounded by WEB_IDS_PER_RECORD at read time); shown up to WEB_BODIES_MAX. */
  bodies: BodyHop[];
  bodiesTotal: number;
  redirect?: RedirectHop;
}

export interface TransferChain {
  xfer: TransferObservation;
  coverage: CoverageKind;
  requests: RequestObservation[];
  requestsTotal: number;
  /** "inline on this record": a Suricata fileinfo carries its request fields itself. */
  requestState: "observed" | "inline on this record" | "not in this upload" | "no request identity";
}

export interface WebObservations {
  requests: RequestObservation[];
  transfers: TransferObservation[];
  /** Records past WEB_OBSERVATIONS_MAX, per kind — never read, never joined. */
  requestsOverflow: number;
  transfersOverflow: number;
}

export function emptyWebObservations(): WebObservations {
  return { requests: [], transfers: [], requestsOverflow: 0, transfersOverflow: 0 };
}

export function addRequest(sink: WebObservations, o: RequestObservation): void {
  if (sink.requests.length >= WEB_OBSERVATIONS_MAX) sink.requestsOverflow += 1;
  else sink.requests.push(o);
}

export function addTransfer(sink: WebObservations, o: TransferObservation): void {
  if (sink.transfers.length >= WEB_OBSERVATIONS_MAX) sink.transfersOverflow += 1;
  else sink.transfers.push(o);
}

// ───────────────────────────── coverage ─────────────────────────────

/** What the digest covers, from the sensor's counters and — for a body — the response status. */
export function coverageOf(x: TransferObservation, requestStatus?: number): CoverageKind {
  if (requestStatus === PARTIAL_CONTENT || (x.startOffset !== undefined && x.startOffset > 0)) return "range";
  if (x.source === "suricata-fileinfo") {
    if (x.gaps) return "gapped";
    if (!x.sensorState) return "not-recorded";
    if (x.sensorState === "CLOSED") return "whole";
    if (x.sensorState === "TRUNCATED") return "partial";
    return "not-recorded";
  }
  if (x.timedOut) return "timed-out";
  if ((x.missingBytes ?? 0) > 0) return "gapped";
  if (x.totalBytes === undefined) return x.seenBytes === undefined ? "not-recorded" : "unsized";
  if (x.seenBytes === undefined) return "not-recorded";
  return x.seenBytes >= x.totalBytes ? "whole" : "partial";
}

/** Only these coverages let a digest name a file. */
export const isFileIdentity = (c: CoverageKind): boolean => c === "whole" || c === "unsized";

// ───────────────────────────── the join ─────────────────────────────

const byDepth = (a: RequestObservation, b: RequestObservation): number =>
  (a.uid ?? "").localeCompare(b.uid ?? "") ||
  (a.depth ?? 0) - (b.depth ?? 0) ||
  a.locator.localeCompare(b.locator);

function redirectHop(
  req: RequestObservation,
  byConn: Map<string, RequestObservation[]>,
): RedirectHop | undefined {
  if (req.status === undefined || !REDIRECT.has(req.status)) return undefined;
  const target = req.redirectTarget
    ? { target: req.redirectTarget, targetState: "stated by the server" as const }
    : { targetState: "not in this record" as const };
  if (req.streamId) return { ...target, nextState: "not read (HTTP/2 stream)" };
  if (!req.uid || req.depth === undefined) return { ...target, nextState: "no transaction identity" };
  const later = (byConn.get(req.uid) ?? []).filter((o) => (o.depth ?? -1) > req.depth!).sort(byDepth);
  if (!later.length) return { ...target, nextState: "not in this upload" };
  const next = later[0];
  if (next.depth === req.depth + 1) return { ...target, next, nextState: "observed" };
  return { ...target, nextState: "later transaction only", laterDepth: next.depth };
}

const flowKey = (flowId: string | undefined, txId: string | undefined): string | undefined =>
  flowId && txId !== undefined ? `${flowId}|${txId}` : undefined;

function bodiesOf(
  req: RequestObservation,
  byFuid: Map<string, TransferObservation>,
  xferByFlowTx: Map<string, TransferObservation[]>,
): BodyHop[] {
  const hops: BodyHop[] = [];
  for (const id of req.respFuids) hops.push({ direction: "response", id, transfer: byFuid.get(id) });
  for (const id of req.origFuids) hops.push({ direction: "request", id, transfer: byFuid.get(id) });
  const fk = flowKey(req.flowId, req.txId);
  if (fk)
    for (const transfer of xferByFlowTx.get(fk) ?? [])
      hops.push({ direction: "not recorded", id: fk, transfer });
  return hops;
}

/** Every hop the upload establishes, for every retained request and transfer. */
export function joinWebChain(obs: WebObservations): { requests: RequestChain[]; transfers: TransferChain[] } {
  const byFuid = new Map<string, TransferObservation>();
  const xferByFlowTx = new Map<string, TransferObservation[]>();
  for (const x of obs.transfers) {
    if (x.fuid && !byFuid.has(x.fuid)) byFuid.set(x.fuid, x);
    const fk = flowKey(x.flowId, x.txId);
    if (fk) (xferByFlowTx.get(fk) ?? xferByFlowTx.set(fk, []).get(fk)!).push(x);
  }
  const byConn = new Map<string, RequestObservation[]>();
  const byFlowTx = new Map<string, RequestObservation[]>();
  const carriers = new Map<string, RequestObservation[]>(); // fuid → the requests naming it
  for (const r of obs.requests) {
    if (r.uid) (byConn.get(r.uid) ?? byConn.set(r.uid, []).get(r.uid)!).push(r);
    const fk = flowKey(r.flowId, r.txId);
    if (fk) (byFlowTx.get(fk) ?? byFlowTx.set(fk, []).get(fk)!).push(r);
    for (const fuid of [...r.respFuids, ...r.origFuids])
      (carriers.get(fuid) ?? carriers.set(fuid, []).get(fuid)!).push(r);
  }

  const requests: RequestChain[] = obs.requests.map((req) => {
    // Every body is kept for the row's identity (the read bound already caps the list); the
    // words and the envelope show the first WEB_BODIES_MAX and count the rest.
    const all = bodiesOf(req, byFuid, xferByFlowTx);
    return {
      req,
      bodies: all,
      bodiesTotal: all.length,
      ...(redirectHop(req, byConn) ? { redirect: redirectHop(req, byConn) } : {}),
    };
  });

  const transfers: TransferChain[] = obs.transfers.map((xfer) => {
    const fk = flowKey(xfer.flowId, xfer.txId);
    const named = xfer.fuid ? (carriers.get(xfer.fuid) ?? []) : fk ? (byFlowTx.get(fk) ?? []) : [];
    const ordered = [...named].sort(byDepth);
    const hasIdentity = Boolean(xfer.fuid || fk);
    // The body's coverage reads the response status when exactly one request carries it (or the
    // fileinfo carries it inline): a 206 makes the body a range whatever the counters say.
    const status =
      ordered.length === 1 ? ordered[0].status : ordered.length ? undefined : xfer.inlineRequest?.status;
    const requestState = ordered.length
      ? "observed"
      : xfer.inlineRequest
        ? "inline on this record"
        : hasIdentity
          ? "not in this upload"
          : "no request identity";
    return {
      xfer,
      coverage: coverageOf(xfer, status),
      requests: ordered.slice(0, WEB_REQUESTS_MAX),
      requestsTotal: ordered.length,
      requestState,
    };
  });

  return { requests, transfers };
}
