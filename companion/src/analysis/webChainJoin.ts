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
// A shared identifier is necessary, not sufficient. Two records that name one fuid but contradict
// each other — a files record over SMTP against an http carrier, a connection id on both sides
// that differs, two sensors — are NOT joined; the hop says so. Two files records with one fuid and
// different facts are a conflict the row names, never a first-wins pick.
//
// Coverage is the sensor's own counters read as what a digest was computed over. Zeek removes its
// hash analyzers on a gap (a gapped file carries no digest) and finalises on EOF (a truncated file
// carries a digest over the bytes seen); Suricata says `state` and `gaps`. Only `whole` and
// `unsized` make the digest a FILE identity; every other coverage keeps it a partial digest that
// identifies nothing on an endpoint. A response body any carrier answered with 206 is a range.
//
// Every identifier bucket is bounded during index construction (BUCKET_MAX): a repeated flow id
// or fuid across thousands of records is attacker-shaped input and must not make the join
// quadratic. Records past WEB_OBSERVATIONS_MAX are counted per source and never read, and an
// absence is then worded "not among the records read", never "not in this upload".

import type { CoverageKind } from "./canonicalWeb.js";
import type {
  RequestObservation,
  RequestSource,
  TransferObservation,
  TransferSource,
} from "./webChainRead.js";

/** Bodies named on a request row; the rest are counted. */
export const WEB_BODIES_MAX = 8;
/** Request records named on a transfer row; the rest are counted. */
export const WEB_REQUESTS_MAX = 4;
/** Observations retained per kind; records past it are counted per source, never read or joined. */
export const WEB_OBSERVATIONS_MAX = 65_536;
/** Records kept per identifier bucket; a bucket past it counts the rest. */
export const BUCKET_MAX = 16;

const REDIRECT = new Set([301, 302, 303, 307, 308]);
const PARTIAL_CONTENT = 206;

export type BodyState =
  | "observed"
  | "no files record in this upload"
  | "not among the records read"
  | "identifier conflict — not joined"
  | "conflicting files records";

export interface BodyHop {
  /** Zeek says which side sent a body (resp_fuids / orig_fuids); a Suricata fileinfo does not. */
  direction: "response" | "request" | "not recorded";
  /** The shared identifier: a Zeek fuid, or Suricata's `flow_id|tx_id`. A locator, never a fact. */
  id: string;
  state: BodyState;
  transfer?: TransferObservation;
}

export type NextState =
  | "observed"
  | "not in this upload"
  | "not among the records read"
  | "later transaction only"
  | "not read (HTTP/2 stream)"
  | "no transaction identity";

export interface RedirectHop {
  target?: string;
  targetState: "stated by the server" | "not in this record";
  next?: RequestObservation;
  nextState: NextState;
  laterDepth?: number;
}

export interface RequestChain {
  req: RequestObservation;
  /** Every body hop (bounded by WEB_IDS_PER_RECORD at read time); shown up to WEB_BODIES_MAX. */
  bodies: BodyHop[];
  bodiesTotal: number;
  redirect?: RedirectHop;
}

export type RequestState =
  | "observed"
  | "inline on this record"
  | "not in this upload"
  | "not among the records read"
  | "identifier conflict — not joined"
  | "no request identity";

export interface TransferChain {
  xfer: TransferObservation;
  coverage: CoverageKind;
  requests: RequestObservation[];
  requestsTotal: number;
  /** "inline on this record": a Suricata fileinfo carries its request fields itself. */
  requestState: RequestState;
}

export interface WebObservations {
  requests: RequestObservation[];
  transfers: TransferObservation[];
  /** Records past WEB_OBSERVATIONS_MAX, per source — never read, never joined. */
  requestsOverflow: Map<RequestSource, number>;
  transfersOverflow: Map<TransferSource, number>;
}

export function emptyWebObservations(): WebObservations {
  return { requests: [], transfers: [], requestsOverflow: new Map(), transfersOverflow: new Map() };
}

const bump = <K>(m: Map<K, number>, k: K): void => {
  m.set(k, (m.get(k) ?? 0) + 1);
};

export function addRequest(sink: WebObservations, o: RequestObservation): void {
  if (sink.requests.length >= WEB_OBSERVATIONS_MAX) bump(sink.requestsOverflow, o.source);
  else sink.requests.push(o);
}

export function addTransfer(sink: WebObservations, o: TransferObservation): void {
  if (sink.transfers.length >= WEB_OBSERVATIONS_MAX) bump(sink.transfersOverflow, o.source);
  else sink.transfers.push(o);
}

const total = (m: Map<unknown, number>): number => [...m.values()].reduce((a, b) => a + b, 0);

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

// The status a body's coverage is read against: a 206 from ANY response-direction carrier makes
// the body a range; carriers that disagree otherwise establish no status. A request body (an
// upload) is never read against the response's status.
function statusForBody(carriers: readonly Carrier[], inline?: number): number | undefined {
  const responses = carriers.filter((c) => c.direction !== "request");
  if (!responses.length) return inline;
  if (responses.some((c) => c.req.status === PARTIAL_CONTENT)) return PARTIAL_CONTENT;
  const statuses = new Set(responses.map((c) => c.req.status));
  return statuses.size === 1 ? responses[0].req.status : undefined;
}

// ───────────────────────────── indexes ─────────────────────────────

interface Bucket<T> {
  kept: T[];
  omitted: number;
}

function push<K, T>(index: Map<K, Bucket<T>>, key: K, value: T): void {
  const b = index.get(key) ?? index.set(key, { kept: [], omitted: 0 }).get(key)!;
  if (b.kept.length < BUCKET_MAX) b.kept.push(value);
  else b.omitted += 1;
}

const byDepth = (a: RequestObservation, b: RequestObservation): number =>
  (a.uid ?? "").localeCompare(b.uid ?? "") ||
  (a.depth ?? 0) - (b.depth ?? 0) ||
  a.locator.localeCompare(b.locator);

const flowKey = (flowId: string | undefined, txId: string | undefined): string | undefined =>
  flowId && txId !== undefined ? `${flowId}|${txId}` : undefined;

interface Carrier {
  req: RequestObservation;
  direction: BodyHop["direction"];
}

interface Indexes {
  /** fuid → the files records naming it (bounded). */
  byFuid: Map<string, Bucket<TransferObservation>>;
  /** flow|tx → the fileinfo records naming it (bounded). */
  xferByFlowTx: Map<string, Bucket<TransferObservation>>;
  /** uid → every transaction on that connection, sorted by depth once. */
  byConn: Map<string, RequestObservation[]>;
  /** flow|tx → the http records naming it (bounded). */
  reqByFlowTx: Map<string, Bucket<RequestObservation>>;
  /** fuid → the http records naming it, with the side they name it on (bounded). */
  carriers: Map<string, Bucket<Carrier>>;
}

function indexes(obs: WebObservations): Indexes {
  const ix: Indexes = {
    byFuid: new Map(),
    xferByFlowTx: new Map(),
    byConn: new Map(),
    reqByFlowTx: new Map(),
    carriers: new Map(),
  };
  for (const x of obs.transfers) {
    if (x.fuid) push(ix.byFuid, x.fuid, x);
    const fk = flowKey(x.flowId, x.txId);
    if (fk) push(ix.xferByFlowTx, fk, x);
  }
  for (const r of obs.requests) {
    if (r.uid) (ix.byConn.get(r.uid) ?? ix.byConn.set(r.uid, []).get(r.uid)!).push(r);
    const fk = flowKey(r.flowId, r.txId);
    if (fk) push(ix.reqByFlowTx, fk, r);
    for (const id of r.respFuids) push(ix.carriers, id, { req: r, direction: "response" });
    for (const id of r.origFuids) push(ix.carriers, id, { req: r, direction: "request" });
  }
  for (const list of ix.byConn.values()) list.sort(byDepth);
  return ix;
}

// ───────────────────────────── compatibility ─────────────────────────────

// A shared fuid joins an http record and a files record only when nothing else on the two records
// contradicts it: the transfer is over HTTP (or names no protocol), a connection id present on
// both sides agrees, and a sensor named on both sides is the same one.
function compatible(r: RequestObservation, x: TransferObservation): boolean {
  if (x.over && x.over !== "HTTP") return false;
  if (r.uid && x.connUids.length && !x.connUids.includes(r.uid)) return false;
  if (r.observer && x.observer && r.observer.name !== x.observer.name) return false;
  return true;
}

// Two files records with one fuid are one record re-exported when their facts agree; otherwise
// the records conflict and neither is chosen.
const transferFacts = (x: TransferObservation): string =>
  [
    x.source,
    x.over,
    x.sha256,
    x.sha1,
    x.md5,
    x.seenBytes,
    x.totalBytes,
    x.missingBytes,
    x.timedOut,
    x.sensorState,
    x.gaps,
    x.mime,
  ].join("|");

function transferFor(bucket: Bucket<TransferObservation> | undefined): {
  transfer?: TransferObservation;
  conflict: boolean;
} {
  if (!bucket?.kept.length) return { conflict: false };
  const first = bucket.kept[0];
  const facts = transferFacts(first);
  const conflict = bucket.kept.some((x) => transferFacts(x) !== facts);
  return conflict ? { conflict: true } : { transfer: first, conflict: false };
}

// ───────────────────────────── hops ─────────────────────────────

function firstLater(list: readonly RequestObservation[], depth: number): RequestObservation | undefined {
  // The list is sorted by depth; find the first transaction deeper than `depth`.
  let lo = 0,
    hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((list[mid].depth ?? -1) > depth) hi = mid;
    else lo = mid + 1;
  }
  return list[lo];
}

function redirectHop(req: RequestObservation, ix: Indexes, requestsUnread: boolean): RedirectHop | undefined {
  if (req.status === undefined || !REDIRECT.has(req.status)) return undefined;
  const target = req.redirectTarget
    ? { target: req.redirectTarget, targetState: "stated by the server" as const }
    : { targetState: "not in this record" as const };
  if (req.streamId) return { ...target, nextState: "not read (HTTP/2 stream)" };
  if (!req.uid || req.depth === undefined) return { ...target, nextState: "no transaction identity" };
  const next = firstLater(ix.byConn.get(req.uid) ?? [], req.depth);
  if (!next)
    return { ...target, nextState: requestsUnread ? "not among the records read" : "not in this upload" };
  if (next.depth === req.depth + 1) return { ...target, next, nextState: "observed" };
  return { ...target, nextState: "later transaction only", laterDepth: next.depth };
}

function bodyHop(
  req: RequestObservation,
  id: string,
  direction: BodyHop["direction"],
  ix: Indexes,
  unread: boolean,
): BodyHop {
  const { transfer, conflict } = transferFor(ix.byFuid.get(id));
  if (conflict) return { direction, id, state: "conflicting files records" };
  if (!transfer)
    return { direction, id, state: unread ? "not among the records read" : "no files record in this upload" };
  if (!compatible(req, transfer)) return { direction, id, state: "identifier conflict — not joined" };
  return { direction, id, state: "observed", transfer };
}

function bodiesOf(req: RequestObservation, ix: Indexes, unread: boolean): BodyHop[] {
  const hops: BodyHop[] = [];
  for (const id of req.respFuids) hops.push(bodyHop(req, id, "response", ix, unread));
  for (const id of req.origFuids) hops.push(bodyHop(req, id, "request", ix, unread));
  const fk = flowKey(req.flowId, req.txId);
  if (fk) {
    const bucket = ix.xferByFlowTx.get(fk);
    for (const transfer of bucket?.kept ?? [])
      hops.push({ direction: "not recorded", id: fk, state: "observed", transfer });
  }
  return hops;
}

function carriersOf(
  xfer: TransferObservation,
  ix: Indexes,
): { carriers: Carrier[]; omitted: number; conflicting: number } {
  const fk = flowKey(xfer.flowId, xfer.txId);
  const bucket = xfer.fuid ? ix.carriers.get(xfer.fuid) : undefined;
  const flowBucket = !xfer.fuid && fk ? ix.reqByFlowTx.get(fk) : undefined;
  const named: Carrier[] =
    bucket?.kept ?? flowBucket?.kept.map((req) => ({ req, direction: "not recorded" as const })) ?? [];
  const carriers = named.filter((c) => compatible(c.req, xfer)).sort((a, b) => byDepth(a.req, b.req));
  return {
    carriers,
    omitted: bucket?.omitted ?? flowBucket?.omitted ?? 0,
    conflicting: named.length - carriers.length,
  };
}

/** Every hop the upload establishes, for every retained request and transfer. */
export function joinWebChain(obs: WebObservations): { requests: RequestChain[]; transfers: TransferChain[] } {
  const ix = indexes(obs);
  const requestsUnread = total(obs.requestsOverflow) > 0;
  const transfersUnread = total(obs.transfersOverflow) > 0;

  const requests: RequestChain[] = obs.requests.map((req) => {
    // Every body is kept for the row's identity (the read bound already caps the list); the
    // words and the envelope show the first WEB_BODIES_MAX and count the rest.
    const bodies = bodiesOf(req, ix, transfersUnread);
    const redirect = redirectHop(req, ix, requestsUnread);
    return { req, bodies, bodiesTotal: bodies.length, ...(redirect ? { redirect } : {}) };
  });

  const transfers: TransferChain[] = obs.transfers.map((xfer) => {
    const { carriers, omitted, conflicting } = carriersOf(xfer, ix);
    const hasIdentity = Boolean(xfer.fuid || flowKey(xfer.flowId, xfer.txId));
    const requestState: RequestState = carriers.length
      ? "observed"
      : conflicting
        ? "identifier conflict — not joined"
        : xfer.inlineRequest
          ? "inline on this record"
          : !hasIdentity
            ? "no request identity"
            : requestsUnread
              ? "not among the records read"
              : "not in this upload";
    return {
      xfer,
      coverage: coverageOf(xfer, statusForBody(carriers, xfer.inlineRequest?.status)),
      requests: carriers.slice(0, WEB_REQUESTS_MAX).map((c) => c.req),
      requestsTotal: carriers.length + omitted,
      requestState,
    };
  });

  return { requests, transfers };
}
