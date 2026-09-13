// What one web request record and one transfer record SAY — read, bounded, and nothing joined yet
// (#993, the second half of #933 item 1). Zeek `http.log` and `files.log`, Suricata `http` and
// `fileinfo`. The join across records is webChainJoin.ts; the rows are webChainRows.ts.
//
// A request record is one request/response pair: Zeek logs the pair as one line and Suricata's
// `http` event carries `status` beside the request, so "the response" is never a second record
// here. The identifiers a join may use are kept verbatim as LOCATORS — `uid` + `trans_depth`,
// `orig_fuids` / `resp_fuids`, `flow_id` + `tx_id`, `fuid` — and are never facts of the row.
//
// Every identifier list is bounded at read time (WEB_IDS_PER_RECORD): a record carrying ten
// thousand fuids is attacker-shaped input, and the row says how many it did not read.

import { isIP } from "node:net";
import { cleanIp, getCI, getPath, isObject, str } from "./siemImport.js";
import { normalizeTime } from "./siemImport.js";
import { clipField } from "./webRequestDecode.js";

type Row = Record<string, unknown>;

/** Identifiers read from one record; the rest are dropped and counted. */
export const WEB_IDS_PER_RECORD = 32;
const PROXIED_MAX = 8;

export type RequestSource = "zeek-http" | "suricata-http";
export type TransferSource = "zeek-files" | "suricata-fileinfo";

export interface SensorRef {
  name: string;
  sourceField: string;
}

export interface RequestObservation {
  source: RequestSource;
  timestamp: string;
  /** `record:<index>` — the row's place in the upload, the evidence pointer. */
  locator: string;
  observer?: SensorRef;
  src?: string;
  dst?: string;
  port?: number;
  method: string;
  /** The request target as logged (Zeek `uri`, Suricata `url`), clipped to MAX_FIELD. */
  target: string;
  /** The Host header as logged — the destination the CLIENT named; never the sensor. */
  host: string;
  version?: string;
  status?: number;
  referrer: string;
  userAgent: string;
  user?: string;
  requestBodyLen?: number;
  responseBodyLen?: number;
  /** Suricata `http.redirect`: the Location header the server sent, as a string. */
  redirectTarget?: string;
  proxied?: string[];
  origFuids: string[];
  respFuids: string[];
  identifiersDropped: number;
  uid?: string;
  depth?: number;
  streamId?: string;
  flowId?: string;
  txId?: string;
}

export interface TransferObservation {
  source: TransferSource;
  timestamp: string;
  locator: string;
  observer?: SensorRef;
  fuid?: string;
  over?: string;
  mime?: string;
  filename?: string;
  seenBytes?: number;
  totalBytes?: number;
  missingBytes?: number;
  timedOut?: boolean;
  /** Suricata `fileinfo.state` verbatim (CLOSED / TRUNCATED / UNKNOWN …). */
  sensorState?: string;
  gaps?: boolean;
  /** Suricata `fileinfo.start`: a non-zero offset means a range, never the object. */
  startOffset?: number;
  sha256?: string;
  sha1?: string;
  md5?: string;
  /** The sender and receiver sets when the record SAYS them (old-schema tx/rx hosts, or is_orig). */
  tx?: string[];
  rx?: string[];
  fromOriginator?: boolean;
  /** The connection's two endpoints when the record names only those (Zeek 6 `id.*`, Suricata). */
  flowSrc?: string;
  flowDst?: string;
  connUids: string[];
  identifiersDropped: number;
  flowId?: string;
  txId?: string;
  /** Suricata carries the request inline on the fileinfo event; the join still goes by flow + tx. */
  inlineRequest?: { method: string; host: string; target: string; status?: number };
}

// ───────────────────────────── field readers ─────────────────────────────

const text = (v: unknown): string | undefined =>
  v === undefined || v === null ? undefined : typeof v === "string" ? v : String(v);
const num = (v: unknown): number | undefined => {
  if (v === undefined || v === null || v === "") return undefined;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : undefined;
};
const bool = (v: unknown): boolean | undefined =>
  typeof v === "boolean"
    ? v
    : v === "true" || v === "T"
      ? true
      : v === "false" || v === "F"
        ? false
        : undefined;

/** A bounded list of identifiers: strings only, trimmed, the first WEB_IDS_PER_RECORD kept. */
export function idList(v: unknown): { ids: string[]; dropped: number } {
  const raw = Array.isArray(v) ? v : typeof v === "string" && v ? v.split(",") : [];
  const ids = raw.map((x) => str(x).trim()).filter((x) => x && x !== "-");
  return { ids: ids.slice(0, WEB_IDS_PER_RECORD), dropped: Math.max(0, ids.length - WEB_IDS_PER_RECORD) };
}

const hexOf = (v: unknown, len: number): string | undefined => {
  const t = text(v)?.trim().toLowerCase();
  return t && t.length === len && /^[0-9a-f]+$/.test(t) ? t : undefined;
};

/** The sensor, from the fields a shipper adds — never from a scalar `host`, which is the HTTP Host. */
export function sensorOf(row: Row): SensorRef | undefined {
  for (const path of ["observer.name", "observer.hostname", "host.name", "agent.hostname", "agent.name"]) {
    const v = text(getCI(row, path) ?? getPath(row, path))?.trim();
    if (v) return { name: v, sourceField: path };
  }
  return undefined;
}

function zeekTime(row: Row): string {
  const ts = getCI(row, "ts");
  const n = typeof ts === "number" ? ts : Number(ts);
  if (Number.isFinite(n) && n > 1e9) return new Date(n * 1000).toISOString();
  return normalizeTime(str(ts)) || "";
}

function suricataTime(row: Row): string {
  return normalizeTime(str(getCI(row, "timestamp"))) || "";
}

const address = (v: unknown): string | undefined => {
  const a = cleanIp(str(v));
  return a && isIP(a) ? a : undefined;
};
const portOf = (v: unknown): number | undefined => {
  const p = num(v);
  return p !== undefined && p > 0 && p <= 65535 ? p : undefined;
};

// A field the client wrote, bounded once here (MAX_FIELD) so no later step sees more of it.
const clientField = (v: unknown): string => clipField(text(v) ?? "").text;

// ───────────────────────────── Zeek http.log ─────────────────────────────

export function readZeekHttp(row: Row, recordIndex: number): RequestObservation {
  const orig = idList(getCI(row, "orig_fuids"));
  const resp = idList(getCI(row, "resp_fuids"));
  const proxied = idList(getCI(row, "proxied"));
  const depth = num(getCI(row, "trans_depth"));
  const streamId = text(getCI(row, "stream_id"))?.trim();
  return {
    source: "zeek-http",
    timestamp: zeekTime(row),
    locator: `record:${recordIndex}`,
    observer: sensorOf(row),
    src: address(getCI(row, "id.orig_h")),
    dst: address(getCI(row, "id.resp_h")),
    port: portOf(getCI(row, "id.resp_p")),
    method: (text(getCI(row, "method"))?.trim() || "-").slice(0, 16).toUpperCase(),
    target: clientField(getCI(row, "uri")),
    host: clientField(getCI(row, "host")),
    version: text(getCI(row, "version"))?.trim() || undefined,
    status: num(getCI(row, "status_code")),
    referrer: clientField(getCI(row, "referrer")),
    userAgent: clientField(getCI(row, "user_agent")),
    user: text(getCI(row, "username"))?.trim() || undefined,
    requestBodyLen: num(getCI(row, "request_body_len")),
    responseBodyLen: num(getCI(row, "response_body_len")),
    ...(proxied.ids.length ? { proxied: proxied.ids.slice(0, PROXIED_MAX).map((p) => p.slice(0, 120)) } : {}),
    origFuids: orig.ids,
    respFuids: resp.ids,
    identifiersDropped: orig.dropped + resp.dropped,
    uid: text(getCI(row, "uid"))?.trim() || undefined,
    ...(depth !== undefined ? { depth } : {}),
    ...(streamId ? { streamId } : {}),
  };
}

// ───────────────────────────── Zeek files.log ─────────────────────────────

// Zeek 6 replaced `conn_uids` / `tx_hosts` / `rx_hosts` (sets: a file could span connections) with
// `uid` / `id.*` (one connection per file record). Both schemas are read; the identifier list and
// the host sets are what each carries.
export function readZeekFiles(row: Row, recordIndex: number): TransferObservation {
  const uids = idList(getCI(row, "conn_uids") ?? getCI(row, "uid"));
  const tx = idList(getCI(row, "tx_hosts"));
  const rx = idList(getCI(row, "rx_hosts"));
  const orig = address(getCI(row, "id.orig_h"));
  const resp = address(getCI(row, "id.resp_h"));
  const isOrig = bool(getCI(row, "is_orig"));
  // Direction is a claim only when the record makes it: the old schema's tx/rx host sets, or
  // `is_orig` beside the connection's endpoints (true: the originator sent the file).
  const txHosts = tx.ids.length
    ? tx.ids.map(address).filter((h): h is string => !!h)
    : isOrig === undefined
      ? []
      : [isOrig ? orig : resp].filter((h): h is string => !!h);
  const rxHosts = rx.ids.length
    ? rx.ids.map(address).filter((h): h is string => !!h)
    : isOrig === undefined
      ? []
      : [isOrig ? resp : orig].filter((h): h is string => !!h);
  return {
    source: "zeek-files",
    timestamp: zeekTime(row),
    locator: `record:${recordIndex}`,
    observer: sensorOf(row),
    fuid: text(getCI(row, "fuid"))?.trim() || undefined,
    over: text(getCI(row, "source"))?.trim().toUpperCase() || undefined,
    mime: text(getCI(row, "mime_type"))?.trim().slice(0, 120) || undefined,
    filename: text(getCI(row, "filename"))?.slice(0, 260) || undefined,
    seenBytes: num(getCI(row, "seen_bytes")),
    totalBytes: num(getCI(row, "total_bytes")),
    missingBytes: num(getCI(row, "missing_bytes")),
    timedOut: bool(getCI(row, "timedout")),
    sha256: hexOf(getCI(row, "sha256"), 64),
    sha1: hexOf(getCI(row, "sha1"), 40),
    md5: hexOf(getCI(row, "md5"), 32),
    ...(txHosts.length ? { tx: txHosts } : {}),
    ...(rxHosts.length ? { rx: rxHosts } : {}),
    ...(isOrig !== undefined ? { fromOriginator: isOrig } : {}),
    ...(orig ? { flowSrc: orig } : {}),
    ...(resp ? { flowDst: resp } : {}),
    connUids: uids.ids,
    identifiersDropped: uids.dropped + tx.dropped + rx.dropped,
  };
}

// ───────────────────────────── Suricata http / fileinfo ─────────────────────────────

function suricataRequest(
  row: Row,
): { method: string; host: string; target: string; status?: number } | undefined {
  const h = getCI(row, "http");
  if (!isObject(h)) return undefined;
  return {
    method: (text(getCI(h, "http_method"))?.trim() || "-").slice(0, 16).toUpperCase(),
    host: clientField(getCI(h, "hostname")),
    target: clientField(getCI(h, "url")),
    status: num(getCI(h, "status")),
  };
}

export function readSuricataHttp(row: Row, recordIndex: number): RequestObservation {
  const h = isObject(getCI(row, "http")) ? (getCI(row, "http") as Row) : {};
  const req = suricataRequest(row) ?? { method: "-", host: "", target: "" };
  const flowId = text(getCI(row, "flow_id"))?.trim();
  const txId = text(getCI(row, "tx_id"))?.trim();
  const redirect = text(getCI(h, "redirect"))?.trim();
  return {
    source: "suricata-http",
    timestamp: suricataTime(row),
    locator: `record:${recordIndex}`,
    observer: sensorOf(row),
    src: address(getCI(row, "src_ip")),
    dst: address(getCI(row, "dest_ip")),
    port: portOf(getCI(row, "dest_port")),
    ...req,
    version: text(getCI(h, "protocol"))?.trim() || undefined,
    referrer: clientField(getCI(h, "http_refer")),
    userAgent: clientField(getCI(h, "http_user_agent")),
    responseBodyLen: num(getCI(h, "length")),
    ...(redirect ? { redirectTarget: clipField(redirect).text } : {}),
    origFuids: [],
    respFuids: [],
    identifiersDropped: 0,
    ...(flowId ? { flowId } : {}),
    ...(txId ? { txId } : {}),
  };
}

export function readSuricataFileinfo(row: Row, recordIndex: number): TransferObservation {
  const fi = isObject(getCI(row, "fileinfo")) ? (getCI(row, "fileinfo") as Row) : {};
  const flowId = text(getCI(row, "flow_id"))?.trim();
  const txId = text(getCI(fi, "tx_id") ?? getCI(row, "tx_id"))?.trim();
  const inline = suricataRequest(row);
  const src = address(getCI(row, "src_ip"));
  const dst = address(getCI(row, "dest_ip"));
  return {
    source: "suricata-fileinfo",
    timestamp: suricataTime(row),
    locator: `record:${recordIndex}`,
    observer: sensorOf(row),
    over: text(getCI(row, "app_proto"))?.trim().toUpperCase() || undefined,
    mime: text(getCI(fi, "magic"))?.trim().slice(0, 120) || undefined,
    filename: text(getCI(fi, "filename"))?.slice(0, 260) || undefined,
    seenBytes: num(getCI(fi, "size")),
    sensorState: text(getCI(fi, "state"))?.trim().toUpperCase() || undefined,
    gaps: bool(getCI(fi, "gaps")),
    startOffset: num(getCI(fi, "start")),
    sha256: hexOf(getCI(fi, "sha256"), 64),
    sha1: hexOf(getCI(fi, "sha1"), 40),
    md5: hexOf(getCI(fi, "md5"), 32),
    // A fileinfo event names the flow's endpoints, not the body's direction: a response body
    // travels dest → src, a request body the other way, and the event says which only through
    // the inline request. Kept as the two addresses, never as sender and receiver.
    ...(src ? { flowSrc: src } : {}),
    ...(dst ? { flowDst: dst } : {}),
    connUids: [],
    identifiersDropped: 0,
    ...(flowId ? { flowId } : {}),
    ...(txId ? { txId } : {}),
    ...(inline ? { inlineRequest: inline } : {}),
  };
}
