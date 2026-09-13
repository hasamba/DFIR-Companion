// What a memory SOCKET record establishes (#933 item 14): its stored state, how the plugin reported
// it, its own owner fields, and whether the process rows submitted in the same upload are
// consistent with them. Nothing here infers liveness, traffic or a cause.
//
//   • `windows.netstat` traverses the network tracking structures; `windows.netscan` (and every
//     other scanner) finds objects by pool tag — allocated or freed. The row says which. Neither
//     says a connection was live, that traffic passed, or when.
//   • The State token is shown verbatim and read from Volatility's own enum. A teardown state is a
//     teardown state; "residual", "live" and "outlived" appear nowhere, because a stored state on a
//     scanned object may predate capture and the record does not say.
//   • PID and Owner are rendered independently by Volatility; either can be absent. An absent
//     field is "not in the record" — no cause (freed, overwritten, hidden) is named.
//   • The consistency note compares the socket's owner fields with the SUBMITTED process rows.
//     They are uploader-controlled, so the note is an internal comparison, never validation, and
//     it never rewrites the socket's own fields. Candidates at a PID are de-duplicated by object
//     offset (one EPROCESS in pslist and psscan is one candidate); more than one distinct
//     candidate is "ambiguous". "Consistent" means this comparison found no conflict.
//   • A tuple has a shape: a UDP or listening endpoint has a wildcard peer; any other TCP state
//     needs a readable, non-wildcard peer with a nonzero port. A row outside that shape is still a
//     row — "tuple incomplete" — and mints no indicator.
//   • Identity is the OBJECT (its offset), not its fields: two rows at one offset are one object
//     reported twice; a row with no offset never folds.

import { isIP } from "node:net";
import { cellStr, isPlaceholderCell } from "./memoryFields.js";
import { baseName, getCI, isObject, normalizeTime } from "./siemImport.js";
import { breakHashRuns, keyDigest, showToken } from "./recordIdentity.js";
import { pstreeChildren } from "./pstreeDepth.js";

type Row = Record<string, unknown>;

const SHOWN_MAX = 120;

/** A collected string safe for prose: no tag, no control character, no bare hash run, bounded. */
export function shown(value: string, max = SHOWN_MAX): string {
  const t = breakHashRuns(showToken(value ?? ""));
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

// ─────────────────────────── state ───────────────────────────

/** Volatility 3's TCP state enum, as it renders (netscan-win*.json). */
const STATE_READING: Readonly<Record<string, string>> = {
  LISTENING: "listening endpoint",
  ESTABLISHED: "stored state ESTABLISHED",
  SYN_SENT: "connection setup state",
  SYN_RCVD: "connection setup state",
  FIN_WAIT1: "TCP teardown state (a half-closed direction may still carry data)",
  FIN_WAIT2: "TCP teardown state (a half-closed direction may still carry data)",
  CLOSE_WAIT: "TCP teardown state (a half-closed direction may still carry data)",
  CLOSING: "TCP teardown state (a half-closed direction may still carry data)",
  LAST_ACK: "TCP teardown state (a half-closed direction may still carry data)",
  TIME_WAIT: "TCP teardown state (a half-closed direction may still carry data)",
  CLOSED: "closed-state object",
  DELETE_TCB: "closed-state object",
};

export interface StateReading {
  /** The token as the record carries it, neutralised; "" when absent. */
  token: string;
  reading: string;
  listening: boolean;
}

export function readState(raw: string, proto: string): StateReading {
  const t = (raw ?? "").trim();
  const absent = !t || isPlaceholderCell(t);
  if (absent) {
    return {
      token: "",
      reading: /udp/i.test(proto) ? "UDP endpoint (no connection state)" : "state not in the record",
      listening: false,
    };
  }
  const known = STATE_READING[t.toUpperCase()];
  return {
    token: shown(t, 40),
    reading: known ?? "state not in the table",
    listening: t.toUpperCase() === "LISTENING",
  };
}

// ─────────────────────────── provenance ───────────────────────────

/** How the plugin reported the object — per its label, which the uploader chose. */
export function socketProvenance(plugin: string): string {
  return /netstat/i.test(plugin)
    ? "reported by traversal of the network tracking structures"
    : "reported by pool scan — an allocated or a freed object";
}

// ─────────────────────────── times ───────────────────────────

export interface TimeReading {
  status: "absent" | "unreadable" | "ok";
  /** Canonical ISO (millisecond) — the row's timestamp. */
  iso: string;
  /** The instant at the record's full precision, for ordering: [epoch ms, fraction beyond ms]. */
  instant?: [number, number];
  raw: string;
}

/** Order two full-precision instants: negative, zero, positive. */
export function compareInstants(a: [number, number], b: [number, number]): number {
  return a[0] !== b[0] ? a[0] - b[0] : a[1] - b[1];
}

function instantOf(iso: string): [number, number] | undefined {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return undefined;
  // Digits beyond the millisecond, as a fraction of one millisecond (Volatility renders microseconds).
  const frac = /\.(\d{3})(\d+)(?:Z|[+-]\d{2}:?\d{2})$/.exec(iso)?.[2] ?? "";
  return [t, frac ? Number(`0.${frac}`) : 0];
}

const SENTINEL_DATE = /^(?:1601-01-01|0001-01-01|1970-01-01)/;

/** A typed, tri-state time: absent (no value, placeholder, sentinel), unreadable, or ok. */
export function readTime(row: Row, keys: readonly string[]): TimeReading {
  for (const k of keys) {
    const v = getCI(row, k);
    if (v === undefined) continue;
    if (isObject(v)) {
      const ep = getCI(v, "epoch") ?? getCI(v, "value");
      const n = typeof ep === "number" ? ep : Number(cellStr(ep));
      if (ep === undefined || ep === null || n === 0) return { status: "absent", iso: "", raw: "" }; // Rekall's zero epoch
      if (Number.isFinite(n) && n > 1e8) {
        const d = new Date(n > 1e12 ? n : n * 1000);
        if (!Number.isNaN(d.getTime())) {
          return { status: "ok", iso: d.toISOString(), instant: [d.getTime(), 0], raw: String(ep) };
        }
      }
      return { status: "unreadable", iso: "", raw: JSON.stringify(v).slice(0, 80) };
    }
    const raw = cellStr(v).trim();
    if (!raw || raw === "0" || isPlaceholderCell(raw) || SENTINEL_DATE.test(raw)) {
      return { status: "absent", iso: "", raw };
    }
    const iso = normalizeTime(raw);
    const instant = iso ? instantOf(iso) : undefined;
    return instant
      ? { status: "ok", iso: new Date(instant[0]).toISOString(), instant, raw }
      : { status: "unreadable", iso: "", raw };
  }
  return { status: "absent", iso: "", raw: "" };
}

export const SOCKET_CREATED_KEYS = ["Created", "created", "create_time"] as const;
const PROCESS_CREATED_KEYS = ["CreateTime", "process_create_time", "CreatedTime", "start_time"] as const;
const PROCESS_EXIT_KEYS = ["ExitTime", "Exit Time", "process_exit_time", "exit_time"] as const;

// ─────────────────────────── submitted process rows ───────────────────────────

export interface ProcessCandidate {
  name: string;
  created: TimeReading;
  exited: TimeReading;
}

export interface ProcessIndex {
  /** True when the upload submitted any process rows at all. */
  any: boolean;
  byPid: Map<string, ProcessCandidate[]>;
}

const PROC_NAME_KEYS = ["ImageFileName", "Name", "name", "Process", "comm", "_EPROCESS"];

function processName(row: Row): string {
  for (const k of PROC_NAME_KEYS) {
    const s = cellStr(getCI(row, k)).trim();
    if (s && !isPlaceholderCell(s)) return baseName(s);
  }
  return "";
}

function processPid(row: Row): string {
  const s = cellStr(getCI(row, "PID") ?? getCI(row, "pid") ?? getCI(row, "Pid")).trim();
  return /^\d+$/.test(s) ? s : "";
}

/** An object offset in canonical form: hex or decimal, with or without 0x, any case → one number. */
export function canonicalOffset(row: Row): string {
  const raw = cellStr(getCI(row, "Offset(V)") ?? getCI(row, "Offset") ?? getCI(row, "offset")).trim();
  if (!raw || isPlaceholderCell(raw)) return "";
  const hex = /^0x([0-9a-f]+)$/i.exec(raw);
  if (hex) return BigInt(`0x${hex[1]}`).toString(16);
  if (/^\d+$/.test(raw)) return BigInt(raw).toString(16);
  if (/^[0-9a-f]+$/i.test(raw)) return BigInt(`0x${raw}`).toString(16);
  return raw.toLowerCase();
}

/**
 * Index the process rows an upload submitted, by PID. One EPROCESS listed by two plugins (pslist
 * and psscan) is ONE candidate: rows are de-duplicated by canonical object offset when the record
 * carries one, else by (name, canonical create time). pstree's nested children are rows too.
 */
export function indexProcessRows(tables: readonly { plugin: string; rows: readonly Row[] }[]): ProcessIndex {
  const byPid = new Map<string, ProcessCandidate[]>();
  const seen = new Set<string>();
  let any = false;
  const walk = (rows: readonly Row[], depth: number): void => {
    for (const r of rows) {
      any = true;
      const pid = processPid(r);
      if (pid) {
        const name = processName(r);
        const created = readTime(r, PROCESS_CREATED_KEYS);
        const exited = readTime(r, PROCESS_EXIT_KEYS);
        const offset = canonicalOffset(r);
        const key = offset
          ? `${pid}|off:${offset}`
          : `${pid}|${name.toLowerCase()}|${created.iso || created.raw}`;
        if (!seen.has(key)) {
          seen.add(key);
          const list = byPid.get(pid) ?? [];
          list.push({ name, created, exited });
          byPid.set(pid, list);
        }
      }
      walk(pstreeChildren(r, depth), depth + 1);
    }
  };
  for (const t of tables) walk(t.rows, 0);
  return { any, byPid };
}

export interface Consistency {
  /** Exactly one submitted row, and this comparison found no conflict. */
  consistent: boolean;
  words: string;
}

/** Compare the socket's own owner fields with the submitted process rows. Never rewrites them. */
export function ownerConsistency(
  pid: string,
  owner: string,
  created: TimeReading,
  index: ProcessIndex,
): Consistency {
  if (!index.any) return { consistent: false, words: "no process rows submitted to compare" };
  if (!pid) return { consistent: false, words: "no PID in the record to compare" };
  const candidates = index.byPid.get(pid) ?? [];
  if (candidates.length === 0) return { consistent: false, words: `no submitted process row has PID ${pid}` };
  if (candidates.length > 1) {
    return {
      consistent: false,
      words: `ambiguous: ${candidates.length} distinct submitted process rows have PID ${pid}`,
    };
  }
  const [c] = candidates;
  if (owner && !c.name) {
    return {
      consistent: false,
      words: `not comparable: the submitted process row at PID ${pid} carries no name`,
    };
  }
  if (owner && c.name && baseName(owner).toLowerCase() !== c.name.toLowerCase()) {
    return {
      consistent: false,
      words: `not consistent: the submitted process row at PID ${pid} is named ${shown(c.name)}`,
    };
  }
  const notComparable: string[] = [];
  if (created.status !== "ok") {
    notComparable.push(
      created.status === "absent"
        ? "this socket's Created value is not in the record"
        : "this socket's Created value is not readable",
    );
  }
  if (c.created.status === "unreadable") notComparable.push("the process row's create time is not readable");
  if (c.exited.status === "unreadable") notComparable.push("the process row's exit time is not readable");
  const socketAt = created.instant;
  const after = (t: TimeReading): boolean =>
    !!socketAt && !!t.instant && compareInstants(t.instant, socketAt) > 0;
  const before = (t: TimeReading): boolean =>
    !!socketAt && !!t.instant && compareInstants(t.instant, socketAt) < 0;
  if (after(c.created)) {
    return {
      consistent: false,
      words: `not consistent: the submitted process row was created at ${c.created.iso}, after this socket's Created value`,
    };
  }
  if (before(c.exited)) {
    return {
      consistent: false,
      words: `not consistent: the submitted process row reports exit at ${c.exited.iso}, before this socket's Created value`,
    };
  }
  const name = c.name ? shown(c.name) : "name not in the record";
  const createdWords =
    c.created.status === "ok" ? `created ${c.created.iso}` : "create time not in the record";
  let words = `consistent with one submitted process row: ${name}, ${createdWords}`;
  if (after(c.exited)) {
    words += `; that row reports exit at ${c.exited.iso}, after this socket's Created value`;
  } else if (socketAt && c.exited.instant) {
    words += `; that row reports exit at ${c.exited.iso}, the same value as this socket's Created`;
  }
  if (notComparable.length) words += `; lifetime not comparable (${notComparable.join("; ")})`;
  return { consistent: true, words };
}

// ─────────────────────────── tuple shape ───────────────────────────

export interface Tuple {
  proto: string;
  laddr: string;
  lport: string;
  faddr: string;
  fport: string;
  state: string;
}

export interface TupleShape {
  ok: boolean;
  /** The offending field and value, neutralised, when not ok. */
  problem: string;
  /** The foreign address when it is a real, non-wildcard peer of a complete tuple. */
  peer: string;
  lport: number;
  fport: number;
}

const PROTO_RE = /^(?:TCP|UDP)(?:v4|v6)?$/i;
/** A local wildcard is the unspecified address; the foreign side also renders `*` for UDP. */
const LOCAL_WILDCARD = new Set(["0.0.0.0", "::"]);
const FOREIGN_WILDCARD = new Set(["", "*", "0.0.0.0", "::"]);

function port(v: string): number {
  return /^\d{1,5}$/.test(v) && Number(v) <= 65535 ? Number(v) : NaN;
}

/** `[::1]` and `::1` are one address; the bracketed form is normalised once, here. */
export function normalizeAddress(v: string): string {
  return (v ?? "").trim().replace(/^\[(.*)\]$/, "$1");
}

/** Does the tuple have the shape its protocol and state imply? */
export function tupleShape(t: Tuple): TupleShape {
  const bad = (field: string, value: string): TupleShape => ({
    ok: false,
    problem: `${field} = ${shown(value, 60)}`,
    peer: "",
    lport: NaN,
    fport: NaN,
  });
  if (!PROTO_RE.test(t.proto)) return bad("proto", t.proto);
  const lp = port(t.lport);
  if (!Number.isFinite(lp)) return bad("local port", t.lport);
  const laddr = normalizeAddress(t.laddr);
  if (!laddr || !(LOCAL_WILDCARD.has(laddr) || isIP(laddr) !== 0)) return bad("local address", t.laddr);
  const fp = port(t.fport === "" || t.fport === "*" ? "0" : t.fport);
  if (!Number.isFinite(fp)) return bad("foreign port", t.fport);
  const faddr = normalizeAddress(t.faddr);
  if (!(FOREIGN_WILDCARD.has(faddr) || isIP(faddr) !== 0)) return bad("foreign address", t.faddr);
  const wildcardPeer = FOREIGN_WILDCARD.has(faddr) || fp === 0;
  const listening = t.state.trim().toUpperCase() === "LISTENING";
  const udp = /^udp/i.test(t.proto);
  const endpoint = `${t.faddr || "*"}:${t.fport || "0"}`;
  // A non-listening TCP object has a peer; a UDP or listening object has none — either way round
  // is not the shape Volatility renders.
  if (!udp && !listening && wildcardPeer) return bad("foreign endpoint", endpoint);
  if ((udp || listening) && !wildcardPeer) return bad("foreign endpoint", endpoint);
  return { ok: true, problem: "", peer: wildcardPeer ? "" : faddr, lport: lp, fport: fp };
}

/** The object's identity: its canonical offset when the record carries one, else "" (nothing folds). */
export function objectOffset(row: Row): string {
  return canonicalOffset(row);
}

/** A digest for a shown value in a key. */
export function ownerDigest(owner: string, pid: string): string {
  return keyDigest(`${owner}|${pid}`);
}
