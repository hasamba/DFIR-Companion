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
  iso: string;
  raw: string;
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
      if (Number.isFinite(n) && n > 1e8) {
        const d = new Date(n > 1e12 ? n : n * 1000);
        if (!Number.isNaN(d.getTime())) return { status: "ok", iso: d.toISOString(), raw: String(ep) };
      }
      return { status: "unreadable", iso: "", raw: JSON.stringify(v).slice(0, 80) };
    }
    const raw = cellStr(v).trim();
    if (!raw || raw === "0" || isPlaceholderCell(raw) || SENTINEL_DATE.test(raw))
      return { status: "absent", iso: "", raw };
    const iso = normalizeTime(raw);
    const t = iso ? Date.parse(iso) : NaN;
    return Number.isFinite(t)
      ? { status: "ok", iso: new Date(t).toISOString(), raw }
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

/**
 * Index the process rows an upload submitted, by PID. One EPROCESS listed by two plugins (pslist
 * and psscan) is ONE candidate: rows are de-duplicated by object offset when the record carries
 * one, else by (name, create time).
 */
export function indexProcessRows(tables: readonly { plugin: string; rows: readonly Row[] }[]): ProcessIndex {
  const byPid = new Map<string, ProcessCandidate[]>();
  const seen = new Set<string>();
  let any = false;
  for (const t of tables) {
    for (const r of t.rows) {
      const pid = processPid(r);
      if (!pid) continue;
      any = true;
      const name = processName(r);
      const created = readTime(r, PROCESS_CREATED_KEYS);
      const exited = readTime(r, PROCESS_EXIT_KEYS);
      const offset = cellStr(getCI(r, "Offset(V)") ?? getCI(r, "Offset") ?? getCI(r, "offset")).trim();
      const key =
        offset && !isPlaceholderCell(offset)
          ? `${pid}|off:${offset.toLowerCase()}`
          : `${pid}|${name.toLowerCase()}|${created.raw}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const list = byPid.get(pid) ?? [];
      list.push({ name, created, exited });
      byPid.set(pid, list);
    }
  }
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
  const socketAt = created.status === "ok" ? Date.parse(created.iso) : NaN;
  if (created.status === "ok" && c.created.status === "ok" && Date.parse(c.created.iso) > socketAt) {
    return {
      consistent: false,
      words: `not consistent: the submitted process row was created at ${c.created.iso}, after this socket's Created value`,
    };
  }
  if (created.status === "ok" && c.exited.status === "ok" && Date.parse(c.exited.iso) < socketAt) {
    return {
      consistent: false,
      words: `not consistent: the submitted process row reports exit at ${c.exited.iso}, before this socket's Created value`,
    };
  }
  const name = c.name ? shown(c.name) : "name not in the record";
  const createdWords =
    c.created.status === "ok" ? `created ${c.created.iso}` : "create time not in the record";
  let words = `consistent with one submitted process row: ${name}, ${createdWords}`;
  if (created.status === "ok" && c.exited.status === "ok") {
    words += `; that row reports exit at ${c.exited.iso}, after this socket's Created value`;
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
const WILDCARD = new Set(["", "*", "0.0.0.0", "::", "0"]);

function port(v: string): number {
  return /^\d{1,5}$/.test(v) && Number(v) <= 65535 ? Number(v) : NaN;
}

function address(v: string): boolean {
  return WILDCARD.has(v) || isIP(v.replace(/^\[|\]$/g, "")) !== 0;
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
  if (!t.laddr || !address(t.laddr)) return bad("local address", t.laddr);
  const fp = port(t.fport === "" || t.fport === "*" ? "0" : t.fport);
  if (!Number.isFinite(fp)) return bad("foreign port", t.fport);
  if (!address(t.faddr)) return bad("foreign address", t.faddr);
  const wildcardPeer = WILDCARD.has(t.faddr) || fp === 0;
  const listening = t.state.trim().toUpperCase() === "LISTENING";
  const udp = /^udp/i.test(t.proto);
  if (!udp && !listening && wildcardPeer)
    return bad("foreign endpoint", `${t.faddr || "*"}:${t.fport || "0"}`);
  return { ok: true, problem: "", peer: wildcardPeer ? "" : t.faddr, lport: lp, fport: fp };
}

/** The object's identity key: the offset when the record carries one, else nothing folds. */
export function objectKey(row: Row, rowIndex: number): string {
  const offset = cellStr(getCI(row, "Offset") ?? getCI(row, "Offset(V)") ?? getCI(row, "offset")).trim();
  return offset && !isPlaceholderCell(offset) ? `off:${offset.toLowerCase()}` : `row:${rowIndex}`;
}

/** A digest for a shown value in a key. */
export function ownerDigest(owner: string, pid: string): string {
  return keyDigest(`${owner}|${pid}`);
}
