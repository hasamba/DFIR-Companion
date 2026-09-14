import type { ForensicEvent } from "./stateTypes.js";
import { normaliseWinPath } from "./canonicalObjectAccess.js";

// Per-host indexes the sensitive-access reading joins through (#930 item 7): process starts and
// ends by pid, logons / logoffs by logon id, boot rows, and file evidence by normalised path.
// Every join here yields a CANDIDATE at most — no object-access record carries a stable id.

export const PROCESS_STARTS_PER_HOST_MAX = 50_000;
export const ACCESS_ROWS_PER_HOST_MAX = 20_000;

export const hostKey = (h: string | undefined): string => (h ?? "").trim().toLowerCase();
export const ms = (ts: string | undefined): number | null => {
  const n = Date.parse(ts ?? "");
  return Number.isFinite(n) ? n : null;
};
/** An image path for equality: case-folded, separators unified. WOW64 / symlinks are not resolved. */
export const imageKey = (p: string | undefined): string =>
  (p ?? "").trim().toLowerCase().replace(/\//g, "\\");

export interface ProcessStart {
  eventId: string;
  at: number;
  pid: number;
  image: string;
  imageKey: string;
  guid?: string;
  severity: ForensicEvent["severity"];
  techniques: string[];
}
export interface LogonRow {
  eventId: string;
  at: number;
  sessionId: string;
  account?: string;
  logonType?: number;
  sourceAddress?: string;
  severity: ForensicEvent["severity"];
}
export interface FileEvidence {
  eventId: string;
  at: number;
  /** open — a create / write / modify; point — an MFT / listing observation; close — a delete. */
  kind: "open" | "point" | "close";
}

export interface HostIndex {
  host: string;
  starts: Map<number, ProcessStart[]>;
  startsTotal: number;
  startsUnread: number;
  ends: Map<number, number[]>;
  logons: Map<string, LogonRow[]>;
  logoffs: Map<string, number[]>;
  boots: number[];
  /** Dated rows of every kind on the host: how far back the host's evidence reaches. */
  earliest: number | null;
  /** Rows by the process GUID they carry (pivots within a window). */
  byGuid: Map<string, ForensicEvent[]>;
  /** File rows by normalised path (evidence that an object is a file). */
  files: Map<string, FileEvidence[]>;
  findings: number;
}

const FILE_OPEN = new Set(["create", "write", "modify"]);
const FILE_POINT = new Set(["observation", "listing"]);
const LISTING = /\bmft\b|mftecmd|\$mft|usn|directory listing|file listing/i;

function fileEvidenceOf(e: ForensicEvent): FileEvidence["kind"] | null {
  const ev = e.canonical?.event;
  if (ev?.category !== "file") return LISTING.test((e.sources ?? []).join(" ")) ? "point" : null;
  if (FILE_OPEN.has(ev.type)) return "open";
  if (ev.type === "delete") return "close";
  if (FILE_POINT.has(ev.type)) return "point";
  return null;
}

function newIndex(host: string): HostIndex {
  return {
    host,
    starts: new Map(),
    startsTotal: 0,
    startsUnread: 0,
    ends: new Map(),
    logons: new Map(),
    logoffs: new Map(),
    boots: [],
    earliest: null,
    byGuid: new Map(),
    files: new Map(),
    findings: 0,
  };
}

const push = <K, V>(m: Map<K, V[]>, k: K, v: V): void => {
  const l = m.get(k);
  if (l) l.push(v);
  else m.set(k, [v]);
};

/** Build every host's index in one pass; lists are sorted by time afterwards. */
export function indexHosts(events: readonly ForensicEvent[]): Map<string, HostIndex> {
  const out = new Map<string, HostIndex>();
  for (const e of events) {
    if (!e.asset) continue;
    const k = hostKey(e.asset);
    const idx = out.get(k) ?? out.set(k, newIndex(e.asset)).get(k)!;
    const at = ms(e.timestamp);
    if (at === null) continue;
    if (idx.earliest === null || at < idx.earliest) idx.earliest = at;
    if (e.relatedFindingIds?.length) idx.findings += 1;
    const c = e.canonical;
    const ev = c?.event;
    if (!c || !ev) continue;
    if (c.process?.id) push(idx.byGuid, c.process.id, e);
    if (ev.category === "process" && ev.type === "start" && c.process?.pid !== undefined) {
      idx.startsTotal += 1;
      if (idx.startsTotal > PROCESS_STARTS_PER_HOST_MAX) {
        idx.startsUnread += 1;
        continue;
      }
      const image = c.process.executable ?? c.process.name ?? "";
      push(idx.starts, c.process.pid, {
        eventId: e.id,
        at,
        pid: c.process.pid,
        image,
        imageKey: imageKey(image),
        ...(c.process.id ? { guid: c.process.id } : {}),
        severity: e.severity,
        techniques: e.mitreTechniques ?? [],
      });
    } else if (ev.category === "process" && ev.type === "end" && c.process?.pid !== undefined)
      push(idx.ends, c.process.pid, at);
    else if (
      ev.category === "authentication" &&
      ev.type === "logon" &&
      ev.outcome !== "failed" &&
      c.authentication?.sessionId
    ) {
      push(idx.logons, c.authentication.sessionId.toLowerCase(), {
        eventId: e.id,
        at,
        sessionId: c.authentication.sessionId,
        ...(c.actor?.kind === "account" && c.actor.name ? { account: c.actor.name } : {}),
        ...(c.authentication.logonType !== undefined ? { logonType: c.authentication.logonType } : {}),
        ...(c.network?.source?.address ? { sourceAddress: c.network.source.address } : {}),
        severity: e.severity,
      });
    } else if (ev.category === "authentication" && ev.type === "logoff" && c.authentication?.sessionId)
      push(idx.logoffs, c.authentication.sessionId.toLowerCase(), at);
    else if (ev.type === "boot") idx.boots.push(at);
    const fk = fileEvidenceOf(e);
    const path = c.file?.path ?? e.path;
    if (fk && path) {
      const n = normaliseWinPath(path);
      if (n && "key" in n) push(idx.files, n.key, { eventId: e.id, at, kind: fk });
    }
  }
  for (const idx of out.values()) {
    for (const l of idx.starts.values()) l.sort((a, b) => a.at - b.at);
    for (const l of idx.ends.values()) l.sort((a, b) => a - b);
    for (const l of idx.logons.values()) l.sort((a, b) => a.at - b.at);
    for (const l of idx.logoffs.values()) l.sort((a, b) => a - b);
    for (const l of idx.files.values()) l.sort((a, b) => a.at - b.at);
    idx.boots.sort((a, b) => a - b);
  }
  return out;
}

export interface InstanceCandidate {
  state: "candidate" | "ambiguous" | "not-established";
  reason: string;
  start?: ProcessStart;
}

/** The process instance a (pid, image, T) may belong to — a candidate at most (see the header). */
export function instanceCandidate(
  idx: HostIndex,
  pid: number | undefined,
  image: string | undefined,
  at: number,
): InstanceCandidate {
  if (pid === undefined) return { state: "not-established", reason: "no process id on the record" };
  const starts = (idx.starts.get(pid) ?? []).filter((s) => s.at <= at);
  if (!starts.length)
    return {
      state: "not-established",
      reason: idx.startsUnread
        ? `no start row read for pid ${pid} (${idx.startsUnread} start row(s) unread on this host)`
        : `no process-start row for pid ${pid} on this host before the access — name and pid only`,
    };
  const latest = starts[starts.length - 1];
  const ended = (idx.ends.get(pid) ?? []).some((t) => t > latest.at && t <= at);
  if (ended)
    return {
      state: "not-established",
      reason: `pid ${pid}'s latest start (${latest.eventId}) ended before the access`,
    };
  if (image && imageKey(image) !== latest.imageKey)
    return {
      state: "ambiguous",
      reason: `pid ${pid} reused: the latest start before the access is ${latest.image}, the record names ${image}`,
    };
  const sameImageEarlier = starts
    .slice(0, -1)
    .filter(
      (s) =>
        s.imageKey === latest.imageKey && !(idx.ends.get(pid) ?? []).some((t) => t > s.at && t <= latest.at),
    );
  if (sameImageEarlier.length)
    return {
      state: "ambiguous",
      reason: `pid ${pid} started ${starts.length} times with the same image before the access and no termination row separates them`,
      start: latest,
    };
  if (idx.startsUnread)
    return {
      state: "ambiguous",
      reason: `${idx.startsUnread} process-start row(s) unread on this host — the start read is incomplete`,
      start: latest,
    };
  return {
    state: "candidate",
    reason: `start row ${latest.eventId} (pid ${pid}, same image) precedes the access with no other start of that pid between`,
    start: latest,
  };
}

export interface SessionCandidate {
  state: "candidate" | "ambiguous" | "not-established";
  reason: string;
  logon?: LogonRow;
}

/** The logon session a SubjectLogonId may belong to on this host at T — a candidate at most. */
export function sessionCandidate(
  idx: HostIndex,
  sessionId: string | undefined,
  at: number,
): SessionCandidate {
  if (!sessionId) return { state: "not-established", reason: "no logon id on the record" };
  const rows = (idx.logons.get(sessionId.toLowerCase()) ?? []).filter((l) => l.at <= at);
  if (!rows.length)
    return {
      state: "not-established",
      reason: `no 4624 with logon id ${sessionId} on this host before the access`,
    };
  if (rows.length > 1)
    return {
      state: "ambiguous",
      reason: `${rows.length} logons share logon id ${sessionId} on this host before the access`,
    };
  const logon = rows[0];
  if ((idx.logoffs.get(sessionId.toLowerCase()) ?? []).some((t) => t > logon.at && t <= at))
    return { state: "ambiguous", reason: `logon id ${sessionId} logged off between its 4624 and the access` };
  if (idx.boots.some((t) => t > logon.at && t <= at))
    return { state: "ambiguous", reason: "a boot row lies between the 4624 and the access" };
  return {
    state: "candidate",
    reason: `4624 ${logon.eventId} precedes the access with no logoff or boot between`,
    logon,
  };
}

/** Whether a normalised path is evidenced as a FILE on this host at T: an open version covering T
 * or a point observation at or before T with no close between. */
export function fileEvidencedAt(
  idx: HostIndex,
  key: string,
  at: number,
): { state: "file"; by: string } | { state: "not-evidenced"; reason: string } {
  const rows = idx.files.get(key) ?? [];
  let by: string | null = null;
  for (const r of rows) {
    if (r.at > at) break;
    if (r.kind === "close") by = null;
    else by = r.eventId;
  }
  if (by) return { state: "file", by };
  return {
    state: "not-evidenced",
    reason: rows.length
      ? "the last file row for this path before the access is a delete, or every file row is later than the access"
      : "no file row for this path on this host before the access",
  };
}
