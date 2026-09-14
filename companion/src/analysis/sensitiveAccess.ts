import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import type { SensitiveLocation } from "./sensitiveLocation.js";
import { normaliseWinPath, type AccessClass } from "./canonicalObjectAccess.js";
import {
  ACCESS_ROWS_PER_HOST_MAX,
  fileEvidencedAt,
  hostKey,
  indexHosts,
  instanceCandidate,
  ms,
  sessionCandidate,
  type HostIndex,
} from "./accessIndexes.js";

// Sensitive-file access by a suspicious process or compromised account (#930 item 7). A 4663
// establishes that a process exercised rights on an object; the rights say read-or-listing,
// write, delete, metadata; sensitivity is the analyst's declaration; the process instance and the
// logon session are candidates joined by pid / logon id on the host; "suspicious" is only what
// the candidate's own rows already carry. Accessed, later archive activity and later network
// connections are three separate columns and none implies the next. Nothing here says
// exfiltration, content, or sensitivity from a filename.

export const OBJECTS_PER_LOCATION_MAX = 500;
export const NAMED_MAX = 20;
const PIVOT_WINDOW_MS = 60 * 60_000;
const DELETE_WINDOW_MS = 5 * 60_000;
const COLLECTION_OBJECTS = 10;
const COLLECTION_WINDOW_MS = 15 * 60_000;
const ARCHIVE = /\.(zip|7z|rar|cab|tar|gz|tgz)$/i;
const HIGH = new Set(["High", "Critical"]);

export type Stage =
  "access-recorded" | "data-read" | "read-by-candidate-instance" | "corroborated-suspicious-read";

export interface AccessRecord {
  eventId: string;
  at: string;
  host: string;
  kind: "access" | "handle-request" | "share-object-check";
  mask?: string;
  rights: string[];
  classes: AccessClass[];
  objectType?: string;
  /** read-or-listing on an object evidenced as a file at that time. */
  dataRead: boolean;
  fileEvidence: string;
  account?: string;
  sid?: string;
  pid?: number;
  image?: string;
  sessionId?: string;
  instance: {
    state: "candidate" | "ambiguous" | "not-established";
    reason: string;
    startEventId?: string;
    processGuid?: string;
  };
  session: {
    state: "candidate" | "ambiguous" | "not-established";
    reason: string;
    logonEventId?: string;
    logonType?: number;
    sourceAddress?: string;
  };
  corroboration: string[];
  pivots: { archiveCreates: string[]; connections: string[]; note: string };
  deletionCandidates: string[];
}

export interface ObjectAccess {
  path: string;
  host: string;
  accesses: AccessRecord[];
  accessesTotal: number;
  stage: Stage;
  stageReason: string;
  evidence: Record<Stage, string[]>;
}

export interface LocationAccess {
  location: SensitiveLocation;
  objects: ObjectAccess[];
  objectsTotal: number;
  hostsRead: { host: string; accessRows: number; accessRowsUnread: number; span?: [string, string] }[];
  note: string;
}

export interface CollectionShape {
  host: string;
  instance: string;
  image?: string;
  objects: number;
  from: string;
  to: string;
  eventIds: string[];
  state: "shape" | "indeterminate";
  note: string;
}

export interface SensitiveAccess {
  locations: LocationAccess[];
  collections: CollectionShape[];
  hosts: {
    host: string;
    accessRows: number;
    accessRowsUnread: number;
    span?: [string, string];
    processStarts: number;
    logons: number;
    findings: number;
    note: string;
  }[];
  generated: string;
}

interface AccessRow {
  e: ForensicEvent;
  at: number;
  key: string;
  classes: AccessClass[];
  kind: AccessRecord["kind"];
}

/** Per host: the object-access rows in event-time order, up to the bound. */
function accessRowsByHost(
  events: readonly ForensicEvent[],
): Map<string, { rows: AccessRow[]; unread: number; total: number }> {
  const out = new Map<string, { rows: AccessRow[]; unread: number; total: number }>();
  for (const e of events) {
    const ev = e.canonical?.event;
    const f = e.canonical?.file;
    if (!ev || !f?.access || !e.asset) continue;
    const kind: AccessRecord["kind"] | null =
      ev.category === "file" && ev.type === "access"
        ? "access"
        : ev.category === "file" && ev.type === "handle-request"
          ? "handle-request"
          : ev.category === "network" && ev.type === "share-object-check"
            ? "share-object-check"
            : null;
    if (!kind) continue;
    const at = ms(e.timestamp);
    const n = normaliseWinPath(f.path);
    if (at === null || !n || !("key" in n)) continue;
    const k = hostKey(e.asset);
    const b = out.get(k) ?? out.set(k, { rows: [], unread: 0, total: 0 }).get(k)!;
    b.total += 1;
    b.rows.push({ e, at, key: n.key, classes: f.access.classes as AccessClass[], kind });
  }
  for (const b of out.values()) {
    b.rows.sort((x, y) => x.at - y.at);
    if (b.rows.length > ACCESS_ROWS_PER_HOST_MAX) {
      b.unread = b.rows.length - ACCESS_ROWS_PER_HOST_MAX;
      b.rows.length = ACCESS_ROWS_PER_HOST_MAX;
    }
  }
  return out;
}

const underLocation = (loc: SensitiveLocation, key: string): boolean =>
  loc.kind === "file" ? key === loc.key : key === loc.key || key.startsWith(`${loc.key}\\`);

function pivotsFor(idx: HostIndex, guid: string | undefined, at: number): AccessRecord["pivots"] {
  if (!guid)
    return {
      archiveCreates: [],
      connections: [],
      note: "no process GUID on the candidate instance — no pivot can be drawn",
    };
  const later = (idx.byGuid.get(guid) ?? []).filter((r) => {
    const t = ms(r.timestamp);
    return t !== null && t > at && t - at <= PIVOT_WINDOW_MS;
  });
  const archiveCreates = later
    .filter(
      (r) =>
        r.canonical?.event?.category === "file" &&
        r.canonical.event.type === "create" &&
        ARCHIVE.test(r.canonical.file?.path ?? ""),
    )
    .map((r) => r.id);
  const connections = later
    .filter((r) => r.canonical?.event?.category === "network" && r.canonical.event.type === "connection")
    .map((r) => r.id);
  return {
    archiveCreates: archiveCreates.slice(0, NAMED_MAX),
    connections: connections.slice(0, NAMED_MAX),
    note: `rows by the same process GUID within 60 minutes after the access: ${archiveCreates.length} archive-path file create(s), ${connections.length} network connection(s) — subsequent activity by that process, not staging or transfer`,
  };
}

function deletionCandidates(rows: readonly AccessRow[], row: AccessRow): string[] {
  const f = row.e.canonical?.file?.access;
  if (!row.classes.includes("delete") || !f?.handleId) return [];
  const pid = row.e.canonical?.process?.pid;
  const session = row.e.canonical?.authentication?.sessionId;
  return rows
    .filter((r) => {
      const c = r.e.canonical;
      return (
        c?.event?.type === "object-deleted" &&
        r.at >= row.at &&
        r.at - row.at <= DELETE_WINDOW_MS &&
        c.file?.access?.handleId === f.handleId &&
        c.process?.pid === pid &&
        c.authentication?.sessionId === session
      );
    })
    .map((r) => r.e.id);
}

function record(row: AccessRow, idx: HostIndex, deletes: readonly AccessRow[]): AccessRecord {
  const c = row.e.canonical!;
  const f = c.file!;
  const pid = c.process?.pid;
  const image = c.process?.executable;
  const inst =
    row.kind === "access"
      ? instanceCandidate(idx, pid, image, row.at)
      : {
          state: "not-established" as const,
          reason: `a ${row.kind} names no exercised access; no instance is joined`,
        };
  const sess = sessionCandidate(idx, c.authentication?.sessionId, row.at);
  const fe =
    row.classes.includes("read-or-listing") && row.kind === "access"
      ? fileEvidencedAt(idx, row.key, row.at)
      : null;
  const corroboration: string[] = [];
  if (inst.state === "candidate" && inst.start && HIGH.has(inst.start.severity))
    corroboration.push(
      `the candidate instance's process row ${inst.start.eventId} is graded ${inst.start.severity}${inst.start.techniques.length ? ` (${inst.start.techniques.join(", ")})` : ""}`,
    );
  if (sess.state === "candidate" && sess.logon && HIGH.has(sess.logon.severity))
    corroboration.push(
      `the candidate session's logon ${sess.logon.eventId} is graded ${sess.logon.severity}`,
    );
  return {
    eventId: row.e.id,
    at: row.e.timestamp,
    host: row.e.asset ?? "",
    kind: row.kind,
    ...(f.access?.mask ? { mask: f.access.mask } : {}),
    rights: f.access?.rights ?? [],
    classes: row.classes,
    ...(f.access?.objectType ? { objectType: f.access.objectType } : {}),
    dataRead: fe?.state === "file",
    fileEvidence: fe
      ? fe.state === "file"
        ? `evidenced as a file by ${fe.by}`
        : `read or listing — ${fe.reason}`
      : row.kind !== "access"
        ? `${row.kind}: not an access`
        : "no read right on this record",
    ...(c.actor?.kind === "account" && c.actor.name ? { account: c.actor.name } : {}),
    ...(c.account?.id ? { sid: c.account.id } : {}),
    ...(pid !== undefined ? { pid } : {}),
    ...(image ? { image } : {}),
    ...(c.authentication?.sessionId ? { sessionId: c.authentication.sessionId } : {}),
    instance: {
      state: inst.state,
      reason: inst.reason,
      ...(inst.start
        ? { startEventId: inst.start.eventId, ...(inst.start.guid ? { processGuid: inst.start.guid } : {}) }
        : {}),
    },
    session: {
      state: sess.state,
      reason: sess.reason,
      ...(sess.logon
        ? {
            logonEventId: sess.logon.eventId,
            ...(sess.logon.logonType !== undefined ? { logonType: sess.logon.logonType } : {}),
            ...(sess.logon.sourceAddress ? { sourceAddress: sess.logon.sourceAddress } : {}),
          }
        : {}),
    },
    corroboration,
    pivots:
      fe?.state === "file" && inst.state === "candidate"
        ? pivotsFor(idx, inst.start?.guid, row.at)
        : {
            archiveCreates: [],
            connections: [],
            note: "no pivot: the access is not a data read by a candidate instance",
          },
    deletionCandidates: deletionCandidates(deletes, row),
  };
}

function objectOf(host: string, path: string, records: AccessRecord[], total: number): ObjectAccess {
  const reads = records.filter((r) => r.dataRead);
  const byInstance = reads.filter((r) => r.instance.state === "candidate");
  const corroborated = byInstance.filter((r) => r.corroboration.length);
  const evidence: Record<Stage, string[]> = {
    "access-recorded": records.map((r) => r.eventId),
    "data-read": reads.map((r) => r.eventId),
    "read-by-candidate-instance": byInstance.map((r) => r.eventId),
    "corroborated-suspicious-read": corroborated.map((r) => r.eventId),
  };
  let stage: Stage = "access-recorded";
  let stageReason: string;
  if (corroborated.length) {
    stage = "corroborated-suspicious-read";
    stageReason = `${corroborated.length} data read(s) by a candidate instance whose own rows are graded High or above`;
  } else if (byInstance.length) {
    stage = "read-by-candidate-instance";
    stageReason =
      "a data read joined to a candidate instance; nothing in that instance's own rows or its session's logon is graded High — the process is not shown suspicious by the case";
  } else if (reads.length) {
    stage = "data-read";
    stageReason = `${reads.length} data read(s); the process instance is ${[...new Set(reads.map((r) => r.instance.state))].join(" / ")} (${reads[0].instance.reason})`;
  } else {
    const first = records[0];
    stageReason = records.some((r) => r.classes.includes("read-or-listing"))
      ? `read or listing only — ${records.find((r) => r.classes.includes("read-or-listing"))!.fileEvidence}`
      : `no read right exercised (${[...new Set(records.flatMap((r) => r.classes))].join(", ") || first.kind})`;
  }
  return {
    path,
    host,
    accesses: records.slice(0, NAMED_MAX),
    accessesTotal: total,
    stage,
    stageReason,
    evidence,
  };
}

function collections(
  rowsByHost: ReadonlyMap<string, { rows: AccessRow[]; unread: number }>,
  hosts: ReadonlyMap<string, HostIndex>,
): CollectionShape[] {
  const out: CollectionShape[] = [];
  for (const [hk, b] of rowsByHost) {
    const idx = hosts.get(hk);
    if (!idx) continue;
    const byInstance = new Map<
      string,
      { image?: string; reads: { at: number; key: string; id: string }[] }
    >();
    for (const row of b.rows) {
      if (row.kind !== "access" || !row.classes.includes("read-or-listing")) continue;
      if (fileEvidencedAt(idx, row.key, row.at).state !== "file") continue;
      const c = row.e.canonical!;
      const inst = instanceCandidate(idx, c.process?.pid, c.process?.executable, row.at);
      const key =
        inst.start?.guid ?? inst.start?.eventId ?? `${c.process?.pid ?? "?"}|${c.process?.executable ?? "?"}`;
      const g =
        byInstance.get(key) ??
        byInstance
          .set(key, { ...(c.process?.executable ? { image: c.process.executable } : {}), reads: [] })
          .get(key)!;
      g.reads.push({ at: row.at, key: row.key, id: row.e.id });
    }
    for (const [instance, g] of byInstance) {
      let best: { from: number; to: number; ids: string[]; n: number } | null = null;
      for (let i = 0; i < g.reads.length; i++) {
        const seen = new Set<string>();
        const ids: string[] = [];
        let j = i;
        for (; j < g.reads.length && g.reads[j].at - g.reads[i].at <= COLLECTION_WINDOW_MS; j++) {
          if (!seen.has(g.reads[j].key)) ids.push(g.reads[j].id);
          seen.add(g.reads[j].key);
        }
        if (seen.size >= COLLECTION_OBJECTS && (!best || seen.size > best.n))
          best = { from: g.reads[i].at, to: g.reads[j - 1].at, ids, n: seen.size };
      }
      if (!best) continue;
      const truncated =
        b.unread > 0 && b.rows.length && best.to >= b.rows[b.rows.length - 1].at - COLLECTION_WINDOW_MS;
      out.push({
        host: idx.host,
        instance,
        ...(g.image ? { image: g.image } : {}),
        objects: best.n,
        from: new Date(best.from).toISOString(),
        to: new Date(best.to).toISOString(),
        eventIds: best.ids.slice(0, NAMED_MAX),
        state: truncated ? "indeterminate" : "shape",
        note: truncated
          ? "indeterminate (truncated read): rows past the host bound overlap this window"
          : `reads ${best.n} distinct file objects in ${Math.round((best.to - best.from) / 60_000)} minute(s): an indexer / backup / AV shape or a collection — the record does not say which; the process row's own grade stands`,
      });
    }
  }
  return out.sort((a, b) => b.objects - a.objects || a.host.localeCompare(b.host)).slice(0, NAMED_MAX);
}

/** The reading over the forensic timeline for the declared locations. Pure; no AI. */
export function sensitiveAccess(
  state: InvestigationState,
  locations: readonly SensitiveLocation[],
  now: string = new Date().toISOString(),
): SensitiveAccess {
  const events = state.forensicTimeline;
  const hosts = indexHosts(events);
  const rowsByHost = accessRowsByHost(events);
  const deletesByHost = new Map<string, AccessRow[]>();
  for (const e of events) {
    if (e.canonical?.event?.type !== "object-deleted" || !e.asset) continue;
    const at = ms(e.timestamp);
    if (at === null) continue;
    const k = hostKey(e.asset);
    const l = deletesByHost.get(k) ?? deletesByHost.set(k, []).get(k)!;
    l.push({ e, at, key: "", classes: ["delete"], kind: "access" });
  }
  const out: LocationAccess[] = locations.map((loc) => {
    const locHost = hostKey(loc.host);
    const objects = new Map<string, { host: string; path: string; records: AccessRecord[]; total: number }>();
    const hostsRead: LocationAccess["hostsRead"] = [];
    for (const [hk, b] of rowsByHost) {
      if (locHost && hk !== locHost) continue;
      const idx = hosts.get(hk)!;
      let touched = false;
      for (const row of b.rows) {
        if (!underLocation(loc, row.key)) continue;
        touched = true;
        const ok = `${hk}|${row.key}`;
        const o =
          objects.get(ok) ??
          objects
            .set(ok, { host: idx.host, path: row.e.canonical?.file?.path ?? row.key, records: [], total: 0 })
            .get(ok)!;
        o.total += 1;
        if (o.records.length < NAMED_MAX * 5) o.records.push(record(row, idx, deletesByHost.get(hk) ?? []));
      }
      if (touched || locHost)
        hostsRead.push({
          host: idx.host,
          accessRows: b.rows.length,
          accessRowsUnread: b.unread,
          ...(b.rows.length
            ? {
                span: [
                  new Date(b.rows[0].at).toISOString(),
                  new Date(b.rows[b.rows.length - 1].at).toISOString(),
                ] as [string, string],
              }
            : {}),
        });
    }
    const all = [...objects.values()].map((o) => objectOf(o.host, o.path, o.records, o.total));
    const rank: Record<Stage, number> = {
      "corroborated-suspicious-read": 0,
      "read-by-candidate-instance": 1,
      "data-read": 2,
      "access-recorded": 3,
    };
    all.sort((a, b) => rank[a.stage] - rank[b.stage] || a.path.localeCompare(b.path));
    const note = all.length
      ? `${all.length} object(s) with access rows under this location`
      : "no object-access row under this location in the case — no conclusion is available for this location and interval (audit policy, SACLs and collection continuity are not in the case)";
    return {
      location: loc,
      objects: all.slice(0, OBJECTS_PER_LOCATION_MAX),
      objectsTotal: all.length,
      hostsRead,
      note,
    };
  });
  const hostRows = [...hosts.values()]
    .map((idx) => {
      const b = rowsByHost.get(hostKey(idx.host));
      return {
        host: idx.host,
        accessRows: b?.rows.length ?? 0,
        accessRowsUnread: b?.unread ?? 0,
        ...(b?.rows.length
          ? {
              span: [
                new Date(b.rows[0].at).toISOString(),
                new Date(b.rows[b.rows.length - 1].at).toISOString(),
              ] as [string, string],
            }
          : {}),
        processStarts: idx.startsTotal,
        logons: [...idx.logons.values()].reduce((n, l) => n + l.length, 0),
        findings: idx.findings,
        note: b?.rows.length
          ? "object-access rows observed on this host — context only, not coverage of any location"
          : "no object-access row on this host — absence of access rows establishes nothing",
      };
    })
    .filter((h) => h.accessRows || locations.some((l) => hostKey(l.host) === hostKey(h.host)))
    .sort((a, b) => a.host.localeCompare(b.host))
    .slice(0, NAMED_MAX * 5);
  return { locations: out, collections: collections(rowsByHost, hosts), hosts: hostRows, generated: now };
}
