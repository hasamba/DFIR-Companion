// SRUM network-usage attribution (#909 item 9).
//
// SRUM is the closest thing Windows keeps to a per-application network meter: for roughly 30 to 60
// days it records, per application and per user, how many bytes went out and came in on which
// interface, in one-hour intervals. On a case where the proxy logs are gone and the EDR was not
// installed, it can be the only record that 4 GB left a host at all.
//
// The importer was rendering it as a sentence — "sent 4000000 / recv 512 bytes" — and grouping by
// executable. That throws away the three things that make the artifact usable: WHICH USER, WHICH
// INTERFACE, and WHICH INTERVAL. Without the user you cannot say whose session moved the data;
// without the interface you cannot tell a VPN from the LAN; without the interval you cannot add two
// rows together without risking double-counting.
//
// ─────────────────────────── WHAT SRUM DOES NOT TELL YOU ───────────────────────────
//
// This is the part that must travel with every number this module produces:
//
//   • It does not identify the REMOTE DESTINATION. A byte counter has no address in it.
//   • It does not identify WHAT was transferred. No filenames, no content.
//   • It therefore cannot show exfiltration. It shows volume, by application, over an interval.
//
// A large outbound total is a lead worth pulling, and it is not a finding on its own — a backup
// client, a cloud sync and an OS update all produce exactly the same shape.
//
// ─────────────────────────── NOT DOUBLE-COUNTING ───────────────────────────
//
// Two things cause the same bytes to be added twice. Re-importing the same export is the obvious
// one. The subtler one is that SRUM rows are SNAPSHOTS: consecutive rows for one application can
// describe overlapping intervals, and adding them produces a total that never happened. Every row
// carries its own record id, and totals are computed over DEDUPLICATED rows keyed on that id plus
// the interval — so a re-import contributes nothing, and an overlapping snapshot is counted once.

import type { Severity } from "./stateTypes.js";

/** One SRUM network-usage row, with the attribution the artifact actually carries. */
export interface SrumRow {
  /** The record id SRUM assigned. The primary defence against counting a row twice. */
  id: string;
  app: string; // the executable SRUM attributes the traffic to
  user: string; // resolved user name, when the export carried one
  sid: string; // the SID, which survives when the name does not
  interfaceId: string; // interface LUID / profile — a VPN and the LAN are not the same path
  timestamp: string; // ISO; the interval this row describes ends here
  bytesSent: number;
  bytesReceived: number;
}

/** A total for one application, user and interface, over deduplicated rows. */
export interface SrumTotal {
  app: string;
  user: string;
  sid: string;
  interfaceId: string;
  bytesSent: number;
  bytesReceived: number;
  rows: number; // how many DISTINCT rows contributed
  first: string;
  last: string;
  /** The record ids that produced this total, so a finding can point at its evidence. */
  rowIds: string[];
}

function num(v: unknown): number {
  const n = Number(String(v ?? "").replace(/[^0-9.-]/g, ""));
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

/**
 * Read one row.
 *
 * The column names are SrumECmd's. `BytesRecvd` is the real spelling — the previous profile matched
 * on `BytesReceived`, which SrumECmd does not emit, so it never recognised a real export.
 */
export function readSrumRow(get: (key: string) => unknown): SrumRow | null {
  const first = (...keys: string[]): string => {
    for (const k of keys) {
      const v = String(get(k) ?? "").trim();
      if (v && v !== "-") return v;
    }
    return "";
  };
  const app = first("ExeInfo", "AppId", "Application", "ExeInfoDescription");
  if (!app) return null;
  return {
    id: first("Id", "RecordId", "AutoIncId"),
    app,
    user: first("UserName", "User"),
    sid: first("Sid", "UserId", "SidType"),
    interfaceId: first("InterfaceLuid", "L2ProfileId", "InterfaceType", "Interface"),
    timestamp: first("Timestamp", "EventTimestamp"),
    bytesSent: num(get("BytesSent")),
    bytesReceived: num(get("BytesRecvd") ?? get("BytesReceived")),
  };
}

/**
 * Total the rows, per application AND user AND interface, counting each distinct row once.
 *
 * Deduplication is on the record id where the export carries one, and on the full attribution plus
 * the interval where it does not. A re-imported export therefore contributes nothing, and two
 * snapshots describing the same interval are counted once rather than summed into a total that
 * never happened.
 */
export function totalSrum(rows: readonly SrumRow[]): SrumTotal[] {
  const seen = new Set<string>();
  const byKey = new Map<string, SrumTotal>();

  for (const r of rows) {
    const dedupKey = r.id
      ? `id:${r.id}`
      : `k:${r.app}|${r.sid || r.user}|${r.interfaceId}|${r.timestamp}|${r.bytesSent}|${r.bytesReceived}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    const key = `${r.app.toLowerCase()}|${(r.sid || r.user).toLowerCase()}|${r.interfaceId}`;
    const t = byKey.get(key) ?? {
      app: r.app,
      user: r.user,
      sid: r.sid,
      interfaceId: r.interfaceId,
      bytesSent: 0,
      bytesReceived: 0,
      rows: 0,
      first: r.timestamp,
      last: r.timestamp,
      rowIds: [],
    };
    t.bytesSent += r.bytesSent;
    t.bytesReceived += r.bytesReceived;
    t.rows += 1;
    if (r.timestamp && (!t.first || r.timestamp < t.first)) t.first = r.timestamp;
    if (r.timestamp && (!t.last || r.timestamp > t.last)) t.last = r.timestamp;
    if (r.id && t.rowIds.length < 50) t.rowIds.push(r.id);
    byKey.set(key, t);
  }

  return [...byKey.values()].sort((a, b) => b.bytesSent - a.bytesSent);
}

/** Bytes rendered so a human can read them, with the exact figure kept alongside. */
export function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** Outbound volume above which a total is worth an analyst's attention at all. */
export const NOTABLE_SENT_BYTES = 100 * 1024 * 1024; // 100 MB

export interface SrumSignal {
  severity: Severity;
  mitre: string[];
  note: string;
}

/**
 * Grade a total.
 *
 * `stagingNearby` says the case already holds archive-staging evidence for this host in the same
 * window. That pairing is the reason SRUM is worth grading at all: volume alone is a backup client,
 * and volume shortly after something built an archive is a lead. Even then it is Low, and the note
 * says what SRUM cannot show — because the number is going into a report.
 */
export function srumSignal(t: SrumTotal, stagingNearby = false): SrumSignal | null {
  if (t.bytesSent < NOTABLE_SENT_BYTES) return null;

  const who = t.user || t.sid || "an unrecorded user";
  const limits =
    "SRUM counts bytes per application; it records no remote address, no filenames and no content, " +
    "so it cannot show where this went or what it was, and it does not establish exfiltration.";

  if (!stagingNearby) {
    return {
      severity: "Info",
      mitre: [],
      note:
        `${humanBytes(t.bytesSent)} sent by ${t.app} as ${who} over ${t.rows} recorded interval(s). ` +
        `Backup clients, cloud sync and OS updates produce this same shape. ${limits}`,
    };
  }

  return {
    severity: "Low",
    mitre: ["T1041"],
    note:
      `${humanBytes(t.bytesSent)} sent by ${t.app} as ${who} over ${t.rows} recorded interval(s), ` +
      `and this host has archive-staging evidence in the same window. The SEQUENCE is the lead, not ` +
      `the volume. ${limits}`,
  };
}
