// The join inside one upload: an LSQuarantineEventsV2 record against the file-attribute records
// carrying the same event UUID, on the same host partition (#933 item 7, join half — #1037).
// Nothing else joins — not a basename, not a URL's last segment, not a time.
//
// What the join establishes: which path(s) carry the identifier the database record names, and
// per fact whether the two records agree — the agent (the attribute keeps a name, the database a
// name and a bundle id), the time (Unix hex on the file, the record's own encoding in the
// database; a band, never a verdict — the attribute is written when the file is created, the
// record when the agent logs the event) and the download flag. Several files with one identifier
// is said as "a copy, or an archive's extracted members; the records do not say which". A UUID
// whose database records disagree (#1009's variants), a file with two attribute values, and a
// named host beside an unnamed record join nothing, and both sides say why.

import { createCanonicalEvent } from "./canonicalEvent.js";
import type { QuarantineLocalFile, QuarantineTimeAgreement } from "./canonicalQuarantine.js";
import { gapBand } from "./dnsConnJoin.js";
import { identityMark, keyDigest, packTags } from "./recordIdentity.js";
import type { MappedEvent } from "./siemImport.js";
import {
  attributeLocator,
  mapAttributeOverflow,
  mapAttributeRow,
  timeWords,
  type AttributeJoin,
  type AttributeJoinFacts,
  type AttributeObservation,
} from "./quarantineAttribute.js";
import { type QuarantineRow } from "./quarantineRecord.js";

/** Attribute records retained per upload; the rest are counted into one overflow row. */
export const QUARANTINE_ATTRIBUTES_MAX = 65_536;
/** Files tracked per identifier; past it the count is "at least". */
export const FILES_PER_ID_MAX = 256;
const FILES_SHOWN_MAX = 3;
const DESCRIPTION_MAX = 600;
const UNJOINED_TAG = " [local file: not in this record — joined by the event identifier]";
const SHARED_MARK = " [event identifier shared by records with different facts]";

export interface AttributeObservations {
  records: AttributeObservation[];
  overflow: number;
}

export function emptyAttributeObservations(): AttributeObservations {
  return { records: [], overflow: 0 };
}

export function addAttribute(store: AttributeObservations, a: AttributeObservation): void {
  if (store.records.length < QUARANTINE_ATTRIBUTES_MAX) store.records.push(a);
  else store.overflow += 1;
}

// ───────────────────────────── agreement ─────────────────────────────

const S = 1000;

function agentAgreement(markAgent: string, row: QuarantineRow): "agrees" | "differs" | "not compared" {
  const { agent, bundleId } = row.envelope;
  if (!agent && !bundleId) return "not compared";
  const a = markAgent.trim().toLowerCase();
  return a === (agent ?? "").trim().toLowerCase() || a === (bundleId ?? "").trim().toLowerCase()
    ? "agrees"
    : "differs";
}

function timeAgreement(markIso: string, row: QuarantineRow): QuarantineTimeAgreement {
  const db = Date.parse(row.timestamp);
  const mark = Date.parse(markIso);
  if (row.envelope.timeEncoding === "unreadable" || !Number.isFinite(db))
    return { state: "not compared", reason: "the database time is not readable" };
  if (!Number.isFinite(mark)) return { state: "not compared", reason: "the attribute time is not readable" };
  const diff = mark - db;
  const encodings = {
    attributeEncoding: "unix-hex-seconds" as const,
    databaseEncoding: row.envelope.timeEncoding,
  };
  if (Math.abs(diff) < S) return { state: "same second", ...encodings };
  return {
    state: diff > 0 ? "marked after the record" : "marked before the record",
    band: gapBand(Math.abs(diff)),
    ...encodings,
  };
}

const agentWords = (row: QuarantineRow): string =>
  [row.envelope.agent, row.envelope.bundleId ? `(${row.envelope.bundleId})` : ""].filter(Boolean).join(" ");

// ───────────────────────────── the join ─────────────────────────────

interface Partition {
  /** UUID → database rows (variants included) */
  db: Map<string, QuarantineRow[]>;
  /** UUID → distinct files (deduplicated by exact path + raw value) */
  files: Map<string, AttributeObservation[]>;
  /** UUIDs carried only by files with two attribute values — an ambiguity, never a join. */
  conflictedIds: Set<string>;
}

const hostKey = (host: string | undefined): string => host ?? "";
const dbHost = (r: QuarantineRow): string | undefined =>
  r.envelope.host && "name" in r.envelope.host ? r.envelope.host.name : undefined;

export interface JoinedRows {
  db: Map<QuarantineRow, QuarantineRow>;
  attributes: MappedEvent[];
}

/**
 * Every database row rewritten with what the attribute records establish (a new object per row;
 * the map gives the original → joined pairing), and every attribute row. Overflow rows included.
 */
export function joinQuarantine(dbRows: readonly QuarantineRow[], store: AttributeObservations): JoinedRows {
  const partitions = new Map<string, Partition>();
  const part = (host: string | undefined): Partition => {
    const k = hostKey(host);
    return (
      partitions.get(k) ??
      partitions.set(k, { db: new Map(), files: new Map(), conflictedIds: new Set() }).get(k)!
    );
  };
  for (const r of dbRows) {
    if (!r.eventId || r.aggKey.endsWith("|overflow")) continue;
    const p = part(dbHost(r));
    (p.db.get(r.eventId) ?? p.db.set(r.eventId, []).get(r.eventId)!).push(r);
  }
  // Identical attribute records are one file; a path with two different values is an ambiguity.
  const valuesByFile = new Map<string, Set<string>>();
  const conflicted = new Set<string>();
  const distinct: AttributeObservation[] = [];
  for (const a of store.records) {
    if (a.path === undefined || a.pathState) {
      distinct.push(a);
      continue;
    }
    const fileKey = `${hostKey(a.host)}|${a.path}`;
    const values = valuesByFile.get(fileKey) ?? valuesByFile.set(fileKey, new Set()).get(fileKey)!;
    if (values.has(a.raw)) continue;
    values.add(a.raw);
    if (values.size > 1) conflicted.add(fileKey);
    distinct.push(a);
  }
  for (const a of distinct) {
    const id = a.mark?.eventId;
    if (!id || a.path === undefined || a.pathState) continue;
    const p = part(a.host);
    if (conflicted.has(`${hostKey(a.host)}|${a.path}`)) p.conflictedIds.add(id);
    else (p.files.get(id) ?? p.files.set(id, []).get(id)!).push(a);
  }

  const out: JoinedRows = { db: new Map(), attributes: [] };
  // An upload with no attribute records leaves every database row as it is: "not in this record —
  // joined by the event identifier" is then the whole truth, and the common dump stays unmarked.
  const anyAttributes = store.records.length > 0 || store.overflow > 0;
  for (const r of dbRows) out.db.set(r, anyAttributes ? rewriteDbRow(r, partitions) : r);
  for (const a of distinct)
    out.attributes.push(mapAttributeRow(a, attributeFacts(a, partitions, conflicted)));
  if (store.overflow) out.attributes.push(mapAttributeOverflow(store.overflow));
  return out;
}

function variants(rows: readonly QuarantineRow[] | undefined): number {
  return new Set((rows ?? []).map((r) => r.factsDigest)).size;
}

function attributeFacts(
  a: AttributeObservation,
  partitions: Map<string, Partition>,
  conflicted: Set<string>,
): AttributeJoinFacts {
  const id = a.mark?.eventId;
  if (!id) return { join: { state: "no identifier" } };
  if (a.path !== undefined && !a.pathState && conflicted.has(`${hostKey(a.host)}|${a.path}`))
    return { join: { state: "two attribute values for one path" } };
  const rows = partitions.get(hostKey(a.host))?.db.get(id);
  if (!rows?.length) return { join: { state: "no database record in this upload" } };
  if (variants(rows) > 1) return { join: { state: "database records disagree" } };
  const row = rows[0];
  const e = row.envelope;
  const join: AttributeJoin = {
    state: "joined",
    agentAgreement: agentAgreement(a.mark!.agent, row),
    timeAgreement: timeAgreement(a.mark!.time.iso, row),
    downloadFlag: a.mark!.flags.named.includes("download"),
  };
  const words = [
    e.dataUrl ? `data url ${showUrl(e.dataUrl)}` : "",
    e.originUrl ? `origin ${showUrl(e.originUrl)}` : "",
    e.agent || e.bundleId ? `agent ${agentWords(row)}` : "",
  ]
    .filter(Boolean)
    .join("; ");
  return {
    join,
    download: {
      kind: e.kind,
      ...(e.agent ? { agent: e.agent } : {}),
      ...(e.bundleId ? { bundleId: e.bundleId } : {}),
      ...(e.dataUrl ? { dataUrl: e.dataUrl } : {}),
      ...(e.originUrl ? { originUrl: e.originUrl } : {}),
      ...(e.originTitle ? { originTitle: e.originTitle } : {}),
    },
    databaseLocator: row.canonicalInput?.evidence.rawRecords[0]?.locator ?? row.aggKey,
    downloadWords: words,
  };
}

const URL_SHOWN_MAX = 120;
const showUrl = (u: string): string => {
  const shown = u.replace(/\[/g, "(").replace(/\]/g, ")").replace(/[ --]/g, " ");
  return shown.length > URL_SHOWN_MAX ? `${shown.slice(0, URL_SHOWN_MAX - 1)}…` : shown;
};

// ───────────────────────────── the database row, rewritten ─────────────────────────────

function localFileOf(r: QuarantineRow, partitions: Map<string, Partition>): QuarantineLocalFile {
  if (!r.eventId || r.aggKey.endsWith("|overflow")) return "not in this record";
  const p = partitions.get(hostKey(dbHost(r)));
  if (variants(p?.db.get(r.eventId)) > 1)
    return { state: "database records with this identifier disagree — not joined" };
  const files = p?.files.get(r.eventId) ?? [];
  if (!files.length)
    return p?.conflictedIds.has(r.eventId)
      ? { state: "the file carries two attribute values — not joined" }
      : { state: "no attribute record carries this identifier in this upload" };
  const paths = files.map((f) => f.path!).sort();
  return {
    state: "joined",
    paths: paths.slice(0, FILES_PER_ID_MAX),
    count: Math.min(paths.length, FILES_PER_ID_MAX),
    ...(paths.length > FILES_PER_ID_MAX ? { atLeast: true } : {}),
  };
}

function localFileTags(lf: QuarantineLocalFile): string[] {
  if (lf === "not in this record") return [];
  if (lf.state === "no attribute record carries this identifier in this upload")
    return ["local file: not in this record — no attribute record carries this identifier in this upload"];
  if (lf.state === "database records with this identifier disagree — not joined")
    return ["local file: database records with this identifier disagree — not joined"];
  if (lf.state === "the file carries two attribute values — not joined")
    return [
      "local file: an attribute record carries this identifier, but the file carries two attribute values — not joined",
    ];
  const shown = lf.paths
    .slice(0, FILES_SHOWN_MAX)
    .map((p) => showPath(p))
    .join(", ");
  if (lf.count === 1 && !lf.atLeast)
    return [`local file: ${shown} — the file's quarantine attribute carries this event identifier`];
  const count = lf.atLeast ? `${FILES_PER_ID_MAX}+` : String(lf.count);
  const more = lf.atLeast
    ? " (and more)"
    : lf.count > FILES_SHOWN_MAX
      ? ` (+${lf.count - FILES_SHOWN_MAX} more)`
      : "";
  return [
    `local files: ${count} — ${shown}${more} — the same identifier on several files: a copy, or an archive's extracted members; the records do not say which`,
  ];
}

const PATH_SHOWN_MAX = 200;
const showPath = (p: string): string => {
  const shown = p.replace(/\[/g, "(").replace(/\]/g, ")").replace(/[ --]/g, " ");
  return shown.length > PATH_SHOWN_MAX ? `${shown.slice(0, PATH_SHOWN_MAX - 1)}…` : shown;
};

function rewriteDbRow(r: QuarantineRow, partitions: Map<string, Partition>): QuarantineRow {
  // An overflow row (#1009's variant bound) names a fold, never a record: nothing to join.
  if (r.aggKey.endsWith("|overflow") || !r.canonicalInput) return r;
  const finalLf = localFileOf(r, partitions);
  const finalTags = localFileTags(finalLf);
  // Agreement against the ONE joined file: with several files each has its own mark; the
  // attribute rows say theirs, the database row says the files only.
  const files =
    typeof finalLf === "object" && finalLf.state === "joined"
      ? partitions.get(hostKey(dbHost(r)))!.files.get(r.eventId!)!
      : [];
  const one = files.length === 1 ? files[0] : undefined;
  const agreement = one
    ? {
        agentAgreement: agentAgreement(one.mark!.agent, r),
        timeAgreement: timeAgreement(one.mark!.time.iso, r),
        downloadFlag: one.mark!.flags.named.includes("download"),
      }
    : {};
  if (agreement.agentAgreement === "agrees") finalTags.push("agent agrees");
  if (agreement.agentAgreement === "differs")
    finalTags.push(`agent differs: attribute ${one!.mark!.agent}; database ${agentWords(r)}`);
  if (agreement.timeAgreement) finalTags.push(timeWords(agreement.timeAgreement));
  if (agreement.downloadFlag === true) finalTags.push("download flag set");
  if (agreement.downloadFlag === false) finalTags.push("download flag not set — sandbox mark only");
  // The partition is said only where it carried a join: an unnamed host beside a joined file.
  const hostTag = !dbHost(r) && one ? ["host not named in the records"] : [];

  const envelope: QuarantineRow["envelope"] = { ...r.envelope, localFile: finalLf, ...agreement };
  const joinDigest = keyDigest(JSON.stringify({ localFile: finalLf, ...agreement }));
  const aggKey = `${r.aggKey}|join:${joinDigest}`;
  const mark = identityMark(aggKey);
  // The words: the unjoined tag out, the join tags in, packed to the width, re-marked for the new key.
  let body = r.description.replace(/ #[A-Za-z0-9_-]{22}$/, "");
  const shared = body.endsWith(SHARED_MARK);
  if (shared) body = body.slice(0, -SHARED_MARK.length);
  body = body.replace(UNJOINED_TAG, "");
  const room = DESCRIPTION_MAX - body.length - mark.length - (shared ? SHARED_MARK.length : 0);
  const description = `${body}${packTags([...finalTags, ...hostTag], Math.max(0, room))}${shared ? SHARED_MARK : ""}${mark}`;
  const input = r.canonicalInput;
  const canonical = input
    ? createCanonicalEvent({
        ...input,
        quarantine: envelope,
        evidence: {
          rawRecords: [
            ...input.evidence.rawRecords,
            ...files.map((f) => ({ source: "macos-quarantine-attribute", locator: attributeLocator(f) })),
          ],
        },
        locatorMap: {
          ...(input.locatorMap ?? {}),
          ...(files.length ? { "quarantine.localFile": attributeLocator(files[0]) } : {}),
          ...(one
            ? Object.fromEntries(
                ["agentAgreement", "timeAgreement", "downloadFlag"].map((leaf) => [
                  `quarantine.${leaf}.attribute`,
                  attributeLocator(one),
                ]),
              )
            : {}),
        },
      })
    : r.canonical;
  return { ...r, description, aggKey, envelope, canonical };
}
