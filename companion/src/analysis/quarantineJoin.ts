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
// whose database records disagree (#1009's variants), a file with two attribute values, a record
// whose path or host is not established, and a named host beside an unnamed record join nothing,
// and both sides say why. Every list is bounded while it is built: FILES_PER_ID_MAX files are
// tracked per identifier and the rest counted; LOCATORS_MAX attribute records are named in a
// database row's provenance; variants are counted once per identifier.

import { createCanonicalEvent } from "./canonicalEvent.js";
import type { QuarantineLocalFile, QuarantineTimeAgreement } from "./canonicalQuarantine.js";
import { gapBand } from "./dnsConnJoin.js";
import { breakHashRuns, identityMark, keyDigest, packTags, showToken } from "./recordIdentity.js";
import type { MappedEvent } from "./siemImport.js";
import {
  attributeLocator,
  flagTags,
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
/** Attribute records named in a joined database row's provenance. */
const LOCATORS_MAX = 8;
const FILES_SHOWN_MAX = 3;
const DESCRIPTION_MAX = 600;
const URL_SHOWN_MAX = 120;
const PATH_SHOWN_MAX = 200;
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

/** The flag word as the attribute has it: the download bit, and whether the word is exactly the sandbox bit. */
function flagsOf(a: AttributeObservation): Pick<AttributeJoin, "downloadFlag" | "sandboxOnly"> {
  const f = a.mark!.flags;
  const downloadFlag = f.named.includes("download");
  const sandboxOnly = !downloadFlag && f.named.length === 1 && f.named[0] === "sandbox" && !f.unnamed;
  return { downloadFlag, ...(sandboxOnly ? { sandboxOnly } : {}) };
}

const agentWords = (row: QuarantineRow): string =>
  [row.envelope.agent, row.envelope.bundleId ? `(${row.envelope.bundleId})` : ""].filter(Boolean).join(" ");

const show = (v: string, max: number): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};

// ───────────────────────────── partitions ─────────────────────────────

interface IdFiles {
  /** Distinct files carrying the identifier, in insertion order; at most FILES_PER_ID_MAX. */
  files: AttributeObservation[];
  /** Files past the bound — counted, never listed. */
  more: number;
}

interface DbGroup {
  rows: QuarantineRow[];
  /** Distinct fact sets among the rows — more than one is #1009's disagreement. */
  variants: number;
}

interface Partition {
  db: Map<string, DbGroup>;
  files: Map<string, IdFiles>;
  /** UUIDs carried only by files with two attribute values — an ambiguity, never a join. */
  conflictedIds: Set<string>;
}

/** The partition key: a hostname case-folded (DNS names are), or "" for records that name none. */
const hostKey = (host: string | undefined): string => (host ?? "").trim().toLowerCase();
const dbHost = (r: QuarantineRow): string | undefined =>
  r.envelope.host && "name" in r.envelope.host ? r.envelope.host.name : undefined;
const dbHostAmbiguous = (r: QuarantineRow): boolean =>
  !!r.envelope.host && "state" in r.envelope.host && r.envelope.host.state === "2 values in this record";
const dbLocator = (r: QuarantineRow): string => r.canonicalInput?.evidence.rawRecords[0]?.locator ?? r.aggKey;

/** A file the join can name: one path, not clipped, one host. */
const fileEstablished = (a: AttributeObservation): boolean =>
  a.path !== undefined && !a.pathState && !a.hostState;

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
  const digests = new Map<string, Set<string>>();
  for (const r of dbRows) {
    if (!r.eventId || r.aggKey.endsWith("|overflow") || dbHostAmbiguous(r)) continue;
    const p = part(dbHost(r));
    const g = p.db.get(r.eventId) ?? p.db.set(r.eventId, { rows: [], variants: 0 }).get(r.eventId)!;
    g.rows.push(r);
    const key = `${hostKey(dbHost(r))}|${r.eventId}`;
    const d = digests.get(key) ?? digests.set(key, new Set()).get(key)!;
    d.add(r.factsDigest);
    g.variants = d.size;
  }
  // Identical attribute records are one observation (every retained fact equal); a path with two
  // different attribute values is an ambiguity, never two files.
  const seenExact = new Set<string>();
  const valuesByFile = new Map<string, Set<string>>();
  const conflicted = new Set<string>();
  const distinct: AttributeObservation[] = [];
  for (const a of store.records) {
    if (!fileEstablished(a)) {
      distinct.push(a);
      continue;
    }
    const fileKey = `${hostKey(a.host)}|${a.path}`;
    const exact = `${fileKey}|${a.raw}|${a.sha256 ?? ""}|${a.md5 ?? ""}|${a.size ?? ""}`;
    if (seenExact.has(exact)) continue;
    seenExact.add(exact);
    const values = valuesByFile.get(fileKey) ?? valuesByFile.set(fileKey, new Set()).get(fileKey)!;
    values.add(a.raw);
    if (values.size > 1) conflicted.add(fileKey);
    distinct.push(a);
  }
  const listed = new Set<string>();
  for (const a of distinct) {
    const id = a.mark?.eventId;
    if (!id || !fileEstablished(a)) continue;
    const p = part(a.host);
    const fileKey = `${hostKey(a.host)}|${a.path}`;
    if (conflicted.has(fileKey)) {
      p.conflictedIds.add(id);
      continue;
    }
    // One entry per file per identifier (a second hash/size reading of one file is not a second file).
    const fileId = `${fileKey}|${id}`;
    if (listed.has(fileId)) continue;
    listed.add(fileId);
    const f = p.files.get(id) ?? p.files.set(id, { files: [], more: 0 }).get(id)!;
    if (f.files.length < FILES_PER_ID_MAX) f.files.push(a);
    else f.more += 1;
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

// ───────────────────────────── the attribute row's facts ─────────────────────────────

function attributeFacts(
  a: AttributeObservation,
  partitions: Map<string, Partition>,
  conflicted: Set<string>,
): AttributeJoinFacts {
  const id = a.mark?.eventId;
  if (!id) return { join: { state: "no identifier" } };
  if (a.hostState) return { join: { state: "host not established" } };
  if (a.path === undefined || a.pathState) return { join: { state: "path not established" } };
  if (conflicted.has(`${hostKey(a.host)}|${a.path}`))
    return { join: { state: "two attribute values for one path" } };
  const group = partitions.get(hostKey(a.host))?.db.get(id);
  if (!group) return { join: { state: "no database record in this upload" } };
  if (group.variants > 1)
    return {
      join: { state: "database records disagree" },
      databaseLocators: [...new Set(group.rows.slice(0, LOCATORS_MAX).map(dbLocator))],
    };
  const row = group.rows[0];
  const e = row.envelope;
  const join: AttributeJoin = {
    state: "joined",
    agentAgreement: agentAgreement(a.mark!.agent, row),
    timeAgreement: timeAgreement(a.mark!.time.iso, row),
    ...flagsOf(a),
  };
  const words = [
    e.dataUrl ? `data url ${show(e.dataUrl, URL_SHOWN_MAX)}` : "",
    e.originUrl ? `origin ${show(e.originUrl, URL_SHOWN_MAX)}` : "",
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
    databaseLocators: [dbLocator(row)],
    downloadWords: words,
  };
}

// ───────────────────────────── the database row, rewritten ─────────────────────────────

function localFileOf(r: QuarantineRow, p: Partition | undefined): QuarantineLocalFile {
  if (!r.eventId || r.aggKey.endsWith("|overflow")) return "not in this record";
  if (dbHostAmbiguous(r)) return { state: "host not established — not joined" };
  const group = p?.db.get(r.eventId);
  if ((group?.variants ?? 0) > 1)
    return { state: "database records with this identifier disagree — not joined" };
  const f = p?.files.get(r.eventId);
  if (!f?.files.length)
    return p?.conflictedIds.has(r.eventId)
      ? { state: "the file carries two attribute values — not joined" }
      : { state: "no attribute record carries this identifier in this upload" };
  const paths = f.files.map((x) => x.path!).sort();
  return {
    state: "joined",
    paths,
    count: paths.length,
    ...(f.more ? { atLeast: true } : {}),
  };
}

function localFileTags(lf: QuarantineLocalFile): string[] {
  if (lf === "not in this record") return [];
  if (lf.state !== "joined") {
    const words: Record<Exclude<typeof lf.state, "joined">, string> = {
      "no attribute record carries this identifier in this upload":
        "local file: not in this record — no attribute record carries this identifier in this upload",
      "database records with this identifier disagree — not joined":
        "local file: database records with this identifier disagree — not joined",
      "the file carries two attribute values — not joined":
        "local file: an attribute record carries this identifier, but the file carries two attribute values — not joined",
      "host not established — not joined":
        "local file: the host is not established by this record — not joined",
    };
    return [words[lf.state]];
  }
  const shown = lf.paths
    .slice(0, FILES_SHOWN_MAX)
    .map((x) => show(x, PATH_SHOWN_MAX))
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

function rewriteDbRow(r: QuarantineRow, partitions: Map<string, Partition>): QuarantineRow {
  // An overflow row (#1009's variant bound) names a fold, never a record: nothing to join.
  if (r.aggKey.endsWith("|overflow") || !r.canonicalInput) return r;
  const p = partitions.get(hostKey(dbHost(r)));
  const lf = localFileOf(r, p);
  const tags = localFileTags(lf);
  // The files, sorted by path like the shown list, so the provenance and the words agree.
  const files =
    typeof lf === "object" && lf.state === "joined"
      ? [...p!.files.get(r.eventId!)!.files].sort((x, y) =>
          x.path! < y.path! ? -1 : x.path! > y.path! ? 1 : 0,
        )
      : [];
  // Agreement against the ONE joined file: with several files each has its own mark; the
  // attribute rows say theirs, the database row says the files only.
  const one = files.length === 1 ? files[0] : undefined;
  const agreement: Pick<
    QuarantineRow["envelope"],
    "agentAgreement" | "timeAgreement" | "downloadFlag" | "sandboxOnly"
  > = one
    ? {
        agentAgreement: agentAgreement(one.mark!.agent, r),
        timeAgreement: timeAgreement(one.mark!.time.iso, r),
        ...flagsOf(one),
      }
    : {};
  if (agreement.agentAgreement === "agrees") tags.push("agent agrees");
  if (agreement.agentAgreement === "differs")
    tags.push(`agent differs: attribute ${one!.mark!.agent}; database ${agentWords(r)}`);
  if (agreement.timeAgreement) tags.push(timeWords(agreement.timeAgreement));
  tags.push(...flagTags(agreement));
  // The partition is said only where it carried a join: an unnamed host beside a joined file.
  if (!dbHost(r) && files.length) tags.push("host not named in the records");

  const envelope: QuarantineRow["envelope"] = { ...r.envelope, localFile: lf, ...agreement };
  const joinDigest = keyDigest(JSON.stringify({ localFile: lf, ...agreement }));
  const aggKey = `${r.aggKey}|join:${joinDigest}`;
  const mark = identityMark(aggKey);
  // The words: the unjoined tag out, the join tags in, packed to the width, re-marked for the new key.
  let body = r.description.replace(/ #[A-Za-z0-9_-]{22}$/, "");
  const shared = body.endsWith(SHARED_MARK);
  if (shared) body = body.slice(0, -SHARED_MARK.length);
  body = body.replace(UNJOINED_TAG, "");
  const room = DESCRIPTION_MAX - body.length - mark.length - (shared ? SHARED_MARK.length : 0);
  const description = `${body}${packTags(tags, Math.max(0, room))}${shared ? SHARED_MARK : ""}${mark}`;

  const input = r.canonicalInput;
  const named = files.slice(0, LOCATORS_MAX);
  // Provenance per leaf: each listed path rests on its own attribute record, the count and the
  // state on every named one beside the database record, the agreement facts on both records.
  const locatorMap: Record<string, string> = { ...(input.locatorMap ?? {}) };
  if (named.length) locatorMap["quarantine.localFile.paths"] = attributeLocator(named[0]);
  named.forEach((f, i) => {
    locatorMap[`quarantine.localFile.paths.${i}`] = attributeLocator(f);
    locatorMap[`quarantine.localFile.count.${i}`] = attributeLocator(f);
    locatorMap[`quarantine.localFile.state.${i}`] = attributeLocator(f);
  });
  if (one)
    for (const leaf of ["agentAgreement", "timeAgreement", "downloadFlag", "sandboxOnly"])
      locatorMap[`quarantine.${leaf}.attribute`] = attributeLocator(one);
  const canonical = createCanonicalEvent({
    ...input,
    quarantine: envelope,
    evidence: {
      rawRecords: [
        ...input.evidence.rawRecords,
        ...named.map((f) => ({ source: "macos-quarantine-attribute", locator: attributeLocator(f) })),
      ],
    },
    locatorMap,
  });
  return { ...r, description, aggKey, envelope, canonical };
}
