import { LT_HASH_WORKER_SOURCE } from "./ltHash.js";

// The per-row facts of the case SQLite worker (#1874). Spliced into caseSqliteWorker.ts's
// WORKER_SOURCE as plain text, so everything here runs inside the worker thread with that file's
// helpers in scope (openDatabase, withTransaction, existsSync). Keep it backtick-free: the fragment
// is a String.raw template.
//
// A forensic or IOC row's facts (its digest and id; for a forensic row also its timeline diff key,
// whether the deobfuscation pass would decode it, and its file hashes) are computed on the main
// thread from the stored payload (analysis/rowFacts.ts) and kept in row_facts. The triggers in
// caseSqliteSchema.ts drop a row's facts and queue it in row_facts_pending whenever the row is
// inserted or its payload is written, so a row that is not queued and has facts has facts of its
// current payload. Every reader below treats a queued row, or a row with no facts, as unknown and
// hands back its payload instead, so a missing fact can never read as "nothing here".
//
// None of these ops is a read-pool op (caseSqliteWorkerPool.ts): they run on the writer, whose
// openDatabase creates the tables, and each one is a single transaction on the only connection that
// writes, so what it returns is one version of the case.
export const FACTS_WORKER_SOURCE =
  LT_HASH_WORKER_SOURCE +
  String.raw`
const FACT_KINDS_SQL = "('forensicTimeline', 'iocs')";

function factsStampOk(db, stamp) {
  const row = db.prepare("SELECT value FROM storage_meta WHERE key='row_facts'").get();
  return !!row && typeof stamp === "string" && row.value === stamp;
}

// Rows whose facts are unknown: queued, or with no facts row. Every row when the stamp differs.
function unknownFactsClause(stampOk) {
  return stampOk ? "(f.row_id IS NULL OR p.row_id IS NOT NULL)" : "1";
}

const FACTS_JOIN =
  "LEFT JOIN row_facts f ON f.row_id=e.row_id LEFT JOIN row_facts_pending p ON p.row_id=e.row_id ";

function payloadsByRowId(db, rowIds) {
  const out = new Map();
  if (!rowIds.length) return out;
  const rows = db.prepare(
    "SELECT row_id, payload FROM entities WHERE row_id IN (SELECT value FROM json_each(?))"
  ).all(JSON.stringify(rowIds));
  for (const row of rows) out.set(Number(row.row_id), JSON.parse(row.payload));
  return out;
}

// The forensic rows whose facts are unknown, for the import section's baseline. Null when the stamp
// differs: then no row's facts are trusted.
function factsUnfresh(db, stamp) {
  const stampOk = factsStampOk(db, stamp);
  if (!stampOk) return null;
  return db.prepare(
    "SELECT e.row_id FROM entities e " + FACTS_JOIN +
    "WHERE e.kind='forensicTimeline' AND " + unknownFactsClause(true) + " ORDER BY e.row_id"
  ).all().map((row) => Number(row.row_id));
}

// The queued rows, a page at a time, with their payloads. A stamp from other code clears every fact
// and queues every row first; a row with no facts that is not queued (a cache miss) is queued too.
function factsPending(dbPath, stamp, limit) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (!factsStampOk(db, stamp)) {
        db.exec("DELETE FROM row_facts; DELETE FROM row_facts_pending;");
        db.prepare(
          "INSERT INTO storage_meta(key, value) VALUES('row_facts', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        ).run(stamp);
      }
      db.exec(
        "INSERT INTO row_facts_pending(row_id, seq) SELECT e.row_id, s.n FROM entities e, row_facts_seq s " +
        "WHERE s.id=1 AND e.kind IN " + FACT_KINDS_SQL + " " +
        "AND NOT EXISTS (SELECT 1 FROM row_facts f WHERE f.row_id=e.row_id) " +
        "AND NOT EXISTS (SELECT 1 FROM row_facts_pending p WHERE p.row_id=e.row_id)"
      );
      return db.prepare(
        "SELECT p.row_id, p.seq, e.kind, e.payload FROM row_facts_pending p JOIN entities e ON e.row_id=p.row_id " +
        "ORDER BY p.row_id LIMIT ?"
      ).all(Math.max(1, Number(limit) || 1)).map((row) => ({
        rowId: Number(row.row_id),
        seq: Number(row.seq),
        kind: row.kind,
        payload: JSON.parse(row.payload),
      }));
    });
  } finally {
    db.close();
  }
}

// Store computed facts. A row is written only while it is still queued under the sequence number
// its payload was read with; a row written since was re-queued under a newer one and is left queued.
function factsWrite(dbPath, stamp, rows) {
  if (!existsSync(dbPath) || !Array.isArray(rows) || !rows.length) return 0;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (!factsStampOk(db, stamp)) return 0;
      const queued = db.prepare("SELECT seq FROM row_facts_pending WHERE row_id=?");
      const put = db.prepare(
        "INSERT OR REPLACE INTO row_facts(row_id, id, digest, diff_key, deob, sha, md5) VALUES (?, ?, ?, ?, ?, ?, ?)"
      );
      const done = db.prepare("DELETE FROM row_facts_pending WHERE row_id=?");
      let written = 0;
      for (const r of rows) {
        const q = queued.get(r.rowId);
        if (!q || Number(q.seq) !== r.seq) continue;
        put.run(r.rowId, r.id ?? null, r.digest, r.diffKey ?? null, r.deob ? 1 : 0, r.sha ?? null, r.md5 ?? null);
        done.run(r.rowId);
        written++;
      }
      return written;
    });
  } finally {
    db.close();
  }
}

// The case's findings, and per forensic row and per IOC, in order, its id and digest — or, where
// the facts are unknown, its payload. What the run record fingerprints, from one transaction.
function factsFingerprint(dbPath, stamp) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='investigation'").get()) return null;
      const stampOk = factsStampOk(db, stamp);
      const findings = db.prepare("SELECT payload FROM entities WHERE kind='findings' ORDER BY ordinal")
        .all().map((row) => JSON.parse(row.payload));
      const listing = (kind) => {
        const out = { rowIds: [], ids: [], digests: [] };
        const rows = db.prepare(
          "SELECT e.row_id, f.id, f.digest, " + unknownFactsClause(stampOk) + " AS unknown FROM entities e " +
          FACTS_JOIN + "WHERE e.kind=? ORDER BY e.ordinal"
        ).all(kind);
        for (const row of rows) {
          out.rowIds.push(Number(row.row_id));
          const known = !Number(row.unknown);
          out.ids.push(known ? row.id : null);
          out.digests.push(known ? row.digest : null);
        }
        return out;
      };
      const forensic = listing("forensicTimeline");
      const iocs = listing("iocs");
      const unknown = [];
      for (const list of [forensic, iocs]) {
        list.digests.forEach((digest, i) => { if (digest === null) unknown.push(list.rowIds[i]); });
      }
      const payloads = payloadsByRowId(db, unknown);
      return { findings, forensic, iocs, payloads: [...payloads], ...caseEntityIds(db) };
    });
  } finally {
    db.close();
  }
}

// #1887: the run record's fingerprint, investigation-state/v3 (analysis/analysisRunSnapshot.ts): an
// LtHash sum per kind (LT_HASH_WORKER_SOURCE, analysis/ltHash.ts, prepended to this fragment).
// storage_meta 'fp_sum' keeps { stamp, forensic, iocs, check }, the sums as base64, a SHA-256 over the
// three (accidental damage fails it and forces a rebuild; it is not a defence against someone who can
// rewrite the database, which could rewrite the row digests too), and the stamp of the
// facts they were computed from plus FP_SUM_MARK. The row_facts triggers (caseSqliteSchema.ts) log
// every digest that entered or left a sum in fp_log; a fingerprint folds the log into the kept sums
// and clears it, so it costs the changed rows, not the case. Under another stamp, or on a case that
// never had sums, fp_rows is rebuilt from row_facts and both sums from scratch, in the same
// transaction, so a crash keeps the old value and rebuilds again.
const FP_SUM_MARK = "|lthash32-1";
const FP_SQL = {
  missing:
    "SELECT 1 AS x FROM entities e WHERE e.kind IN " + FACT_KINDS_SQL +
    " AND NOT EXISTS (SELECT 1 FROM row_facts f WHERE f.row_id=e.row_id) LIMIT 1",
  mirror:
    "INSERT INTO fp_rows(row_id, kind, digest) SELECT f.row_id, e.kind, f.digest FROM row_facts f " +
    "JOIN entities e ON e.row_id=f.row_id WHERE e.kind IN " + FACT_KINDS_SQL,
};

function fpSumCheck(kept) {
  return createHash("sha256").update(String(kept.stamp) + "|" + String(kept.forensic) + "|" + String(kept.iocs)).digest("hex");
}

function fpKeptSums(db, stamp) {
  const row = db.prepare("SELECT value FROM storage_meta WHERE key='fp_sum'").get();
  let kept = null;
  try { kept = row ? JSON.parse(row.value) : null; } catch { kept = null; }
  if (!kept || kept.stamp !== stamp || kept.check !== fpSumCheck(kept)) return null;
  const forensic = ltWorkerDecode(kept.forensic, "base64");
  const iocs = ltWorkerDecode(kept.iocs, "base64");
  return forensic && iocs ? { forensicTimeline: forensic, iocs } : null;
}

function fpSumValue(stamp, sums) {
  const kept = {
    stamp,
    forensic: ltWorkerEncode(sums.forensicTimeline, "base64"),
    iocs: ltWorkerEncode(sums.iocs, "base64"),
  };
  return { ...kept, check: fpSumCheck(kept) };
}

function fpRebuild(db) {
  db.exec("DELETE FROM fp_rows; DELETE FROM fp_log;" + FP_SQL.mirror);
  const sums = { forensicTimeline: new Uint32Array(LT_LANES), iocs: new Uint32Array(LT_LANES) };
  const rows = db.prepare("SELECT kind, digest FROM fp_rows");
  rows.setReturnArrays(true);
  for (const row of rows.iterate()) ltApply(sums[row[0]], row[1], 1);
  return sums;
}

// Fold every logged change into the sums, then clear the log.
function fpFold(db, sums) {
  const rows = db.prepare("SELECT kind, digest, sign FROM fp_log");
  rows.setReturnArrays(true);
  for (const row of rows.iterate()) {
    const sum = sums[row[0]];
    if (sum) ltApply(sum, row[1], Number(row[2]) < 0 ? -1 : 1);
  }
  db.exec("DELETE FROM fp_log");
}

// The case's findings and both sums (hex). Null for a case with no state; { needsFull: true } when
// the facts are another build's or a forensic or IOC row's facts are unknown (queued, or missing):
// the caller then hashes the full listing.
// The forensic and the IOC ids, each in order, as the outlines read them (#1887): read in the
// fingerprint's own transaction, so a receipt's counts and change lists describe the snapshot its
// hash covers.
function caseEntityIds(db) {
  return { forensicIds: outlineRows(db, false).ids, iocIds: iocOutlineRows(db).ids };
}

function factsFingerprintV3(dbPath, stamp) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='investigation'").get()) return null;
      if (!factsStampOk(db, stamp)) return { needsFull: true };
      if (db.prepare("SELECT 1 AS x FROM row_facts_pending LIMIT 1").get()) return { needsFull: true };
      if (db.prepare(FP_SQL.missing).get()) return { needsFull: true };
      const sumStamp = stamp + FP_SUM_MARK;
      let sums = fpKeptSums(db, sumStamp);
      if (sums) fpFold(db, sums);
      else sums = fpRebuild(db);
      db.prepare(
        "INSERT INTO storage_meta(key, value) VALUES('fp_sum', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).run(JSON.stringify(fpSumValue(sumStamp, sums)));
      const findings = db.prepare("SELECT payload FROM entities WHERE kind='findings' ORDER BY ordinal")
        .all().map((row) => JSON.parse(row.payload));
      return {
        needsFull: false, findings,
        forensic: ltWorkerEncode(sums.forensicTimeline, "hex"), iocs: ltWorkerEncode(sums.iocs, "hex"),
        ...caseEntityIds(db),
      };
    });
  } finally {
    db.close();
  }
}

// The forensic rows a sweep has to look at, in timeline order: the deobfuscation candidates
// ("deob": rows the pass would decode) or the rows carrying a file hash ("nsrl"), plus every row
// whose facts are unknown. Payloads for the unknown rows, and for every row in "deob" mode.
function factsCandidates(dbPath, stamp, mode) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const stampOk = factsStampOk(db, stamp);
      const unknown = unknownFactsClause(stampOk);
      const wanted = mode === "deob" ? "f.deob=1" : "(f.sha IS NOT NULL OR f.md5 IS NOT NULL)";
      const rows = db.prepare(
        "SELECT e.row_id, f.sha, f.md5, " + unknown + " AS unknown FROM entities e " + FACTS_JOIN +
        "WHERE e.kind='forensicTimeline' AND (" + unknown + " OR " + wanted + ") ORDER BY e.ordinal"
      ).all();
      const out = rows.map((row) => ({
        rowId: Number(row.row_id),
        unknown: !!Number(row.unknown),
        sha: row.sha,
        md5: row.md5,
      }));
      const need = out.filter((r) => mode === "deob" || r.unknown).map((r) => r.rowId);
      const payloads = payloadsByRowId(db, need);
      for (const r of out) if (payloads.has(r.rowId)) r.payload = payloads.get(r.rowId);
      return out;
    });
  } finally {
    db.close();
  }
}

// The timeline diff's three fields of the named forensic rows, read like the keyed outline reads them.
function forensicKeyFields(dbPath, rowIds) {
  if (!existsSync(dbPath) || !Array.isArray(rowIds) || !rowIds.length) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare(
      "SELECT row_id, json_extract(payload, '$.timestamp', '$.description', '$.severity') AS k FROM entities " +
      "WHERE kind='forensicTimeline' AND row_id IN (SELECT value FROM json_each(?))"
    ).all(JSON.stringify(rowIds)).map((row) => ({ rowId: Number(row.row_id), fields: JSON.parse(row.k) }));
  } finally {
    db.close();
  }
}

// Forensic rows outside 'exclude' whose known diff key is one of 'keys', with their three fields so
// the caller checks the real key. Null when the stamp differs (no fact is trusted).
function factsKeyHolders(dbPath, stamp, keys, exclude) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (!factsStampOk(db, stamp)) return null;
      if (!Array.isArray(keys) || !keys.length) return [];
      return db.prepare(
        "SELECT f.row_id, json_extract(e.payload, '$.timestamp', '$.description', '$.severity') AS k " +
        "FROM row_facts f JOIN entities e ON e.row_id=f.row_id " +
        "WHERE f.diff_key IN (SELECT value FROM json_each(?)) AND e.kind='forensicTimeline' " +
        "AND NOT EXISTS (SELECT 1 FROM row_facts_pending p WHERE p.row_id=f.row_id) " +
        "AND f.row_id NOT IN (SELECT value FROM json_each(?))"
      ).all(JSON.stringify(keys), JSON.stringify(exclude || [])).map((row) => ({
        rowId: Number(row.row_id),
        fields: JSON.parse(row.k),
      }));
    });
  } finally {
    db.close();
  }
}

function dispatchFacts(message) {
  switch (message.op) {
    case "factsPending": return factsPending(message.dbPath, message.stamp, message.limit);
    case "factsWrite": return factsWrite(message.dbPath, message.stamp, message.rows);
    case "factsFingerprint": return factsFingerprint(message.dbPath, message.stamp);
    case "factsFingerprintV3": return factsFingerprintV3(message.dbPath, message.stamp);
    case "factsCandidates": return factsCandidates(message.dbPath, message.stamp, message.mode);
    case "forensicKeyFields": return forensicKeyFields(message.dbPath, message.rowIds);
    case "factsKeyHolders": return factsKeyHolders(message.dbPath, message.stamp, message.keys, message.exclude);
    default: return dispatchIoc(message); // caseSqliteWorkerIoc.ts
  }
}
`;

/** A queued row's payload, read for its facts (analysis/rowFacts.ts). */
export interface PendingFactRow {
  rowId: number;
  seq: number;
  kind: "forensicTimeline" | "iocs";
  payload: unknown;
}

/** One row's computed facts, as factsWrite stores them. */
export interface RowFactRecord {
  rowId: number;
  seq: number;
  id: string | null;
  digest: string;
  diffKey?: string | null;
  deob?: boolean;
  sha?: string | null;
  md5?: string | null;
}

/** Ids and digests in order; null at a row whose facts are unknown (its payload is in `payloads`). */
export interface FactsListing {
  rowIds: number[];
  ids: (string | null)[];
  digests: (string | null)[];
}

export interface FactsFingerprint {
  findings: unknown[];
  forensic: FactsListing;
  iocs: FactsListing;
  payloads: [number, unknown][];
  /** The forensic ids, in order, from the same transaction. */
  forensicIds: unknown[];
  /** The IOC ids, in order, from the same transaction. */
  iocIds: unknown[];
}

/** The kept v3 LtHash sums (hex, analysis/ltHash.ts), or a request to hash the full listing. */
export type FactsFingerprintV3 =
  | { needsFull: true }
  | {
      needsFull: false;
      findings: unknown[];
      forensic: string;
      iocs: string;
      /** The forensic ids, in order, from the same transaction. */
      forensicIds: unknown[];
      /** The IOC ids, in order, from the same transaction. */
      iocIds: unknown[];
    };

export interface FactCandidate {
  rowId: number;
  unknown: boolean;
  sha: string | null;
  md5: string | null;
  payload?: unknown;
}

/** A row's three timeline-diff fields, as the keyed outline reads them ([timestamp, description, severity]). */
export interface KeyFieldsRow {
  rowId: number;
  fields: [unknown, unknown, unknown];
}
