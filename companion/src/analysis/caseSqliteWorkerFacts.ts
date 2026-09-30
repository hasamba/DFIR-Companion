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
export const FACTS_WORKER_SOURCE = String.raw`
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
      return { findings, forensic, iocs, payloads: [...payloads] };
    });
  } finally {
    db.close();
  }
}

// #1887: the run record's fingerprint, investigation-state/v3 (analysis/analysisRunSnapshot.ts), from
// the bucket hashes kept in fp_buckets (caseSqliteSchema.ts; the row_facts triggers mark a bucket
// dirty whenever a digest enters or leaves it). storage_meta 'fp_buckets' stamps the facts the kept
// hashes were computed from: under another stamp, or on a case that never had them, every bucket
// present in row_facts is marked dirty, in the same transaction as the re-hash, so a crash keeps the
// old stamp and seeds again.
const { createHash } = require("node:crypto");
const FP_SQL = {
  seed:
    "INSERT INTO fp_buckets(kind, bucket, hash) SELECT k.kind, b.bucket, NULL FROM " +
    "(SELECT DISTINCT substr(digest, 1, 4) AS bucket FROM row_facts) b, " +
    "(SELECT 'forensicTimeline' AS kind UNION ALL SELECT 'iocs') k",
  missing:
    "SELECT 1 AS x FROM entities e WHERE e.kind IN " + FACT_KINDS_SQL +
    " AND NOT EXISTS (SELECT 1 FROM row_facts f WHERE f.row_id=e.row_id) LIMIT 1",
  digests:
    "SELECT f.digest FROM row_facts f INDEXED BY row_facts_bucket_idx JOIN entities e ON e.row_id=f.row_id " +
    "WHERE substr(f.digest, 1, 4)=? AND e.kind=? ORDER BY substr(f.digest, 1, 4), f.digest",
};

function fpSeed(db, stamp) {
  const row = db.prepare("SELECT value FROM storage_meta WHERE key='fp_buckets'").get();
  if (row && row.value === stamp) return;
  db.exec("DELETE FROM fp_buckets;" + FP_SQL.seed);
  db.prepare(
    "INSERT INTO storage_meta(key, value) VALUES('fp_buckets', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).run(stamp);
}

// Re-hash every dirty bucket: its digests of that kind, sorted ascending, joined with a newline. A
// bucket with none left is dropped.
function fpRehash(db) {
  const digests = db.prepare(FP_SQL.digests);
  const put = db.prepare("UPDATE fp_buckets SET hash=? WHERE kind=? AND bucket=?");
  const drop = db.prepare("DELETE FROM fp_buckets WHERE kind=? AND bucket=?");
  const dirty = db.prepare("SELECT kind, bucket FROM fp_buckets WHERE hash IS NULL").all();
  for (const d of dirty) {
    const list = digests.all(d.bucket, d.kind).map((row) => row.digest);
    if (list.length) put.run(createHash("sha256").update(list.join("\n")).digest("hex"), d.kind, d.bucket);
    else drop.run(d.kind, d.bucket);
  }
}

// The case's findings and, per kind, every non-empty bucket with its hash in bucket order. Null for
// a case with no state; { needsFull: true } when the facts are another build's or a forensic or IOC
// row's facts are unknown (queued, or missing): the caller then hashes the full listing.
function factsFingerprintV3(dbPath, stamp) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='investigation'").get()) return null;
      if (!factsStampOk(db, stamp)) return { needsFull: true };
      if (db.prepare("SELECT 1 AS x FROM row_facts_pending LIMIT 1").get()) return { needsFull: true };
      if (db.prepare(FP_SQL.missing).get()) return { needsFull: true };
      fpSeed(db, stamp);
      fpRehash(db);
      const findings = db.prepare("SELECT payload FROM entities WHERE kind='findings' ORDER BY ordinal")
        .all().map((row) => JSON.parse(row.payload));
      const buckets = (kind) => db.prepare("SELECT bucket, hash FROM fp_buckets WHERE kind=? ORDER BY bucket")
        .all(kind).map((row) => [row.bucket, row.hash]);
      return { needsFull: false, findings, forensic: buckets("forensicTimeline"), iocs: buckets("iocs") };
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
}

/** The kept v3 bucket hashes ([bucket, hash], ascending), or a request to hash the full listing. */
export type FactsFingerprintV3 =
  | { needsFull: true }
  | { needsFull: false; findings: unknown[]; forensic: [string, string][]; iocs: [string, string][] };

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
