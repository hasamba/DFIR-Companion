/**
 * The per-case SQLite schema, as one statement string.
 *
 * Lifted out of caseSqliteWorker.ts because that file is frozen at its length by
 * scripts/check-file-size.mjs and this is the largest piece of it that is pure DATA: no control
 * flow, no worker plumbing, nothing that reads a message. The worker interpolates it into its
 * source string and appends the PRAGMA that stamps SCHEMA_VERSION, so bumping the version stays
 * next to the migrations that care about it.
 */
// A written row's facts are dropped and the row queued under the next sequence number.
const FACTS_REQUEUE =
  "UPDATE row_facts_seq SET n = n + 1 WHERE id = 1; DELETE FROM row_facts WHERE row_id = new.row_id; " +
  "INSERT OR REPLACE INTO row_facts_pending(row_id, seq) VALUES (new.row_id, (SELECT n FROM row_facts_seq WHERE id = 1));";

// #1887: the run record's case fingerprint (investigation-state/v3, analysis/analysisRunSnapshot.ts)
// keeps an LtHash sum per kind (analysis/ltHash.ts) and folds in only what changed. fp_rows mirrors
// each forensic and IOC row's (kind, digest) as the sums count it, with no foreign key, so a cascade
// delete of the entity can still read the kind; fp_log records every digest that entered (+1) or left
// (-1) a sum since the last fingerprint (factsFingerprintV3, caseSqliteWorkerFacts.ts, folds and
// clears it). Triggers on row_facts keep both, so no writer has to remember: a row whose payload is
// written loses its facts (DELETE), a deleted entity cascades its facts (DELETE; SQLite fires
// triggers for a cascade), and a refresh inserts the new ones. An INSERT OR REPLACE deletes the old
// row without firing a trigger while recursive_triggers is off, so every insert first takes out any
// mirror row already under its row_id (in the AFTER trigger, so an INSERT OR IGNORE that inserts
// nothing changes nothing). No statement here can conflict (fp_log's key is a fresh rowid; fp_rows is
// cleared before it is written), so the firing statement's conflict policy cannot skip one.
const fpTakeOut = (rowId: string): string =>
  `INSERT INTO fp_log(kind, digest, sign) SELECT kind, digest, -1 FROM fp_rows WHERE row_id = ${rowId}; ` +
  `DELETE FROM fp_rows WHERE row_id = ${rowId};`;
const FP_PUT_IN =
  "INSERT INTO fp_log(kind, digest, sign) SELECT e.kind, new.digest, 1 FROM entities e " +
  "WHERE e.row_id = new.row_id AND e.kind IN ('forensicTimeline', 'iocs'); " +
  "INSERT INTO fp_rows(row_id, kind, digest) SELECT e.row_id, e.kind, new.digest FROM entities e " +
  "WHERE e.row_id = new.row_id AND e.kind IN ('forensicTimeline', 'iocs');";
const FP_LTHASH_SQL =
  // The bucket design this replaced, on a database a development build opened.
  "DROP TRIGGER IF EXISTS row_facts_fp_replace; DROP TRIGGER IF EXISTS row_facts_fp_insert;" +
  "DROP TRIGGER IF EXISTS row_facts_fp_delete; DROP TRIGGER IF EXISTS row_facts_fp_update;" +
  "DROP INDEX IF EXISTS row_facts_bucket_idx; DROP TABLE IF EXISTS fp_buckets;" +
  "CREATE TABLE IF NOT EXISTS fp_rows (row_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL);" +
  "CREATE TABLE IF NOT EXISTS fp_log (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL, " +
  "sign INTEGER NOT NULL);" +
  `CREATE TRIGGER IF NOT EXISTS row_facts_lt_insert AFTER INSERT ON row_facts BEGIN ${fpTakeOut("new.row_id")} ${FP_PUT_IN} END;` +
  `CREATE TRIGGER IF NOT EXISTS row_facts_lt_delete AFTER DELETE ON row_facts BEGIN ${fpTakeOut("old.row_id")} END;` +
  "CREATE TRIGGER IF NOT EXISTS row_facts_lt_update AFTER UPDATE OF digest, row_id ON row_facts BEGIN " +
  `${fpTakeOut("old.row_id")} ${fpTakeOut("new.row_id")} ${FP_PUT_IN} END;`;

// #1874: the IOC side of the import journal, and the indexes that let an import find IOC rows without
// reading every IOC payload. The journal copies the stored image of an IOC row the first time it is
// written or deleted while an import section holds the journal armed (import_journal_arm), exactly
// like the forensic journal above; the settle's IOC diff and the undo checkpoint read only those rows
// (analysis/iocJournal.ts). The indexes are partial (kind='iocs') and every query that relies on one
// names it with INDEXED BY: without ANALYZE statistics SQLite's planner prefers (kind, entity_id).
//  - value: lower() of the stored value, for value lookups (merge candidates, diff holders);
//  - odd: IOCs whose value is not text or not printable ASCII (lower() folds ASCII only);
//  - bad id: IOCs whose id is not a non-empty string (their entity_id is not their id);
//  - seq: ids shaped i<digits>, by number, so the next IOC sequence is one index probe.
export const IOC_ODD_VALUE_WHERE =
  "kind='iocs' AND (json_type(payload, '$.value') IS NOT 'text' OR json_extract(payload, '$.value') GLOB '*[^ -~]*')";
export const IOC_BAD_ID_WHERE =
  "kind='iocs' AND (json_type(payload, '$.id') IS NOT 'text' OR json_extract(payload, '$.id') = '')";
export const IOC_SEQ_WHERE =
  "kind='iocs' AND entity_id GLOB 'i[0-9]*' AND NOT substr(entity_id, 2) GLOB '*[^0-9]*'";
const IOC_JOURNAL_SQL =
  "CREATE TABLE IF NOT EXISTS import_journal_ioc (row_id INTEGER PRIMARY KEY, entity_id TEXT, payload TEXT NOT NULL);" +
  "CREATE TRIGGER IF NOT EXISTS entities_journal_ioc_update BEFORE UPDATE OF payload ON entities " +
  "WHEN old.kind = 'iocs' AND EXISTS (SELECT 1 FROM import_journal_arm) BEGIN " +
  "INSERT OR IGNORE INTO import_journal_ioc(row_id, entity_id, payload) VALUES (old.row_id, old.entity_id, old.payload); END;" +
  "CREATE TRIGGER IF NOT EXISTS entities_journal_ioc_delete BEFORE DELETE ON entities " +
  "WHEN old.kind = 'iocs' AND EXISTS (SELECT 1 FROM import_journal_arm) BEGIN " +
  "INSERT OR IGNORE INTO import_journal_ioc(row_id, entity_id, payload) VALUES (old.row_id, old.entity_id, old.payload); END;" +
  "CREATE INDEX IF NOT EXISTS entities_ioc_value_idx ON entities(lower(json_extract(payload, '$.value'))) WHERE kind='iocs';" +
  `CREATE INDEX IF NOT EXISTS entities_ioc_odd_idx ON entities(ordinal) WHERE ${IOC_ODD_VALUE_WHERE};` +
  `CREATE INDEX IF NOT EXISTS entities_ioc_badid_idx ON entities(ordinal) WHERE ${IOC_BAD_ID_WHERE};` +
  `CREATE INDEX IF NOT EXISTS entities_ioc_seq_idx ON entities(CAST(substr(entity_id, 2) AS INTEGER)) WHERE ${IOC_SEQ_WHERE};`;

// #1874: analyst and tagger tags (analysis/tags.ts; worker ops in caseSqliteWorkerTags.ts), moved here
// from state/tags.json so a tagger batch writes only its new rows. `seq` is the list order the file
// had. No UNIQUE constraint: a legacy file can hold duplicate rows, and load() has always returned
// them; TagsStore's own lookup keeps new ones unique per (target, label). tags_protect_gen moves
// whenever an ANALYST event tag is added or removed (tagger tags never protect a raw row): the
// super-timeline store re-derives its protection when it differs from the value it last synced.
// 'tagger:' is TAGGER_AUTHOR_PREFIX (analysis/superTimeline.ts); a test pins the two together.
export const TAGGER_PREFIX_SQL = "tagger:";
const ANALYST_EVENT = (row: string): string =>
  `${row}.target_type = 'event' AND substr(${row}.author, 1, ${TAGGER_PREFIX_SQL.length}) <> '${TAGGER_PREFIX_SQL}'`;
const TAGS_SQL =
  "CREATE TABLE IF NOT EXISTS tags (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, target_type TEXT NOT NULL, " +
  "target_id TEXT NOT NULL, label TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL);" +
  "CREATE INDEX IF NOT EXISTS tags_target_idx ON tags(target_type, target_id, label);" +
  "CREATE INDEX IF NOT EXISTS tags_id_idx ON tags(id);" +
  "CREATE TABLE IF NOT EXISTS tags_protect_gen (id INTEGER PRIMARY KEY CHECK (id = 1), n INTEGER NOT NULL);" +
  "INSERT OR IGNORE INTO tags_protect_gen(id, n) VALUES (1, 0);" +
  `CREATE TRIGGER IF NOT EXISTS tags_protect_insert AFTER INSERT ON tags WHEN ${ANALYST_EVENT("new")} BEGIN ` +
  "UPDATE tags_protect_gen SET n = n + 1 WHERE id = 1; END;" +
  `CREATE TRIGGER IF NOT EXISTS tags_protect_delete AFTER DELETE ON tags WHEN ${ANALYST_EVENT("old")} BEGIN ` +
  "UPDATE tags_protect_gen SET n = n + 1 WHERE id = 1; END;" +
  // An analyst event tag between its protect call and its insert: the targets TagsStore planned to
  // add, stamped with the writer thread that planned them. The super-timeline re-derive keeps these
  // protected while that writer lives (a concurrent re-derive must not release a row whose tag is
  // one step from landing) and drops them as stale under any other writer (the process died between
  // the two steps, so the protection names a tag that never got written).
  "CREATE TABLE IF NOT EXISTS tags_protect_pending (target_id TEXT NOT NULL, boot TEXT NOT NULL, " +
  "PRIMARY KEY(target_id, boot)) WITHOUT ROWID;";

export const CASE_SQLITE_SCHEMA_SQL =
  "CREATE TABLE IF NOT EXISTS storage_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);CREATE TABLE IF NOT EXISTS entities (row_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT,ordinal INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1,timestamp TEXT,timestamp_ms INTEGER,host TEXT,source TEXT,severity TEXT,content_key TEXT,payload TEXT NOT NULL,UNIQUE(kind, ordinal));CREATE INDEX IF NOT EXISTS entities_time_idx ON entities(kind, timestamp_ms, row_id);CREATE INDEX IF NOT EXISTS entities_host_idx ON entities(kind, host);CREATE INDEX IF NOT EXISTS entities_source_idx ON entities(kind, source);CREATE INDEX IF NOT EXISTS entities_severity_idx ON entities(kind, severity);CREATE INDEX IF NOT EXISTS entities_id_idx ON entities(kind, entity_id);CREATE INDEX IF NOT EXISTS entities_content_idx ON entities(kind, content_key);CREATE TABLE IF NOT EXISTS entity_counts (kind TEXT PRIMARY KEY,count INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS entity_values (row_id INTEGER NOT NULL REFERENCES entities(row_id) ON DELETE CASCADE,name TEXT NOT NULL,value TEXT NOT NULL,kind TEXT NOT NULL,host TEXT,ordinal INTEGER NOT NULL,PRIMARY KEY(row_id, name, value));CREATE INDEX IF NOT EXISTS entity_values_lookup_idx ON entity_values(name, value, kind, ordinal, row_id);CREATE INDEX IF NOT EXISTS entity_values_host_lookup_idx ON entity_values(name, value, kind, host, ordinal, row_id);CREATE TABLE IF NOT EXISTS super_labels (event_id TEXT NOT NULL,label TEXT NOT NULL,PRIMARY KEY(event_id, label));CREATE TABLE IF NOT EXISTS super_protected (event_id TEXT PRIMARY KEY);CREATE TABLE IF NOT EXISTS super_set_aside (event_id TEXT PRIMARY KEY);" +
  // #1535: the rows a NAMED rule deliberately graded Info. Not protection — the cap still
  // evicts them, it just evicts everything else first. Derived by the worker from the stored
  // row (severity + the stated reason in its description), never written by a caller.

  // #1452: the IOC-provenance term index. One contentless FTS5 row per forensic/super row (rowid =
  // entities.row_id), holding the row's description tokens and structured values. `tokenchars`
  // mirrors the builders' TOKEN_RE (/[\w.@:/\\-]{3,}/) so a stored token is exactly one regex run;
  // the doubled backslash below reaches SQLite as ONE literal backslash. The trigger covers every
  // delete path (tail trim, prune, cap eviction) so no JS bookkeeping can drift.
  "CREATE VIRTUAL TABLE IF NOT EXISTS event_terms USING fts5(terms, content='', contentless_delete=1, " +
  "tokenize=\"unicode61 tokenchars '.@:/\\-_'\");" +
  "CREATE TRIGGER IF NOT EXISTS entities_terms_delete AFTER DELETE ON entities " +
  "BEGIN DELETE FROM event_terms WHERE rowid = old.row_id; END;" +
  // #1874: the import journal. While an import section holds it armed (one token row), the first
  // UPDATE or DELETE of a forensic row copies the row's stored image here, keyed by row_id so a
  // duplicate event id keeps its own image. The undo checkpoint and "which old rows did this import
  // touch" are read from it (caseSqliteWorkerRows.ts), so no full copy of the case is held for the
  // import. Unarmed, each trigger costs one lookup in an empty table.
  "CREATE TABLE IF NOT EXISTS import_journal (row_id INTEGER PRIMARY KEY, entity_id TEXT, payload TEXT NOT NULL);" +
  "CREATE TABLE IF NOT EXISTS import_journal_arm (token TEXT PRIMARY KEY);" +
  "CREATE TRIGGER IF NOT EXISTS entities_journal_update BEFORE UPDATE OF payload ON entities " +
  "WHEN old.kind = 'forensicTimeline' AND EXISTS (SELECT 1 FROM import_journal_arm) BEGIN " +
  "INSERT OR IGNORE INTO import_journal(row_id, entity_id, payload) VALUES (old.row_id, old.entity_id, old.payload); END;" +
  "CREATE TRIGGER IF NOT EXISTS entities_journal_delete BEFORE DELETE ON entities " +
  "WHEN old.kind = 'forensicTimeline' AND EXISTS (SELECT 1 FROM import_journal_arm) BEGIN " +
  "INSERT OR IGNORE INTO import_journal(row_id, entity_id, payload) VALUES (old.row_id, old.entity_id, old.payload); END;" +
  // #1874: the importer merge's index (analysis/caseSqliteWorkerMerge.ts). One row per forensic row the
  // merge wrote — its version, time, year, correlation bucket keys and activity flags — so the next
  // merge reads only the rows a delta needs. A row whose index version is not its stored version was
  // written since by someone else and is read in full. Deleting a forensic row leaves its bucket keys
  // in merge_dirty_keys (the rest of those buckets may group differently now), and every write to a
  // forensic row, an IOC or the case metadata moves merge_generation, which the merge's write checks.
  "CREATE TABLE IF NOT EXISTS merge_rows (row_id INTEGER PRIMARY KEY REFERENCES entities(row_id) ON DELETE CASCADE, " +
  "version INTEGER NOT NULL, time_ms INTEGER, year INTEGER, year_inferred INTEGER NOT NULL DEFAULT 0, flags INTEGER NOT NULL DEFAULT 0);" +
  "CREATE TABLE IF NOT EXISTS merge_keys (key TEXT NOT NULL, row_id INTEGER NOT NULL REFERENCES entities(row_id) ON DELETE CASCADE, " +
  "PRIMARY KEY(key, row_id)) WITHOUT ROWID;" +
  "CREATE INDEX IF NOT EXISTS merge_keys_row_idx ON merge_keys(row_id);" +
  "CREATE TABLE IF NOT EXISTS merge_dirty_keys (key TEXT PRIMARY KEY) WITHOUT ROWID;" +
  "CREATE TABLE IF NOT EXISTS merge_generation (id INTEGER PRIMARY KEY CHECK (id = 1), n INTEGER NOT NULL);" +
  "INSERT OR IGNORE INTO merge_generation(id, n) VALUES (1, 0);" +
  "CREATE TRIGGER IF NOT EXISTS entities_merge_dirty BEFORE DELETE ON entities WHEN old.kind = 'forensicTimeline' BEGIN " +
  "INSERT OR IGNORE INTO merge_dirty_keys(key) SELECT key FROM merge_keys WHERE row_id = old.row_id; END;" +
  "CREATE TRIGGER IF NOT EXISTS entities_merge_gen_insert AFTER INSERT ON entities " +
  "WHEN new.kind IN ('forensicTimeline', 'iocs') BEGIN UPDATE merge_generation SET n = n + 1 WHERE id = 1; END;" +
  "CREATE TRIGGER IF NOT EXISTS entities_merge_gen_update AFTER UPDATE ON entities " +
  "WHEN old.kind IN ('forensicTimeline', 'iocs') OR new.kind IN ('forensicTimeline', 'iocs') BEGIN " +
  "UPDATE merge_generation SET n = n + 1 WHERE id = 1; END;" +
  "CREATE TRIGGER IF NOT EXISTS entities_merge_gen_delete AFTER DELETE ON entities " +
  "WHEN old.kind IN ('forensicTimeline', 'iocs') BEGIN UPDATE merge_generation SET n = n + 1 WHERE id = 1; END;" +
  "CREATE TRIGGER IF NOT EXISTS meta_merge_gen_insert AFTER INSERT ON storage_meta " +
  "WHEN new.key = 'investigation' BEGIN UPDATE merge_generation SET n = n + 1 WHERE id = 1; END;" +
  "CREATE TRIGGER IF NOT EXISTS meta_merge_gen_update AFTER UPDATE ON storage_meta " +
  "WHEN new.key = 'investigation' BEGIN UPDATE merge_generation SET n = n + 1 WHERE id = 1; END;" +
  // #1874: the timeline's ids in order, read from the index alone (the settle and the run record
  // read them on every import; reading the rows themselves touched every page of the case).
  "CREATE INDEX IF NOT EXISTS entities_order_idx ON entities(kind, ordinal, entity_id);" +
  // #1887: the importer merge's walks over every forensic row (MERGE_SCAN_SQL in
  // caseSqliteWorkerMerge.ts) read each row's version; from this index, not from the payload's page.
  "CREATE INDEX IF NOT EXISTS entities_merge_order_idx ON entities(kind, ordinal, version);" +
  // #1874: each host's first row, for the host-duplicate check every import runs (hostScopeLoad.ts).
  "CREATE INDEX IF NOT EXISTS entities_host_order_idx ON entities(kind, host, ordinal);" +
  // #1874: per-row facts (analysis/rowFacts.ts computes them; caseSqliteWorkerFacts.ts stores them)
  // for the forensic and IOC rows: the row's own digest and id, and for a forensic row its timeline
  // diff key, whether the deobfuscation pass would decode it and its file hashes. Computed from the
  // stored payload only, so they hold until the payload changes: inserting a row or writing its
  // payload drops its facts and queues it in row_facts_pending under a fresh sequence number, and a
  // computation is stored only if the row is still queued under the number it read. Deleting a row
  // cascades both. An ordinal move changes no fact. storage_meta 'row_facts' stamps the code that
  // computed them; another stamp means none of them is trusted.
  "CREATE TABLE IF NOT EXISTS row_facts (row_id INTEGER PRIMARY KEY REFERENCES entities(row_id) ON DELETE CASCADE, " +
  "id TEXT, digest TEXT NOT NULL, diff_key TEXT, deob INTEGER NOT NULL DEFAULT 0, sha TEXT, md5 TEXT);" +
  "CREATE INDEX IF NOT EXISTS row_facts_diff_idx ON row_facts(diff_key) WHERE diff_key IS NOT NULL;" +
  "CREATE TABLE IF NOT EXISTS row_facts_pending (row_id INTEGER PRIMARY KEY REFERENCES entities(row_id) ON DELETE CASCADE, " +
  "seq INTEGER NOT NULL);" +
  "CREATE TABLE IF NOT EXISTS row_facts_seq (id INTEGER PRIMARY KEY CHECK (id = 1), n INTEGER NOT NULL);" +
  "INSERT OR IGNORE INTO row_facts_seq(id, n) VALUES (1, 0);" +
  "CREATE TRIGGER IF NOT EXISTS entities_facts_insert AFTER INSERT ON entities " +
  "WHEN new.kind IN ('forensicTimeline', 'iocs') BEGIN " +
  FACTS_REQUEUE +
  " END;" +
  "CREATE TRIGGER IF NOT EXISTS entities_facts_update AFTER UPDATE OF payload ON entities " +
  "WHEN new.kind IN ('forensicTimeline', 'iocs') BEGIN " +
  FACTS_REQUEUE +
  " END;" +
  FP_LTHASH_SQL +
  IOC_JOURNAL_SQL +
  TAGS_SQL;
