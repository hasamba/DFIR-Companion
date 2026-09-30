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
  " END;";
