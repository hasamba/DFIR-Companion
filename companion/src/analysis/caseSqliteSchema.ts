/**
 * The per-case SQLite schema, as one statement string.
 *
 * Lifted out of caseSqliteWorker.ts because that file is frozen at its length by
 * scripts/check-file-size.mjs and this is the largest piece of it that is pure DATA: no control
 * flow, no worker plumbing, nothing that reads a message. The worker interpolates it into its
 * source string and appends the PRAGMA that stamps SCHEMA_VERSION, so bumping the version stays
 * next to the migrations that care about it.
 */
export const CASE_SQLITE_SCHEMA_SQL =
  "CREATE TABLE IF NOT EXISTS storage_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);CREATE TABLE IF NOT EXISTS entities (row_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT,ordinal INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1,timestamp TEXT,timestamp_ms INTEGER,host TEXT,source TEXT,severity TEXT,content_key TEXT,payload TEXT NOT NULL,UNIQUE(kind, ordinal));CREATE INDEX IF NOT EXISTS entities_time_idx ON entities(kind, timestamp_ms, row_id);CREATE INDEX IF NOT EXISTS entities_host_idx ON entities(kind, host);CREATE INDEX IF NOT EXISTS entities_source_idx ON entities(kind, source);CREATE INDEX IF NOT EXISTS entities_severity_idx ON entities(kind, severity);CREATE INDEX IF NOT EXISTS entities_id_idx ON entities(kind, entity_id);CREATE INDEX IF NOT EXISTS entities_content_idx ON entities(kind, content_key);CREATE TABLE IF NOT EXISTS entity_counts (kind TEXT PRIMARY KEY,count INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS entity_values (row_id INTEGER NOT NULL REFERENCES entities(row_id) ON DELETE CASCADE,name TEXT NOT NULL,value TEXT NOT NULL,kind TEXT NOT NULL,host TEXT,ordinal INTEGER NOT NULL,PRIMARY KEY(row_id, name, value));CREATE INDEX IF NOT EXISTS entity_values_lookup_idx ON entity_values(name, value, kind, ordinal, row_id);CREATE INDEX IF NOT EXISTS entity_values_host_lookup_idx ON entity_values(name, value, kind, host, ordinal, row_id);CREATE TABLE IF NOT EXISTS super_labels (event_id TEXT NOT NULL,label TEXT NOT NULL,PRIMARY KEY(event_id, label));";
