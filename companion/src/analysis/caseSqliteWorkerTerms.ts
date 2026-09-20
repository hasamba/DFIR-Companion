// The IOC-provenance term index of the case SQLite worker (#1452): what goes into a row's
// `event_terms` entry, the writer hook that keeps it beside every forensic/super row, the backfill
// for a database built before the index existed, and the `iocCandidates` op that turns IOC values
// into the candidate rows the builders in iocProvenance.ts / iocProvenanceChain.ts then match
// exactly. Spliced into caseSqliteWorker.ts's WORKER_SOURCE as plain text, so everything here runs
// inside the worker thread with that file's helpers in scope (openDatabase, withTransaction,
// existsSync). Keep it backtick-free: the fragment is a String.raw template.
//
// The index only has to be a SUPERSET of the builders' matches — they re-check every candidate. A
// stored term is one TOKEN_RE run of the description (the FTS tokenizer's `tokenchars` mirror the
// regex, see caseSqliteSchema.ts) or one raw structured value, all trimmed and lowercased. A phrase
// query for a key therefore hits a row iff the key is a whole token or an adjacent token run.
export const TERMS_WORKER_SOURCE = String.raw`
// Bump whenever eventTermsText changes: a lower stored version triggers a rebuild on the next read.
const EVENT_TERMS_VERSION = 1;
const EVENT_TERMS_KINDS = ["forensicTimeline", "superTimeline"];
const EVENT_TERMS_TOKEN_RE = /[\w.@:/\\-]{3,}/g;
const EVENT_TERMS_FIELDS = ["sha256", "md5", "srcIp", "dstIp", "path"];
const IOC_CANDIDATE_FETCH_CHUNK = 500;

function indexesTerms(kind) {
  return EVENT_TERMS_KINDS.includes(kind);
}

function eventTermsText(event) {
  const description = event && typeof event.description === "string" ? event.description : "";
  const raw = description.match(EVENT_TERMS_TOKEN_RE) || [];
  for (const field of EVENT_TERMS_FIELDS) {
    if (event && typeof event[field] === "string") raw.push(event[field]);
  }
  const terms = new Set();
  for (const value of raw) {
    const term = value.trim().toLowerCase();
    if (term.length >= 3) terms.add(term);
  }
  return [...terms].join(" ");
}

// Prepared once per writer: an import writes hundreds of thousands of rows through it.
function createTermsWriter(db) {
  const insertStatement = db.prepare("INSERT INTO event_terms(rowid, terms) VALUES (?, ?)");
  const deleteStatement = db.prepare("DELETE FROM event_terms WHERE rowid=?");
  const write = (rowId, event) => {
    const terms = eventTermsText(event);
    if (terms) insertStatement.run(rowId, terms);
  };
  return {
    insert(kind, rowId, event) {
      if (indexesTerms(kind)) write(rowId, event);
    },
    update(kind, rowId, event) {
      if (!indexesTerms(kind)) return;
      deleteStatement.run(rowId);
      write(rowId, event);
    },
  };
}

function readEventTermsVersion(db) {
  const row = db.prepare("SELECT value FROM storage_meta WHERE key='event_terms_version'").get();
  return row ? Number(row.value) : null;
}

function stampEventTermsVersion(db) {
  db.prepare(
    "INSERT INTO storage_meta(key, value) VALUES('event_terms_version', ?) " +
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).run(String(EVENT_TERMS_VERSION));
}

// A brand-new database has nothing to index, so it is current from its first open and never pays
// the backfill. Called by openDatabase; a database that already holds rows is left to the backfill.
function stampEventTermsOnNewDatabase(db) {
  if (readEventTermsVersion(db) !== null) return;
  if (db.prepare("SELECT 1 AS x FROM entities LIMIT 1").get()) return;
  stampEventTermsVersion(db);
}

// Backfill for a database created before the index, or indexed by an older eventTermsText: one
// pass over the two timeline kinds inside one transaction, row_id order, payload parsed here in the
// worker so nothing is structured-cloned to the main thread.
function ensureEventTerms(db) {
  const version = readEventTermsVersion(db);
  if (version !== null && version >= EVENT_TERMS_VERSION) return false;
  withTransaction(db, () => {
    db.exec("INSERT INTO event_terms(event_terms) VALUES('delete-all')");
    const writer = createTermsWriter(db);
    const rows = db.prepare(
      "SELECT row_id, kind, payload FROM entities " +
      "WHERE kind IN (SELECT value FROM json_each(?)) ORDER BY row_id"
    ).iterate(JSON.stringify(EVENT_TERMS_KINDS));
    for (const row of rows) writer.insert(row.kind, Number(row.row_id), JSON.parse(row.payload));
    stampEventTermsVersion(db);
  });
  return true;
}

// A key made only of separator characters tokenizes to nothing and can match no row; the
// tokenizer's own token characters are excluded from "separator" so a key like "..." still runs.
function termsPhraseForKey(key) {
  if (typeof key !== "string") return null;
  const trimmed = key.trim().toLowerCase();
  if (!trimmed) return null;
  if (/^[\p{P}\p{Z}\s]*$/u.test(trimmed) && !/[.@:/\\_-]/.test(trimmed)) return null;
  return '"' + trimmed.replace(/"/g, '""') + '"';
}

function iocCandidateRowIds(db, keys, ids) {
  const rowIds = new Set();
  const match = db.prepare("SELECT rowid AS id FROM event_terms WHERE event_terms MATCH ?");
  for (const key of new Set(keys || [])) {
    const phrase = termsPhraseForKey(key);
    if (!phrase) continue;
    for (const row of match.all(phrase)) rowIds.add(Number(row.id));
  }
  const wantedIds = [...new Set((ids || []).filter((id) => typeof id === "string" && id))];
  if (wantedIds.length) {
    const rows = db.prepare(
      "SELECT row_id AS id FROM entities WHERE kind IN (SELECT value FROM json_each(?)) " +
      "AND entity_id IN (SELECT value FROM json_each(?))"
    ).all(JSON.stringify(EVENT_TERMS_KINDS), JSON.stringify(wantedIds));
    for (const row of rows) rowIds.add(Number(row.id));
  }
  return [...rowIds];
}

function fetchIocCandidateRows(db, rowIds) {
  const fetch = db.prepare(
    "SELECT row_id, kind, ordinal, timestamp_ms, payload FROM entities " +
    "WHERE kind IN (SELECT value FROM json_each(?)) AND row_id IN (SELECT value FROM json_each(?))"
  );
  const out = [];
  for (let start = 0; start < rowIds.length; start += IOC_CANDIDATE_FETCH_CHUNK) {
    const chunk = rowIds.slice(start, start + IOC_CANDIDATE_FETCH_CHUNK);
    for (const row of fetch.all(JSON.stringify(EVENT_TERMS_KINDS), JSON.stringify(chunk))) out.push(row);
  }
  return out;
}

// Super rows in the order eventBatches() streams them (dated by timestamp then row_id, undated
// last by row_id), so the builders see candidates exactly as the full scan fed them.
function compareSuperCandidates(a, b) {
  const aMs = a.timestamp_ms === null ? Number.MAX_SAFE_INTEGER : Number(a.timestamp_ms);
  const bMs = b.timestamp_ms === null ? Number.MAX_SAFE_INTEGER : Number(b.timestamp_ms);
  return aMs - bMs || Number(a.row_id) - Number(b.row_id);
}

function iocCandidates(dbPath, keys, ids) {
  if (!existsSync(dbPath)) return { forensic: [], super: [], candidates: 0 };
  const db = openDatabase(dbPath);
  try {
    ensureEventTerms(db);
    const rows = fetchIocCandidateRows(db, iocCandidateRowIds(db, keys, ids));
    const forensic = rows.filter((row) => row.kind === "forensicTimeline")
      .sort((a, b) => Number(a.ordinal) - Number(b.ordinal));
    const superRows = rows.filter((row) => row.kind === "superTimeline").sort(compareSuperCandidates);
    return {
      forensic: forensic.map((row) => JSON.parse(row.payload)),
      super: superRows.map((row) => JSON.parse(row.payload)),
      candidates: rows.length,
    };
  } finally {
    db.close();
  }
}
`;
