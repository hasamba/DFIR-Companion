// The grade mark's worker side (#2909, analysis/gradeMark.ts). Spliced into caseSqliteWorker.ts's
// WORKER_SOURCE as plain text, so everything here runs inside the worker thread with that file's
// helpers in scope (openDatabase, withTransaction, existsSync). Keep it backtick-free: the fragment
// is a String.raw template.
//
// THE ARM. An import section that will end in the settle (routes/importSettle.ts) arms the case for
// the importer's merge window (import_grade_arm, one row, under the import journal's token, right after
// the snapshot and before the importer runs; a capture clears any older arm). While it is armed, every forensic row INSERTED gets the grade mark in the same
// write (createEntityWriter → gradeArmReader). Those are the rows the settle would have marked at its
// stamp anyway — the import's new rows — plus any other writer's new row in that window (a manual
// row, a promotion), which the re-grade only unmarks. Marking at insert closes the window between the
// merge and the stamp: an importer that throws after a partial merge, a Watson dispatch throw or a
// process kill leaves the rows marked, so the case-wide demote holds them and a re-grade grades them.
// The settle's first act drops the arm, so nothing the settle itself inserts (hunt summaries) is marked.
//
// The mark's value is the arm's mode: true, or "held" (a Watson paste, whose tagger only proposes).
export const GRADE_WORKER_SOURCE = String.raw`
const GRADE_PENDING_IDS_SQL =
  "SELECT entity_id FROM entities INDEXED BY entities_grade_pending_idx WHERE kind='forensicTimeline' " +
  "AND json_extract(payload, '$.gradePending') IS NOT NULL";

// The arm, read once per writer (a writer lives for one transaction).
function gradeArmReader(db) {
  let mode;
  return function mark(projection, entity) {
    if (projection.kind !== "forensicTimeline") return projection;
    if (mode === undefined) {
      const row = db.prepare("SELECT mode FROM import_grade_arm LIMIT 1").get();
      mode = row ? row.mode : null;
    }
    if (!mode || !entity || entity.gradePending !== undefined) return projection;
    const p = projection.payload;
    if (typeof p !== "string" || p.length < 2 || p[0] !== "{" || p[p.length - 1] !== "}") return projection;
    const value = mode === "held" ? '"held"' : "true";
    const body = p === "{}" ? "" : p.slice(1, -1) + ",";
    return Object.assign({}, projection, { payload: "{" + body + '"gradePending":' + value + "}" });
  };
}

function armGrade(db, token, mode) {
  db.exec("DELETE FROM import_grade_arm;");
  if (mode === true || mode === "held") {
    db.prepare("INSERT INTO import_grade_arm(token, mode) VALUES (?, ?)").run(token, mode === "held" ? "held" : "true");
  }
}

// Arm the case. A case with no database yet (its first import) gets the file created (schema only, no
// state — every reader treats a database without the 'investigation' row as no state).
function armGradeCase(dbPath, token, mode) {
  const db = openDatabase(dbPath);
  try {
    withTransaction(db, () => armGrade(db, token, mode));
    return true;
  } finally {
    db.close();
  }
}

// token: only that section's arm; none: whatever arm there is (the settle's first act, a stale arm).
function disarmGrade(dbPath, token) {
  if (!existsSync(dbPath)) return false;
  const db = openDatabase(dbPath);
  try {
    if (typeof token === "string") db.prepare("DELETE FROM import_grade_arm WHERE token=?").run(token);
    else db.exec("DELETE FROM import_grade_arm;");
    return true;
  } finally {
    db.close();
  }
}

// The ids of the marked forensic rows, from the partial index alone (no payload is read or sent).
function forensicGradePendingIds(dbPath) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare(GRADE_PENDING_IDS_SQL).all().map((row) => row.entity_id);
  } finally {
    db.close();
  }
}

// Start-up's question for each case: is it armed (a section that never finished), does it hold marks?
function gradeProbe(dbPath) {
  if (!existsSync(dbPath)) return { armed: false, marked: false };
  const db = openDatabase(dbPath);
  try {
    const armed = !!db.prepare("SELECT 1 AS x FROM import_grade_arm LIMIT 1").get();
    const marked = !!db.prepare(GRADE_PENDING_IDS_SQL + " LIMIT 1").get();
    return { armed, marked };
  } finally {
    db.close();
  }
}

function dispatchGrade(message) {
  switch (message.op) {
    case "armGrade": return armGradeCase(message.dbPath, message.token, message.mode);
    case "disarmGrade": return disarmGrade(message.dbPath, message.token);
    case "forensicGradePendingIds": return forensicGradePendingIds(message.dbPath);
    case "gradeProbe": return gradeProbe(message.dbPath);
    default: return dispatchFacts(message); // caseSqliteWorkerFacts.ts
  }
}
`;

/** The plan the marked-ids query must use (pinned by a test with EXPLAIN QUERY PLAN). */
export const GRADE_PENDING_INDEX = "entities_grade_pending_idx";
