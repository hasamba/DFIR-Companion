// The run() result guard of the case SQLite worker (#2445, the same defect as #2377). Spliced into
// caseSqliteWorker.ts's WORKER_SOURCE as plain text, ahead of openDatabase, which applies it to
// every connection it opens. Keep it backtick-free: the fragment is a String.raw template.
//
// A DELETE from the contentless_delete FTS5 term index (event_terms) writes a tombstone page into
// event_terms_data at rowid 2^53 + segid * 2^37. When the segment already has a tombstone page,
// that write is the statement's last internal insert, so SQLite leaves it in the connection's
// last-insert-rowid until the next real INSERT. Node releases that range-check
// StatementSync.run() then throw ERR_OUT_OF_RANGE on that DELETE or on any later UPDATE/DELETE,
// and the case-state save fails. A statement that returns no columns has nothing to read but its
// run() result, so it reads that result as BigInt and hands back plain numbers: exact for every
// real rowid and change count, and never a throw. Statements with columns (SELECT, RETURNING)
// keep normal semantics; they run through get/all/iterate, which never report a rowid.
export const RUN_GUARD_WORKER_SOURCE = String.raw`
function guardRunResults(db) {
  const prepare = db.prepare.bind(db);
  db.prepare = function (sql, ...rest) {
    const statement = prepare(sql, ...rest);
    if (statement.columns().length === 0) {
      statement.setReadBigInts(true);
      const run = statement.run.bind(statement);
      statement.run = (...args) => {
        const result = run(...args);
        return { changes: Number(result.changes), lastInsertRowid: Number(result.lastInsertRowid) };
      };
    }
    return statement;
  };
  return db;
}
`;
