// The super-timeline relink (#2619), spliced into caseSqliteWorker.ts's WORKER_SOURCE after
// SUPER_WORKER_SOURCE, so it runs inside the worker thread with that fragment's helpers in scope
// (superContentKey, superBaseContentKey, superRecordId, markSetAsideRows, bumpSuperGeneration,
// stampSuperContent) and the worker's own (openDatabase, withTransaction, createEntityWriter,
// entityProjection, scalarText, hasTagsTable, existsSync). Keep it backtick-free: String.raw template.
//
// The case: an import is undone, then the same file is imported again. The forensic timeline gets the
// rows back under NEW ids (ids are per import), while the super-timeline's content dedup keeps the
// OLD row, whose id is no longer in the forensic timeline — so the raw record never shows it as
// Promoted. Relinking moves the stored row onto the id the forensic timeline now holds.
export const SUPER_RELINK_WORKER_SOURCE = String.raw`
// The stored super row an incoming row content-deduped against: full content key, then the base key
// a record-id'd row also folds into (#2140) — the same lookup protectSuperRows uses. The statement is
// prepared once per call site, not once per row: a plain re-import drops every row through here.
function storedSuperMatcher(db) {
  const byContent = db.prepare(
    "SELECT entity_id FROM entities WHERE kind='superTimeline' AND content_key=? AND entity_id IS NOT NULL ORDER BY row_id LIMIT 1"
  );
  return (event) => {
    const row = byContent.get(superContentKey(event)) ||
      (superRecordId(event) ? byContent.get(superBaseContentKey(event)) : undefined);
    return row ? String(row.entity_id) : "";
  };
}

function forensicHolds(db) {
  const stmt = db.prepare("SELECT 1 AS x FROM entities WHERE kind='forensicTimeline' AND entity_id=? LIMIT 1");
  return (id) => !!stmt.get(id);
}

// The incoming rows of one append that content-deduped against a stored row with ANOTHER id, which
// the forensic timeline does not hold. Only candidates: the settle relinks the ones whose new id is
// still in the forensic timeline once demote has run, so a plain re-import of Info rows (demoted
// again) rewrites nothing.
function superRelinkCandidates(db, dropped) {
  if (!dropped.length) return [];
  const inForensic = forensicHolds(db);
  const storedMatch = storedSuperMatcher(db);
  const out = [];
  for (const event of dropped) {
    const id = scalarText(event && event.id);
    if (!id) continue;
    const storedId = storedMatch(event);
    if (!storedId || storedId === id || inForensic(storedId)) continue;
    out.push({ id, storedId });
  }
  return out;
}

// Carry every row keyed by the old event id across to the new one. A tag whose label and author the
// new id already carries (the tagger tags the re-imported row too) is a duplicate and is dropped.
function moveSuperEventKeys(db, fromId, toId) {
  db.prepare("UPDATE OR IGNORE super_labels SET event_id=? WHERE event_id=?").run(toId, fromId);
  db.prepare("DELETE FROM super_labels WHERE event_id=?").run(fromId);
  db.prepare("UPDATE OR IGNORE super_protected SET event_id=? WHERE event_id=?").run(toId, fromId);
  db.prepare("DELETE FROM super_protected WHERE event_id=?").run(fromId);
  db.prepare("DELETE FROM super_set_aside WHERE event_id=?").run(fromId);
  if (!hasTagsTable(db)) return;
  db.prepare(
    "DELETE FROM tags WHERE target_type='event' AND target_id=? AND EXISTS (SELECT 1 FROM tags t " +
    "WHERE t.target_type='event' AND t.target_id=? AND t.label=tags.label AND t.author=tags.author)"
  ).run(fromId, toId);
  db.prepare("UPDATE tags SET target_id=? WHERE target_type='event' AND target_id=?").run(toId, fromId);
  db.prepare("UPDATE OR IGNORE tags_protect_pending SET target_id=? WHERE target_id=?").run(toId, fromId);
}

// Rewrite each stored row onto its forensic id, re-checked here inside one transaction: the old id
// must still be a super row the forensic timeline does not hold, and the new id must be in the
// forensic timeline and not already a super row. The payload keeps its content (so the content key
// and every later re-import's dedup are unchanged); only the id and the grade follow the forensic
// row. Returns the count rewritten.
function relinkSuper(dbPath, links, setAsideMarkers) {
  if (!existsSync(dbPath)) return 0;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const writer = createEntityWriter(db);
      const inForensic = forensicHolds(db);
      const find = db.prepare(
        "SELECT row_id, ordinal, payload FROM entities WHERE kind='superTimeline' AND entity_id=? ORDER BY ordinal LIMIT 1"
      );
      const rewritten = [];
      for (const link of links || []) {
        const fromId = scalarText(link && link.fromId);
        const toId = scalarText(link && link.toId);
        if (!fromId || !toId || fromId === toId) continue;
        if (inForensic(fromId) || !inForensic(toId) || find.get(toId)) continue;
        const row = find.get(fromId);
        if (!row) continue;
        let stored;
        try { stored = JSON.parse(row.payload); } catch { continue; }
        const severity = typeof link.severity === "string" && link.severity ? link.severity : stored.severity;
        const event = { ...stored, id: toId, severity };
        writer.update(row.row_id, entityProjection("superTimeline", event, row.ordinal, superContentKey(event)), event);
        moveSuperEventKeys(db, fromId, toId);
        rewritten.push(toId);
      }
      if (rewritten.length) {
        db.prepare("DELETE FROM super_set_aside WHERE event_id IN (SELECT value FROM json_each(?))")
          .run(JSON.stringify(rewritten));
        markSetAsideRows(db, setAsideMarkers, { ids: rewritten });
        bumpSuperGeneration(db);
        stampSuperContent(db);
      }
      return rewritten.length;
    });
  } finally {
    db.close();
  }
}
`;
