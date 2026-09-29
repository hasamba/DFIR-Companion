// How a full-state save writes one array kind (#1874). Spliced into caseSqliteWorker.ts's
// WORKER_SOURCE as plain text, so it runs inside the worker thread with that file's helpers in
// scope (entityIdOf, entityProjection, and the writer createEntityWriter returns). Keep it
// backtick-free: the fragment is a String.raw template.
//
// The forensic timeline's rows are matched to the list being saved BY EVENT ID, not by position.
// That timeline is kept in time order, so an import of earlier evidence inserts rows at the front:
// matched by position, every later row looked changed, and each of an import's five or six saves
// rewrote the payload, the value index and the term index of the whole case, while the worker held
// every stored payload in memory to compare them. Matched by id, a row that only moved gets its
// ordinal updated and nothing else, and keeps its row_id and term-index entry. Only ids, ordinals
// and row ids are held; a payload is read back one row at a time to compare.
//
// Event ids are meant to be unique, but a bulk append does not enforce it. Inside a group of
// duplicates the identical stored payload is matched first, so an unchanged duplicate keeps its
// row; only then the next in stored order. The ordinal is UNIQUE per kind, so every row that moves
// is first parked on a negative ordinal (-row_id, unique), then placed.
//
// Every other kind is small, and several have no id at all, so it keeps the positional rewrite it
// always had.
export const SAVE_STATE_WORKER_SOURCE = String.raw`
function writeStateKind(db, writer, kind, values) {
  if (kind === "forensicTimeline") return writeStateKindById(db, writer, kind, values);
  const existing = new Map(db.prepare(
    "SELECT row_id, ordinal, payload FROM entities WHERE kind=? ORDER BY ordinal"
  ).all(kind).map((row) => [row.ordinal, row]));
  for (let ordinal = 0; ordinal < values.length; ordinal++) {
    const projection = entityProjection(kind, values[ordinal], ordinal);
    const prior = existing.get(ordinal);
    if (!prior) writer.insert(projection, values[ordinal]);
    else if (prior.payload !== projection.payload) writer.update(prior.row_id, projection, values[ordinal]);
  }
  db.prepare("DELETE FROM entities WHERE kind=? AND ordinal>=?").run(kind, values.length);
}

function writeStateKindById(db, writer, kind, values) {
  const stored = db.prepare(
    "SELECT row_id, ordinal, entity_id FROM entities WHERE kind=? ORDER BY ordinal"
  ).all(kind);
  const byId = new Map();
  const idless = [];
  for (const row of stored) {
    if (row.entity_id == null) { idless.push(row); continue; }
    const group = byId.get(row.entity_id);
    if (group) { group.push(row); group.duplicated = true; } else byId.set(row.entity_id, [row]);
  }
  const readPayload = db.prepare("SELECT payload FROM entities WHERE row_id=?");
  const priors = new Array(values.length);
  const kept = new Set();
  const take = (ordinal, prior) => {
    kept.add(prior.row_id);
    priors[ordinal] = prior;
  };
  // Duplicate groups first, identical payloads only, so no other duplicate can claim that row.
  // Each stored duplicate's payload is read once into a payload -> rows bucket: linear, however
  // large or reordered the group.
  const buckets = new Map();
  for (let ordinal = 0; ordinal < values.length; ordinal++) {
    const entityId = entityIdOf(kind, values[ordinal]);
    const group = entityId == null ? null : byId.get(entityId);
    if (!group || !group.duplicated) continue;
    if (!buckets.has(entityId)) {
      const byPayload = new Map();
      for (const row of group) {
        const payload = readPayload.get(row.row_id).payload;
        const same = byPayload.get(payload);
        if (same) same.push(row); else byPayload.set(payload, [row]);
      }
      buckets.set(entityId, byPayload);
    }
    const same = buckets.get(entityId).get(entityProjection(kind, values[ordinal], ordinal).payload);
    const row = same && same.shift();
    if (row) take(ordinal, row);
  }
  // Then every entry still unmatched takes its group's next unclaimed row, in stored order. The
  // cursor only moves forward, so this pass is linear too.
  for (let ordinal = 0; ordinal < values.length; ordinal++) {
    if (priors[ordinal]) continue;
    const entityId = entityIdOf(kind, values[ordinal]);
    const group = entityId == null ? null : byId.get(entityId);
    if (!group) continue;
    let next = group.next || 0;
    while (next < group.length && kept.has(group[next].row_id)) next++;
    group.next = next + 1;
    if (next < group.length) take(ordinal, group[next]);
  }
  const deleteRow = db.prepare("DELETE FROM entities WHERE row_id=?");
  for (const row of stored) if (!kept.has(row.row_id)) deleteRow.run(row.row_id);
  const setOrdinal = db.prepare("UPDATE entities SET ordinal=? WHERE row_id=?");
  const setValueOrdinal = db.prepare("UPDATE entity_values SET ordinal=? WHERE row_id=?");
  for (let ordinal = 0; ordinal < values.length; ordinal++) {
    const prior = priors[ordinal];
    if (prior && prior.ordinal !== ordinal) setOrdinal.run(-prior.row_id, prior.row_id);
  }
  for (let ordinal = 0; ordinal < values.length; ordinal++) {
    const projection = entityProjection(kind, values[ordinal], ordinal);
    const prior = priors[ordinal];
    if (!prior) { writer.insert(projection, values[ordinal]); continue; }
    if (prior.ordinal !== ordinal) {
      setOrdinal.run(ordinal, prior.row_id);
      setValueOrdinal.run(ordinal, prior.row_id);
    }
    if (readPayload.get(prior.row_id).payload !== projection.payload) {
      writer.update(prior.row_id, projection, values[ordinal]);
    }
  }
}
`;
