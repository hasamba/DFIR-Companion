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
// A row keeps its ordinal whenever the order allows (keepOrdinals below): ordinals are an order, not
// a position, so an import of earlier evidence moves no stored row unless the gap it lands in is full.
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

// The spacing a respaced timeline gets, and the widest step between rows placed into one gap: a run of
// later imports appending after the same row then finds room many times before the gap is used up.
const ORDINAL_GAP = 1024;
const ORDINAL_STEP_MAX = 64;
// Ordinals stay far below 2^53 (exact in a JS number); a respace resets them to (i + 1) * ORDINAL_GAP.
const ORDINAL_MAX = 2 ** 50;

// New ordinals for a list whose i-th entry currently sits at own[i] (undefined: a new row), in list
// order (#1874). Ordinals are only an order — every reader sorts or pages by them — so the longest run
// of rows already in order keeps its ordinals and every other row takes a free one in the gap where it
// now belongs. Only when a gap is too small is the whole list respaced, with room left between every
// two rows, so the next save (or the importer merge) finds room instead of renumbering the case.
function keepOrdinals(own) {
  const n = own.length;
  // Longest strictly increasing subsequence of the known ordinals (patience sorting, O(n log n)).
  const tails = [];
  const tailAt = [];
  const back = new Array(n).fill(-1);
  for (let i = 0; i < n; i++) {
    const o = own[i];
    if (o === undefined) continue;
    let lo = 0, hi = tails.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (tails[mid] < o) lo = mid + 1; else hi = mid; }
    tails[lo] = o;
    tailAt[lo] = i;
    back[i] = lo > 0 ? tailAt[lo - 1] : -1;
  }
  const assigned = new Array(n);
  const anchor = new Array(n).fill(false);
  for (let i = tails.length ? tailAt[tails.length - 1] : -1; i >= 0; i = back[i]) {
    anchor[i] = true;
    assigned[i] = own[i];
  }
  if (!fillOrdinalGaps(assigned, anchor)) respaceOrdinals(assigned);
  return assigned;
}

// Every row ORDINAL_GAP apart, from ORDINAL_GAP.
function respaceOrdinals(assigned) {
  for (let k = 0; k < assigned.length; k++) assigned[k] = (k + 1) * ORDINAL_GAP;
}

// The rows between two anchors (rows keeping their ordinal) take free ordinals in the gap between
// them, at most ORDINAL_STEP_MAX apart; past the last anchor, ORDINAL_GAP apart. False (assigned then
// incomplete) when some gap is too small or an ordinal would pass ORDINAL_MAX.
function fillOrdinalGaps(assigned, anchor) {
  const n = assigned.length;
  // Nothing stored to keep (a first save): 0..n-1, as a save always wrote them.
  if (!anchor.some(Boolean)) {
    for (let k = 0; k < n; k++) assigned[k] = k;
    return true;
  }
  for (let i = 0, prev = -1; i < n; ) {
    if (anchor[i]) { prev = assigned[i]; i++; continue; }
    let j = i;
    while (j < n && !anchor[j]) j++;
    const count = j - i;
    if (j === n) {
      if (prev + ORDINAL_GAP * count > ORDINAL_MAX) return false;
      for (let k = 0; k < count; k++) assigned[i + k] = prev + ORDINAL_GAP * (k + 1);
    } else if (assigned[j] - prev - 1 >= count) {
      const step = Math.min((assigned[j] - prev) / (count + 1), ORDINAL_STEP_MAX);
      for (let k = 0; k < count; k++) assigned[i + k] = prev + Math.floor(step * (k + 1));
    } else {
      return false;
    }
    i = j;
  }
  return true;
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
  const assigned = keepOrdinals(priors.map((prior) => (prior ? prior.ordinal : undefined)));
  for (let i = 0; i < values.length; i++) {
    const prior = priors[i];
    if (prior && prior.ordinal !== assigned[i]) setOrdinal.run(-prior.row_id, prior.row_id);
  }
  for (let i = 0; i < values.length; i++) {
    const projection = entityProjection(kind, values[i], assigned[i]);
    const prior = priors[i];
    if (!prior) { writer.insert(projection, values[i]); continue; }
    if (prior.ordinal !== assigned[i]) {
      setOrdinal.run(assigned[i], prior.row_id);
      setValueOrdinal.run(assigned[i], prior.row_id);
    }
    if (readPayload.get(prior.row_id).payload !== projection.payload) {
      writer.update(prior.row_id, projection, values[i]);
    }
  }
}
`;
