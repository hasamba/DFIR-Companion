// A bounded sink of row shapes with rank eviction, shared by the network telemetry rows (#996).
// A shape is everything a row's words and envelope show; a repeated shape folds with a count
// and an earliest time. The sink holds at most `max` distinct shapes: a new shape past the bound
// folds into the overflow row for its source — unless it outranks a retained lower shape, in
// which case the lowest-ranked retained shape is the one that folds, so upload order cannot hide
// the evidence a rank names behind a wall of plain rows. Overflow rows do not count.

export interface ShapeRow<T> {
  key: string;
  source: string;
  first?: T;
  count: number;
  firstTs: string;
  rank: number;
  overflow?: boolean;
}

export interface ShapeSink<T> {
  rows: Map<string, ShapeRow<T>>;
  byRank: Set<string>[];
  max: number;
  overflowKey: (source: string) => string;
}

export function newShapeSink<T>(
  max: number,
  ranks: number,
  overflowKey: (source: string) => string,
): ShapeSink<T> {
  return {
    rows: new Map(),
    byRank: Array.from({ length: ranks }, () => new Set<string>()),
    max,
    overflowKey,
  };
}

export function foldOverflow<T>(sink: ShapeSink<T>, source: string, ts: string, n: number): void {
  const ok = sink.overflowKey(source);
  const over = sink.rows.get(ok);
  if (over) {
    over.count += n;
    if (ts && (!over.firstTs || ts < over.firstTs)) over.firstTs = ts;
  } else sink.rows.set(ok, { key: ok, source, count: n, firstTs: ts, rank: 0, overflow: true });
}

export function foldShape<T>(
  sink: ShapeSink<T>,
  shape: { key: string; source: string; ts: string; first: T; rank: number },
): void {
  const { key, source, ts, first, rank } = shape;
  const existing = sink.rows.get(key);
  if (existing) {
    existing.count += 1;
    if (ts && (!existing.firstTs || ts < existing.firstTs)) existing.firstTs = ts;
    return;
  }
  const retained = sink.byRank.reduce((n, set) => n + set.size, 0);
  if (retained >= sink.max) {
    const lower = sink.byRank.findIndex((set, i) => i < rank && set.size > 0);
    if (lower < 0) {
      foldOverflow(sink, source, ts, 1);
      return;
    }
    const victimKey = sink.byRank[lower].values().next().value as string;
    const victim = sink.rows.get(victimKey)!;
    sink.byRank[lower].delete(victimKey);
    sink.rows.delete(victimKey);
    foldOverflow(sink, victim.source, victim.firstTs, victim.count);
  }
  sink.rows.set(key, { key, source, first, count: 1, firstTs: ts, rank });
  sink.byRank[rank].add(key);
}

/** Highest rank first, then the most seen, then the earliest — up to `budget`. */
export function rankedRows<T>(sink: ShapeSink<T>, budget: number): ShapeRow<T>[] {
  return [...sink.rows.values()]
    .sort((a, b) => b.rank - a.rank || b.count - a.count || a.firstTs.localeCompare(b.firstTs))
    .slice(0, budget);
}
