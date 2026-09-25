/**
 * How many clients a hunt reached, read from Velociraptor's hunt stats (#1612).
 *
 * An empty hunt result speaks only for the clients that ran the hunt. A hunt that reached no client,
 * or was collected before its scheduled clients finished, returns zero rows too — so the collect
 * records these counts, and an empty result settles an evidence class only with full coverage.
 *
 * `completed` is `total_finished_clients` when the server reports it, else
 * `total_clients_with_results` (older servers). If an old server counts only clients that returned
 * rows there, a clean empty reads as unfinished: the safe direction. Errors may also be counted as
 * finished, so a reader must require zero errors as well as full completion.
 *
 * Protobuf JSON omits a zero counter, so an ABSENT counter reads 0. A counter that is present but not
 * a non-negative safe integer voids the whole snapshot: coverage is then unknown, never assumed.
 */
export interface HuntClientCounts {
  scheduled: number;
  completed: number;
  errors: number;
}

function counter(stats: Record<string, unknown>, key: string): number {
  if (!(key in stats)) return 0;
  const v = stats[key];
  const n = typeof v === "number" || (typeof v === "string" && /^\d+$/.test(v)) ? Number(v) : NaN;
  return Number.isSafeInteger(n) && n >= 0 ? n : NaN;
}

/** The `stats` object of a `hunts()` row, as client counts; undefined when absent or malformed. */
export function parseHuntClientCounts(stats: unknown): HuntClientCounts | undefined {
  if (!stats || typeof stats !== "object" || Array.isArray(stats)) return undefined;
  const s = stats as Record<string, unknown>;
  const done = "total_finished_clients" in s ? "total_finished_clients" : "total_clients_with_results";
  const counts = {
    scheduled: counter(s, "total_clients_scheduled"),
    completed: counter(s, done),
    errors: counter(s, "total_clients_with_errors"),
  };
  return Object.values(counts).every(Number.isSafeInteger) ? counts : undefined;
}
