import type { ToolTurn } from "../../../providers/toolCalling.js";

// The per-question budget for tool-result text (D4c, R1). Before each send, while the results exceed
// the budget, the OLDEST result is replaced by a stub, one at a time. No result of the newest tool
// turn is stubbed (review M1): the model reads every result of its latest batch at least once. Only the model's copy is shortened: the card's lookups and the roster keep everything.

export const TRIMMED_RESULT = "(result trimmed to save cost)";

type ResultAt = { turn: number; index: number; size: number };

function resultsOf(turns: readonly ToolTurn[]): ResultAt[] {
  return turns.flatMap((t, turn) =>
    t.role === "tool" ? t.results.map((r, index) => ({ turn, index, size: r.content.length })) : [],
  );
}

/** The transcript with the oldest results stubbed until the results fit `budget`. Pure. */
export function fitTranscript(turns: readonly ToolTurn[], budget: number): ToolTurn[] {
  const all = resultsOf(turns);
  let total = all.reduce((n, r) => n + r.size, 0);
  const newest = all.at(-1)?.turn;
  const stub = new Set<string>();
  for (const r of all.filter((x) => x.turn !== newest)) {
    if (total <= budget) break;
    if (r.size <= TRIMMED_RESULT.length) continue;
    stub.add(`${r.turn}:${r.index}`);
    total -= r.size - TRIMMED_RESULT.length;
  }
  if (stub.size === 0) return [...turns];
  return turns.map((t, turn) =>
    t.role !== "tool"
      ? t
      : {
          ...t,
          results: t.results.map((r, index) =>
            stub.has(`${turn}:${index}`) ? { ...r, content: TRIMMED_RESULT } : r,
          ),
        },
  );
}
