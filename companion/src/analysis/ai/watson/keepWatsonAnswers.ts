import type { InvestigationQuestion } from "../../stateTypes.js";

/**
 * Synthesis keeps the answers the analyst applied from Watson.
 *
 * Synthesis replaces keyQuestions wholesale, and several deterministic passes after the pinned merge
 * (the false-positive reset, the contradiction flag, the negative-answer backstop) and the merge
 * itself (which drops `author`) can still change a question. So the fold calls this as its LAST
 * step, and the locked persist calls it again against the store. A Watson question keeps its own
 * question, status, answer and pointer; when synthesis ends on a DIFFERENT STATUS it says so in
 * `synthesisDisagrees` instead. Questions Watson never touched pass through unchanged.
 */

const isWatson = (q: InvestigationQuestion | undefined): q is InvestigationQuestion => q?.author === "watson";

/** The fields an apply or undo is judged on. Annotations (disagreement, collect) do not count. */
export function sameAnswer(a: InvestigationQuestion, b: InvestigationQuestion): boolean {
  return a.status === b.status && a.answer === b.answer && a.pointer === b.pointer;
}

/**
 * Watson's question `w`, given synthesis's copy `run` of the same id. A copy that agrees on the
 * status keeps whatever disagreement it carries (none for a fresh model copy, the recorded one for
 * a copy this function already produced), so calling it twice gives the same result.
 */
export function protectWatsonQuestion(
  w: InvestigationQuestion,
  run: InvestigationQuestion | undefined,
): InvestigationQuestion {
  const { synthesisDisagrees: _old, contradicted: _c, staleReSynth: _s, collect: ownCollect, ...own } = w;
  if (!run) return w;
  const disagrees =
    run.status !== w.status ? { status: run.status, answer: run.answer } : run.synthesisDisagrees;
  // A copy already protected (author kept) holds Watson's collect plus anything the passes after the
  // pinned merge added or stamped (the coverage backstop, the import high-water stamp). A fresh model
  // copy's collect belongs to the model's answer, so Watson's own stays.
  const collect = run.author === "watson" ? run.collect : ownCollect;
  return {
    ...own,
    pinned: true,
    author: "watson",
    // This run's deterministic flags, computed over Watson's answer once the pinned merge kept it.
    ...(run.contradicted ? { contradicted: run.contradicted } : {}),
    ...(collect ? { collect } : {}),
    ...(run.staleReSynth ? { staleReSynth: run.staleReSynth } : {}),
    ...(disagrees ? { synthesisDisagrees: disagrees } : {}),
  };
}

/**
 * Re-apply Watson protection over a finished list.
 *
 * - `questions`: the run's result.
 * - `latest`: the store's key questions now.
 * - `seen`: the copy the run reasoned over (the fold: its snapshot; the persist: the fold's result).
 *
 * A question that is Watson's in `latest` or in `seen` but whose Watson answer changed between them
 * was applied or undone WHILE the run worked. The run never saw that decision, so the store's copy
 * wins outright (or the question goes, when an undo removed it). Otherwise Watson's stored answer is
 * protected against the run's copy.
 */
export function keepWatsonAnswers(
  questions: readonly InvestigationQuestion[],
  latest: readonly InvestigationQuestion[],
  seen: readonly InvestigationQuestion[],
): InvestigationQuestion[] {
  const latestById = new Map(latest.map((q) => [q.id, q] as const));
  const seenById = new Map(seen.map((q) => [q.id, q] as const));
  const ids = new Set([...latest.filter(isWatson), ...seen.filter(isWatson)].map((q) => q.id));
  if (ids.size === 0) return [...questions];

  const decided = new Map<string, InvestigationQuestion | null>();
  for (const id of ids) {
    const l = latestById.get(id);
    const s = seenById.get(id);
    const stable = isWatson(l) && isWatson(s) && sameAnswer(l, s);
    const run = questions.find((q) => q.id === id);
    decided.set(id, stable ? protectWatsonQuestion(l, run) : (l ?? null));
  }

  const out: InvestigationQuestion[] = [];
  for (const q of questions) {
    if (!decided.has(q.id)) out.push(q);
    else {
      const d = decided.get(q.id);
      if (d) out.push(d);
      decided.delete(q.id);
    }
  }
  // Watson questions the run did not return (e.g. a question applied during the run) are appended.
  for (const d of decided.values()) if (d) out.push(d);
  return out;
}
