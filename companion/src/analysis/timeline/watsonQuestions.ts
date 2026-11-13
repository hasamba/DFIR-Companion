import type { CollectDirective, InvestigationQuestion } from "../stateTypes.js";

/**
 * Every merge keeps the answers the analyst applied from Watson.
 *
 * Synthesis and import deltas replace keyQuestions wholesale, and the deterministic passes after the
 * synthesis pinned merge (the false-positive reset, the contradiction flag, the negative-answer
 * backstop) can still change a question. So the merge itself (assembleMerge), the synthesis fold's
 * last step and the locked synthesis persist all call this. Questions Watson never touched pass
 * through unchanged.
 *
 * A Watson question is PROTECTED when it holds Watson's information: a status other than "unknown"
 * or a non-empty answer, and no `answeredBy: "synthesis"`. It keeps its question, status, answer and
 * pointer; when synthesis ends on a DIFFERENT STATUS it says so in `synthesisDisagrees` instead.
 *
 * An UNANSWERED Watson question (a standard seed, a fresh new question) is not protected: synthesis
 * answers it, and the answer is marked `answeredBy: "synthesis"` so synthesis can keep updating it.
 * It keeps its id, `pinned` and `author`, so no merge drops it. Watson applying a new answer clears
 * the mark and protects the question again.
 */

const isWatson = (q: InvestigationQuestion | undefined): q is InvestigationQuestion => q?.author === "watson";

const holdsAnswer = (q: InvestigationQuestion): boolean => q.status !== "unknown" || q.answer.trim() !== "";

/** A Watson question whose answer synthesis may not overwrite. */
export function isProtectedWatson(q: InvestigationQuestion): boolean {
  return q.author === "watson" && q.answeredBy !== "synthesis" && holdsAnswer(q);
}

/** The fields an apply or undo is judged on. Annotations (disagreement, collect) do not count. */
export function sameAnswer(a: InvestigationQuestion, b: InvestigationQuestion): boolean {
  return a.status === b.status && a.answer === b.answer && a.pointer === b.pointer;
}

/**
 * Protected question `w`, given the run's copy `run` of the same id. A copy that agrees on the
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

/** Unprotected Watson question `w`: the run's answer, under Watson's id, question text and pin. */
function adoptRunAnswer(
  w: InvestigationQuestion,
  run: InvestigationQuestion | undefined,
): InvestigationQuestion {
  if (!run) return w;
  const { synthesisDisagrees: _d, answeredBy: _a, ...rest } = run;
  return {
    ...rest,
    question: w.question,
    pinned: true,
    author: "watson",
    ...(holdsAnswer(run) ? { answeredBy: "synthesis" as const } : {}),
  };
}

/** Watson question `w` against the run's copy: protected, or answered by the run. */
export function guardWatsonQuestion(
  w: InvestigationQuestion,
  run: InvestigationQuestion | undefined,
): InvestigationQuestion {
  return isProtectedWatson(w) ? protectWatsonQuestion(w, run) : adoptRunAnswer(w, run);
}

/**
 * Re-apply Watson protection over a finished list.
 *
 * - `questions`: the run's result.
 * - `latest`: the store's key questions now.
 * - `seen`: the store's key questions when the run read them.
 *
 * A question that is Watson's in `latest` or in `seen` but whose Watson answer changed between them
 * was applied or undone WHILE the run worked. The run never saw that decision, so the store's copy
 * wins outright (or the question goes, when an undo removed it). Otherwise the stored Watson
 * question is guarded against the run's copy, and one the run did not return is kept.
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
    decided.set(id, stable ? guardWatsonQuestion(l, run) : (l ?? null));
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

/** One key question as a model or import delta states it. */
export type DeltaKeyQuestion = Pick<
  InvestigationQuestion,
  "id" | "question" | "status" | "answer" | "pointer"
> & {
  relatedFindingIds?: string[];
  collect?: CollectDirective;
};

/**
 * The key questions a delta that provides them leaves (assembleMerge): the delta's set, wholesale,
 * with every stored Watson question kept or guarded as above.
 */
export function mergeKeyQuestions(
  stored: readonly InvestigationQuestion[],
  incoming: readonly DeltaKeyQuestion[],
  cleanCollect: (c: CollectDirective | undefined) => CollectDirective | undefined,
): InvestigationQuestion[] {
  const replaced = incoming.map((q) => {
    const collect = cleanCollect(q.collect);
    return {
      id: q.id,
      question: q.question,
      status: q.status,
      answer: q.answer,
      pointer: q.pointer,
      ...(q.relatedFindingIds?.length ? { relatedFindingIds: q.relatedFindingIds } : {}),
      ...(collect ? { collect } : {}),
    };
  });
  return keepWatsonAnswers(replaced, stored, stored);
}
