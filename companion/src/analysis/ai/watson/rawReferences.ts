import type { WatsonReply } from "./replySchema.js";
import type { WatsonChat } from "./types.js";

// D4 / D6b: which reply items reference a raw super-timeline row, and what survives once promotion
// lands, is withheld or fails. Pure: nothing here reads a store or writes. A reference is a structured
// citation (answer.relatedEventIds, findings[].eventIds) or a whole-token mention, in a case-bound
// text field, of an id a super-timeline search showed Watson. Chat `message`, `learned` and `memory`
// are not citations (they are masked instead). Any other token is not recognised as an id.

/** Every reply item that can reach the case, with the ids its structured fields cite and its text names. */
export type RefItem =
  | { kind: "answer" }
  | { kind: "questionUpdate"; index: number }
  | { kind: "newQuestion"; index: number }
  | { kind: "finding"; index: number }
  | { kind: "nextStep"; index: number }
  | { kind: "report"; index: number };

export interface RawRefs {
  item: RefItem;
  ids: string[];
}

type ListKind = Exclude<RefItem["kind"], "answer">;

/** The key `settleRawRefs` uses for an item's evidence: `${kind}:${index}`, or `answer` for the answer. */
export const refKey = (item: RefItem): string =>
  item.kind === "answer" ? "answer" : `${item.kind}:${item.index}`;

// An id is its own token-part when neither neighbour is a letter, digit or underscore, whatever joins
// it ("e1-raw1", "raw1-related", "...raw1", "raw1:4624", "raw1.5" all name raw1). Controller ruling
// (Task 5 re-review NEW-I1): no exceptions — over-matching only promotes a shown row or drops the
// item, while under-matching would let an unpromoted raw id reach the case.
const WORD = /[A-Za-z0-9_]/;

const isWord = (c: string | undefined): boolean => c !== undefined && WORD.test(c);

const isMention = (text: string, at: number, id: string): boolean =>
  !isWord(text[at - 1]) && !isWord(text[at + id.length]);

function mentionsAt(text: string, id: string): number | null {
  let from = 0;
  while (id !== "") {
    const at = text.indexOf(id, from);
    if (at < 0) return null;
    if (isMention(text, at, id)) return at;
    from = at + 1;
  }
  return null;
}

/** Whole-token mentions of `candidates` in `text` (see isMention for what bounds a token). */
export function mentionedIds(text: string, candidates: ReadonlySet<string>): string[] {
  if (text === "") return [];
  return [...candidates]
    .flatMap((id) => {
      const at = mentionsAt(text, id);
      return at === null ? [] : [{ id, at }];
    })
    .sort((a, b) => a.at - b.at)
    .map((m) => m.id);
}

/** All ids shown by earlier super-timeline searches in this chat (turn.lookedUp.shownIds). */
export function earlierShownIds(chat: Pick<WatsonChat, "turns">): Set<string> {
  return new Set(chat.turns.flatMap((t) => t.lookedUp?.shownIds ?? []));
}

function idsOf(structured: readonly string[], texts: readonly string[], raw: ReadonlySet<string>): string[] {
  const cited = structured.filter((id) => raw.has(id));
  return [...new Set([...cited, ...texts.flatMap((t) => mentionedIds(t, raw))])];
}

function listRefs<T>(
  items: readonly T[],
  kind: ListKind,
  read: (item: T) => { structured?: string[]; texts: string[] },
  raw: ReadonlySet<string>,
): RawRefs[] {
  return items.flatMap((x, index) => {
    const { structured = [], texts } = read(x);
    const ids = idsOf(structured, texts, raw);
    return ids.length ? [{ item: { kind, index }, ids }] : [];
  });
}

/** Per item: the raw ids it references, among `raw` (this round's shown ∪ earlier shown, minus live forensic). */
export function collectRawRefs(reply: WatsonReply, raw: ReadonlySet<string>): RawRefs[] {
  if (raw.size === 0) return [];
  const a = reply.answer;
  const answerIds = a ? idsOf(a.relatedEventIds, [a.question, a.answer, a.pointer], raw) : [];
  const w = reply.writes;
  return [
    ...(answerIds.length ? [{ item: { kind: "answer" } as RefItem, ids: answerIds }] : []),
    ...listRefs(reply.questionUpdates, "questionUpdate", (u) => ({ texts: [u.answer, u.pointer] }), raw),
    ...listRefs(reply.newQuestions, "newQuestion", (q) => ({ texts: [q.question, q.why] }), raw),
    ...listRefs(
      w.findings,
      "finding",
      (d) => ({ structured: d.eventIds, texts: [d.title, d.description] }),
      raw,
    ),
    ...listRefs(w.nextSteps, "nextStep", (st) => ({ texts: [st.action, st.rationale, st.pointer] }), raw),
    ...listRefs(w.report, "report", (r) => ({ texts: [r.text] }), raw),
  ];
}

/** Structured citations with each referenced raw id swapped for its canonical id (unlanded ones removed). */
function rewriteIds(
  ids: readonly string[],
  refIds: ReadonlySet<string>,
  landed: ReadonlyMap<string, string>,
): string[] {
  return [
    ...new Set(
      ids.flatMap((id) => (refIds.has(id) ? (landed.has(id) ? [landed.get(id) as string] : []) : [id])),
    ),
  ];
}

const canonicalOf = (ids: readonly string[], landed: ReadonlyMap<string, string>): string[] => [
  ...new Set(ids.flatMap((id) => (landed.has(id) ? [landed.get(id) as string] : []))),
];

interface ListSettled<T> {
  kept: T[];
  dropped: number;
  evidence: [string, string[]][];
}

/** Keep an item only when every raw id it references landed; evidence keys use the surviving index. */
function settleList<T>(
  items: readonly T[],
  kind: ListKind,
  refs: ReadonlyMap<string, RawRefs>,
  landed: ReadonlyMap<string, string>,
  rewrite: (item: T, refIds: ReadonlySet<string>) => T = (item) => item,
): ListSettled<T> {
  return items.reduce<ListSettled<T>>(
    (acc, item, index) => {
      const ref = refs.get(refKey({ kind, index }));
      if (!ref) return { ...acc, kept: [...acc.kept, item] };
      if (!ref.ids.every((id) => landed.has(id))) return { ...acc, dropped: acc.dropped + 1 };
      const key = refKey({ kind, index: acc.kept.length });
      return {
        ...acc,
        kept: [...acc.kept, rewrite(item, new Set(ref.ids))],
        evidence: [...acc.evidence, [key, canonicalOf(ref.ids, landed)]],
      };
    },
    { kept: [], dropped: 0, evidence: [] },
  );
}

/** The chat answer is chat, never dropped: it only loses unlanded raw ids from relatedEventIds. */
function settleAnswer(
  reply: WatsonReply,
  ref: RawRefs | undefined,
  landed: ReadonlyMap<string, string>,
): { answer: WatsonReply["answer"]; evidence: [string, string[]][] } {
  const a = reply.answer;
  if (!a || !ref) return { answer: a, evidence: [] };
  const relatedEventIds = rewriteIds(a.relatedEventIds, new Set(ref.ids), landed);
  const canon = canonicalOf(ref.ids, landed);
  return { answer: { ...a, relatedEventIds }, evidence: canon.length ? [["answer", canon]] : [] };
}

/**
 * The reply after promotion: `landed` maps a this-round raw id to its canonical forensic id; every item
 * referencing a raw id NOT in `landed` is dropped whole (answer: only its relatedEventIds lose the id);
 * structured citations are rewritten to canonical ids. Returns the reply, how many items were dropped,
 * and per surviving item its canonical rawEvidenceIds, keyed by `refKey` at the item's index in the
 * RETURNED reply (the index proposals are built from).
 */
export function settleRawRefs(
  reply: WatsonReply,
  refs: readonly RawRefs[],
  landed: ReadonlyMap<string, string>,
): { reply: WatsonReply; dropped: number; evidence: Map<string, string[]> } {
  const byKey = new Map(refs.map((r) => [refKey(r.item), r]));
  const w = reply.writes;
  const ans = settleAnswer(reply, byKey.get("answer"), landed);
  const updates = settleList(reply.questionUpdates, "questionUpdate", byKey, landed);
  const questions = settleList(reply.newQuestions, "newQuestion", byKey, landed);
  const findings = settleList(w.findings, "finding", byKey, landed, (d, ids) => ({
    ...d,
    eventIds: rewriteIds(d.eventIds, ids, landed),
  }));
  const steps = settleList(w.nextSteps, "nextStep", byKey, landed);
  const report = settleList(w.report, "report", byKey, landed);
  const lists = [updates, questions, findings, steps, report];
  return {
    reply: {
      ...reply,
      answer: ans.answer,
      questionUpdates: updates.kept,
      newQuestions: questions.kept,
      writes: { findings: findings.kept, nextSteps: steps.kept, report: report.kept },
    },
    dropped: lists.reduce((n, l) => n + l.dropped, 0),
    evidence: new Map([...ans.evidence, ...lists.flatMap((l) => l.evidence)]),
  };
}
