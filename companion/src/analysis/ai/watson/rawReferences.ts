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

const ID_CHAR = /[\w.:-]/;
const SEPARATOR = /[.:-]/;
const SENTENCE_START = /[A-Z]/;

const isIdChar = (c: string | undefined): boolean => c !== undefined && ID_CHAR.test(c);

/** A candidate id that starts at `at` and is itself closed there: the right end of a range ("raw1-raw3"). */
function candidateAt(text: string, at: number, candidates: ReadonlySet<string>): boolean {
  for (const id of candidates) {
    if (id !== "" && text.startsWith(id, at) && closesToken(text, at + id.length, candidates)) return true;
  }
  return false;
}

/**
 * True when `text[end]` closes a token: the text ends, the next char is outside [\w.:-], or a run of
 * `.`/`:`/`-` follows and then the token ends ("see raw1." names raw1; "raw1.5" and "raw1:x" do not).
 * A run before another candidate id is a range or a joined pair ("raw1-raw3"); a full stop before a
 * capital letter is a sentence end with no space ("raw1.Next").
 */
function closesToken(text: string, end: number, candidates: ReadonlySet<string>): boolean {
  let i = end;
  while (i < text.length && SEPARATOR.test(text[i] ?? "")) i++;
  if (i >= text.length || !isIdChar(text[i])) return true;
  if (i === end) return false;
  if (text[i - 1] === "." && SENTENCE_START.test(text[i] ?? "")) return true;
  return candidateAt(text, i, candidates);
}

/** The id at `at` is not the tail of a longer token: start of text, a non-id char, ':' or an ellipsis. */
function opensToken(text: string, at: number): boolean {
  const prev = text[at - 1];
  if (at === 0 || !isIdChar(prev) || prev === ":") return true;
  if (prev !== ".") return false;
  let i = at - 1;
  while (i > 0 && text[i - 1] === ".") i--;
  return at - i >= 3 || i === 0 || !isIdChar(text[i - 1]);
}

function mentionsAt(text: string, id: string, candidates: ReadonlySet<string>): number | null {
  let from = 0;
  while (id !== "") {
    const at = text.indexOf(id, from);
    if (at < 0) return null;
    if (
      (opensToken(text, at) || rangeEnd(text, at, candidates)) &&
      closesToken(text, at + id.length, candidates)
    )
      return at;
    from = at + 1;
  }
  return null;
}

/** The id at `at` follows a separator run that closes another candidate: "raw1-raw3" names raw3. */
function rangeEnd(text: string, at: number, candidates: ReadonlySet<string>): boolean {
  let i = at;
  while (i > 0 && SEPARATOR.test(text[i - 1] ?? "")) i--;
  if (i === at) return false;
  for (const id of candidates) {
    const start = i - id.length;
    if (id !== "" && start >= 0 && text.startsWith(id, start) && opensToken(text, start)) return true;
  }
  return false;
}

/** Whole-token mentions of `candidates` in `text` (see opensToken / closesToken for what bounds a token). */
export function mentionedIds(text: string, candidates: ReadonlySet<string>): string[] {
  if (text === "") return [];
  return [...candidates]
    .flatMap((id) => {
      const at = mentionsAt(text, id, candidates);
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
  const answerIds = a ? idsOf(a.relatedEventIds, [a.answer, a.pointer], raw) : [];
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
