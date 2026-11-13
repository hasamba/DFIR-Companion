import { z } from "zod";
import { questionStatusSchema } from "../../responseSchema.js";
import type { QuestionStatus } from "../../stateTypes.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { WATSON_HISTORY_ID } from "./historyStore.js";
import { ANSWER_MAX, POINTER_MAX, QUESTION_MAX } from "./roundProposals.js";
import type { WatsonAnswer, WatsonRequest } from "./types.js";

// Boundary for the model's JSON reply. The reply is untrusted: every field is lenient (.catch),
// and sanitizeWatsonReply clamps lengths and drops references to ids that do not exist.

const MAX_NEW_QUESTIONS = 3;
const MAX_SEARCH_TERMS = 8;
const MAX_TERM_CHARS = 200;
const MAX_MEMORY_CHARS = 4000;
const MAX_QUERY_CHARS = 20000;
const MAX_ANSWER_EVENTS = 20;
const LANGUAGES = ["vql", "kql", "spl", "cql", "esql", "sql", "other"];

const str = z.string().catch("");

// Parse an array element by element: a bad element is dropped, the valid ones stay.
function lenientArray<T extends z.ZodTypeAny>(element: T) {
  return z
    .array(z.unknown())
    .catch([])
    .transform((items) =>
      items.flatMap((item) => {
        const parsed = element.safeParse(item);
        return parsed.success ? [parsed.data as z.infer<T>] : [];
      }),
    );
}

const requestSchema = z
  .union([
    z.object({ kind: z.literal("query"), language: str, query: str, why: str }),
    z.object({ kind: z.literal("import"), what: str, why: str }),
  ])
  .nullable()
  .catch(null);

const answerSchema = z
  .object({
    question: str,
    status: questionStatusSchema,
    answer: str,
    pointer: str,
    relatedEventIds: lenientArray(z.string()),
  })
  .nullable()
  .catch(null);

export const watsonReplySchema = z.object({
  message: str,
  workingOn: str,
  learned: str,
  questionUpdates: lenientArray(
    z.object({ questionId: str, status: questionStatusSchema, answer: str, pointer: str }),
  ),
  newQuestions: lenientArray(z.object({ question: str, why: str })),
  request: requestSchema,
  search: z
    .object({ pasteId: str, terms: lenientArray(z.string()) })
    .nullable()
    .catch(null),
  memory: str,
  answer: answerSchema,
});

export interface WatsonReply {
  message: string;
  workingOn: string;
  learned: string;
  questionUpdates: { questionId: string; status: QuestionStatus; answer: string; pointer: string }[];
  newQuestions: { question: string; why: string }[];
  request: WatsonRequest | null;
  search: { pasteId: string; terms: string[] } | null;
  memory: string;
  /** Set only when the analyst asked a question about the case. */
  answer: WatsonAnswer | null;
}

function sanitizeRequest(req: WatsonRequest | null): WatsonRequest | null {
  if (!req) return null;
  if (req.kind === "import") return req;
  const lang = req.language.trim().toLowerCase();
  return {
    ...req,
    language: LANGUAGES.includes(lang) ? lang : "other",
    query: req.query.slice(0, MAX_QUERY_CHARS),
  };
}

/**
 * The free-form answer: cited ids kept only when they are in the case's forensic timeline, texts
 * capped, and `unanswerable` turned into `unknown` (only an approved Watson proposal may set it).
 * An answer with no question is no answer.
 */
export function sanitizeAnswer(
  answer: WatsonAnswer | null,
  knownEventIds: ReadonlySet<string>,
): WatsonAnswer | null {
  if (!answer || answer.question.trim() === "") return null;
  return {
    question: answer.question.slice(0, QUESTION_MAX),
    status: answer.status === "unanswerable" ? "unknown" : answer.status,
    answer: answer.answer.slice(0, ANSWER_MAX),
    pointer: answer.pointer.slice(0, POINTER_MAX),
    relatedEventIds: [...new Set(answer.relatedEventIds.filter((id) => knownEventIds.has(id)))].slice(
      0,
      MAX_ANSWER_EVENTS,
    ),
  };
}

export function sanitizeWatsonReply(
  reply: WatsonReply,
  knownQuestionIds: ReadonlySet<string>,
  knownPasteIds: ReadonlySet<string>,
  knownEventIds: ReadonlySet<string>,
): WatsonReply {
  const search =
    reply.search && (reply.search.pasteId === WATSON_HISTORY_ID || knownPasteIds.has(reply.search.pasteId))
      ? {
          pasteId: reply.search.pasteId,
          terms: reply.search.terms
            .filter((t) => t.trim() !== "")
            .slice(0, MAX_SEARCH_TERMS)
            .map((t) => t.slice(0, MAX_TERM_CHARS)),
        }
      : null;
  return {
    ...reply,
    message: reply.message.slice(0, WATSON_TURN_TEXT_MAX),
    memory: reply.memory.slice(0, MAX_MEMORY_CHARS),
    questionUpdates: reply.questionUpdates.filter((u) => knownQuestionIds.has(u.questionId)),
    newQuestions: reply.newQuestions.filter((q) => q.question.trim() !== "").slice(0, MAX_NEW_QUESTIONS),
    request: sanitizeRequest(reply.request),
    search,
    answer: sanitizeAnswer(reply.answer, knownEventIds),
  };
}
