import { z } from "zod";
import { questionStatusSchema } from "../../responseSchema.js";
import type { QuestionStatus } from "../../stateTypes.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import type { WatsonRequest } from "./types.js";

// Boundary for the model's JSON reply. The reply is untrusted: every field is lenient (.catch),
// and sanitizeWatsonReply clamps lengths and drops references to ids that do not exist.

const MAX_NEW_QUESTIONS = 3;
const MAX_SEARCH_TERMS = 8;
const MAX_TERM_CHARS = 200;
const MAX_MEMORY_CHARS = 4000;
const MAX_QUERY_CHARS = 20000;
const LANGUAGES = ["vql", "kql", "spl", "cql", "esql", "sql", "other"];

const str = z.string().catch("");

const requestSchema = z
  .union([
    z.object({ kind: z.literal("query"), language: str, query: str, why: str }),
    z.object({ kind: z.literal("import"), what: str, why: str }),
  ])
  .nullable()
  .catch(null);

export const watsonReplySchema = z.object({
  message: str,
  workingOn: str,
  learned: str,
  questionUpdates: z
    .array(z.object({ questionId: str, status: questionStatusSchema, answer: str, pointer: str }))
    .catch([]),
  newQuestions: z.array(z.object({ question: str, why: str })).catch([]),
  request: requestSchema,
  search: z
    .object({ pasteId: str, terms: z.array(z.string()).catch([]) })
    .nullable()
    .catch(null),
  memory: str,
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

export function sanitizeWatsonReply(
  reply: WatsonReply,
  knownQuestionIds: ReadonlySet<string>,
  knownPasteIds: ReadonlySet<string>,
): WatsonReply {
  const search =
    reply.search && knownPasteIds.has(reply.search.pasteId)
      ? {
          pasteId: reply.search.pasteId,
          terms: reply.search.terms.slice(0, MAX_SEARCH_TERMS).map((t) => t.slice(0, MAX_TERM_CHARS)),
        }
      : null;
  return {
    ...reply,
    message: reply.message.slice(0, WATSON_TURN_TEXT_MAX),
    memory: reply.memory.slice(0, MAX_MEMORY_CHARS),
    questionUpdates: reply.questionUpdates.filter((u) => knownQuestionIds.has(u.questionId)),
    newQuestions: reply.newQuestions.slice(0, MAX_NEW_QUESTIONS),
    request: sanitizeRequest(reply.request),
    search,
  };
}
