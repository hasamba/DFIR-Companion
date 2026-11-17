import { z } from "zod";
import { questionStatusSchema } from "../../responseSchema.js";
import { WATSON_MAX_TOOL_CALLS_CEILING } from "./toolMode.js";

// The persisted shape of one Watson turn: a lenient parse shared by the chat file (chatStore.ts) and
// the append-only history file (historyStore.ts).

/** A super-timeline search shows at most 100 rows, so a turn records at most 100 shown ids. */
const WATSON_SHOWN_IDS_MAX = 100;

const requestSchema = z.union([
  z.object({ kind: z.literal("query"), language: z.string(), query: z.string(), why: z.string() }),
  z.object({ kind: z.literal("import"), what: z.string(), why: z.string() }),
  z.object({
    kind: z.literal("velociraptor"),
    mode: z.enum(["hunt", "collection"]).catch("collection"),
    hostname: z.string().optional().catch(undefined),
    title: z.string().catch(""),
    vql: z.string().catch(""),
    why: z.string().catch(""),
  }),
  z.object({
    kind: z.literal("crowdstrike_search"),
    title: z.string().catch(""),
    query: z.string().catch(""),
    start: z.string().optional().catch(undefined),
    end: z.string().optional().catch(undefined),
    why: z.string().catch(""),
  }),
]);

const answerSchema = z.object({
  question: z.string(),
  status: questionStatusSchema,
  answer: z.string(),
  pointer: z.string(),
  relatedEventIds: z.array(z.string()).catch([]),
  matchesQuestionId: z.string().optional().catch(undefined),
});

const lookedUpSchema = z.object({
  shown: z.number(),
  matched: z.number(),
  what: z.string(),
  source: z.enum(["supertimeline", "paste", "history"]).optional().catch(undefined),
  matchedIsFloor: z.boolean().optional().catch(undefined),
  capEvicted: z.number().optional().catch(undefined),
  shownIds: z.array(z.string()).max(WATSON_SHOWN_IDS_MAX).optional().catch(undefined),
});

export const turnSchema = z.object({
  id: z.string(),
  at: z.string(),
  role: z.enum(["analyst", "watson", "system"]),
  text: z.string(),
  actor: z.string().optional(),
  workingOn: z.string().optional(),
  learned: z.string().optional(),
  request: requestSchema.optional(),
  proposalIds: z.array(z.string()).optional(),
  pasteId: z.string().optional(),
  error: z.boolean().optional(),
  costUSD: z.number().optional(),
  inputTokens: z.number().nonnegative().optional().catch(undefined),
  cacheReadTokens: z.number().nonnegative().optional().catch(undefined),
  coverage: z
    .object({
      usedEvents: z.number(),
      eventCount: z.number(),
      decisionsTrimmed: z.boolean().optional(),
      headTrimmed: z.boolean().optional(),
    })
    .optional(),
  answer: answerSchema.optional().catch(undefined),
  answerProposalId: z.string().optional(),
  answerRawEvidenceIds: z.array(z.string()).optional().catch(undefined),
  veloNote: z.string().optional().catch(undefined),
  lookedUp: lookedUpSchema.optional().catch(undefined),
  lookups: z
    .array(lookedUpSchema.nullable().catch(null))
    .optional()
    .transform((a) =>
      a?.filter((l): l is NonNullable<typeof l> => l !== null).slice(0, WATSON_MAX_TOOL_CALLS_CEILING),
    )
    .catch(undefined),
  superCapHit: z.boolean().optional().catch(undefined),
  superCapLimit: z.number().optional().catch(undefined),
});
