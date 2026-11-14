import { z } from "zod";
import { questionStatusSchema } from "../../responseSchema.js";

// The persisted shape of one Watson turn: a lenient parse shared by the chat file (chatStore.ts) and
// the append-only history file (historyStore.ts).

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
]);

const answerSchema = z.object({
  question: z.string(),
  status: questionStatusSchema,
  answer: z.string(),
  pointer: z.string(),
  relatedEventIds: z.array(z.string()).catch([]),
  matchesQuestionId: z.string().optional().catch(undefined),
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
  veloNote: z.string().optional().catch(undefined),
});
