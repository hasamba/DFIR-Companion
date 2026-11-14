import { z } from "zod";
import type { Finding, ForensicEvent, InvestigationQuestion, NextStep } from "../../stateTypes.js";
import type { WatsonProposal } from "./types.js";

// The persisted shape of one Watson proposal: a lenient parse for the chat file. A proposal that
// does not parse is dropped, never the whole chat. zod strips keys a schema does not name, so every
// field a proposal carries is named here, or it would vanish on the next save.

const withId = <T>() =>
  z.custom<T>((v) => typeof v === "object" && v !== null && typeof (v as { id?: unknown }).id === "string");

const question = withId<InvestigationQuestion>();
const finding = withId<Finding>();
const event = withId<ForensicEvent>();
const step = withId<NextStep>();

const common = {
  id: z.string(),
  turnId: z.string(),
  status: z.enum(["pending", "applied", "rejected", "undone"]),
  appliedBy: z.string().optional(),
  appliedAt: z.string().optional(),
};

const createdRows = {
  createdEventIds: z.array(z.string()).optional(),
  promotedAt: z.string().optional(),
};

const questionProposal = z.object({
  ...common,
  kind: z.enum(["question_update", "question_new"]),
  questionId: z.string(),
  targetId: z.string().optional(),
  before: question.optional(),
  after: question,
});

const findingProposal = z.object({
  ...common,
  ...createdRows,
  kind: z.enum(["finding_new", "finding_update"]),
  targetId: z.string(),
  before: finding.optional(),
  after: finding,
  pasteLineEvents: z.array(event).catch([]),
  keptEventIds: z.array(z.string()).optional().catch(undefined),
});

const nextStepProposal = z.object({
  ...common,
  kind: z.literal("next_step_new"),
  targetId: z.string(),
  after: step,
});

const reportTextProposal = z.object({
  ...common,
  kind: z.literal("report_text"),
  targetId: z.string(),
  field: z.enum(["conclusions", "investigationLimitations"]),
  before: z.string(),
  after: z.string(),
});

const eventPromoteProposal = z.object({
  ...common,
  ...createdRows,
  kind: z.literal("event_promote"),
  targetId: z.string(),
  events: z.array(event),
  pasteId: z.string(),
  landedRows: z
    .array(
      z.object({
        id: z.string(),
        severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]),
        description: z.string(),
      }),
    )
    .optional()
    .catch(undefined),
});

const veloLaunchProposal = z.object({
  ...common,
  kind: z.literal("velo_launch"),
  targetId: z.string(),
  mode: z.enum(["hunt", "collection"]),
  hostname: z.string().optional(),
  title: z.string(),
  vql: z.string(),
  fingerprint: z.string(),
  fingerprints: z.array(z.string()).catch([]),
  launched: z
    .object({
      huntId: z.string().optional(),
      clientId: z.string().optional(),
      flowId: z.string().optional(),
      at: z.string(),
      by: z.string(),
    })
    .optional()
    .catch(undefined),
});

export const proposalSchema: z.ZodType<WatsonProposal, z.ZodTypeDef, unknown> = z.union([
  questionProposal,
  findingProposal,
  nextStepProposal,
  reportTextProposal,
  eventPromoteProposal,
  veloLaunchProposal,
]);
