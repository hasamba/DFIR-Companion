import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type {
  CockpitActionInput,
  CockpitCardDecision,
  CockpitDecisionState,
  CockpitReview,
} from "./cockpit.js";

const MAX_CARD_ID_LENGTH = 240;
const MAX_ACTOR_LENGTH = 120;
const MAX_VALUE_LENGTH = 500;

const cockpitActionSchema = z.enum(["pin", "unpin", "dismiss", "restore", "defer", "assign", "review"]);
const cockpitCardDecisionSchema = z.object({
  cardId: z.string(),
  pinned: z.boolean().optional().catch(undefined),
  dismissedAt: z.string().optional().catch(undefined),
  deferredUntil: z.string().optional().catch(undefined),
  assignee: z.string().optional().catch(undefined),
  updatedAt: z.string(),
  updatedBy: z.string().catch("analyst"),
});
const cockpitReviewSchema = z.object({
  investigatorKey: z.string(),
  investigator: z.string(),
  reviewedAt: z.string(),
});
const cockpitHistorySchema = z.object({
  action: cockpitActionSchema,
  cardId: z.string().optional().catch(undefined),
  actor: z.string().catch("analyst"),
  at: z.string(),
  value: z.string().optional().catch(undefined),
});
const cockpitDecisionStateSchema = z.object({
  cards: z.array(cockpitCardDecisionSchema).catch([]),
  reviews: z.array(cockpitReviewSchema).catch([]),
  history: z.array(cockpitHistorySchema).catch([]),
});

const EMPTY: CockpitDecisionState = { cards: [], reviews: [], history: [] };

function cleanText(value: unknown, max: number): string {
  return String(value ?? "")
    .trim()
    .slice(0, max);
}

function validIso(value: string): boolean {
  return Boolean(value) && Number.isFinite(Date.parse(value));
}

export function investigatorKey(value: unknown): string {
  return cleanText(value, MAX_ACTOR_LENGTH).toLowerCase();
}

function updateDecision(
  current: CockpitCardDecision | undefined,
  cardId: string,
  input: CockpitActionInput,
  at: string,
): CockpitCardDecision {
  const actor = cleanText(input.actor, MAX_ACTOR_LENGTH) || "analyst";
  const base: CockpitCardDecision = current
    ? { ...current, updatedAt: at, updatedBy: actor }
    : { cardId, updatedAt: at, updatedBy: actor };

  if (input.action === "pin") return { ...base, pinned: true };
  if (input.action === "unpin") return { ...base, pinned: false };
  if (input.action === "dismiss") return { ...base, dismissedAt: at };
  if (input.action === "restore") {
    const { dismissedAt: _dismissedAt, deferredUntil: _deferredUntil, ...rest } = base;
    return rest;
  }
  if (input.action === "defer") {
    const until = cleanText(input.value, MAX_VALUE_LENGTH);
    if (!validIso(until)) {
      const { deferredUntil: _deferredUntil, ...rest } = base;
      return rest;
    }
    return { ...base, deferredUntil: new Date(until).toISOString() };
  }
  if (input.action === "assign") {
    const assignee = cleanText(input.value, MAX_ACTOR_LENGTH);
    if (!assignee) {
      const { assignee: _assignee, ...rest } = base;
      return rest;
    }
    return { ...base, assignee };
  }
  return base;
}

export class CockpitStore {
  private readonly lock = new StateLock();

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "cockpit.json");
  }

  async load(caseId: string): Promise<CockpitDecisionState> {
    try {
      return cockpitDecisionStateSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  private async save(caseId: string, state: CockpitDecisionState): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(state, null, 2));
  }

  async recordAction(
    caseId: string,
    rawCardId: string,
    input: CockpitActionInput,
    at: string = new Date().toISOString(),
  ): Promise<CockpitDecisionState> {
    const cardId = cleanText(rawCardId, MAX_CARD_ID_LENGTH);
    if (!cardId) throw new Error("cardId is required");
    if (input.action === "review" || !cockpitActionSchema.safeParse(input.action).success) {
      throw new Error(`unsupported cockpit card action: ${input.action}`);
    }
    const actor = cleanText(input.actor, MAX_ACTOR_LENGTH) || "analyst";
    const value = cleanText(input.value, MAX_VALUE_LENGTH);
    return this.lock.runExclusive(caseId, async () => {
      const existing = await this.load(caseId);
      const current = existing.cards.find((card) => card.cardId === cardId);
      const updated = updateDecision(current, cardId, input, at);
      const cards = [...existing.cards.filter((card) => card.cardId !== cardId), updated];
      const history = [
        ...existing.history,
        {
          action: input.action,
          cardId,
          actor,
          at,
          ...(value ? { value } : {}),
        },
      ];
      const next: CockpitDecisionState = { ...existing, cards, history };
      await this.save(caseId, next);
      return next;
    });
  }

  async markReviewed(
    caseId: string,
    rawInvestigator: string,
    at: string = new Date().toISOString(),
  ): Promise<CockpitReview> {
    const investigator = cleanText(rawInvestigator, MAX_ACTOR_LENGTH) || "analyst";
    const key = investigatorKey(investigator) || "analyst";
    return this.lock.runExclusive(caseId, async () => {
      const existing = await this.load(caseId);
      const review: CockpitReview = { investigatorKey: key, investigator, reviewedAt: at };
      const reviews = [...existing.reviews.filter((item) => item.investigatorKey !== key), review].sort(
        (a, b) => a.investigatorKey.localeCompare(b.investigatorKey),
      );
      const history = [
        ...existing.history,
        {
          action: "review" as const,
          actor: investigator,
          at,
        },
      ];
      await this.save(caseId, { ...existing, reviews, history });
      return review;
    });
  }
}
