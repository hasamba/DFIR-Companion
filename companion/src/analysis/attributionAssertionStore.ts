import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";

// An analyst's own claim that a cluster/campaign/operator/sponsor label applies to activity in
// this case (#933 item 20). Analyst-authored, never auto-generated — there is no synthesis/AI/
// derivation path anywhere that creates a record here, which is the mechanism the item's own
// guardrails forbid ("technique overlap or geographic infrastructure must not automatically
// assign actor identity, intent, or state sponsorship"). Mirrors evidenceAttestationStore.ts's
// own append-only, FAIL-LOUD (never silently-degrading) posture — a brand-new schema with no
// legacy data to migrate leniently, unlike hypothesis.ts's own per-field `.catch()` pattern.
//
// `periodStart`/`periodEnd` are both optional: an analyst who does not know an exact start date
// must never be pushed to fabricate one.
//
// `buildsOn` may reference ONLY a strictly weaker tier (cluster < campaign < operator < sponsor),
// validated at write time against the case's own loaded records — this is what makes a cycle
// structurally impossible, without a separate graph-walk check.
//
// A correction is a retract of the old record plus a new one naming it via `supersedesId` — never
// an in-place edit, same pattern as huntRequirementStore.ts's own field.

export const ATTRIBUTION_TIERS = ["cluster", "campaign", "operator", "sponsor"] as const;
export type AttributionTier = (typeof ATTRIBUTION_TIERS)[number];

const TIER_RANK: Record<AttributionTier, number> = {
  cluster: 0,
  campaign: 1,
  operator: 2,
  sponsor: 3,
};

const attributionAssertionSchema = z.object({
  id: z.string(),
  tier: z.enum(ATTRIBUTION_TIERS),
  label: z.string().min(1),
  sources: z.string().min(1),
  periodStart: z.string().datetime({ offset: true }).optional(),
  periodEnd: z.string().datetime({ offset: true }).optional(),
  alternatives: z.string().min(1),
  analystAssessment: z.string().min(1),
  relatedTechniqueIds: z.array(z.string()).default([]),
  relatedEventIds: z.array(z.string()).default([]),
  relatedIocIds: z.array(z.string()).default([]),
  buildsOn: z.array(z.string()).default([]),
  status: z.enum(["open", "retracted"]).default("open"),
  retractedBy: z.string().optional(),
  retractedAt: z.string().optional(),
  retractedReason: z.string().optional(),
  supersedesId: z.string().min(1).max(200).optional(),
  createdBy: z.string().min(1),
  createdAt: z.string().datetime({ offset: true }),
});

const fileSchema = z.object({
  version: z.literal(1),
  assertions: z.array(attributionAssertionSchema),
});

export type AttributionAssertion = z.infer<typeof attributionAssertionSchema>;

// A client-correctable rejection (a bad buildsOn/supersedesId reference), distinct from a genuine
// server fault — lets the route return 400 instead of 500, same pattern as
// huntRequirementStore.ts's own InvalidSupersedesIdError.
export class InvalidBuildsOnError extends Error {}
export class InvalidSupersedesIdError extends Error {}

export class AttributionAssertionStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  private readonly appendQueue = new Map<string, Promise<unknown>>();

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "attribution-assertions.json");
  }

  private enqueue<T>(caseId: string, job: () => Promise<T>): Promise<T> {
    const prior = this.appendQueue.get(caseId) ?? Promise.resolve();
    const run = prior.then(job, job);
    this.appendQueue.set(
      caseId,
      run.catch(() => undefined),
    );
    return run;
  }

  async load(caseId: string): Promise<AttributionAssertion[]> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }

    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch {
      throw new Error(
        `attribution-assertions.json for case ${caseId} is not valid JSON; it was left untouched so no analyst assertion is lost`,
      );
    }

    const parsed = fileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(
        `attribution-assertions.json for case ${caseId} does not match the assertion schema and was left untouched: ${parsed.error.message}`,
      );
    }
    return parsed.data.assertions;
  }

  async create(
    caseId: string,
    input: Pick<
      AttributionAssertion,
      "tier" | "label" | "sources" | "alternatives" | "analystAssessment" | "createdBy" | "createdAt"
    > &
      Partial<
        Pick<
          AttributionAssertion,
          | "periodStart"
          | "periodEnd"
          | "relatedTechniqueIds"
          | "relatedEventIds"
          | "relatedIocIds"
          | "buildsOn"
          | "supersedesId"
        >
      >,
  ): Promise<AttributionAssertion> {
    const validated = attributionAssertionSchema.parse({ ...input, id: randomUUID() });
    return this.enqueue(caseId, async () => {
      const all = await this.load(caseId);

      for (const targetId of validated.buildsOn) {
        const target = all.find((a) => a.id === targetId);
        if (!target) {
          throw new InvalidBuildsOnError(`buildsOn ${targetId} does not exist in case ${caseId}`);
        }
        if (TIER_RANK[target.tier] >= TIER_RANK[validated.tier]) {
          throw new InvalidBuildsOnError(
            `buildsOn ${targetId} is tier "${target.tier}", not strictly weaker than "${validated.tier}"`,
          );
        }
      }

      if (validated.supersedesId) {
        const target = all.find((a) => a.id === validated.supersedesId);
        if (!target) {
          throw new InvalidSupersedesIdError(
            `supersedesId ${validated.supersedesId} does not exist in case ${caseId}`,
          );
        }
        if (target.status !== "retracted") {
          throw new InvalidSupersedesIdError(
            `supersedesId ${validated.supersedesId} must be retracted before it can be superseded`,
          );
        }
      }

      const assertions = [...all, validated];
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, assertions }, null, 2));
      return validated;
    });
  }

  // Marks ONE assertion (by id) retracted — the one place this store mutates an existing row
  // rather than appending a new one. A no-op (not an error) when the id is unknown or already
  // retracted, matching every other analyst-record store's own revoke/retire posture.
  async retract(
    caseId: string,
    id: string,
    retractedBy: string,
    retractedAt: string,
    retractedReason?: string,
  ): Promise<AttributionAssertion[]> {
    return this.enqueue(caseId, async () => {
      const assertions = await this.load(caseId);
      const idx = assertions.findIndex((a) => a.id === id);
      if (idx === -1 || assertions[idx].status === "retracted") return assertions;
      const next = assertions.map((a, i) =>
        i === idx ? { ...a, status: "retracted" as const, retractedBy, retractedAt, retractedReason } : a,
      );
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, assertions: next }, null, 2));
      return next;
    });
  }
}
