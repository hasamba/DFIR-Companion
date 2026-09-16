import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { resolvedSubjectScopeSchema } from "./hypothesis.js";

// An analyst's own statement of what decision they need evidence to support, by when, for whom,
// and what they expect to see (#933 item 17). Analyst-authored, never inferred. Mirrors
// evidenceAttestationStore.ts's own append-only, per-case, signed-record pattern — a sibling file,
// not a variant, since this domain (decision/audience/deadline) does not fit that schema.
//
// `subjectScope` is REQUIRED here, unlike Hypothesis.subjectScope (hypothesis.ts), which is
// optional only to stay readable for stored data written before that field existed. This is a
// brand-new schema with no such legacy case, and the spec's own text has the analyst state scope
// explicitly.
//
// A changed investigative question is a revoke of the old requirement plus a NEW record naming
// the old one via `supersedesId` — never an in-place edit, matching the store's own append-only
// posture.

const huntRequirementSchema = z.object({
  id: z.string(),
  decision: z.string().min(1),
  audience: z.string().min(1),
  deadline: z.string().min(1),
  subjectScope: resolvedSubjectScopeSchema,
  expectedObservableEvidence: z.string().min(1),
  createdBy: z.string().min(1),
  createdAt: z.string(),
  supersedesId: z.string().optional(),
  revokedBy: z.string().optional(),
  revokedAt: z.string().optional(),
  revokedReason: z.string().optional(),
});

const fileSchema = z.object({
  version: z.literal(1),
  requirements: z.array(huntRequirementSchema),
});

export type HuntRequirement = z.infer<typeof huntRequirementSchema>;

export class HuntRequirementStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  // Per-case append queue (mirrors EvidenceAttestationStore) — two analysts creating/revoking on
  // the same case concurrently must never let the second write silently clobber the first's own
  // entry.
  private readonly appendQueue = new Map<string, Promise<unknown>>();

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "hunt-requirements.json");
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

  async load(caseId: string): Promise<HuntRequirement[]> {
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
        `hunt-requirements.json for case ${caseId} is not valid JSON; it was left untouched so no analyst requirement is lost`,
      );
    }

    const parsed = fileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(
        `hunt-requirements.json for case ${caseId} does not match the requirement schema and was left untouched: ${parsed.error.message}`,
      );
    }
    return parsed.data.requirements;
  }

  // The non-revoked requirements — what the checklist route actually reads.
  async active(caseId: string): Promise<HuntRequirement[]> {
    return (await this.load(caseId)).filter((r) => !r.revokedAt);
  }

  async create(
    caseId: string,
    input: Pick<
      HuntRequirement,
      | "decision"
      | "audience"
      | "deadline"
      | "subjectScope"
      | "expectedObservableEvidence"
      | "createdBy"
      | "createdAt"
    > &
      Partial<Pick<HuntRequirement, "supersedesId">>,
  ): Promise<HuntRequirement> {
    const validated = huntRequirementSchema.parse({ ...input, id: randomUUID() });
    return this.enqueue(caseId, async () => {
      const requirements = [...(await this.load(caseId)), validated];
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, requirements }, null, 2));
      return validated;
    });
  }

  // Marks ONE requirement (by id) revoked — the one place this store mutates an existing row
  // rather than appending a new one, since a revocation is a fact ABOUT that specific record. A
  // no-op (not an error) when the id is unknown or already revoked, matching
  // EvidenceAttestationStore.revoke()'s own posture.
  async revoke(
    caseId: string,
    id: string,
    revokedBy: string,
    revokedAt: string,
    revokedReason?: string,
  ): Promise<HuntRequirement[]> {
    return this.enqueue(caseId, async () => {
      const requirements = await this.load(caseId);
      const idx = requirements.findIndex((r) => r.id === id);
      if (idx === -1 || requirements[idx].revokedAt) return requirements;
      const next = requirements.map((r, i) =>
        i === idx ? { ...r, revokedBy, revokedAt, revokedReason } : r,
      );
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, requirements: next }, null, 2));
      return next;
    });
  }
}
