import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";

// Analyst decisions for the host scope ledger, in state/host-scope.json. DECISIONS ONLY — every
// derived field is recomputed on read, so an import can never desynchronise this file.
//
// Deliberate divergence from the zod `.catch()` side-file stores (assetOverrides, playbook…): a
// corrupt file here FAILS the read instead of degrading to empty. Those stores hold derived or
// cosmetic state that can be rebuilt; this one holds signed assertions about whether a machine is
// clean, and silently returning "no decisions" would erase them. SourceTrustStore already rethrows
// anything that is not ENOENT — this is the same posture, made explicit.

export type HostScopeStatus = "unknown" | "suspected" | "confirmed" | "cleared" | "out-of-scope";

const statusSchema = z.enum(["unknown", "suspected", "confirmed", "cleared", "out-of-scope"]);

const basisSchema = z.object({
  sources: z.array(z.string()),
  windowCovered: z.boolean(),
  tacticsCovered: z.array(z.string()),
  evidenceFingerprint: z.string(),
});

const decisionSchema = z.object({
  host: z.string().min(1),
  from: statusSchema,
  to: statusSchema,
  reason: z.string(),
  analyst: z.string(),
  at: z.string(),
  basis: basisSchema,
});

const fileSchema = z.object({
  version: z.literal(1),
  decisions: z.array(decisionSchema),
});

export type ClearanceBasis = z.infer<typeof basisSchema>;
export type HostScopeDecision = z.infer<typeof decisionSchema>;

export class HostScopeStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  // Per-case append queue. Two analysts deciding on the same case concurrently would otherwise both
  // read the same array and both write it back, and the second write would silently drop the first
  // analyst's SIGNED decision — the one thing an append-only audit trail may never do. Each case
  // gets a promise chain so its read-modify-write runs to completion before the next one starts.
  private readonly appendQueue = new Map<string, Promise<unknown>>();

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "host-scope.json");
  }

  // Run `job` after every append already queued for this case. The chain itself never rejects — a
  // failed append must not poison the queue for the next writer — while the caller still sees its
  // own error.
  private enqueue<T>(caseId: string, job: () => Promise<T>): Promise<T> {
    const prior = this.appendQueue.get(caseId) ?? Promise.resolve();
    const run = prior.then(job, job);
    this.appendQueue.set(
      caseId,
      run.catch(() => undefined),
    );
    return run;
  }

  async load(caseId: string): Promise<HostScopeDecision[]> {
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
        `host-scope.json for case ${caseId} is not valid JSON; it was left untouched so no analyst decision is lost`,
      );
    }

    const parsed = fileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(
        `host-scope.json for case ${caseId} does not match the decision schema and was left untouched: ${parsed.error.message}`,
      );
    }
    return parsed.data.decisions;
  }

  // Append-only: the decision log is the audit trail the report cites, so nothing is ever rewritten.
  // Validation happens before the queue so a malformed decision fails fast without taking a turn.
  async append(caseId: string, decision: HostScopeDecision): Promise<HostScopeDecision[]> {
    const validated = decisionSchema.parse(decision);
    return this.enqueue(caseId, async () => {
      const decisions = [...(await this.load(caseId)), validated];
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, decisions }, null, 2));
      return decisions;
    });
  }
}
