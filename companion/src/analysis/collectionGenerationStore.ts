import { randomUUID, createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { ImportMetadata } from "../types.js";
import { extractRows } from "./velociraptorImport.js";
import { isPersistenceSniperRow, persistenceEntryFact } from "./persistenceSniperImport.js";
import {
  collectionGenerationSchema,
  type CollectionGeneration,
  type CollectionDomain,
  type CompletenessState,
  type PersistenceFilter,
  type GenerationOrder,
} from "./canonicalCollectionGeneration.js";

// The durable, human-authored ledger #1108 exists to build (see RECOMMENDATION-1108.md): one row
// per generation of a host's collection, in exactly one v1 evidence domain ("persistence"). Mirrors
// hostScopeStore.ts's own append-only file mechanics; revoke() mirrors evidenceAttestationStore.ts's
// own mutate-one-row shape exactly (a THIRD instance of this codebase's established ledger pattern).
//
// Never wired into refutationGate.ts, stateMerge.ts, or the forensic timeline — disclosure-only
// case metadata, matching #932.1's and #1111's own precedent. The comparator this ledger exists to
// make possible (932.2's own follow-on) is not built here.

const fileSchema = z.object({
  version: z.literal(1),
  generations: z.array(collectionGenerationSchema),
});

export interface RecordGenerationInput {
  rawHost: string;
  domain: CollectionDomain;
  order: GenerationOrder;
  importSeq: number;
  completenessState: CompletenessState;
  filtersApplied?: PersistenceFilter[];
  checked?: string;
  gaps?: string;
  recordedBy: { id: string; displayName: string };
}

export class CollectionGenerationStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir" | "importsLogPath" | "importsDir">) {}

  private readonly enqueueMap = new Map<string, Promise<unknown>>();

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "collection-generations.json");
  }

  private enqueue<T>(caseId: string, job: () => Promise<T>): Promise<T> {
    const prior = this.enqueueMap.get(caseId) ?? Promise.resolve();
    const run = prior.then(job, job);
    this.enqueueMap.set(
      caseId,
      run.catch(() => undefined),
    );
    return run;
  }

  async load(caseId: string): Promise<CollectionGeneration[]> {
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
        `collection-generations.json for case ${caseId} is not valid JSON; it was left untouched so no generation record is lost`,
      );
    }
    const parsed = fileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(
        `collection-generations.json for case ${caseId} does not match the generation schema and was left untouched: ${parsed.error.message}`,
      );
    }
    return parsed.data.generations;
  }

  /** Every generation, including revoked ones (the full audit trail). */
  async all(caseId: string): Promise<CollectionGeneration[]> {
    return this.load(caseId);
  }

  /** Only never-revoked generations — what a comparator (932.2's own follow-on) should read. */
  async active(caseId: string): Promise<CollectionGeneration[]> {
    return (await this.load(caseId)).filter((g) => !g.revokedAt);
  }

  private async importRow(caseId: string, importSeq: number): Promise<ImportMetadata> {
    let raw: string;
    try {
      raw = await readFile(this.cases.importsLogPath(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error(`case ${caseId} has no imports at all; import sequence ${importSeq} does not exist`);
      }
      throw err;
    }
    const rows: ImportMetadata[] = [];
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      rows.push(JSON.parse(line) as ImportMetadata);
    }
    const matches = rows.filter((r) => r.sequenceNumber === importSeq);
    if (matches.length === 0)
      throw new Error(`import sequence ${importSeq} does not exist in case ${caseId}`);
    // A pre-existing allocator gap (#1119, now fixed) could in principle have produced a duplicate
    // sequenceNumber in an already-corrupted historical log — fail closed rather than silently
    // pointing at whichever row happens to match first.
    if (matches.length > 1) {
      throw new Error(
        `import sequence ${importSeq} is ambiguous in case ${caseId} (${matches.length} matching rows)`,
      );
    }
    return matches[0];
  }

  /**
   * Append one new generation. ALL state-dependent validation — the import exists and is
   * unambiguous, its own stored file re-parses with at least one matching row, and (for a
   * `declared` order) the sequence is unique within its (rawHost, domain) cohort — runs inside the
   * queued callback, immediately before the write, so two concurrent writers can never both pass a
   * check that only one of them should have.
   */
  async record(caseId: string, input: RecordGenerationInput): Promise<CollectionGeneration> {
    return this.enqueue(caseId, async () => {
      const importRow = await this.importRow(caseId, input.importSeq);
      const rawFile = await readFile(join(this.cases.importsDir(caseId), importRow.filename), "utf8");
      const artifactHash = createHash("sha256").update(Buffer.from(rawFile, "utf8")).digest("hex");

      const { rows } = extractRows(rawFile);
      const inventory = rows.filter(isPersistenceSniperRow).map(persistenceEntryFact);
      if (inventory.length === 0) {
        throw new Error(
          `import sequence ${input.importSeq} in case ${caseId} has no rows matching domain "${input.domain}" — cannot record this generation`,
        );
      }

      const existing = await this.load(caseId);
      if (input.order.kind === "declared") {
        const cohortSequence = input.order.sequence;
        const collision = existing.some(
          (g) =>
            g.rawHost === input.rawHost &&
            g.domain === input.domain &&
            g.order.kind === "declared" &&
            g.order.sequence === cohortSequence,
        );
        if (collision) {
          throw new Error(
            `declared sequence ${cohortSequence} already exists for host "${input.rawHost}" / domain "${input.domain}"`,
          );
        }
      }

      const generation = collectionGenerationSchema.parse({
        generationId: randomUUID(),
        rawHost: input.rawHost,
        domain: input.domain,
        completenessState: input.completenessState,
        filtersApplied: input.filtersApplied ?? [],
        order: input.order,
        artifactRef: { importSeq: input.importSeq, artifactHash },
        inventory,
        checked: input.checked,
        gaps: input.gaps,
        recordedBy: input.recordedBy,
        recordedAt: new Date().toISOString(),
      });

      const generations = [...existing, generation];
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, generations }, null, 2));
      return generation;
    });
  }

  /** Marks one specific generation revoked — a correction appends a NEW generation via record()
   * and separately revokes the mistaken one; history is never rewritten. No-op if the id does not
   * exist or is already revoked (mirrors evidenceAttestationStore.ts's own revoke() exactly). */
  async revoke(
    caseId: string,
    generationId: string,
    revokedBy: { id: string; displayName: string },
    revokedAt: string,
  ): Promise<CollectionGeneration[]> {
    return this.enqueue(caseId, async () => {
      const generations = await this.load(caseId);
      const idx = generations.findIndex((g) => g.generationId === generationId);
      if (idx === -1 || generations[idx].revokedAt) return generations;
      const next = generations.map((g, i) => (i === idx ? { ...g, revokedBy, revokedAt } : g));
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, generations: next }, null, 2));
      return next;
    });
  }
}
