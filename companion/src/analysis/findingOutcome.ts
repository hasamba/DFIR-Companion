import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { deriveSemanticKey } from "./semanticKey.js";
import {
  CONTROL_DISPOSITIONS,
  EXECUTION_OUTCOMES,
  type ControlDisposition,
  type ExecutionOutcome,
  type Finding,
  type InvestigationState,
  type OutcomeSource,
} from "./stateTypes.js";

// The analyst's statement of a finding's attack outcome (#930 item 8), kept in a per-case side
// file (`state/finding-outcome.json`), NOT in InvestigationState — for the same reason
// findingWorkflow.ts, comments, tags and pinned findings live outside it: synthesis rebuilds the
// finding list from an EMPTY base every run (replaceConclusions), so anything a human wrote onto a
// Finding would be gone by the next pass. A record here is keyed by findingId and applied OVER the
// machine-set axes at read time; the analyst wins on every axis they set and only those.
//
// The two axes and their vocabularies are defined once, in stateTypes.ts, next to the Finding
// fields they mirror — read the EXECUTION_OUTCOMES comment there for why there are two and not one.
//
// `null` on an axis means the analyst has not said. `"unknown"` means they looked and cannot tell.
// Those are different statements and both are preserved.

export const MAX_OUTCOME_NOTE_LENGTH = 500;

export const findingOutcomeSchema = z.object({
  findingId: z.string(),
  execution: z.enum(EXECUTION_OUTCOMES).nullable().default(null).catch(null),
  control: z.enum(CONTROL_DISPOSITIONS).nullable().default(null).catch(null),
  note: z.string().default("").catch(""),
  // The finding's semanticKey at the time the analyst spoke, when it had one. Finding ids are kept
  // stable by the merge for a claim the model re-emits, but a known id could in principle be reused
  // for a DIFFERENT claim — and an analyst-certified outcome attached to the wrong claim is the one
  // failure this file must never produce. So a record applies only while the keys still agree.
  // Empty when the finding had no key: then the id is all there is, as for every sibling side store.
  semanticKey: z.string().default("").catch(""),
  updatedAt: z.string(),
  updatedBy: z.string().default("").catch(""),
});
export type FindingOutcome = z.infer<typeof findingOutcomeSchema>;
const findingOutcomesSchema = z.array(findingOutcomeSchema).catch([]);

// Fields an analyst may PATCH. An absent field is left unchanged; a present field (including null
// on an axis or an empty note) is applied, so each can be explicitly cleared.
export interface FindingOutcomePatch {
  execution?: ExecutionOutcome | null;
  control?: ControlDisposition | null;
  note?: string;
  updatedBy?: string;
  semanticKey?: string; // the finding's key as the route saw it; refreshed on every patch
}

// Serializes load→modify→save per case, as findingWorkflow.ts does: the file is rewritten whole
// on every patch, so two analysts setting two findings at once would otherwise lose one.
const outcomeLock = new StateLock();

export class FindingOutcomeStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "finding-outcome.json");
  }

  async load(caseId: string): Promise<FindingOutcome[]> {
    try {
      return findingOutcomesSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, records: FindingOutcome[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(records, null, 2));
  }

  // Upsert one finding's outcome. A record whose axes are both null AND whose note is empty is
  // DROPPED, so the file only ever holds findings an analyst has actually said something about.
  // Returns the resulting record, or null when it was cleared. Throws on a blank findingId.
  async patch(caseId: string, findingId: string, patch: FindingOutcomePatch): Promise<FindingOutcome | null> {
    const id = String(findingId ?? "").trim();
    if (!id) throw new Error("findingId is required");
    return outcomeLock.runExclusive(caseId, () => this.applyPatch(caseId, id, patch));
  }

  private async applyPatch(
    caseId: string,
    id: string,
    patch: FindingOutcomePatch,
  ): Promise<FindingOutcome | null> {
    const records = await this.load(caseId);
    const existing = records.find((r) => r.findingId === id);

    const execution = pickAxis(EXECUTION_OUTCOMES, patch.execution, existing?.execution ?? null);
    const control = pickAxis(CONTROL_DISPOSITIONS, patch.control, existing?.control ?? null);
    const note =
      patch.note !== undefined
        ? String(patch.note).trim().slice(0, MAX_OUTCOME_NOTE_LENGTH)
        : (existing?.note ?? "");

    const rest = records.filter((r) => r.findingId !== id);
    if (execution === null && control === null && !note) {
      if (existing) await this.save(caseId, rest);
      return null;
    }

    const record: FindingOutcome = {
      findingId: id,
      execution,
      control,
      note,
      // A key is only ever ADDED or REPLACED by another key, never downgraded to empty: an empty key
      // applies by id alone, so letting a transient lookup failure blank an existing key would
      // quietly widen a record that was correctly guarded.
      semanticKey: String(patch.semanticKey ?? "").trim() || (existing?.semanticKey ?? ""),
      updatedAt: new Date().toISOString(),
      updatedBy: String(patch.updatedBy ?? "").trim(),
    };
    await this.save(caseId, [...rest, record]);
    return record;
  }
}

// One axis of a patch: absent → keep the existing value; present → the value if it is in the
// vocabulary, else null (a value outside the vocabulary is a client bug and must not be stored).
function pickAxis<T extends string>(
  vocab: readonly T[],
  incoming: T | null | undefined,
  current: T | null,
): T | null {
  if (incoming === undefined) return current;
  return incoming !== null && vocab.includes(incoming) ? incoming : null;
}

// Apply the analyst's records over the machine-set axes. Pure: returns a new state with new
// Finding objects; the input is untouched. Per axis, the analyst wins where they said something and
// the machine value survives where they did not — and each axis carries its OWN source, so a
// one-axis override never relabels the machine's value on the other. A record whose semanticKey
// disagrees with the finding's is not applied at all: same id, different claim.
export function withAnalystOutcomes(
  state: InvestigationState,
  records: readonly FindingOutcome[],
): InvestigationState {
  if (state.findings.length === 0) return state;
  const byId = new Map(records.map((r) => [r.findingId, r] as const));
  return {
    ...state,
    findings: state.findings.map((f) => {
      const candidate = byId.get(f.id);
      const r = candidate && sameClaim(candidate, f) ? candidate : undefined;
      const execution = r?.execution ?? f.execution;
      const control = r?.control ?? f.control;
      if (execution === undefined && control === undefined) return f;
      return {
        ...f,
        ...(execution !== undefined
          ? { execution, executionSource: (r?.execution ? "analyst" : "machine") as OutcomeSource }
          : {}),
        ...(control !== undefined
          ? { control, controlSource: (r?.control ? "analyst" : "machine") as OutcomeSource }
          : {}),
      };
    }),
  };
}

// A keyed record must match the finding's key EXACTLY — derived on the spot when the finding has
// none stored, with the same function grounding uses to store one, so the two agree. An unkeyed
// record applies by id: the only way one arises is a deployment with no state store (tests), since
// the route refuses to store a record it could not key. Sibling stores have no guard at all.
function sameClaim(
  r: FindingOutcome,
  f: Pick<Finding, "semanticKey" | "title" | "mitreTechniques">,
): boolean {
  return !r.semanticKey || r.semanticKey === (f.semanticKey || deriveSemanticKey(f));
}

// The bracketed label a report puts next to a finding's severity. Both axes always render when
// known, each with its own attribution — "execution observed (analyst) · control allowed" — and
// there is deliberately no single-word summary like "prevented" to collapse into: that collapse is
// the bug this whole field exists to end. Empty when nothing is known, so a legacy finding renders
// exactly as before.
export function outcomeLabel(
  f: Pick<Finding, "execution" | "control" | "executionSource" | "controlSource">,
): string {
  const parts: string[] = [];
  if (f.execution)
    parts.push(`execution ${f.execution}${f.executionSource === "analyst" ? " (analyst)" : ""}`);
  if (f.control) parts.push(`control ${f.control}${f.controlSource === "analyst" ? " (analyst)" : ""}`);
  return parts.length ? `[${parts.join(" · ")}]` : "";
}
