import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { EVIDENCE_CLASSES, type EvidenceClass } from "./refutationGate.js";

// Analyst-attested evidence-class coverage (#1111, narrowed after #1101's design review found
// reusing collectionPlan.ts's own coarser taxonomy unsound — "endpoint-triage: collected" there is
// satisfied by ShimCache alone, but refutationGate.ts deliberately EXCLUDES ShimCache from
// "execution" proof, so laundering one through the other would reintroduce exactly the mistake the
// gate exists to prevent).
//
// This store records a different, narrower fact than collectionPlan.ts: an identified analyst
// confirms that evidence CAPABLE OF SETTLING one of refutationGate.ts's own four EvidenceClass
// values was fully examined for this case — direct human provenance, not an inference through any
// importer or checklist. It is deliberately CASE-WIDE, not host/interval/volume-scoped (#1110's own
// host-scoping infrastructure is a separate PR); a natural follow-up once that lands.
//
// SIGNED ASSERTIONS, never silently dropped: mirrors hostScopeStore.ts's own posture exactly — a
// corrupt file FAILS the read instead of degrading to empty, because this holds an analyst's own
// vouching for evidence completeness, not derived or cosmetic state that can be rebuilt.

const evidenceClassSchema = z.enum(EVIDENCE_CLASSES as [EvidenceClass, ...EvidenceClass[]]);

const attestationSchema = z.object({
  evidenceClass: evidenceClassSchema,
  confirmedBy: z.string().min(1),
  confirmedAt: z.string(),
  reason: z.string().min(1),
  revokedBy: z.string().optional(),
  revokedAt: z.string().optional(),
});

const fileSchema = z.object({
  version: z.literal(1),
  attestations: z.array(attestationSchema),
});

export type EvidenceAttestation = z.infer<typeof attestationSchema>;

export class EvidenceAttestationStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  // Per-case append queue (mirrors HostScopeStore) — two analysts attesting/revoking on the same
  // case concurrently must never let the second write silently clobber the first's own entry.
  private readonly appendQueue = new Map<string, Promise<unknown>>();

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "evidence-attestations.json");
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

  async load(caseId: string): Promise<EvidenceAttestation[]> {
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
        `evidence-attestations.json for case ${caseId} is not valid JSON; it was left untouched so no analyst attestation is lost`,
      );
    }

    const parsed = fileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(
        `evidence-attestations.json for case ${caseId} does not match the attestation schema and was left untouched: ${parsed.error.message}`,
      );
    }
    return parsed.data.attestations;
  }

  // Only the LATEST entry for a class is ever meaningfully "current" — an older entry is superseded
  // history the moment a newer one for the same class is appended, whether or not anyone ever
  // revoked it. Both activeClasses() and revoke() key off this SAME rule so they can never disagree
  // about which row is the one that matters.
  private latestPerClass(attestations: readonly EvidenceAttestation[]): Map<EvidenceClass, number> {
    const indexByClass = new Map<EvidenceClass, number>();
    attestations.forEach((a, i) => indexByClass.set(a.evidenceClass, i)); // later index wins
    return indexByClass;
  }

  // The FULL active (non-revoked) LATEST attestation per class, keyed by class — what
  // refutationGate.ts actually consumes (it needs confirmedBy/confirmedAt/reason to write an
  // honest disclosure, not just the bare class name). A class attested then revoked is NOT
  // included; a class attested, revoked, then re-attested IS (the re-attestation is the new latest
  // entry).
  async activeAttestations(caseId: string): Promise<Map<EvidenceClass, EvidenceAttestation>> {
    const all = await this.load(caseId);
    const out = new Map<EvidenceClass, EvidenceAttestation>();
    for (const [cls, idx] of this.latestPerClass(all)) if (!all[idx].revokedAt) out.set(cls, all[idx]);
    return out;
  }

  // Just the class names — for callers (routes, UI) that only need to know WHICH classes are
  // covered, not the full attestation record.
  async activeClasses(caseId: string): Promise<Set<EvidenceClass>> {
    return new Set((await this.activeAttestations(caseId)).keys());
  }

  // Append-only: attesting one class again (after a revoke, or to change the reason) appends a NEW
  // entry rather than rewriting history — the prior entry, revoked or not, stays in the audit trail,
  // and immediately becomes superseded history per latestPerClass() above.
  async attest(
    caseId: string,
    input: Pick<EvidenceAttestation, "evidenceClass" | "confirmedBy" | "confirmedAt" | "reason">,
  ): Promise<EvidenceAttestation[]> {
    const validated = attestationSchema.parse(input);
    return this.enqueue(caseId, async () => {
      const attestations = [...(await this.load(caseId)), validated];
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, attestations }, null, 2));
      return attestations;
    });
  }

  // Marks the CURRENT (latest) attestation for a class revoked — the one place this store mutates an
  // existing row rather than appending a new one, since a revocation is a fact ABOUT that specific
  // attestation, not a new assertion of its own. A no-op (not an error) when the latest entry for
  // that class is already revoked, or none exists — matches activeClasses()'s own rule exactly, so a
  // revoke can never target a row activeClasses() had already stopped counting.
  async revoke(
    caseId: string,
    evidenceClass: EvidenceClass,
    revokedBy: string,
    revokedAt: string,
  ): Promise<EvidenceAttestation[]> {
    return this.enqueue(caseId, async () => {
      const attestations = await this.load(caseId);
      const latestIdx = this.latestPerClass(attestations).get(evidenceClass);
      if (latestIdx === undefined || attestations[latestIdx].revokedAt) return attestations;
      const next = attestations.map((a, i) => (i === latestIdx ? { ...a, revokedBy, revokedAt } : a));
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, attestations: next }, null, 2));
      return next;
    });
  }
}
