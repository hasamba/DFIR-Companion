import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { claimSnapshot, hashManifestValue } from "./analysisRunHash.js";
import { emptyState, type InvestigationState } from "./stateTypes.js";
import type { InvestigationStateStorage } from "./stateStore.js";
import type { FactsListing } from "./caseSqliteWorkerFacts.js";
import {
  forensicFacts,
  hasRowFacts,
  iocFacts,
  itemDigest,
  refreshRowFacts,
  rowFactsStamp,
  type FactsStore,
} from "./rowFacts.js";
import type { AnalysisRunArtifact, AnalysisRunOutput } from "./analysisRunTypes.js";

export async function importedArtifact(
  cases: CaseStore,
  caseId: string,
  storedName: string,
): Promise<AnalysisRunArtifact> {
  const data = await readFile(join(cases.importsDir(caseId), storedName));
  return {
    path: `imports/${storedName}`,
    sha256: createHash("sha256").update(data).digest("hex"),
  };
}

/**
 * The run record's fingerprint of the case (#1874), hash id `investigation-state/v2`:
 *
 *   SHA-256 of JSON.stringify(canonicalize({ findings, forensicTimeline: E, iocs: I }))
 *
 * where E and I are, in timeline and list order, each event's and each IOC's own digest —
 * SHA-256 (lowercase hex) of that item's canonical JSON (itemDigest), the event as the loaders return
 * it (upgradeForensicEvent applied). canonicalize sorts every object's keys, so the top level reads
 * {"findings":…,"forensicTimeline":[…],"iocs":[…]}. It fingerprints what the first version
 * (`investigation-state`, the same JSON with each item inline) did — every finding, every IOC, every
 * event and their order; a change to any of them changes the hash — but a case's digest can be
 * computed from per-row digests kept in the case database instead of from every row's bytes. The two
 * ids are different constructions: compare hashes only under the same id. Manifests written before
 * keep `investigation-state` and read as they always did.
 */
export const STATE_HASH_ID = "investigation-state/v2";

export function stateHash(
  findings: readonly unknown[],
  eventDigests: readonly string[],
  iocDigests: readonly string[],
): string {
  return hashManifestValue({ findings, forensicTimeline: eventDigests, iocs: iocDigests });
}

function outputOf(
  findings: InvestigationState["findings"],
  iocIds: readonly (string | null)[],
  eventIds: readonly (string | null)[],
  sha256: string,
): AnalysisRunOutput {
  const id = (v: string | null): string => v as string; // a row without a string id records as the loader saw it
  return {
    entityIds: [...findings.map((finding) => finding.id), ...iocIds.map(id), ...eventIds.map(id)],
    hashes: [{ id: STATE_HASH_ID, sha256 }],
    claims: findings.map((finding) =>
      claimSnapshot(finding.id, {
        title: finding.title,
        severity: finding.severity,
        description: finding.description,
        evidenceEventIds: finding.relatedEventIds,
      }),
    ),
  };
}

export function investigationOutput(state: InvestigationState): AnalysisRunOutput {
  const hash = stateHash(state.findings, state.forensicTimeline.map(itemDigest), state.iocs.map(itemDigest));
  return outputOf(
    state.findings,
    state.iocs.map((ioc) => ioc.id),
    state.forensicTimeline.map((event) => event.id),
    hash,
  );
}

/**
 * investigationOutput of the case as stored, without reading every row (#1874): the per-row digests
 * come from the case database's row facts (analysis/rowFacts.ts), refreshed first; a row whose facts
 * are unknown is digested from its payload, read in the same transaction. Call it inside the case's
 * state lock, as the import run recorder does.
 */
export async function investigationOutputOfCase(
  store: InvestigationStateStorage | FactsStore,
  caseId: string,
): Promise<AnalysisRunOutput> {
  if (!hasRowFacts(store)) return investigationOutput(await store.load(caseId));
  await refreshRowFacts(store, caseId);
  const fp = await store.factsFingerprint(caseId, rowFactsStamp());
  if (!fp) return investigationOutput(emptyState(caseId));
  const payloads = new Map(fp.payloads);
  const fill = (list: FactsListing, facts: (payload: unknown) => { id: string | null; digest: string }) => {
    const ids = [...list.ids];
    const digests = list.digests.map((digest, i) => {
      if (digest !== null) return digest;
      const computed = facts(payloads.get(list.rowIds[i]));
      ids[i] = computed.id;
      return computed.digest;
    });
    return { ids, digests };
  };
  const events = fill(fp.forensic, forensicFacts);
  const iocs = fill(fp.iocs, iocFacts);
  const findings = fp.findings as InvestigationState["findings"];
  return outputOf(findings, iocs.ids, events.ids, stateHash(findings, events.digests, iocs.digests));
}
