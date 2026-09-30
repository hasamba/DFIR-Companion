import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { claimSnapshot, hashManifestValue } from "./analysisRunHash.js";
import { emptyState, type InvestigationState } from "./stateTypes.js";
import type { InvestigationStateStorage } from "./stateStore.js";
import type { FactsFingerprint, FactsListing } from "./caseSqliteWorkerFacts.js";
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
import { ltHex, ltSum } from "./ltHash.js";

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
 * The run record's fingerprint of the case (#1887), hash id `investigation-state/v3`:
 *
 *   SHA-256 of JSON.stringify(canonicalize({ findings, forensicTimeline: E, iocs: I }))
 *
 * where E and I are LtHash sums (Lewi, Kim, Maykov, Weis 2019; analysis/ltHash.ts) of the events' and
 * the IOCs' item digests, as lowercase hex of 1024 little-endian 32-bit lanes. An item's digest is
 * SHA-256 (lowercase hex) of its canonical JSON (itemDigest), the event as the loaders return it
 * (upgradeForensicEvent applied); its element is SHAKE128("dfir-companion/v3\n" + digest), 4096
 * bytes read as the 1024 lanes; a sum is the lane-wise sum mod 2^32 of its items' elements, a
 * duplicate counted twice. canonicalize sorts every object's keys, so the top level reads
 * {"findings":…,"forensicTimeline":"…","iocs":"…"}.
 *
 * It commits to every finding and their order, and to the events and the IOCs as multisets of their
 * content (an event's time is part of its content): a change to any finding, event or IOC, or one
 * more copy of an item, changes it. Unlike `investigation-state/v2` (the per-item digests in list
 * order) it does NOT cover the order the rows are stored in. The case database keeps both sums and
 * folds in only the rows a write changed (fp_rows and fp_log, caseSqliteSchema.ts), so a case's
 * fingerprint costs the changed rows, not the case. The ids are different constructions: compare
 * hashes only under the same id. Manifests written before keep `investigation-state` or
 * `investigation-state/v2` and read as they always did.
 */
export const STATE_HASH_ID = "investigation-state/v3";

/** The v3 hash from the two sums as hex (as the case database keeps them). */
export function stateHashOfSums(findings: readonly unknown[], eventSum: string, iocSum: string): string {
  return hashManifestValue({ findings, forensicTimeline: eventSum, iocs: iocSum });
}

export function stateHash(
  findings: readonly unknown[],
  eventDigests: readonly string[],
  iocDigests: readonly string[],
): string {
  return stateHashOfSums(findings, ltHex(ltSum(eventDigests)), ltHex(ltSum(iocDigests)));
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

/** Digests of a facts listing, the unknown rows digested from their payloads. */
function digestsOf(fp: FactsFingerprint) {
  const payloads = new Map(fp.payloads);
  const fill = (list: FactsListing, facts: (payload: unknown) => { digest: string }) => ({
    digests: list.digests.map((digest, i) => digest ?? facts(payloads.get(list.rowIds[i])).digest),
  });
  return { events: fill(fp.forensic, forensicFacts), iocs: fill(fp.iocs, iocFacts) };
}

export interface InvestigationFingerprint {
  sha256: string;
  findings: InvestigationState["findings"];
  /** The forensic then IOC ids, in order, from the snapshot the hash covers (#1887). */
  entityIds: unknown[];
}

/** The fingerprint with its forensic and IOC ids kept apart. */
interface CaseFingerprint {
  sha256: string;
  findings: InvestigationState["findings"];
  forensicIds: unknown[];
  iocIds: unknown[];
}

function fingerprintOfState(state: InvestigationState): CaseFingerprint {
  return {
    sha256: stateHash(state.findings, state.forensicTimeline.map(itemDigest), state.iocs.map(itemDigest)),
    findings: state.findings,
    forensicIds: state.forensicTimeline.map((e) => e.id),
    iocIds: state.iocs.map((i) => i.id),
  };
}

/**
 * Reads only the rows written since the last call: the case database folds those into the kept sums
 * (factsFingerprintV3, caseSqliteWorkerFacts.ts). When a row's facts are unknown after the refresh
 * (a writer raced it) or the facts are another build's, it hashes the full per-row listing instead.
 */
async function caseFingerprint(
  store: InvestigationStateStorage | FactsStore,
  caseId: string,
): Promise<CaseFingerprint> {
  if (!hasRowFacts(store)) return fingerprintOfState(await store.load(caseId));
  const stamp = rowFactsStamp();
  await refreshRowFacts(store, caseId);
  const kept = await store.factsFingerprintV3(caseId, stamp);
  if (!kept) return fingerprintOfState(emptyState(caseId));
  if (!kept.needsFull) {
    const findings = kept.findings as InvestigationState["findings"];
    const { forensicIds, iocIds } = kept;
    return { sha256: stateHashOfSums(findings, kept.forensic, kept.iocs), findings, forensicIds, iocIds };
  }
  const fp = await store.factsFingerprint(caseId, stamp);
  if (!fp) return fingerprintOfState(emptyState(caseId));
  const { events, iocs } = digestsOf(fp);
  const findings = fp.findings as InvestigationState["findings"];
  const { forensicIds, iocIds } = fp;
  return { sha256: stateHash(findings, events.digests, iocs.digests), findings, forensicIds, iocIds };
}

/**
 * The case's `investigation-state/v3` hash as stored, its findings, and its forensic then IOC ids
 * (#1887), from the kept sums (caseFingerprint). Call it inside the case's state lock, as the
 * import run recorder does.
 */
export async function investigationFingerprintOfCase(
  store: InvestigationStateStorage | FactsStore,
  caseId: string,
): Promise<InvestigationFingerprint> {
  const fp = await caseFingerprint(store, caseId);
  return { sha256: fp.sha256, findings: fp.findings, entityIds: [...fp.forensicIds, ...fp.iocIds] };
}

/**
 * investigationOutput of the case as stored, without reading every row (#1874, #1887): the same
 * hash, findings, claims and ids (findings, IOCs, events), from the kept sums (caseFingerprint).
 * Call it inside the case's state lock, right after the write it describes.
 */
export async function investigationOutputOfCase(
  store: InvestigationStateStorage | FactsStore,
  caseId: string,
): Promise<AnalysisRunOutput> {
  const fp = await caseFingerprint(store, caseId);
  return outputOf(
    fp.findings,
    fp.iocIds as (string | null)[],
    fp.forensicIds as (string | null)[],
    fp.sha256,
  );
}
