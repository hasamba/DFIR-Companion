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
 * where each item's digest is SHA-256 (lowercase hex) of its canonical JSON (itemDigest), the event as
 * the loaders return it (upgradeForensicEvent applied), and E and I are lists of [bucket, bucketHash]:
 * an item's bucket is the first FP_BUCKET_CHARS hex characters of its digest, and a bucket's hash is
 * SHA-256 of its items' digests sorted ascending and joined with "\n", duplicates kept. Only non-empty
 * buckets are listed, in ascending order. canonicalize sorts every object's keys, so the top level reads
 * {"findings":…,"forensicTimeline":[…],"iocs":[…]}.
 *
 * It commits to every finding and their order, and to the events and the IOCs as multisets of their
 * content (an event's time is part of its content): a change to any finding, event or IOC, or one
 * more copy of an item, changes it. Unlike `investigation-state/v2` (the per-item digests in list
 * order) it does NOT cover the order the rows are stored in. The case database keeps each bucket's hash
 * (fp_buckets, caseSqliteSchema.ts) and re-hashes only the buckets a write touched, so a case's
 * fingerprint costs the changed rows, not the case. The ids are different constructions: compare
 * hashes only under the same id. Manifests written before keep `investigation-state` or
 * `investigation-state/v2` and read as they always did.
 */
export const STATE_HASH_ID = "investigation-state/v3";

/** Hex characters of an item digest that name its bucket (65,536 buckets per list). */
export const FP_BUCKET_CHARS = 4;

const sha256Hex = (text: string): string => createHash("sha256").update(text).digest("hex");

/** One bucket's hash: its digests sorted ascending, joined with "\n". */
export function bucketHash(digests: readonly string[]): string {
  return sha256Hex([...digests].sort().join("\n"));
}

/** Every non-empty bucket of a list of item digests, with its hash, in ascending bucket order. */
export function bucketHashes(digests: readonly string[]): [string, string][] {
  const byBucket = new Map<string, string[]>();
  for (const digest of digests) {
    const bucket = digest.slice(0, FP_BUCKET_CHARS);
    const list = byBucket.get(bucket);
    if (list) list.push(digest);
    else byBucket.set(bucket, [digest]);
  }
  return [...byBucket.keys()].sort().map((bucket) => [bucket, bucketHash(byBucket.get(bucket)!)]);
}

/** The v3 hash from the bucket lists (as the case database keeps them). */
export function stateHashOfBuckets(
  findings: readonly unknown[],
  eventBuckets: readonly (readonly [string, string])[],
  iocBuckets: readonly (readonly [string, string])[],
): string {
  return hashManifestValue({ findings, forensicTimeline: eventBuckets, iocs: iocBuckets });
}

export function stateHash(
  findings: readonly unknown[],
  eventDigests: readonly string[],
  iocDigests: readonly string[],
): string {
  return stateHashOfBuckets(findings, bucketHashes(eventDigests), bucketHashes(iocDigests));
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

/** Ids and digests of a facts listing, the unknown rows digested from their payloads. */
function digestsOf(fp: FactsFingerprint) {
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
  return { events: fill(fp.forensic, forensicFacts), iocs: fill(fp.iocs, iocFacts) };
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
  const { events, iocs } = digestsOf(fp);
  const findings = fp.findings as InvestigationState["findings"];
  return outputOf(findings, iocs.ids, events.ids, stateHash(findings, events.digests, iocs.digests));
}

export interface InvestigationFingerprint {
  sha256: string;
  findings: InvestigationState["findings"];
}

function fingerprintOfState(state: InvestigationState): InvestigationFingerprint {
  return {
    sha256: stateHash(state.findings, state.forensicTimeline.map(itemDigest), state.iocs.map(itemDigest)),
    findings: state.findings,
  };
}

/**
 * The case's `investigation-state/v3` hash as stored, and its findings (#1887). Reads only the
 * buckets written since the last call: the case database re-hashes those from the row facts and
 * keeps the rest (factsFingerprintV3, caseSqliteWorkerFacts.ts). When a row's facts are unknown after
 * the refresh (a writer raced it) or the facts are another build's, it hashes the full per-row
 * listing instead. Call it inside the case's state lock, as the import run recorder does.
 */
export async function investigationFingerprintOfCase(
  store: InvestigationStateStorage | FactsStore,
  caseId: string,
): Promise<InvestigationFingerprint> {
  if (!hasRowFacts(store)) return fingerprintOfState(await store.load(caseId));
  const stamp = rowFactsStamp();
  await refreshRowFacts(store, caseId);
  const kept = await store.factsFingerprintV3(caseId, stamp);
  if (!kept) return fingerprintOfState(emptyState(caseId));
  if (!kept.needsFull) {
    const findings = kept.findings as InvestigationState["findings"];
    return { sha256: stateHashOfBuckets(findings, kept.forensic, kept.iocs), findings };
  }
  const fp = await store.factsFingerprint(caseId, stamp);
  if (!fp) return fingerprintOfState(emptyState(caseId));
  const { events, iocs } = digestsOf(fp);
  const findings = fp.findings as InvestigationState["findings"];
  return { sha256: stateHash(findings, events.digests, iocs.digests), findings };
}
