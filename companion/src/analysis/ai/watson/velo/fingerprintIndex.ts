import { deployedFingerprints, type HuntDeployInput } from "../../../huntOutcomes.js";
import { HuntOutcomeStore } from "../../../huntOutcomeStore.js";
import type { CaseStore } from "../../../../storage/caseStore.js";
import { HuntFingerprintStore } from "./huntFingerprintStore.js";
export { HuntFingerprintStore };
import { launchFingerprints } from "./launchFingerprint.js";
export { launchFingerprints };

// Wires the durable fingerprint index (huntFingerprintStore.ts) into every hunt deploy, Watson's or
// not: server.ts wraps ctx.recordHuntDeploy with withFingerprintIndex, so all four deploy routes
// index without touching the capped veloHunts.ts / routes/velociraptor.ts.

type RecordDeploy = (caseId: string, input: HuntDeployInput) => Promise<void>;

/** Wrap recordHuntDeploy so each deploy is first added to the durable index. Index errors are logged, never thrown.
 * A fleet deploy is keyed by its VQL alone, a collection (input.hostname) by VQL + host only; an add is idempotent, so a launch reserved beforehand
 * (HuntFingerprintStore.reserve) is unaffected. */
export function withFingerprintIndex(
  inner: RecordDeploy,
  index: Pick<HuntFingerprintStore, "add">,
  log: (line: string) => void,
): RecordDeploy {
  return async (caseId, input) => {
    try {
      await index.add(caseId, launchFingerprints(input.vql, input.hostname));
    } catch (e) {
      log(`[hunt-fingerprints] index write failed: ${(e as Error).message}`);
    }
    await inner(caseId, input);
  };
}

/**
 * What already ran on the case, from the durable index alone (the outcome ledger is VQL-only, so it
 * cannot tell a collection from a fleet hunt). Throws when the index is corrupt — the caller must refuse.
 */
export async function loadLaunchFingerprints(
  caseId: string,
  index: Pick<HuntFingerprintStore, "load">,
): Promise<Set<string>> {
  return index.load(caseId);
}

/**
 * The store every caller should use: the index, seeded from the outcome ledger for a case that has
 * no index file yet. A legacy entry cannot be told apart from a fleet hunt, so it is treated as one
 * (refuses more, never less), and it is persisted with the first write.
 */
export function fingerprintStoreFor(cases: CaseStore): HuntFingerprintStore {
  const outcomes = new HuntOutcomeStore(cases);
  return new HuntFingerprintStore(cases, async (caseId) => [
    ...deployedFingerprints(await outcomes.load(caseId)),
  ]);
}
