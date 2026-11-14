import { deployedFingerprints, vqlFingerprint, type HuntDeployInput } from "../../../huntOutcomes.js";
import type { HuntOutcomeStore } from "../../../huntOutcomeStore.js";
import type { HuntFingerprintStore } from "./huntFingerprintStore.js";
export { HuntFingerprintStore } from "./huntFingerprintStore.js";
import { canonicalVqlFingerprint } from "./vqlAllowed.js";

// Wires the durable fingerprint index (huntFingerprintStore.ts) into every hunt deploy, Watson's or
// not: server.ts wraps ctx.recordHuntDeploy with withFingerprintIndex, so all four deploy routes
// index without touching the capped veloHunts.ts / routes/velociraptor.ts.

type RecordDeploy = (caseId: string, input: HuntDeployInput) => Promise<void>;

/** Both fingerprints a launch is remembered by: the ledger's own and the comment-blind canonical one. */
export function launchFingerprints(vql: string | undefined): string[] {
  if (!vql) return [];
  return [vqlFingerprint(vql), canonicalVqlFingerprint(vql)].filter(Boolean);
}

/** Wrap recordHuntDeploy so each deploy is first added to the durable index. Index errors are logged, never thrown. */
export function withFingerprintIndex(
  inner: RecordDeploy,
  index: Pick<HuntFingerprintStore, "add">,
  log: (line: string) => void,
): RecordDeploy {
  return async (caseId, input) => {
    try {
      await index.add(caseId, launchFingerprints(input.vql));
    } catch (e) {
      log(`[hunt-fingerprints] index write failed: ${(e as Error).message}`);
    }
    await inner(caseId, input);
  };
}

/**
 * What already ran on the case: the durable index unioned with the outcome ledger (cases that
 * deployed before the index existed). Throws when the index is corrupt — the caller must refuse.
 */
export async function loadLaunchFingerprints(
  caseId: string,
  index: Pick<HuntFingerprintStore, "load">,
  outcomes: Pick<HuntOutcomeStore, "load"> | undefined,
): Promise<Set<string>> {
  const fromIndex = await index.load(caseId);
  const fromOutcomes = outcomes ? deployedFingerprints(await outcomes.load(caseId)) : new Set<string>();
  return new Set([...fromIndex, ...fromOutcomes]);
}
