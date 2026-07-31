import type { AnalysisRunClaim, AnalysisRunManifest } from "./analysisRunTypes.js";

export interface AnalysisRunClaimRef {
  id: string;
  evidenceEventIds: string[];
}

export interface ChangedAnalysisRunClaim {
  id: string;
  beforeEvidenceEventIds: string[];
  afterEvidenceEventIds: string[];
}

export interface AnalysisRunComparison {
  fromRunId: string;
  toRunId: string;
  added: AnalysisRunClaimRef[];
  removed: AnalysisRunClaimRef[];
  changed: ChangedAnalysisRunClaim[];
}

function ref(claim: AnalysisRunClaim): AnalysisRunClaimRef {
  return { id: claim.id, evidenceEventIds: claim.evidenceEventIds };
}

export function compareAnalysisRuns(
  from: AnalysisRunManifest,
  to: AnalysisRunManifest,
): AnalysisRunComparison {
  const before = new Map(from.output.claims.map((claim) => [claim.id, claim]));
  const after = new Map(to.output.claims.map((claim) => [claim.id, claim]));
  const added = [...after.values()].filter((claim) => !before.has(claim.id)).map(ref);
  const removed = [...before.values()].filter((claim) => !after.has(claim.id)).map(ref);
  const changed = [...after.values()].flatMap((claim) => {
    const prior = before.get(claim.id);
    if (!prior || prior.hash === claim.hash) return [];
    return [
      {
        id: claim.id,
        beforeEvidenceEventIds: prior.evidenceEventIds,
        afterEvidenceEventIds: claim.evidenceEventIds,
      },
    ];
  });
  return { fromRunId: from.id, toRunId: to.id, added, removed, changed };
}
