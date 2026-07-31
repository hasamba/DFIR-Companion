import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { claimSnapshot, hashManifestValue } from "./analysisRunHash.js";
import type { InvestigationState } from "./stateTypes.js";
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

export function investigationOutput(state: InvestigationState): AnalysisRunOutput {
  return {
    entityIds: [
      ...state.findings.map((finding) => finding.id),
      ...state.iocs.map((ioc) => ioc.id),
      ...state.forensicTimeline.map((event) => event.id),
    ],
    hashes: [
      {
        id: "investigation-state",
        sha256: hashManifestValue({
          findings: state.findings,
          iocs: state.iocs,
          forensicTimeline: state.forensicTimeline,
        }),
      },
    ],
    claims: state.findings.map((finding) =>
      claimSnapshot(finding.id, {
        title: finding.title,
        severity: finding.severity,
        description: finding.description,
        evidenceEventIds: finding.relatedEventIds,
      }),
    ),
  };
}
