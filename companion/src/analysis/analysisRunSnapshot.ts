import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { canonicalize, claimSnapshot, hashManifestValue } from "./analysisRunHash.js";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
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

/**
 * investigationOutput without the whole case in memory (#1874): the forensic timeline arrives a page
 * at a time and is hashed as it goes. The bytes hashed are exactly JSON.stringify(canonicalize({
 * findings, iocs, forensicTimeline })) — keys sorted, so "findings", "forensicTimeline", "iocs" —
 * which is what hashManifestValue hashes, so the digest is the same.
 */
export async function investigationOutputStreamed(
  overview: Pick<InvestigationState, "findings" | "iocs">,
  timeline: AsyncIterable<readonly ForensicEvent[]>,
): Promise<AnalysisRunOutput> {
  const hash = createHash("sha256");
  const eventIds: string[] = [];
  hash.update(`{"findings":${JSON.stringify(canonicalize(overview.findings))},"forensicTimeline":[`);
  let first = true;
  for await (const batch of timeline) {
    for (const event of batch) {
      eventIds.push(event.id);
      hash.update((first ? "" : ",") + (JSON.stringify(canonicalize(event)) ?? "null"));
      first = false;
    }
  }
  hash.update(`],"iocs":${JSON.stringify(canonicalize(overview.iocs))}}`);
  const full = investigationOutput({ ...overview, forensicTimeline: [] } as unknown as InvestigationState);
  return {
    ...full,
    entityIds: [...overview.findings.map((f) => f.id), ...overview.iocs.map((i) => i.id), ...eventIds],
    hashes: [{ id: "investigation-state", sha256: hash.digest("hex") }],
  };
}
