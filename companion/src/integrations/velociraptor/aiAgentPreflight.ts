// AI Agent Forensics (#2690, §4.6): what the run can do on THIS server, decided before launch.
//
//   no Windows endpoint selected          → cannot run (the artifact and the triage target are Windows-only);
//   Windows.Triage.Targets lacks the AICodingAgents rule (older triage release)
//                                         → run detection + inventory anyway, report "artifacts not preserved";
//   the catalog could not be read         → run without preservation and say why (never block on a diagnostic).
// The ARTIFACT_WRITER permission artifact_set needs has no cheap read-only probe: the launch's first
// artifact_set call is the check, and its refusal names the permission (aiAgentLaunch.ts).

import type { VeloArtifactInfo } from "./artifactCatalog.js";
import { TRIAGE_ARTIFACT, TRIAGE_RULE } from "./aiAgentLaunch.js";

export interface AiAgentEndpoint {
  clientId: string;
  hostname: string;
  os: string;
}

export interface AiAgentPreflight {
  clientIds: string[]; // the Windows endpoints the run will target
  skipped: { clientId: string; hostname: string; reason: string }[];
  preserve: boolean;
  warnings: string[];
  error?: string;
}

/** Decide the run's targets and whether preservation can run. */
export async function preflightAiAgentRun(
  endpoints: readonly AiAgentEndpoint[],
  fetchDefinitions: () => Promise<VeloArtifactInfo[]>,
): Promise<AiAgentPreflight> {
  const skipped = endpoints
    .filter((e) => e.os && e.os.toLowerCase() !== "windows")
    .map((e) => ({
      clientId: e.clientId,
      hostname: e.hostname,
      reason: `${e.os} — this version runs on Windows only`,
    }));
  const clientIds = endpoints.filter((e) => !e.os || e.os.toLowerCase() === "windows").map((e) => e.clientId);
  if (clientIds.length === 0)
    return { clientIds, skipped, preserve: false, warnings: [], error: "no Windows endpoint is selected" };
  const warnings: string[] = [];
  let preserve = false;
  try {
    const defs = await fetchDefinitions();
    const triage = defs.find((d) => d.name === TRIAGE_ARTIFACT);
    preserve = !!triage?.parameters.some((p) => p.name === TRIAGE_RULE);
    if (!preserve)
      warnings.push(
        triage
          ? `${TRIAGE_ARTIFACT} on this server has no ${TRIAGE_RULE} rule (an older triage release): detection and inventory run, artifacts not preserved`
          : `${TRIAGE_ARTIFACT} is not on this server: detection and inventory run, artifacts not preserved`,
      );
  } catch (e) {
    warnings.push(
      `could not read the server's artifact catalog (${(e as Error).message}): detection and inventory run, artifacts not preserved`,
    );
  }
  if (skipped.length) warnings.push(`${skipped.length} non-Windows endpoint(s) left out`);
  return { clientIds, skipped, preserve, warnings };
}
