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

// What a run without preservation still does, said the way an analyst reads it (#2898).
const STILL_RUNS =
  "The run still checks the AI-agent files for tampering, lists the AI tools, and saves a copy of each file a rule matched in Velociraptor, but not the full set of AI-agent files.";
// #2920: how to get the full set back. Windows.Triage.Targets is built into the Velociraptor server.
const HOW_TO_FIX =
  "To save them all, update your Velociraptor server to a release whose Windows.Triage.Targets has the AICodingAgents option (check in View Artifacts → Windows.Triage.Targets → Parameters).";

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
          ? `Your Velociraptor server has an older ${TRIAGE_ARTIFACT} artifact that does not know where AI coding agents keep their files. ${STILL_RUNS} ${HOW_TO_FIX}`
          : `Your Velociraptor server does not have the ${TRIAGE_ARTIFACT} artifact. ${STILL_RUNS} ${HOW_TO_FIX}`,
      );
  } catch (e) {
    warnings.push(
      `Could not read your Velociraptor server's artifact list (${(e as Error).message}). ${STILL_RUNS}`,
    );
  }
  if (skipped.length)
    warnings.push(`${skipped.length} endpoint(s) left out: this check runs on Windows only`);
  return { clientIds, skipped, preserve, warnings };
}
