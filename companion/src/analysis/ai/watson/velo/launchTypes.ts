import type { HuntFingerprintStore } from "./huntFingerprintStore.js";
import type { LaunchContext } from "./launchCheck.js";
import type { VeloFleetSeams } from "./veloFleet.js";

// The seams an approved Watson launch needs (phase 3). The route builds them: `launch` wraps the
// existing deploy path (routes/veloDeploy.ts → deployCaseHunt), which analysis/ai may not import.

export interface VeloLaunchRequest {
  mode: "hunt" | "collection";
  vql: string;
  title: string;
  hostname?: string;
}

/**
 * What the deploy reported. `phase` says whether anything reached Velociraptor:
 * `invalid` / `before-launch` — nothing ran; `launch-unknown` — maybe; `launched` — it ran (ids known).
 */
export interface VeloLaunchOutcome {
  phase: "invalid" | "before-launch" | "launch-unknown" | "launched";
  error?: string;
  launched?: { huntId?: string; flowId?: string; clientId?: string };
}

export interface VeloLaunchDeps {
  launch(caseId: string, req: VeloLaunchRequest, actor: string): Promise<VeloLaunchOutcome>;
  fleet: VeloFleetSeams;
  matchClient: LaunchContext["matchClient"];
  fingerprints: Pick<HuntFingerprintStore, "load" | "reserve" | "release">;
  log?(line: string): void;
}
