import { MIN_ATTESTED_RUNS } from "./baseline.js";
import type { EvalCliOptions } from "./cli.js";

// #1579: an attestation is the evidence the change gate trusts, so it may only come from a run
// shaped like the one the gate checks. Refuse up front — before any provider is built or any
// model call is paid for — rather than spend an hour and then have checkChange reject the result.
function missingRequirements(options: EvalCliOptions): string[] {
  const missing: string[] = [];
  if (!options.real) missing.push("--real");
  if (options.runs < MIN_ATTESTED_RUNS) missing.push(`--runs ${MIN_ATTESTED_RUNS} or more`);
  if (options.mode !== "all") missing.push('mode "all"');
  if (!options.outputPath) missing.push("--output");
  if (!options.baselinePath) missing.push("--baseline");
  if (!options.requireBaseline) missing.push("--require-baseline");
  return missing;
}

export function attestationPreflight(options: EvalCliOptions): string | undefined {
  if (!options.attestationPath) return undefined;
  const missing = missingRequirements(options);
  if (!missing.length) return undefined;
  return `--attestation needs an attested run shape; missing: ${missing.join(", ")}`;
}
