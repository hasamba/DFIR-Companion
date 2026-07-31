export type EvalMode = "all" | "extraction" | "synthesis" | "screenshots";

export interface EvalCliOptions {
  mode: EvalMode;
  real: boolean;
  requireProvider: boolean;
  requireBaseline: boolean;
  outputPath?: string;
  baselinePath?: string;
  baselineDirectory?: string;
  attestationPath?: string;
}

const MODES = new Set<EvalMode>(["all", "extraction", "synthesis", "screenshots"]);
const VALUE_FLAGS = new Set(["--output", "--baseline", "--write-baseline", "--attestation"]);

function flagValue(argv: readonly string[], flag: string): string | undefined {
  const index = argv.indexOf(flag);
  if (index < 0) return undefined;
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a path`);
  return value;
}

export function parseEvalCli(argv: readonly string[]): EvalCliOptions {
  const positional = argv.filter((value, index) => {
    if (value.startsWith("--")) return false;
    return index === 0 || !VALUE_FLAGS.has(argv[index - 1]);
  });
  const candidate = positional[0];
  const mode = candidate && MODES.has(candidate as EvalMode) ? (candidate as EvalMode) : "all";
  return {
    mode,
    real: argv.includes("--real"),
    requireProvider: argv.includes("--require-provider"),
    requireBaseline: argv.includes("--require-baseline"),
    ...(flagValue(argv, "--output") ? { outputPath: flagValue(argv, "--output") } : {}),
    ...(flagValue(argv, "--baseline") ? { baselinePath: flagValue(argv, "--baseline") } : {}),
    ...(flagValue(argv, "--write-baseline")
      ? { baselineDirectory: flagValue(argv, "--write-baseline") }
      : {}),
    ...(flagValue(argv, "--attestation") ? { attestationPath: flagValue(argv, "--attestation") } : {}),
  };
}
