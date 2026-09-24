export type EvalMode = "all" | "extraction" | "synthesis" | "screenshots";

export interface EvalCliOptions {
  mode: EvalMode;
  real: boolean;
  // How many times the selected sections run back to back (#1579). 1..MAX_RUNS.
  runs: number;
  requireProvider: boolean;
  requireBaseline: boolean;
  outputPath?: string;
  baselinePath?: string;
  baselineDirectory?: string;
  attestationPath?: string;
}

const MODES = new Set<EvalMode>(["all", "extraction", "synthesis", "screenshots"]);
const VALUE_FLAGS = new Set(["--output", "--baseline", "--write-baseline", "--attestation", "--runs"]);
const MAX_RUNS = 10;

function flagValue(argv: readonly string[], flag: string, kind = "a path"): string | undefined {
  const index = argv.indexOf(flag);
  if (index < 0) return undefined;
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires ${kind}`);
  return value;
}

function parseRuns(argv: readonly string[]): number {
  if (argv.filter((value) => value === "--runs").length > 1) {
    throw new Error("--runs was given more than once");
  }
  const raw = flagValue(argv, "--runs", "a number");
  if (raw === undefined) return 1;
  if (!/^-?\d+$/.test(raw)) throw new Error(`--runs must be an integer, got "${raw}"`);
  const runs = Number(raw);
  if (runs < 1 || runs > MAX_RUNS) throw new Error(`--runs must be between 1 and ${MAX_RUNS}, got ${runs}`);
  return runs;
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
    runs: parseRuns(argv),
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
