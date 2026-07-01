import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import type { ToolConfig } from "./toolConfig.js";
import { substituteArgs, tokenizeArgs, type ToolRunner } from "./toolRunner.js";

// Orchestrates "run the analyst's tool against a raw file on disk → hand its TEXT output to the existing
// importer". Pure of any server/HTTP concern; the ToolRunner is injected so tests never spawn. Security
// is enforced here: the TARGET path must be contained in the case dir, and the OUTPUT path is
// server-owned (a temp dir under the case work dir) so the tool can't overwrite an arbitrary file.

// Resolve `userPath` (case-relative or absolute) to an absolute path and assert it is strictly INSIDE
// `caseDir` — rejecting `..` traversal and absolute escapes. Throws otherwise. The caseDir itself is not
// a valid target (a file must live under it).
export function resolveContainedPath(caseDir: string, userPath: string): string {
  const root = resolve(caseDir);
  const abs = isAbsolute(userPath) ? resolve(userPath) : resolve(root, userPath);
  const rel = relative(root, abs);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`path "${userPath}" is outside the case directory`);
  }
  return abs;
}

export interface RunToolResult {
  outputText: string;   // the tool's output (stdout, or the read-back result file), fed to the importer
  importKind: string;   // the fixed downstream importer kind for this tool
  stderr: string;       // captured stderr (for surfacing warnings/errors to the analyst)
}

// Run `cfg` against `targetPath` and return the tool's output text + its importKind. `workDir` is a
// server-owned scratch directory (created if missing) under which a unique run dir holds any output
// file; it is removed afterwards. A tool whose template needs <rules> but has no rules path configured
// fails fast with an actionable message.
export async function runToolAgainstFile(opts: {
  cfg: ToolConfig;
  runner: ToolRunner;
  targetPath: string;    // already validated/absolute
  workDir: string;       // e.g. cases/<id>/.toolwork
  rulesPath?: string;    // overrides cfg.rulesPath when provided
}): Promise<RunToolResult> {
  const { cfg, runner, targetPath, workDir } = opts;
  const rules = (opts.rulesPath ?? cfg.rulesPath ?? "").trim();
  if (cfg.runArgs.includes("<rules>") && !rules) {
    throw new Error(`${cfg.id}: a rules file is required — set it in Settings → Tools (DFIR_TOOL_${cfg.id.toUpperCase()}_RULES)`);
  }

  await mkdir(workDir, { recursive: true });
  const runDir = await mkdtemp(join(workDir, "run-"));
  try {
    let outputArg: string | undefined;
    let readPath: string | undefined;
    if (cfg.outputMode === "file") {
      outputArg = join(runDir, cfg.outputFile ?? "output.dat");
      readPath = outputArg;
    } else if (cfg.outputMode === "dir") {
      outputArg = runDir;
      readPath = join(runDir, cfg.outputFile ?? "eve.json");
    }

    const argv = substituteArgs(tokenizeArgs(cfg.runArgs), {
      target: targetPath,
      output: outputArg,
      rules: rules || undefined,
    });

    const res = await runner(cfg.binary, argv, { timeoutMs: cfg.timeoutMs, maxOutputBytes: cfg.maxOutputBytes });

    const outputText = cfg.outputMode === "stdout"
      ? res.stdout
      : await readFile(readPath as string, "utf8").catch(() => "");

    if (!outputText.trim()) {
      const detail = res.stderr.trim() ? `: ${res.stderr.trim().slice(0, 400)}`
        : res.code ? ` (exit ${res.code})` : "";
      throw new Error(`${cfg.id} produced no output${detail}`);
    }
    return { outputText, importKind: cfg.importKind, stderr: res.stderr };
  } finally {
    await rm(runDir, { recursive: true, force: true }).catch(() => {});
  }
}

// Run the tool's "update rules" command (a full standalone command line — its first token is the
// executable, which may be a sibling like `suricata-update`). Returns combined stdout/stderr for a UI
// toast. Does NOT touch case data — a rule update is not evidence.
export async function updateToolRules(cfg: ToolConfig, runner: ToolRunner): Promise<string> {
  if (!cfg.updateCommand) throw new Error(`no update command configured for ${cfg.id}`);
  const argv = tokenizeArgs(cfg.updateCommand);
  const bin = argv[0];
  if (!bin) throw new Error(`invalid update command for ${cfg.id}`);
  const res = await runner(bin, argv.slice(1), { timeoutMs: cfg.timeoutMs, maxOutputBytes: cfg.maxOutputBytes });
  const text = [res.stdout.trim(), res.stderr.trim()].filter(Boolean).join("\n").trim();
  if (res.code !== 0 && !text) throw new Error(`${cfg.id} update exited with code ${res.code}`);
  return text || `${cfg.id} update completed`;
}
