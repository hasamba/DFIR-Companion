import { mkdtemp, mkdir, readFile, rm, copyFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import type { ToolConfig } from "./toolConfig.js";
import { substituteArgs, tokenizeArgs, stripAnsi, cleanToolOutput, type ToolRunner } from "./toolRunner.js";

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
  definitions?: string;  // overrides cfg.definitions when provided
}): Promise<RunToolResult> {
  const { cfg, runner, targetPath, workDir } = opts;
  const rules = (opts.rulesPath ?? cfg.rulesPath ?? "").trim();
  const definitions = (opts.definitions ?? cfg.definitions ?? "").trim();
  if (cfg.runArgs.includes("<rules>") && !rules) {
    throw new Error(`${cfg.id}: a rules file is required — set it in Settings → Tools (DFIR_TOOL_${cfg.id.toUpperCase()}_RULES)`);
  }
  if (cfg.runArgs.includes("<definitions>") && !definitions) {
    throw new Error(`${cfg.id}: a definitions path is required — set it in Settings → Tools (DFIR_TOOL_${cfg.id.toUpperCase()}_DEFINITIONS)`);
  }

  await mkdir(workDir, { recursive: true });
  const runDir = await mkdtemp(join(workDir, "run-"));
  let inputDir: string | undefined;
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

    // Folder-root tools (Velociraptor `--ROOT`) run against a DIRECTORY and glob the files inside — and
    // detect the log channel from the filename — so place the target in a fresh dir under its ORIGINAL
    // name and pass that dir as <targetdir>. Isolating it in its own dir avoids processing siblings.
    let targetDirArg: string | undefined;
    if (cfg.runArgs.includes("<targetdir>")) {
      inputDir = await mkdtemp(join(workDir, "in-"));
      await copyFile(targetPath, join(inputDir, basename(targetPath)));
      targetDirArg = inputDir;
    }

    let tokens = tokenizeArgs(cfg.runArgs);
    // Shell-style stdout redirect `> <file>`: the tool writes results to stdout and the analyst's command
    // redirects them to a file (e.g. Velociraptor's collection). We run shell-free, so we strip the `>`
    // and its target token and redirect stdout to a server-owned file natively — then import that file.
    // This also avoids buffering a huge output in memory (no maxOutputBytes cap on the stream).
    let stdoutFile: string | undefined;
    const gt = tokens.indexOf(">");
    if (gt >= 0) {
      stdoutFile = join(runDir, cfg.outputFile ?? "output.json");
      readPath = stdoutFile;
      tokens = tokens.filter((_, i) => i !== gt && i !== gt + 1);   // drop `>` and its (usually <output>) target
    }

    const argv = substituteArgs(tokens, {
      target: targetPath,
      targetdir: targetDirArg,
      output: outputArg,
      rules: rules || undefined,
      definitions: definitions || undefined,
    });

    const res = await runner(cfg.binary, argv, { timeoutMs: cfg.timeoutMs, maxOutputBytes: cfg.maxOutputBytes, stdoutFile });

    // Redirected/file/dir output → read the file. Pure stdout tools (YARA/Snort) → strip ANSI so a
    // colour-forcing CLI can't break the importer parser.
    const outputText = stdoutFile || cfg.outputMode !== "stdout"
      ? await readFile(readPath as string, "utf8").catch(() => "")
      : stripAnsi(res.stdout);

    if (!outputText.trim()) {
      const cleanErr = cleanToolOutput(res.stderr, 4);
      const detail = cleanErr ? `: ${cleanErr.slice(0, 400)}`
        : res.code ? ` (exit ${res.code})` : "";
      throw new Error(`${cfg.id} produced no output${detail}`);
    }
    return { outputText, importKind: cfg.importKind, stderr: stripAnsi(res.stderr) };
  } finally {
    await rm(runDir, { recursive: true, force: true }).catch(() => {});
    if (inputDir) await rm(inputDir, { recursive: true, force: true }).catch(() => {});
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
  // Strip ANSI colour codes + collapse CR progress redraws so the UI toast is readable, not garbage
  // (Hayabusa's update-rules forces colour). Keep the tail — the meaningful "N rules updated" summary.
  const text = cleanToolOutput(`${res.stdout}\n${res.stderr}`);
  if (res.code !== 0 && !text) throw new Error(`${cfg.id} update exited with code ${res.code}`);
  return text || `${cfg.id} update completed`;
}
