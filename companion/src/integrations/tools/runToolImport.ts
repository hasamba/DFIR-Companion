import { mkdtemp, mkdir, readFile, rm, copyFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import type { ToolConfig } from "./toolConfig.js";
import { substituteArgs, tokenizeArgs, stripAnsi, cleanToolOutput, type ToolRunner } from "./toolRunner.js";
import {
  hashOutputText,
  hashRuleset,
  invalidateToolRunCaches,
  probeToolVersion,
  type ToolRunCache,
  type ToolRunProvenance,
} from "./toolProvenance.js";

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
  outputText: string; // the tool's output (stdout, or the read-back result file), fed to the importer
  importKind: string; // the fixed downstream importer kind for this tool
  stderr: string; // captured stderr (for surfacing warnings/errors to the analyst)
  // The full account of the run — binary, version, argv, exit code, rule set, output hash (#688).
  // Written into the stored output's chain-of-custody record so a parse can be defended later.
  provenance: ToolRunProvenance;
}

// Run `cfg` against `targetPath` and return the tool's output text + its importKind. `workDir` is a
// server-owned scratch directory (created if missing) under which a unique run dir holds any output
// file; it is removed afterwards. A tool whose template needs <rules> but has no rules path configured
// fails fast with an actionable message.
export async function runToolAgainstFile(opts: {
  cfg: ToolConfig;
  runner: ToolRunner;
  targetPath: string; // already validated/absolute
  workDir: string; // e.g. cases/<id>/.toolwork
  rulesPath?: string; // overrides cfg.rulesPath when provided
  definitions?: string; // overrides cfg.definitions when provided
  // Per-import-job memo for the ruleset hash + version probe. Omit for a one-off run (#721).
  cache?: ToolRunCache;
}): Promise<RunToolResult> {
  const { cfg, runner, targetPath, workDir } = opts;
  const rules = (opts.rulesPath ?? cfg.rulesPath ?? "").trim();
  const definitions = (opts.definitions ?? cfg.definitions ?? "").trim();
  if (cfg.runArgs.includes("<rules>") && !rules) {
    throw new Error(
      `${cfg.id}: a rules file is required — set it in Settings → Tools (DFIR_TOOL_${cfg.id.toUpperCase()}_RULES)`,
    );
  }
  if (cfg.runArgs.includes("<definitions>") && !definitions) {
    throw new Error(
      `${cfg.id}: a definitions path is required — set it in Settings → Tools (DFIR_TOOL_${cfg.id.toUpperCase()}_DEFINITIONS)`,
    );
  }

  // The rule set behind the verdicts, reduced to one hash for the custody record (#688). Resolved
  // BEFORE the tool is spawned so a fail-closed parser refuses to run at all rather than reporting a
  // confident "no detections" over rules it never loaded — which is indistinguishable, in the output,
  // from a genuinely clean log.
  const ruleset = rules ? await hashRuleset(rules, opts.cache) : null;
  if (cfg.requireRuleset && !ruleset) {
    throw new Error(
      `${cfg.id}: the rule set at "${rules}" could not be identified — the path must exist and hold at least one readable rule file. ` +
        `Refusing to run: a parser with no rules loaded reports "no detections" over evidence it never examined.`,
    );
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
      tokens = tokens.filter((_, i) => i !== gt && i !== gt + 1); // drop `>` and its (usually <output>) target
    }

    const argv = substituteArgs(tokens, {
      target: targetPath,
      targetdir: targetDirArg,
      output: outputArg,
      rules: rules || undefined,
      definitions: definitions || undefined,
    });

    // Best effort, and deliberately before the run so a version probe that hangs is bounded by its
    // own short timeout rather than eating into the parse. A blank version never fails the run.
    const version = await probeToolVersion(cfg, runner, opts.cache);

    const res = await runner(cfg.binary, argv, {
      timeoutMs: cfg.timeoutMs,
      maxOutputBytes: cfg.maxOutputBytes,
      stdoutFile,
    });

    // FAIL CLOSED (#688). A parser that died halfway still leaves the rows it managed to write, and
    // importing those puts a silently partial view of the evidence into the case with nothing saying
    // so. For a tool whose exit code is meaningful this rejects the whole run. YARA and Snort are not
    // flagged: they exit non-zero to mean "matches found", which is a successful run.
    //
    // A SIGNAL kill counts too, and is the likeliest way a parser dies on real evidence: the OOM
    // killer takes it out partway through a large EVTX, or it segfaults on a malformed chunk. Both
    // leave a plausible-looking partial output file behind.
    //
    // The two halves are gated SEPARATELY (#719). Only the exit CODE is tool-specific — the flag is
    // unset for YARA and Snort because they exit non-zero to mean "matches found". A signal is not a
    // return value: no tool uses one to report matches, so a killed process is a partial parse for
    // EVERY tool, flag or no flag. Riding both halves on the flag meant a YARA scan the OOM killer
    // took out imported its half-written stdout as a completed scan.
    if (res.signal || (cfg.failOnNonZeroExit && res.code !== 0)) {
      const detail = cleanToolOutput(res.stderr, 4);
      const how = res.signal ? `was killed by ${res.signal}` : `exited with code ${res.code}`;
      throw new Error(
        `${cfg.id} ${how} — refusing to import a partial parse${detail ? `: ${detail.slice(0, 400)}` : ""}`,
      );
    }

    // Redirected/file/dir output → read the file. Pure stdout tools (YARA/Snort) → strip ANSI so a
    // colour-forcing CLI can't break the importer parser.
    const outputText =
      stdoutFile || cfg.outputMode !== "stdout"
        ? await readFile(readPath as string, "utf8").catch(() => "")
        : stripAnsi(res.stdout);

    if (!outputText.trim()) {
      const cleanErr = cleanToolOutput(res.stderr, 4);
      const detail = cleanErr ? `: ${cleanErr.slice(0, 400)}` : res.code ? ` (exit ${res.code})` : "";
      throw new Error(`${cfg.id} produced no output${detail}`);
    }
    const stderr = stripAnsi(res.stderr);
    return {
      outputText,
      importKind: cfg.importKind,
      stderr,
      provenance: {
        toolId: cfg.id,
        binary: cfg.binary,
        version,
        argv,
        exitCode: res.code,
        stderr: cleanToolOutput(stderr, 20),
        outputSha256: hashOutputText(outputText),
        ruleset,
      },
    };
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
  const res = await runner(bin, argv.slice(1), {
    timeoutMs: cfg.timeoutMs,
    maxOutputBytes: cfg.maxOutputBytes,
  });
  // The rules on disk may have moved under any import running right now, so drop the job memos
  // that would otherwise stamp the PREVIOUS rule set into those runs' custody records (#736).
  // Done on any completion, not only exit 0: a failed update can still have written part of the
  // tree. A command that never ran (no updateCommand, unparseable) threw above and leaves them.
  invalidateToolRunCaches();
  // Strip ANSI colour codes + collapse CR progress redraws so the UI toast is readable, not garbage
  // (Hayabusa's update-rules forces colour). Keep the tail — the meaningful "N rules updated" summary.
  const text = cleanToolOutput(`${res.stdout}\n${res.stderr}`);
  if (res.code !== 0 && !text) throw new Error(`${cfg.id} update exited with code ${res.code}`);
  return text || `${cfg.id} update completed`;
}
