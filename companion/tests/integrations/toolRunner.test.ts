import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  tokenizeArgs,
  substituteArgs,
  toolSpawnErrorMessage,
  stripAnsi,
  cleanToolOutput,
  type ToolRunner,
} from "../../src/integrations/tools/toolRunner.js";
import {
  loadToolConfig,
  loadAllToolConfigs,
  toolForExtension,
  suggestedToolForExtension,
  TOOL_DEFS,
  type ToolId,
} from "../../src/integrations/tools/toolConfig.js";
import {
  resolveContainedPath,
  runToolAgainstFile,
  updateToolRules,
} from "../../src/integrations/tools/runToolImport.js";

describe("tokenizeArgs", () => {
  it("splits on unquoted whitespace", () => {
    expect(tokenizeArgs("-r a.pcap -l out")).toEqual(["-r", "a.pcap", "-l", "out"]);
  });
  it("keeps a double-quoted token with spaces as one element", () => {
    expect(tokenizeArgs('-f "C:\\Program Files\\a.evtx" -o out')).toEqual([
      "-f",
      "C:\\Program Files\\a.evtx",
      "-o",
      "out",
    ]);
  });
  it("keeps a single-quoted token with spaces as one element", () => {
    expect(tokenizeArgs("-c 'my rules.rules'")).toEqual(["-c", "my rules.rules"]);
  });
  it("returns [] for empty/blank", () => {
    expect(tokenizeArgs("")).toEqual([]);
    expect(tokenizeArgs("   ")).toEqual([]);
  });
});

describe("substituteArgs", () => {
  it("replaces a whole-token placeholder with a path containing spaces as ONE element", () => {
    const argv = tokenizeArgs("-f <target> -o <output>");
    expect(substituteArgs(argv, { target: "C:\\Program Files\\a.evtx", output: "/tmp/o.csv" })).toEqual([
      "-f",
      "C:\\Program Files\\a.evtx",
      "-o",
      "/tmp/o.csv",
    ]);
  });
  it("substitutes a placeholder embedded in a token, keeping one element", () => {
    const argv = tokenizeArgs("collect --args EvtxGlob=<target>");
    expect(substituteArgs(argv, { target: "C:\\ev tx\\a.evtx" })).toEqual([
      "collect",
      "--args",
      "EvtxGlob=C:\\ev tx\\a.evtx",
    ]);
  });
  it("leaves an unset placeholder verbatim", () => {
    expect(substituteArgs(["-c", "<rules>"], {})).toEqual(["-c", "<rules>"]);
  });
  it("substitutes <targetdir> and <definitions> without <target> shadowing <targetdir>", () => {
    const argv = tokenizeArgs("--definitions <definitions> --ROOT <targetdir>");
    expect(substituteArgs(argv, { targetdir: "/work/in", definitions: "/defs/a.zip" })).toEqual([
      "--definitions",
      "/defs/a.zip",
      "--ROOT",
      "/work/in",
    ]);
  });
});

describe("stripAnsi / cleanToolOutput", () => {
  const ESC = String.fromCharCode(0x1b);
  it("removes SGR colour codes (Hayabusa forces colour on a non-TTY)", () => {
    // e.g. `hayabusa: <ESC>[0m<ESC>[38;2;0;255;0m Rules updated`
    const raw = `hayabusa: ${ESC}[0m${ESC}[38;2;0;255;0m Rules updated: 4200${ESC}[0m`;
    expect(stripAnsi(raw)).toBe("hayabusa:  Rules updated: 4200");
  });
  it("leaves plain brackets and text untouched", () => {
    expect(stripAnsi("no codes [here] (at all)")).toBe("no codes [here] (at all)");
  });
  it("cleanToolOutput collapses CR progress redraws + keeps the tail summary", () => {
    const raw = `cloning...${ESC}[32m\rProgress 10%\rProgress 100%\n${ESC}[0mDone: 4200 rules\n\n`;
    const out = cleanToolOutput(raw);
    expect(out).not.toContain(ESC);
    expect(out).toContain("Done: 4200 rules");
  });
});

describe("toolSpawnErrorMessage", () => {
  it("gives ENOENT a not-found hint", () => {
    expect(toolSpawnErrorMessage("hayabusa", { code: "ENOENT", message: "spawn ENOENT" })).toMatch(/not found/i);
  });
  it("gives EPERM an AV/EDR hint", () => {
    expect(toolSpawnErrorMessage("yara", { code: "EPERM", message: "spawn EPERM" })).toMatch(/antivirus|EDR/i);
  });
});

describe("loadToolConfig / loadAllToolConfigs", () => {
  it("returns null when the binary is unset", () => {
    expect(loadToolConfig("hayabusa", {})).toBeNull();
  });
  it("populates from defaults + overrides when the binary is set", () => {
    const cfg = loadToolConfig("hayabusa", {
      DFIR_TOOL_HAYABUSA_BINARY: "C:\\tools\\hayabusa.exe",
      DFIR_TOOL_HAYABUSA_TIMEOUT_MS: "12345",
    })!;
    expect(cfg.binary).toBe("C:\\tools\\hayabusa.exe");
    expect(cfg.importKind).toBe("hayabusa");
    expect(cfg.runArgs).toBe(TOOL_DEFS.hayabusa.defaultRunArgs);
    expect(cfg.timeoutMs).toBe(12345);
    expect(cfg.autoRun).toBe(false);   // opt-in: default off so imports/drops ask first
    // default update command reuses the binary (no spaces → unquoted) + subcommand
    expect(cfg.updateCommand).toBe("C:\\tools\\hayabusa.exe update-rules");
  });
  it("auto-run is opt-in (on only when explicitly set) and gated by the master switch", () => {
    expect(loadToolConfig("snort", { DFIR_TOOL_SNORT_BINARY: "snort", DFIR_TOOL_SNORT_AUTO_RUN: "on" })!.autoRun).toBe(true);
    expect(loadToolConfig("snort", { DFIR_TOOL_SNORT_BINARY: "snort" })!.autoRun).toBe(false);
    // master kill-switch overrides an explicit per-tool on
    expect(loadToolConfig("snort", { DFIR_TOOL_SNORT_BINARY: "snort", DFIR_TOOL_SNORT_AUTO_RUN: "on", DFIR_TOOL_AUTO_RUN: "false" })!.autoRun).toBe(false);
  });
  it("has no default update command for suricata (suricata-update is Linux-only)", () => {
    expect(loadToolConfig("suricata", { DFIR_TOOL_SURICATA_BINARY: "suricata" })!.updateCommand).toBeUndefined();
    // ...but an explicit standalone command is honored verbatim (first token = its own binary).
    expect(loadToolConfig("suricata", { DFIR_TOOL_SURICATA_BINARY: "suricata", DFIR_TOOL_SURICATA_UPDATE_CMD: "suricata-update" })!.updateCommand).toBe("suricata-update");
  });
  it("loadAllToolConfigs returns only configured tools", () => {
    const all = loadAllToolConfigs({ DFIR_TOOL_YARA_BINARY: "yara", DFIR_TOOL_SNORT_BINARY: "snort" });
    expect([...all.keys()].sort()).toEqual(["snort", "yara"]);
  });
});

describe("extension → tool routing", () => {
  it("prefers hayabusa for evtx, suricata for pcap when configured", () => {
    const all = loadAllToolConfigs({
      DFIR_TOOL_HAYABUSA_BINARY: "h",
      DFIR_TOOL_VELOCIRAPTOR_CLI_BINARY: "v",
      DFIR_TOOL_SURICATA_BINARY: "s",
      DFIR_TOOL_SNORT_BINARY: "sn",
    });
    expect(toolForExtension(".evtx", all)).toBe("hayabusa");
    expect(toolForExtension(".pcap", all)).toBe("suricata");
  });
  it("falls back to the next configured tool", () => {
    const all = loadAllToolConfigs({ DFIR_TOOL_VELOCIRAPTOR_CLI_BINARY: "v", DFIR_TOOL_SNORT_BINARY: "sn" });
    expect(toolForExtension(".evtx", all)).toBe("velociraptor_cli");
    expect(toolForExtension(".pcap", all)).toBe("snort");
  });
  it("suggests a tool even when none configured", () => {
    expect(suggestedToolForExtension(".evtx")).toBe("hayabusa");
    expect(suggestedToolForExtension(".pcapng")).toBe("suricata");
    expect(suggestedToolForExtension(".txt")).toBeNull();
  });
});

describe("resolveContainedPath", () => {
  it("resolves a case-relative path inside the case dir", () => {
    const p = resolveContainedPath("/cases/abc", "drop/a.evtx");
    expect(p.replace(/\\/g, "/")).toMatch(/\/cases\/abc\/drop\/a\.evtx$/);
  });
  it("rejects traversal outside the case dir", () => {
    expect(() => resolveContainedPath("/cases/abc", "../def/x")).toThrow(/outside the case/);
  });
  it("rejects the case dir itself", () => {
    expect(() => resolveContainedPath("/cases/abc", ".")).toThrow(/outside the case/);
  });
});

describe("runToolAgainstFile", () => {
  it("runs a stdout tool and returns its output + importKind", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "a.bin"), "sample");
    const cfg = loadToolConfig("yara", { DFIR_TOOL_YARA_BINARY: "yara", DFIR_TOOL_YARA_RULES: "/rules/r.yar" })!;
    let seenBinary = "";
    let seenArgs: string[] = [];
    const runner: ToolRunner = async (binary, args) => {
      seenBinary = binary;
      seenArgs = args;
      return { stdout: "EvilRule /x/a.bin", stderr: "", code: 0 };
    };
    const res = await runToolAgainstFile({
      cfg,
      runner,
      targetPath: join(caseDir, "a.bin"),
      workDir: join(caseDir, ".toolwork"),
    });
    expect(res.importKind).toBe("yara");
    expect(res.outputText).toBe("EvilRule /x/a.bin");
    expect(seenBinary).toBe("yara");
    expect(seenArgs).toContain("/rules/r.yar");
    expect(seenArgs).toContain(join(caseDir, "a.bin"));
  });

  it("stages the target into a folder under its ORIGINAL name for a <targetdir> tool + requires definitions", async () => {
    const { readdir } = await import("node:fs/promises");
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "Security.evtx"), "evtx-bytes");
    // Default velociraptor_cli command uses <definitions> + <targetdir> → definitions is required.
    const cfg = loadToolConfig("velociraptor_cli", { DFIR_TOOL_VELOCIRAPTOR_CLI_BINARY: "velociraptor" })!;
    expect(cfg.runArgs).toContain("--ROOT <targetdir>");
    expect(cfg.outputMode).toBe("stdout");
    const runner: ToolRunner = async () => ({ stdout: "x", stderr: "", code: 0 });
    await expect(
      runToolAgainstFile({ cfg, runner, targetPath: join(caseDir, "Security.evtx"), workDir: join(caseDir, ".toolwork") }),
    ).rejects.toThrow(/definitions path is required/i);

    // With definitions set, <targetdir> resolves to a folder holding the file under its original name.
    const cfg2 = loadToolConfig("velociraptor_cli", {
      DFIR_TOOL_VELOCIRAPTOR_CLI_BINARY: "velociraptor",
      DFIR_TOOL_VELOCIRAPTOR_CLI_DEFINITIONS: "/defs/Velociraptor.Sigma.Artifacts.zip",
    })!;
    let rootDir = "";
    const runner2: ToolRunner = async (_binary, args, opts) => {
      rootDir = args[args.indexOf("--ROOT") + 1];
      const files = await readdir(rootDir);
      // the folder must contain the ORIGINAL evtx filename (Velociraptor detects the channel from it)
      expect(files).toContain("Security.evtx");
      expect(args).toContain("/defs/Velociraptor.Sigma.Artifacts.zip");
      // the `>` redirect + its <output> target are stripped from argv and handled via stdoutFile
      expect(args).not.toContain(">");
      expect(args).not.toContain("<output>");
      expect(opts.stdoutFile).toBeTruthy();
      await writeFile(opts.stdoutFile as string, '[{"a":1}]');   // the tool "writes" its stdout to the file
      return { stdout: "", stderr: "", code: 0 };
    };
    const res = await runToolAgainstFile({ cfg: cfg2, runner: runner2, targetPath: join(caseDir, "Security.evtx"), workDir: join(caseDir, ".toolwork") });
    expect(res.importKind).toBe("velociraptor");
    expect(res.outputText).toBe('[{"a":1}]');
  });

  it("reads back a file-mode tool's output written by the runner", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "a.evtx"), "binary-evtx");
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    const runner: ToolRunner = async (_binary, args) => {
      // The runner writes the tool's output to the server-owned <output> path (the arg after -o).
      const oi = args.indexOf("-o");
      const outPath = args[oi + 1];
      await writeFile(outPath, "Timestamp,RuleTitle\n2026-01-01,Evil");
      return { stdout: "", stderr: "", code: 0 };
    };
    const res = await runToolAgainstFile({
      cfg,
      runner,
      targetPath: join(caseDir, "a.evtx"),
      workDir: join(caseDir, ".toolwork"),
    });
    expect(res.importKind).toBe("hayabusa");
    expect(res.outputText).toMatch(/RuleTitle/);
  });

  it("fails fast when a rules-requiring tool has no rules path", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "a.bin"), "x");
    const cfg = loadToolConfig("yara", { DFIR_TOOL_YARA_BINARY: "yara" })!;
    const runner: ToolRunner = async () => ({ stdout: "x", stderr: "", code: 0 });
    await expect(
      runToolAgainstFile({ cfg, runner, targetPath: join(caseDir, "a.bin"), workDir: join(caseDir, ".toolwork") }),
    ).rejects.toThrow(/rules file is required/i);
  });

  it("throws with stderr detail when the tool produces no output", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "a.bin"), "x");
    const cfg = loadToolConfig("yara", { DFIR_TOOL_YARA_BINARY: "yara", DFIR_TOOL_YARA_RULES: "/r.yar" })!;
    const runner: ToolRunner = async () => ({ stdout: "   ", stderr: "bad rule syntax", code: 1 });
    await expect(
      runToolAgainstFile({ cfg, runner, targetPath: join(caseDir, "a.bin"), workDir: join(caseDir, ".toolwork") }),
    ).rejects.toThrow(/no output.*bad rule syntax/i);
  });
});

describe("updateToolRules", () => {
  it("runs the standalone update command (own binary) and returns output", async () => {
    const cfg = loadToolConfig("suricata", { DFIR_TOOL_SURICATA_BINARY: "suricata", DFIR_TOOL_SURICATA_UPDATE_CMD: "suricata-update" })!;
    let seenBinary = "";
    const runner: ToolRunner = async (binary) => {
      seenBinary = binary;
      return { stdout: "Rules updated: 42000", stderr: "", code: 0 };
    };
    const out = await updateToolRules(cfg, runner);
    expect(seenBinary).toBe("suricata-update");
    expect(out).toMatch(/Rules updated/);
  });
  it("runs the binary+subcommand update for hayabusa", async () => {
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    let seenBinary = "";
    let seenArgs: string[] = [];
    const runner: ToolRunner = async (binary, args) => {
      seenBinary = binary;
      seenArgs = args;
      return { stdout: "rules updated", stderr: "", code: 0 };
    };
    await updateToolRules(cfg, runner);
    expect(seenBinary).toBe("hayabusa");
    expect(seenArgs).toEqual(["update-rules"]);
  });
  it("throws when no update command is configured", async () => {
    const cfg = loadToolConfig("snort", { DFIR_TOOL_SNORT_BINARY: "snort" })!;
    const runner: ToolRunner = async () => ({ stdout: "", stderr: "", code: 0 });
    await expect(updateToolRules(cfg, runner)).rejects.toThrow(/no update command/i);
  });
});
