import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { link, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, isAbsolute } from "node:path";
import { loadToolConfig, type ToolConfig } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";
import { runToolAgainstFile } from "../../src/integrations/tools/runToolImport.js";
import { describeToolRun } from "../../src/integrations/tools/toolProvenance.js";
import { mapStagedPath } from "../../src/integrations/tools/toolInput.js";
import { CaseFileRefusedError } from "../../src/storage/caseFileRead.js";

// #1857: the target of a local tool run is judged on an open handle at hand-over, and (team mode, or a
// <targetdir> tool) the tool reads a private copy of the judged bytes — never a name a case writer can
// swap after the check. The ToolRunner is injected: nothing is spawned.

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const inside = (root: string, p: string): boolean => {
  const rel = relative(root, p);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
};

let root: string;
let casesRoot: string;
let caseDir: string;
let otherCase: string;
let workDir: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "toolinput-"));
  casesRoot = join(root, "cases");
  caseDir = join(casesRoot, "c1");
  otherCase = join(casesRoot, "c2");
  workDir = join(casesRoot, ".export-staging");
  await mkdir(join(caseDir, "drop"), { recursive: true });
  await mkdir(otherCase, { recursive: true });
  await writeFile(join(caseDir, "drop", "a.bin"), "THIS-CASE");
  await writeFile(join(otherCase, "secret.bin"), "OTHER-CASE");
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const yara = (): ToolConfig =>
  loadToolConfig("yara", { DFIR_TOOL_YARA_BINARY: "yara", DFIR_TOOL_YARA_RULES: "/rules/r.yar" })!;
const velo = (): ToolConfig =>
  loadToolConfig("velociraptor_cli", {
    DFIR_TOOL_VELOCIRAPTOR_CLI_BINARY: "velociraptor",
    DFIR_TOOL_VELOCIRAPTOR_CLI_DEFINITIONS: "/defs/d.zip",
  })!;
const scope = () => ({ casesRoot, caseDir });
const target = () => join(caseDir, "drop", "a.bin");
const lastArg = (args: string[]): string => args[args.length - 1];

// A yara stdout runner that reads the file it was handed, after an optional swap of the case name.
function yaraRunner(onRun?: (handed: string) => Promise<void>): {
  runner: ToolRunner;
  seen: { handed: string; bytes: string; runs: number };
} {
  const seen = { handed: "", bytes: "", runs: 0 };
  const runner: ToolRunner = async (_bin, args) => {
    if (args.includes("--version")) return { stdout: "4.5.0", stderr: "", code: 0 };
    seen.runs++;
    seen.handed = lastArg(args);
    await onRun?.(seen.handed);
    seen.bytes = await readFile(seen.handed, "utf8");
    return { stdout: `EvilRule ${seen.handed}`, stderr: "", code: 0 };
  };
  return { runner, seen };
}

async function swapToLink(): Promise<void> {
  await rename(target(), join(caseDir, "drop", "moved.bin"));
  await symlink(join(otherCase, "secret.bin"), target());
}

describe("team mode: <target> runs against a private snapshot (#1857)", () => {
  it("a swap of the case name after the check changes nothing the tool reads", async () => {
    const { runner, seen } = yaraRunner(async () => swapToLink());
    const res = await runToolAgainstFile({
      cfg: yara(),
      runner,
      targetPath: target(),
      workDir,
      scope: scope(),
      teamMode: true,
    });
    expect(seen.bytes).toBe("THIS-CASE");
    expect(seen.handed).not.toBe(target());
    expect(inside(caseDir, seen.handed)).toBe(false);
    expect(res.provenance.input).toEqual({ sha256: sha("THIS-CASE"), bytes: 9 });
    expect(describeToolRun(res.provenance)).toContain(`input sha256:${sha("THIS-CASE")} (9 bytes)`);
  });

  it("maps the staged path in the output back to the case path, so events name the case file", async () => {
    const { runner } = yaraRunner();
    const res = await runToolAgainstFile({
      cfg: yara(),
      runner,
      targetPath: target(),
      workDir,
      scope: scope(),
      teamMode: true,
    });
    expect(res.outputText).toBe(`EvilRule ${target()}`);
  });

  it("removes the snapshot after a successful run", async () => {
    const { runner } = yaraRunner();
    await runToolAgainstFile({
      cfg: yara(),
      runner,
      targetPath: target(),
      workDir,
      scope: scope(),
      teamMode: true,
    });
    expect(await readdir(workDir)).toEqual([]);
  });

  it("removes the snapshot after a failed run", async () => {
    const runner: ToolRunner = async (_bin, args) =>
      args.includes("--version")
        ? { stdout: "4.5.0", stderr: "", code: 0 }
        : { stdout: "partial", stderr: "", code: -1, signal: "SIGKILL" };
    await expect(
      runToolAgainstFile({
        cfg: yara(),
        runner,
        targetPath: target(),
        workDir,
        scope: scope(),
        teamMode: true,
      }),
    ).rejects.toThrow(/SIGKILL/);
    expect(await readdir(workDir)).toEqual([]);
  });

  it("removes the snapshot when the runner itself throws", async () => {
    const runner: ToolRunner = async (_bin, args) => {
      if (args.includes("--version")) return { stdout: "4.5.0", stderr: "", code: 0 };
      throw new Error("spawn failed");
    };
    await expect(
      runToolAgainstFile({
        cfg: yara(),
        runner,
        targetPath: target(),
        workDir,
        scope: scope(),
        teamMode: true,
      }),
    ).rejects.toThrow(/spawn failed/);
    expect(await readdir(workDir)).toEqual([]);
  });
});

describe("every mode: the target is judged at hand-over (#1857)", () => {
  for (const teamMode of [false, true]) {
    it(`refuses a target that is already a link (teamMode=${teamMode}), tool never runs`, async () => {
      await swapToLink();
      const { runner, seen } = yaraRunner();
      await expect(
        runToolAgainstFile({ cfg: yara(), runner, targetPath: target(), workDir, scope: scope(), teamMode }),
      ).rejects.toBeInstanceOf(CaseFileRefusedError);
      expect(seen.runs).toBe(0);
    });

    it(`refuses a hard link (teamMode=${teamMode})`, async () => {
      await rm(target());
      await link(join(otherCase, "secret.bin"), target());
      const { runner, seen } = yaraRunner();
      await expect(
        runToolAgainstFile({ cfg: yara(), runner, targetPath: target(), workDir, scope: scope(), teamMode }),
      ).rejects.toThrow(/hardlink/);
      expect(seen.runs).toBe(0);
    });
  }

  it.skipIf(process.platform === "win32")("refuses a FIFO fast instead of blocking on it", async () => {
    await rm(target());
    execFileSync("mkfifo", [target()], { stdio: ["ignore", "pipe", "pipe"] });
    const { runner, seen } = yaraRunner();
    const started = Date.now();
    await expect(
      runToolAgainstFile({
        cfg: velo(),
        runner,
        targetPath: target(),
        workDir,
        scope: scope(),
        teamMode: false,
      }),
    ).rejects.toThrow(/special file/);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(seen.runs).toBe(0);
  });
});

describe("<targetdir> copies from the judged handle (#1857)", () => {
  it("never follows a link: a linked target is refused, the tool never runs", async () => {
    await swapToLink();
    let runs = 0;
    const runner: ToolRunner = async () => {
      runs++;
      return { stdout: "x", stderr: "", code: 0 };
    };
    await expect(
      runToolAgainstFile({
        cfg: velo(),
        runner,
        targetPath: target(),
        workDir,
        scope: scope(),
        teamMode: false,
      }),
    ).rejects.toBeInstanceOf(CaseFileRefusedError);
    expect(runs).toBe(0);
  });

  it("hands a folder holding only the checked bytes under the original name, outside the case", async () => {
    let dirSeen = "";
    let files: string[] = [];
    let bytes = "";
    const runner: ToolRunner = async (_bin, args, opts) => {
      if (args.includes("--version")) return { stdout: "0.7", stderr: "", code: 0 };
      dirSeen = args[args.indexOf("--ROOT") + 1];
      await swapToLink();
      files = await readdir(dirSeen);
      bytes = await readFile(join(dirSeen, "a.bin"), "utf8");
      await writeFile(opts.stdoutFile as string, '[{"a":1}]');
      return { stdout: "", stderr: "", code: 0 };
    };
    const res = await runToolAgainstFile({
      cfg: velo(),
      runner,
      targetPath: target(),
      workDir,
      scope: scope(),
      teamMode: false,
    });
    expect(files).toEqual(["a.bin"]);
    expect(bytes).toBe("THIS-CASE");
    expect(inside(caseDir, dirSeen)).toBe(false);
    expect(res.provenance.input?.sha256).toBe(sha("THIS-CASE"));
    expect(await readdir(workDir)).toEqual([]);
  });

  it("a tool with both placeholders gets one snapshot for both", async () => {
    const cfg: ToolConfig = { ...velo(), id: "custom_both", runArgs: "--file <target> --root <targetdir>" };
    let args: string[] = [];
    const runner: ToolRunner = async (_bin, a) => {
      if (a.includes("--version")) return { stdout: "", stderr: "", code: 0 };
      args = a;
      return { stdout: "out", stderr: "", code: 0 };
    };
    await runToolAgainstFile({ cfg, runner, targetPath: target(), workDir, scope: scope(), teamMode: false });
    const file = args[args.indexOf("--file") + 1];
    const dir = args[args.indexOf("--root") + 1];
    expect(file).toBe(join(dir, "a.bin"));
  });
});

describe("single-user mode keeps <target> zero-copy (#1857)", () => {
  it("hands the original case path and copies nothing", async () => {
    let during: string[] = [];
    const { runner, seen } = yaraRunner(async () => {
      during = await readdir(workDir, { recursive: true });
    });
    const res = await runToolAgainstFile({
      cfg: yara(),
      runner,
      targetPath: target(),
      workDir,
      scope: scope(),
      teamMode: false,
    });
    expect(seen.handed).toBe(target());
    expect(during.filter((f) => f.endsWith("a.bin"))).toEqual([]);
    expect(res.provenance.input).toBeNull();
    expect(describeToolRun(res.provenance)).not.toContain("input sha256");
  });
});

describe("mapStagedPath", () => {
  it("maps the raw and the JSON-escaped staged path, and nothing else", () => {
    const staged = "C:\\stage\\run-1\\a.evtx";
    const original = "C:\\cases\\c1\\a.evtx";
    const text = `${staged}\n${JSON.stringify({ p: staged })}\nC:\\stage\\other`;
    expect(mapStagedPath(text, staged, original)).toBe(
      `${original}\n${JSON.stringify({ p: original })}\nC:\\stage\\other`,
    );
  });
});
