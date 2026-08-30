import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  hashRuleset,
  probeToolVersion,
  describeToolRun,
  hashOutputText,
  createToolRunCache,
} from "../../src/integrations/tools/toolProvenance.js";
import { loadToolConfig, TOOL_DEFS } from "../../src/integrations/tools/toolConfig.js";
import { runToolAgainstFile } from "../../src/integrations/tools/runToolImport.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";

async function ruleDir(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "rules-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    await mkdir(join(abs, ".."), { recursive: true });
    await writeFile(abs, body, "utf8");
  }
  return dir;
}

describe("hashRuleset", () => {
  it("hashes a single rules FILE", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rules-"));
    const file = join(dir, "my.rules");
    await writeFile(file, "alert tcp any any -> any any (msg:'x'; sid:1;)", "utf8");
    const id = (await hashRuleset(file))!;
    expect(id.files).toBe(1);
    expect(id.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(id.path).toBe(file);
  });

  it("hashes a rules DIRECTORY, and the hash does not depend on nesting order", async () => {
    const a = await ruleDir({ "b.yml": "two", "a.yml": "one", "win/c.yml": "three" });
    const b = await ruleDir({ "win/c.yml": "three", "a.yml": "one", "b.yml": "two" });
    const ha = (await hashRuleset(a))!;
    const hb = (await hashRuleset(b))!;
    expect(ha.files).toBe(3);
    expect(ha.sha256).toBe(hb.sha256);
  });

  it("changes when a rule is edited, added, or renamed", async () => {
    const dir = await ruleDir({ "a.yml": "one", "b.yml": "two" });
    const base = (await hashRuleset(dir))!.sha256;

    await writeFile(join(dir, "a.yml"), "one-edited", "utf8");
    const edited = (await hashRuleset(dir))!.sha256;
    expect(edited).not.toBe(base);

    await writeFile(join(dir, "c.yml"), "three", "utf8");
    const added = (await hashRuleset(dir))!.sha256;
    expect(added).not.toBe(edited);

    // A rename changes nothing about the bytes, but it IS a different rule set.
    await rename(join(dir, "c.yml"), join(dir, "d.yml"));
    expect((await hashRuleset(dir))!.sha256).not.toBe(added);
  });

  it("ignores dot-directories so a .git checkout does not dominate the hash", async () => {
    const dir = await ruleDir({ "a.yml": "one", ".git/objects/x": "gitblob" });
    const withGit = (await hashRuleset(dir))!;
    await rm(join(dir, ".git"), { recursive: true, force: true });
    const withoutGit = (await hashRuleset(dir))!;
    expect(withGit.sha256).toBe(withoutGit.sha256);
    expect(withGit.files).toBe(1);
  });

  it("returns null for a missing path, an empty directory, and a blank path", async () => {
    expect(await hashRuleset(join(tmpdir(), "definitely-not-here-688"))).toBeNull();
    expect(await hashRuleset(await mkdtemp(join(tmpdir(), "rules-")))).toBeNull();
    expect(await hashRuleset("   ")).toBeNull();
  });
});

describe("probeToolVersion", () => {
  it("returns the first line of the version output", async () => {
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    let seenArgs: string[] = [];
    const runner: ToolRunner = async (_b, args) => {
      seenArgs = args;
      return { stdout: "Hayabusa v3.2.0\nmore banner\n", stderr: "", code: 0 };
    };
    expect(await probeToolVersion(cfg, runner)).toBe("Hayabusa v3.2.0");
    expect(seenArgs).toEqual(["--version"]);
  });

  it("reads a banner printed to stderr, and honours the tool's own version flag", async () => {
    const cfg = loadToolConfig("suricata", { DFIR_TOOL_SURICATA_BINARY: "suricata" })!;
    let seenArgs: string[] = [];
    const runner: ToolRunner = async (_b, args) => {
      seenArgs = args;
      return { stdout: "", stderr: "This is Suricata version 7.0.5 RELEASE", code: 0 };
    };
    expect(await probeToolVersion(cfg, runner)).toBe("This is Suricata version 7.0.5 RELEASE");
    expect(seenArgs).toEqual(["-V"]);
  });

  it("records nothing when the binary rejects the flag instead of rejecting the promise", async () => {
    // The common shape: the tool does not know the flag, complains on stderr and exits non-zero. The
    // runner resolves normally, so without an exit-code check that complaint becomes the "version"
    // stamped into the chain of custody.
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    const runner: ToolRunner = async () => ({
      stdout: "",
      stderr: "error: unexpected argument '--version' found",
      code: 2,
    });
    expect(await probeToolVersion(cfg, runner)).toBe("");
  });

  it("records nothing when the version probe is killed by a signal", async () => {
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    const runner: ToolRunner = async () => ({
      stdout: "Hayabusa v3.2.0",
      stderr: "",
      code: -1,
      signal: "SIGKILL",
    });
    expect(await probeToolVersion(cfg, runner)).toBe("");
  });

  it("never throws — a binary with no version flag just records nothing", async () => {
    const cfg = loadToolConfig("yara", { DFIR_TOOL_YARA_BINARY: "yara" })!;
    const runner: ToolRunner = async () => {
      throw new Error("ENOENT");
    };
    expect(await probeToolVersion(cfg, runner)).toBe("");
  });
});

describe("describeToolRun", () => {
  it("states the tool, version, argv, exit code, rule set, output hash and stderr on one line", () => {
    const line = describeToolRun({
      toolId: "chainsaw",
      binary: "/opt/chainsaw",
      version: "chainsaw 2.9.1",
      argv: ["hunt", "/in", "-s", "/sigma"],
      exitCode: 0,
      stderr: "1 file skipped",
      outputSha256: "a".repeat(64),
      ruleset: { path: "/sigma", sha256: "b".repeat(64), files: 3182, bytes: 4096 },
    });
    expect(line).toContain("tool chainsaw chainsaw 2.9.1");
    expect(line).toContain("binary /opt/chainsaw");
    expect(line).toContain("exit 0");
    expect(line).toContain('"hunt"');
    expect(line).toContain(`ruleset /sigma sha256:${"b".repeat(64)} (3182 file(s)`);
    expect(line).toContain(`output sha256:${"a".repeat(64)}`);
    expect(line).toContain("1 file skipped");
    expect(line.split("\n")).toHaveLength(1);
  });

  it("says so explicitly when the tool used no rule set", () => {
    const line = describeToolRun({
      toolId: "hayabusa",
      binary: "hayabusa",
      version: "",
      argv: ["csv-timeline"],
      exitCode: 0,
      stderr: "",
      outputSha256: hashOutputText("x"),
      ruleset: null,
    });
    expect(line).toContain("ruleset none");
    expect(line).toContain("tool hayabusa |"); // no version → no trailing version token
  });
});

describe("Chainsaw as a built-in EVTX parser (#688)", () => {
  it("is off until its binary is set, then loads the hunt defaults", () => {
    expect(loadToolConfig("chainsaw", {})).toBeNull();
    const cfg = loadToolConfig("chainsaw", { DFIR_TOOL_CHAINSAW_BINARY: "/opt/chainsaw" })!;
    expect(cfg.importKind).toBe("chainsaw");
    expect(cfg.outputMode).toBe("file");
    expect(cfg.runArgs).toContain("<targetdir>");
    expect(cfg.runArgs).toContain("-s <rules>");
    expect(cfg.runArgs).toContain("--mapping <definitions>");
    expect(cfg.failOnNonZeroExit).toBe(true);
    expect(cfg.requireRuleset).toBe(true);
    // No update button: Chainsaw has no update subcommand.
    expect(cfg.updateCommand).toBeUndefined();
  });

  it("claims evtx and ranks behind Hayabusa but ahead of the Velociraptor CLI", async () => {
    const { toolPreferenceForExtension } = await import("../../src/integrations/tools/toolConfig.js");
    const order = toolPreferenceForExtension(".evtx");
    expect(order.indexOf("chainsaw")).toBeGreaterThan(order.indexOf("hayabusa"));
    expect(order.indexOf("chainsaw")).toBeLessThan(order.indexOf("velociraptor_cli"));
    expect(TOOL_DEFS.chainsaw.extensions).toEqual([".evtx", ".evt"]);
  });
});

describe("runToolAgainstFile fails closed (#688)", () => {
  const chainsawEnv = {
    DFIR_TOOL_CHAINSAW_BINARY: "chainsaw",
    DFIR_TOOL_CHAINSAW_DEFINITIONS: "/maps/sigma.yml",
  };

  it("refuses to run a rule-driven parser when the rule directory is empty — and never spawns it", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "Security.evtx"), "evtx-bytes");
    const emptyRules = await mkdtemp(join(tmpdir(), "rules-"));
    const cfg = loadToolConfig("chainsaw", { ...chainsawEnv, DFIR_TOOL_CHAINSAW_RULES: emptyRules })!;
    let spawned = 0;
    const runner: ToolRunner = async () => {
      spawned++;
      return { stdout: "[]", stderr: "", code: 0 };
    };
    await expect(
      runToolAgainstFile({
        cfg,
        runner,
        targetPath: join(caseDir, "Security.evtx"),
        workDir: join(caseDir, ".toolwork"),
      }),
    ).rejects.toThrow(/rule set at .* could not be identified/i);
    expect(spawned).toBe(0);
  });

  it("rejects a non-zero exit from an EVTX parser even when it wrote partial output", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "Security.evtx"), "evtx-bytes");
    const rules = await ruleDir({ "a.yml": "title: x" });
    const cfg = loadToolConfig("chainsaw", { ...chainsawEnv, DFIR_TOOL_CHAINSAW_RULES: rules })!;
    const runner: ToolRunner = async (_b, args) => {
      // The version probe has no <output>; only the real run writes one.
      const out = args[args.indexOf("--output") + 1];
      if (args.includes("--output")) await writeFile(out, '[{"partial":true}]', "utf8");
      return { stdout: "", stderr: "error: failed to parse chunk 4", code: 2 };
    };
    await expect(
      runToolAgainstFile({
        cfg,
        runner,
        targetPath: join(caseDir, "Security.evtx"),
        workDir: join(caseDir, ".toolwork"),
      }),
    ).rejects.toThrow(/exited with code 2 — refusing to import a partial parse.*failed to parse chunk 4/is);
  });

  it("rejects a parser the OS killed with a signal, which reports a null exit code", async () => {
    // The OOM killer taking out a parser partway through a large EVTX is the likeliest real failure,
    // and Node reports it as code null / signal SIGKILL. Reading that null as 0 said "clean exit"
    // about a run that had written half a file.
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "Security.evtx"), "evtx-bytes");
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    const runner: ToolRunner = async (_b, args) => {
      if (args.includes("--version")) return { stdout: "Hayabusa v3.2.0", stderr: "", code: 0 };
      await writeFile(args[args.indexOf("-o") + 1], "Timestamp,RuleTitle\n1,x\n", "utf8");
      return { stdout: "", stderr: "", code: -1, signal: "SIGKILL" };
    };
    await expect(
      runToolAgainstFile({
        cfg,
        runner,
        targetPath: join(caseDir, "Security.evtx"),
        workDir: join(caseDir, ".toolwork"),
      }),
    ).rejects.toThrow(/was killed by SIGKILL — refusing to import a partial parse/i);
  });

  it("still accepts a non-zero exit from YARA, where it means 'matches found'", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "a.bin"), "sample");
    const rulesDir = await ruleDir({ "r.yar": "rule Evil { condition: true }" });
    const cfg = loadToolConfig("yara", {
      DFIR_TOOL_YARA_BINARY: "yara",
      DFIR_TOOL_YARA_RULES: rulesDir,
    })!;
    const runner: ToolRunner = async () => ({ stdout: "EvilRule /x/a.bin", stderr: "", code: 1 });
    const res = await runToolAgainstFile({
      cfg,
      runner,
      targetPath: join(caseDir, "a.bin"),
      workDir: join(caseDir, ".toolwork"),
    });
    expect(res.outputText).toBe("EvilRule /x/a.bin");
    expect(res.provenance.exitCode).toBe(1);
  });
});

describe("runToolAgainstFile records what the run was (#688)", () => {
  it("returns the version, the substituted argv, the rule-set hash and the output hash", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "a.bin"), "sample");
    const rulesDir = await ruleDir({ "r.yar": "rule Evil { condition: true }" });
    const cfg = loadToolConfig("yara", {
      DFIR_TOOL_YARA_BINARY: "yara",
      DFIR_TOOL_YARA_RULES: rulesDir,
    })!;
    const runner: ToolRunner = async (_b, args) =>
      args.includes("--version")
        ? { stdout: "4.5.0", stderr: "", code: 0 }
        : { stdout: "EvilRule /x/a.bin", stderr: "warning: slow rule", code: 0 };

    const res = await runToolAgainstFile({
      cfg,
      runner,
      targetPath: join(caseDir, "a.bin"),
      workDir: join(caseDir, ".toolwork"),
    });

    expect(res.provenance.toolId).toBe("yara");
    expect(res.provenance.binary).toBe("yara");
    expect(res.provenance.version).toBe("4.5.0");
    expect(res.provenance.argv).toContain(rulesDir);
    expect(res.provenance.argv).toContain(join(caseDir, "a.bin"));
    expect(res.provenance.argv).not.toContain("<rules>"); // placeholders already substituted
    expect(res.provenance.exitCode).toBe(0);
    expect(res.provenance.stderr).toContain("warning: slow rule");
    expect(res.provenance.ruleset?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(res.provenance.outputSha256).toBe(hashOutputText("EvilRule /x/a.bin"));
  });

  it("records no rule set for a tool that uses none, and a blank version when the probe fails", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    await writeFile(join(caseDir, "Security.evtx"), "evtx-bytes");
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    const runner: ToolRunner = async (_b, args) => {
      if (args.includes("--version")) throw new Error("no such flag");
      await writeFile(args[args.indexOf("-o") + 1], "Timestamp,RuleTitle\n1,x\n", "utf8");
      return { stdout: "", stderr: "", code: 0 };
    };
    const res = await runToolAgainstFile({
      cfg,
      runner,
      targetPath: join(caseDir, "Security.evtx"),
      workDir: join(caseDir, ".toolwork"),
    });
    expect(res.provenance.version).toBe("");
    expect(res.provenance.ruleset).toBeNull();
    expect(res.importKind).toBe("hayabusa");
  });
});

// #721. hashRuleset walks and SHA-256s the whole rules tree and probeToolVersion spawns the binary,
// both on EVERY run. A folder import runs the tool once per evidence file — 20-60 for a real
// collection — so one import re-derived the same identity that many times.
describe("ToolRunCache — one derivation per import job (#721)", () => {
  it("hashes a rules tree once per cache, and re-derives without one", async () => {
    const dir = await ruleDir({ "a.yml": "one", "b.yml": "two" });
    const cache = createToolRunCache();
    const first = (await hashRuleset(dir, cache))!;

    // Change the CONTENT of a rule. The parent directory's mtime is untouched by this, which is
    // exactly why a global cache must not key on it.
    await writeFile(join(dir, "a.yml"), "one-edited", "utf8");

    expect((await hashRuleset(dir, cache))!.sha256).toBe(first.sha256); // cached for this job
    expect((await hashRuleset(dir))!.sha256).not.toBe(first.sha256); // uncached sees the edit
  });

  it("shares ONE walk between concurrent callers (memoizes the promise, not the result)", async () => {
    const dir = await ruleDir({ "a.yml": "one" });
    const cache = createToolRunCache();
    const [x, y] = await Promise.all([hashRuleset(dir, cache), hashRuleset(dir, cache)]);
    expect(x!.sha256).toBe(y!.sha256);
    expect(cache.ruleset.size).toBe(1);
  });

  it("keeps caches independent, so a later job re-derives", async () => {
    const dir = await ruleDir({ "a.yml": "one" });
    const first = (await hashRuleset(dir, createToolRunCache()))!;
    await writeFile(join(dir, "a.yml"), "changed", "utf8");
    expect((await hashRuleset(dir, createToolRunCache()))!.sha256).not.toBe(first.sha256);
  });

  it("spawns the version probe once per cache", async () => {
    const cfg = loadToolConfig("hayabusa", { DFIR_TOOL_HAYABUSA_BINARY: "hayabusa" })!;
    let probes = 0;
    const runner: ToolRunner = async () => {
      probes++;
      return { stdout: "hayabusa 3.2.0", stderr: "", code: 0 };
    };
    const cache = createToolRunCache();
    expect(await probeToolVersion(cfg, runner, cache)).toBe("hayabusa 3.2.0");
    expect(await probeToolVersion(cfg, runner, cache)).toBe("hayabusa 3.2.0");
    expect(probes).toBe(1);
    await probeToolVersion(cfg, runner); // no cache → probes again
    expect(probes).toBe(2);
  });

  it("runToolAgainstFile threads the cache, so a 3-file batch derives once", async () => {
    const caseDir = await mkdtemp(join(tmpdir(), "case-"));
    const rules = await ruleDir({ "a.yar": "rule A {condition: true}" });
    const cfg = loadToolConfig("yara", {
      DFIR_TOOL_YARA_BINARY: "yara",
      DFIR_TOOL_YARA_RULES: rules,
    })!;
    let probes = 0;
    const runner: ToolRunner = async (_binary, args) => {
      if (args.includes("--version")) {
        probes++;
        return { stdout: "YARA 4.5.0", stderr: "", code: 0 };
      }
      return { stdout: "EvilRule /x/a.bin", stderr: "", code: 0 };
    };
    const cache = createToolRunCache();
    for (const name of ["a.bin", "b.bin", "c.bin"]) {
      await writeFile(join(caseDir, name), "sample");
      const res = await runToolAgainstFile({
        cfg,
        runner,
        targetPath: join(caseDir, name),
        workDir: join(caseDir, ".toolwork"),
        cache,
      });
      expect(res.provenance.ruleset?.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(res.provenance.version).toBe("YARA 4.5.0");
    }
    expect(probes).toBe(1);
    expect(cache.ruleset.size).toBe(1);
  });
});
