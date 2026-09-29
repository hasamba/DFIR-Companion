import { describe, it, expect, afterEach } from "vitest";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createExternalTools } from "../../src/composition/externalTools.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { TeamAuth } from "../../src/auth/teamAuth.js";
import { loadToolConfig, type ToolConfig, type ToolId } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";
import type { ArtifactProvenance } from "../../src/storage/caseStore.js";

// #1857: team mode is decided by the caller from options.teamAuth — never from env inside the run —
// and the run folder (staged input + output) sits outside the case folder.

const roots: string[] = [];
afterEach(async () => {
  for (const r of roots.splice(0)) await rm(r, { recursive: true, force: true });
});

async function harness(teamAuth: TeamAuth | undefined) {
  const root = await mkdtemp(join(tmpdir(), "ext-team-"));
  roots.push(root);
  const store = new CaseStore(root);
  const caseDir = store.caseDir("c1");
  await mkdir(join(caseDir, "drop"), { recursive: true });
  await writeFile(join(caseDir, "drop", "a.bin"), "sample");
  let handed = "";
  let custody: ArtifactProvenance | undefined;
  const runner: ToolRunner = async (_bin, args) => {
    if (args.includes("--version")) return { stdout: "4.5.0", stderr: "", code: 0 };
    handed = args[args.length - 1];
    return { stdout: `EvilRule ${handed}`, stderr: "", code: 0 };
  };
  const cfg = loadToolConfig("yara", { DFIR_TOOL_YARA_BINARY: "yara", DFIR_TOOL_YARA_RULES: "/r.yar" })!;
  const options = {
    toolRunner: runner,
    loadToolConfigs: () => new Map<ToolId, ToolConfig>([["yara", cfg]]),
    ...(teamAuth ? { teamAuth } : {}),
  } as unknown as AppOptions;
  const tools = createExternalTools({
    store,
    options,
    resolveImportKind: () => "yara",
    ingestStreamed: async (_c, _k, _t, _n, _s, provenance) => {
      custody = provenance;
      return { storedName: "out", addedEvents: 1, addedIocs: 0, analyzed: true };
    },
    persistRawEvidence: async () => ({ storedName: "x", importedAt: "", seq: 0 }),
    pushImportCheckpoint: async () => undefined,
  });
  return {
    store,
    caseDir,
    tools,
    get handed() {
      return handed;
    },
    get custody() {
      return custody;
    },
  };
}

const inside = (root: string, p: string): boolean => {
  const rel = relative(root, p);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
};

describe("runToolAndIngest passes team mode from options.teamAuth (#1857)", () => {
  it("team mode: the tool reads a snapshot outside the case, and custody carries its hash", async () => {
    const h = await harness({} as TeamAuth);
    await h.tools.runToolAndIngest("c1", "yara", "drop/a.bin");
    expect(h.handed).not.toBe(join(h.caseDir, "drop", "a.bin"));
    expect(inside(h.caseDir, h.handed)).toBe(false);
    expect(h.custody?.source).toMatch(/input sha256:[0-9a-f]{64} \(6 bytes\)/);
    expect(await readdir(join(h.store.casesRoot, ".export-staging"))).toEqual([]);
  });

  it("single-user: the tool reads the case file in place, no input hash", async () => {
    const h = await harness(undefined);
    await h.tools.runToolAndIngest("c1", "yara", "drop/a.bin");
    expect(h.handed).toBe(join(h.caseDir, "drop", "a.bin"));
    expect(h.custody?.source).not.toContain("input sha256");
  });
});
