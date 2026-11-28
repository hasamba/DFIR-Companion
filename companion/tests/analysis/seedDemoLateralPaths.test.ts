import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seedDemoCase } from "../../src/analysis/seedDemoCase.js";
import { buildEvidenceGraph, buildLateralPaths } from "../../src/analysis/evidenceGraph.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

// #3024: the demo's story is PsExec movement off the workstation onto DC01, then FS01 and WEB01, but
// its seeded events carried no shared account or binary hash, so Evidence Chain → "Lateral movement
// paths" showed nothing. The seed now records the 4648 explicit-credential account (jsmith, also
// active on the workstation) and the PSEXESVC.exe hash PsExec drops on each target. The path
// inference orders hosts by when the same account/binary next appeared — it does not claim who
// initiated each connection — so these asserts pin the evidence each hop rests on.
describe("seeded demo case — lateral movement paths (#3024)", () => {
  let root: string;
  let state: InvestigationState;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "demo-lateral-"));
    const { caseDir } = await seedDemoCase(root, { caseId: "demo" });
    state = JSON.parse(await readFile(join(caseDir, "state", "investigation.json"), "utf8"));
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("reconstructs a multi-hop chain from the workstation through DC01 to FS01 and WEB01", () => {
    const paths = buildLateralPaths(state);
    const route = (ids: string[]) => ids.map((id) => id.toLowerCase());
    const chain = paths.find(
      (p) => route(p.hostIds).join(">") === "host:wkstn-jsmith>host:dc01>host:fs01>host:web01",
    );
    expect(chain, JSON.stringify(paths.map((p) => p.hostIds))).toBeDefined();
    expect(chain!.hops.map((h) => [h.rule, h.actor, h.eventIds])).toEqual([
      ["shared-account", "GLOBALTECH\\jsmith", ["e002", "e012"]],
      ["shared-hash", "psexesvc.exe", ["e013", "e017"]],
      ["shared-hash", "psexesvc.exe", ["e017", "e018"]],
    ]);
    expect(chain!.confidence).toBe("medium"); // weakest link: the shared-account hop
  });

  it("forms lateral_move edges in the evidence graph", () => {
    const lateral = buildEvidenceGraph(state).edges.filter((e) => e.type === "lateral_move");
    expect(lateral.some((e) => e.rule === "shared-hash")).toBe(true);
    expect(lateral.some((e) => e.rule === "shared-account")).toBe(true);
  });
});
