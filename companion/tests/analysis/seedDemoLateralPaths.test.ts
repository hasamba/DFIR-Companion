import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seedDemoCase } from "../../src/analysis/seedDemoCase.js";
import { buildEvidenceGraph, buildLateralPaths } from "../../src/analysis/evidenceGraph.js";
import { buildSharedHostLinks } from "../../src/analysis/sharedHostLinks.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

// #3024 gave the demo the evidence its PsExec story needs; #3085 changed what that evidence may
// claim. Paths are now built only from DIRECTION evidence the targets recorded — a network logon
// naming WKSTN-JSMITH (10.10.10.45) on DC01, FS01 and WEB01, each beside its PSEXESVC sighting — so the
// demo shows the real fan-out WKSTN-JSMITH → DC01 / FS01 / WEB01. The old chain WKSTN → DC01 → FS01 →
// WEB01 claimed DC01 → FS01 and FS01 → WEB01 hops that nothing in the case shows; it came from
// lining up the hosts that share PSEXESVC.exe in time order. Those shared links are still reported,
// as hosts that share a binary/account.
const SOURCE = "host:wkstn-jsmith";
const FAN_OUT: Record<string, string[]> = {
  "host:dc01": ["e062", "e013"],
  "host:fs01": ["e063", "e017"],
  "host:web01": ["e064", "e018"],
};

describe("seeded demo case — lateral movement paths (#3024, #3085)", () => {
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

  it("shows the workstation moving to DC01, FS01 and WEB01 as a fan-out, one path each", () => {
    const paths = buildLateralPaths(state);
    const routes = paths.map((p) => p.hostIds.map((id) => id.toLowerCase()).join(">")).sort();
    expect(routes).toEqual(
      Object.keys(FAN_OUT)
        .map((t) => `${SOURCE}>${t}`)
        .sort(),
    );
    for (const p of paths) {
      const [hop] = p.hops;
      const target = hop.to.toLowerCase();
      expect([hop.rule, hop.confidence, hop.actorKind]).toEqual(["network-logon", "medium", "account"]);
      expect(hop.eventIds).toEqual(FAN_OUT[target]); // the target's logon, then its PSEXESVC sighting
    }
  });

  it("never draws a hop between two targets", () => {
    const targets = new Set(Object.keys(FAN_OUT));
    const between = buildLateralPaths(state)
      .flatMap((p) => p.hops)
      .filter((h) => targets.has(h.from.toLowerCase()) && targets.has(h.to.toLowerCase()));
    expect(between).toEqual([]);
  });

  it("reports PSEXESVC.exe and the domain admin as links the targets share, not hops", () => {
    const links = buildSharedHostLinks(state);
    const psexesvc = links.find((l) => l.actor === "psexesvc.exe")!;
    expect([...psexesvc.hostIds].sort()).toEqual(["host:dc01", "host:fs01", "host:web01"]);
    const admin = links.find((l) => l.actor === "GLOBALTECH\\svc-admin")!;
    expect([...admin.hostIds].sort()).toEqual(["host:fs01", "host:web01"]);
  });

  it("forms directed lateral_move edges from the workstation in the evidence graph", () => {
    const directed = buildEvidenceGraph(state).edges.filter(
      (e) => e.type === "lateral_move" && !e.undirected,
    );
    expect(directed.map((e) => `${e.source}>${e.target}`.toLowerCase()).sort()).toEqual(
      Object.keys(FAN_OUT)
        .map((t) => `${SOURCE}>${t}`)
        .sort(),
    );
  });

  // #3086: the encrypt.exe events must each name the server they ran on, or the ransomware hash
  // links no hosts. DC01 is the staging host (it wrote the binary); FS01 detected it; DC01 and WEB01
  // quarantined it. This is the existing first-observation heuristic, not proof of who copied what.
  const RANSOM_EVENTS: Record<string, string> = { e026: "DC01", e027: "FS01", e028: "DC01", e032: "WEB01" };
  const ransomHash = () => state.forensicTimeline.find((e) => e.id === "e027")!.sha256!.toLowerCase();

  it("gives every seeded encryption event the host it ran on", () => {
    const events = state.forensicTimeline.filter((e) => e.sha256?.toLowerCase() === ransomHash());
    expect(Object.fromEntries(events.map((e) => [e.id, e.asset]))).toEqual(RANSOM_EVENTS);
  });

  it("links DC01, FS01 and WEB01 through the encrypt.exe hash", () => {
    const link = buildSharedHostLinks(state).find((l) => l.actor === "encrypt.exe")!;
    expect(link.hostIds).toEqual(["host:dc01", "host:fs01", "host:web01"]);
    expect(link.eventIds).toEqual(["e026", "e027", "e032"]);
    const edges = buildEvidenceGraph(state).edges.filter(
      (e) => e.type === "lateral_move" && e.id.startsWith(`lateral|hash:${ransomHash()}|`),
    );
    expect(edges.every((e) => e.undirected)).toBe(true);
    const linked = new Set(edges.flatMap((e) => [e.source, e.target].map((id) => id.toLowerCase())));
    expect([...linked].sort()).toEqual(["host:dc01", "host:fs01", "host:web01"]);
  });

  it("keeps every forensic event id unique", () => {
    const ids = state.forensicTimeline.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("forms lateral_move edges in the evidence graph", () => {
    const lateral = buildEvidenceGraph(state).edges.filter((e) => e.type === "lateral_move");
    expect(lateral.some((e) => e.rule === "shared-hash")).toBe(true);
    expect(lateral.some((e) => e.rule === "shared-account")).toBe(true);
  });
});
