import { describe, it, expect } from "vitest";
import { buildEvidenceGraph } from "../../src/analysis/evidenceGraph.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const HASH2 = "1111111122222222333333334444444455555555666666667777777788888888";

// Minimal forensic-event factory so each test only states the fields it cares about.
function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "",
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

describe("buildEvidenceGraph — spawned (process tree)", () => {
  it("chains parent→child→grandchild into one tree via shared process nodes", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "ALCLIENT07", parentName: "excel.exe", processName: "powershell.exe", severity: "High" }),
      ev({ id: "e2", asset: "ALCLIENT07", parentName: "powershell.exe", processName: "cmd.exe", severity: "Medium" }),
    );

    const g = buildEvidenceGraph(s);
    const spawned = g.edges.filter((e) => e.type === "spawned");
    expect(spawned).toHaveLength(2);

    // The shared powershell node makes excel→powershell→cmd one connected tree.
    const ps = g.nodes.find((n) => n.kind === "process" && /powershell/.test(n.label))!;
    expect(ps).toBeDefined();
    const intoPs = spawned.find((e) => e.target === ps.id)!;
    const outOfPs = spawned.find((e) => e.source === ps.id)!;
    expect(intoPs).toBeDefined();
    expect(outOfPs).toBeDefined();
    expect(spawned.every((e) => e.confidence === "high")).toBe(true);
  });

  it("dedups the same parent→child pair across events and unions provenance", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "DC01", parentName: "services.exe", processName: "svchost.exe" }),
      ev({ id: "e2", asset: "DC01", parentName: "services.exe", processName: "svchost.exe" }),
    );
    const spawned = buildEvidenceGraph(s).edges.filter((e) => e.type === "spawned");
    expect(spawned).toHaveLength(1);
    expect(new Set(spawned[0].eventIds)).toEqual(new Set(["e1", "e2"]));
  });

  it("keeps the same process name on different assets as distinct nodes", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", parentName: "explorer.exe", processName: "cmd.exe" }),
      ev({ id: "e2", asset: "HOST-B", parentName: "explorer.exe", processName: "cmd.exe" }),
    );
    const procs = buildEvidenceGraph(s).nodes.filter((n) => n.kind === "process" && /cmd/.test(n.label));
    expect(procs).toHaveLength(2); // cmd.exe on HOST-A ≠ cmd.exe on HOST-B
  });

  it("skips a self-spawn (parent === child)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "H", parentName: "svchost.exe", processName: "svchost.exe" }));
    expect(buildEvidenceGraph(s).edges).toHaveLength(0);
  });
});

describe("buildEvidenceGraph — lateral_move", () => {
  it("links hosts sharing the same binary hash (high confidence)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "ALCLIENT07", sha256: HASH, severity: "Critical" }),
      ev({ id: "e2", asset: "DC01", sha256: HASH, severity: "High" }),
    );
    const lat = buildEvidenceGraph(s).edges.filter((e) => e.type === "lateral_move");
    expect(lat).toHaveLength(1);
    expect(lat[0].confidence).toBe("high");
    const ends = new Set([lat[0].source, lat[0].target]);
    expect(ends).toEqual(new Set(["host:alclient07", "host:dc01"]));
  });

  it("does NOT create a lateral edge for a hash seen on a single asset", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "ALCLIENT07", sha256: HASH }),
      ev({ id: "e2", asset: "ALCLIENT07", sha256: HASH }),
    );
    expect(buildEvidenceGraph(s).edges.filter((e) => e.type === "lateral_move")).toHaveLength(0);
  });

  it("links an account used across hosts via an account node (medium confidence)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "ALCLIENT07", description: "logon by ADATUMLAB\\jdoe", severity: "High" }),
      ev({ id: "e2", asset: "DC01", description: "logon by ADATUMLAB\\jdoe", severity: "High" }),
    );
    const g = buildEvidenceGraph(s);
    const lat = g.edges.filter((e) => e.type === "lateral_move" && e.rule === "shared-account");
    expect(lat).toHaveLength(2); // account → HOST-A, account → HOST-B (star)
    expect(lat.every((e) => e.confidence === "medium")).toBe(true);
    expect(g.nodes.some((n) => n.kind === "account")).toBe(true);
  });

  it("does NOT treat Windows virtual principals (DWM/UMFD/MSI namespaces) as lateral movement", () => {
    const s = emptyState("c1");
    // These appear on every host but are session/service objects, not roaming users.
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", description: "process by Manager\\DWM-1" }),
      ev({ id: "e2", asset: "HOST-B", description: "process by Manager\\DWM-1" }),
      ev({ id: "e3", asset: "HOST-A", description: "mutex Global\\MSI0000 created" }),
      ev({ id: "e4", asset: "HOST-B", description: "mutex Global\\MSI0000 created" }),
    );
    expect(buildEvidenceGraph(s).edges).toHaveLength(0);
  });
});

describe("buildEvidenceGraph — invariants", () => {
  it("returns an empty graph for an empty case", () => {
    expect(buildEvidenceGraph(emptyState("c1"))).toEqual({ nodes: [], edges: [] });
  });

  it("every edge carries an auditable rule, basis, and ≥1 backing event; every node ≥1", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "H", parentName: "a.exe", processName: "b.exe" }),
      ev({ id: "e2", asset: "H1", sha256: HASH2, description: "logon by CORP\\admin" }),
      ev({ id: "e3", asset: "H2", sha256: HASH2, description: "logon by CORP\\admin" }),
    );
    const g = buildEvidenceGraph(s);
    expect(g.edges.length).toBeGreaterThan(0);
    for (const e of g.edges) {
      expect(e.rule).toBeTruthy();
      expect(e.basis).toBeTruthy();
      expect(e.eventIds.length).toBeGreaterThan(0);
    }
    for (const n of g.nodes) expect(n.eventIds.length).toBeGreaterThan(0);

    // Only nodes that participate in an edge are emitted.
    const inEdge = new Set(g.edges.flatMap((e) => [e.source, e.target]));
    expect(g.nodes.every((n) => inEdge.has(n.id))).toBe(true);
  });
});
