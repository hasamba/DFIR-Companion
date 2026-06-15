import { describe, it, expect } from "vitest";
import { buildGraphContext, DEFAULT_MAX_GRAPH_EDGES } from "../../src/analysis/graphContext.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

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

describe("buildGraphContext — empty / no edges", () => {
  it("returns '' for a case with no causal edges", () => {
    expect(buildGraphContext(emptyState("c1"))).toBe("");
  });

  it("returns '' when maxEdges is 0 even with edges present", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "H", parentName: "excel.exe", processName: "powershell.exe" }));
    expect(buildGraphContext(s, { maxEdges: 0 })).toBe("");
  });

  it("clamps a negative maxEdges to 0 → ''", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "H", parentName: "excel.exe", processName: "powershell.exe" }));
    expect(buildGraphContext(s, { maxEdges: -5 })).toBe("");
  });
});

describe("buildGraphContext — rendering", () => {
  it("renders the header, a process-spawn section, and cites the backing event id", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WEB01", parentName: "excel.exe", processName: "powershell.exe", severity: "High" }),
    );
    const out = buildGraphContext(s);
    expect(out).toContain("ATTACK GRAPH");
    expect(out).toContain("Process spawns (parent → child):");
    expect(out).toContain("excel.exe → powershell.exe on WEB01");
    expect(out).toContain("[e1]");
  });

  it("groups multiple edge types under their own labelled sections", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WEB01", parentName: "excel.exe", processName: "powershell.exe", severity: "High" }),
      ev({ id: "e2", asset: "WEB01", dstIp: "1.2.3.4", port: 443, severity: "High" }),
    );
    const out = buildGraphContext(s);
    expect(out).toContain("Process spawns (parent → child):");
    expect(out).toContain("Network connections (source → destination):");
    expect(out).toContain("1.2.3.4:443");
  });

  it("surfaces lateral movement (same binary across hosts) as its own section", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WEB01", sha256: HASH, severity: "Critical" }),
      ev({ id: "e2", asset: "DC01", sha256: HASH, severity: "Critical" }),
    );
    const out = buildGraphContext(s);
    expect(out).toContain("Lateral movement (same binary/account across hosts):");
    expect(out).toContain("WEB01");
    expect(out).toContain("DC01");
  });
});

describe("buildGraphContext — capping", () => {
  it("caps the rendered edges and notes the truncation", () => {
    const s = emptyState("c1");
    // 5 spawn events → 5 `spawned` edges + 5 `ran_on` anchor edges (each root process is anchored
    // to its host) = 10 total edges; cap the render to 2.
    for (let i = 0; i < 5; i++) {
      s.forensicTimeline.push(
        ev({ id: `e${i}`, asset: "WEB01", parentName: `p${i}.exe`, processName: `c${i}.exe`, severity: "High" }),
      );
    }
    const out = buildGraphContext(s, { maxEdges: 2 });
    const bulletCount = (out.match(/^- /gm) || []).length;
    expect(bulletCount).toBe(2);
    expect(out).toContain("showing 2 of 10 graph edges");
  });

  it("does not add a truncation footer when everything fits", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WEB01", parentName: "excel.exe", processName: "powershell.exe", severity: "High" }),
    );
    const out = buildGraphContext(s);
    expect(out).not.toContain("showing");
  });

  it("prioritizes higher-severity edges when capping", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "low", asset: "WEB01", parentName: "a.exe", processName: "b.exe", severity: "Low" }),
      ev({ id: "crit", asset: "WEB01", parentName: "x.exe", processName: "y.exe", severity: "Critical" }),
    );
    const out = buildGraphContext(s, { maxEdges: 1 });
    expect(out).toContain("x.exe → y.exe");
    expect(out).not.toContain("a.exe → b.exe");
  });
});

describe("buildGraphContext — defaults", () => {
  it("exports a positive default edge cap", () => {
    expect(DEFAULT_MAX_GRAPH_EDGES).toBeGreaterThan(0);
  });
});
