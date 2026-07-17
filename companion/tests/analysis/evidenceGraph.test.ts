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

describe("buildEvidenceGraph — ran_on (host anchoring connects the two halves)", () => {
  it("anchors each process tree to its host so lateral movement bridges them into one graph", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", parentName: "wmiprvse.exe", processName: "evil.exe", sha256: HASH, severity: "Critical" }),
      ev({ id: "e2", asset: "HOST-B", parentName: "services.exe", processName: "evil.exe", sha256: HASH, severity: "High" }),
      ev({ id: "e3", asset: "HOST-B", parentName: "evil.exe", processName: "powershell.exe" }),
    );
    const g = buildEvidenceGraph(s);

    // Each tree ROOT (not its children) anchors to its host via ran_on.
    const ranOn = g.edges.filter((e) => e.type === "ran_on");
    expect(ranOn.some((e) => e.source === "host:host-a" && e.target === "proc:host-a:wmiprvse.exe")).toBe(true);
    expect(ranOn.some((e) => e.source === "host:host-b" && e.target === "proc:host-b:services.exe")).toBe(true);
    expect(ranOn.every((e) => e.confidence === "high" && e.rule === "process-on-host")).toBe(true);
    // A non-root (evil.exe on HOST-B has a parent) does NOT get a host anchor.
    expect(ranOn.some((e) => e.target === "proc:host-b:evil.exe")).toBe(false);

    // The shared hash links the two hosts (lateral), so the whole thing is ONE component.
    const adj = new Map<string, string[]>();
    for (const e of g.edges) {
      (adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!).push(e.target);
      (adj.get(e.target) ?? adj.set(e.target, []).get(e.target)!).push(e.source);
    }
    const seen = new Set<string>(["proc:host-a:evil.exe"]);
    const queue = ["proc:host-a:evil.exe"];
    while (queue.length) {
      const u = queue.shift()!;
      for (const v of adj.get(u) ?? []) if (!seen.has(v)) { seen.add(v); queue.push(v); }
    }
    expect(seen.has("proc:host-b:powershell.exe")).toBe(true);   // reachable across hosts
  });
});

describe("buildEvidenceGraph — file_lineage (wrote→executed)", () => {
  it("creates a file node and two edges when a hash is both written and executed", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", action: "write", sha256: HASH, path: "C:\\Temp\\evil.exe", severity: "High" }),
      ev({ id: "e2", asset: "HOST-B", action: "execute", sha256: HASH, severity: "Critical" }),
    );
    const g = buildEvidenceGraph(s);
    const lineage = g.edges.filter((e) => e.type === "file_lineage");
    expect(lineage).toHaveLength(2); // wrote edge + executed edge
    expect(lineage.every((e) => e.confidence === "high")).toBe(true);

    const fileNode = g.nodes.find((n) => n.kind === "file");
    expect(fileNode).toBeDefined();
    expect(fileNode!.label).toBe("evil.exe");   // filename derived from path
    // The file node is the common hub: one edge points IN (wrote), one OUT (exec).
    const intoFile = lineage.find((e) => e.target === fileNode!.id);
    const outOfFile = lineage.find((e) => e.source === fileNode!.id);
    expect(intoFile?.rule).toBe("wrote-file");
    expect(outOfFile?.rule).toBe("executed-file");
  });

  it("produces no file-lineage edges when only write events exist (no matching execute)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "HOST-A", action: "write", sha256: HASH }));
    expect(buildEvidenceGraph(s).edges.filter((e) => e.type === "file_lineage")).toHaveLength(0);
  });

  it("produces no file-lineage edges when only execute events exist (no matching write)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "HOST-A", action: "execute", sha256: HASH }));
    expect(buildEvidenceGraph(s).edges.filter((e) => e.type === "file_lineage")).toHaveLength(0);
  });

  it("uses process node for execute-context when processName is set", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", action: "write", sha256: HASH }),
      ev({ id: "e2", asset: "HOST-B", action: "execute", sha256: HASH, processName: "evil.exe" }),
    );
    const g = buildEvidenceGraph(s);
    const execEdge = g.edges.find((e) => e.type === "file_lineage" && e.rule === "executed-file");
    expect(execEdge).toBeDefined();
    const targetNode = g.nodes.find((n) => n.id === execEdge!.target);
    expect(targetNode?.kind).toBe("process");
  });

  it("skips write or execute events without an asset (no context to anchor)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      // write event has no asset — cannot create a write-host node
      ev({ id: "e1", action: "write", sha256: HASH }),
      ev({ id: "e2", asset: "HOST-B", action: "execute", sha256: HASH }),
    );
    const g = buildEvidenceGraph(s);
    const lineage = g.edges.filter((e) => e.type === "file_lineage");
    // The wrote edge is skipped (no write asset); the exec edge still creates file→HOST-B.
    expect(lineage).toHaveLength(1);
    expect(lineage[0].rule).toBe("executed-file");
  });
});

describe("buildEvidenceGraph — network_flow (src→dst)", () => {
  it("creates network nodes and a flow edge from srcIp to dstIp:port", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", srcIp: "10.0.0.5", dstIp: "8.8.8.8", port: 443, severity: "High" }),
    );
    const g = buildEvidenceGraph(s);
    const flows = g.edges.filter((e) => e.type === "network_flow");
    expect(flows).toHaveLength(1);
    expect(flows[0].confidence).toBe("high");
    expect(flows[0].rule).toBe("network-connection");

    const srcNode = g.nodes.find((n) => n.id === flows[0].source);
    const dstNode = g.nodes.find((n) => n.id === flows[0].target);
    expect(srcNode?.kind).toBe("network");
    expect(dstNode?.kind).toBe("network");
    expect(dstNode?.label).toBe("8.8.8.8:443");
    expect(dstNode?.ip).toBe("8.8.8.8");
  });

  it("falls back to event.asset as source host node when srcIp is absent", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "HOST-A", dstIp: "1.2.3.4", severity: "Medium" }));
    const g = buildEvidenceGraph(s);
    const flows = g.edges.filter((e) => e.type === "network_flow");
    expect(flows).toHaveLength(1);
    const srcNode = g.nodes.find((n) => n.id === flows[0].source);
    expect(srcNode?.label).toBe("HOST-A");
    expect(srcNode?.kind).toBe("host");  // asset → host node, not a network node
  });

  it("deduplicates flows between the same src→dst pair", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", srcIp: "10.0.0.1", dstIp: "8.8.8.8", port: 443 }),
      ev({ id: "e2", srcIp: "10.0.0.1", dstIp: "8.8.8.8", port: 443 }),
    );
    const flows = buildEvidenceGraph(s).edges.filter((e) => e.type === "network_flow");
    expect(flows).toHaveLength(1);
    expect(new Set(flows[0].eventIds)).toEqual(new Set(["e1", "e2"]));
  });

  it("produces no network-flow edge when dstIp is absent", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", srcIp: "10.0.0.1" }));
    expect(buildEvidenceGraph(s).edges.filter((e) => e.type === "network_flow")).toHaveLength(0);
  });

  it("produces no network-flow edge when neither srcIp nor asset is set", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", dstIp: "8.8.8.8" }));
    expect(buildEvidenceGraph(s).edges.filter((e) => e.type === "network_flow")).toHaveLength(0);
  });

  it("treats different destination ports as distinct target nodes", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", srcIp: "10.0.0.1", dstIp: "8.8.8.8", port: 80 }),
      ev({ id: "e2", srcIp: "10.0.0.1", dstIp: "8.8.8.8", port: 443 }),
    );
    const flows = buildEvidenceGraph(s).edges.filter((e) => e.type === "network_flow");
    expect(flows).toHaveLength(2);
    const targets = new Set(flows.map((e) => e.target));
    expect(targets.size).toBe(2);
  });
});

describe("buildEvidenceGraph — kill-chain tactic per node (#93)", () => {
  it("tags a process node with the dominant ATT&CK tactic of its backing events", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      // T1059 (Command-Line Interpreter) → Execution, on both events backing the powershell node.
      ev({ id: "e1", asset: "HOST-A", parentName: "excel.exe", processName: "powershell.exe", mitreTechniques: ["T1059"] }),
      ev({ id: "e2", asset: "HOST-A", parentName: "powershell.exe", processName: "cmd.exe", mitreTechniques: ["T1059.001"] }),
    );
    const g = buildEvidenceGraph(s);
    const ps = g.nodes.find((n) => n.kind === "process" && /powershell/.test(n.label))!;
    expect(ps.tactic).toBe("Execution");
  });

  it("degrades cleanly: a node whose events map to no tactic has no tactic field", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", parentName: "explorer.exe", processName: "notepad.exe" }),
    );
    const g = buildEvidenceGraph(s);
    for (const n of g.nodes) expect(n.tactic).toBeUndefined();
  });

  it("wins the dominant-tactic vote by frequency across a node's backing events", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      // Two Discovery events + one Execution event back the same host node → Discovery wins.
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, mitreTechniques: ["T1087"] }), // Discovery
      ev({ id: "e2", asset: "HOST-A", sha256: HASH, mitreTechniques: ["T1083"] }), // Discovery
      ev({ id: "e3", asset: "HOST-A", sha256: HASH, mitreTechniques: ["T1059"] }), // Execution
      ev({ id: "e4", asset: "HOST-B", sha256: HASH, mitreTechniques: ["T1087"] }), // makes the hash lateral
    );
    const g = buildEvidenceGraph(s);
    const hostA = g.nodes.find((n) => n.id === "host:host-a")!;
    expect(hostA.tactic).toBe("Discovery");
  });

  it("derives a tactic from the keyword fallback when no technique id is present", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", parentName: "svc.exe", processName: "rclone.exe", description: "rclone copy to remote — data staged for exfiltration" }),
    );
    const g = buildEvidenceGraph(s);
    const proc = g.nodes.find((n) => n.kind === "process" && /rclone/.test(n.label))!;
    expect(proc.tactic).toBe("Exfiltration");
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
