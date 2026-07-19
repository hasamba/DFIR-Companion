import { describe, it, expect } from "vitest";
import { buildEvidenceGraph, buildLateralPaths } from "../../src/analysis/evidenceGraph.js";
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

describe("buildLateralPaths — ordered lateral-movement chains (#92)", () => {
  it("chains a binary hopping across 3 hosts into one ordered entry→pivot→target path", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "ALCLIENT07", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "DC01", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
      ev({ id: "e3", asset: "FILESVR01", sha256: HASH, timestamp: "2026-05-20T11:00:00Z" }),
    );
    const paths = buildLateralPaths(s);
    expect(paths).toHaveLength(1);
    expect(paths[0].hostIds).toEqual(["host:alclient07", "host:dc01", "host:filesvr01"]);
    expect(paths[0].confidence).toBe("high");
    expect(paths[0].hops).toHaveLength(2);
    expect(paths[0].hops.every((h) => h.rule === "shared-hash")).toBe(true);
    expect(paths[0].startTime).toBe("2026-05-20T09:00:00Z");
    expect(paths[0].endTime).toBe("2026-05-20T11:00:00Z");
  });

  it("orders hops by real timestamp, not by alphabetical host name", () => {
    const s = emptyState("c1");
    // ZEBRA seen first, ALPHA second — an alphabetical sort would reverse this.
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "ZEBRA", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "ALPHA", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
    );
    const paths = buildLateralPaths(s);
    expect(paths).toHaveLength(1);
    expect(paths[0].hostIds).toEqual(["host:zebra", "host:alpha"]);
  });

  it("stitches a hash hop and a later account hop into one mixed-rule path, confidence = weakest link", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
      ev({ id: "e3", asset: "HOST-B", description: "logon by CORP\\jdoe", timestamp: "2026-05-20T11:00:00Z" }),
      ev({ id: "e4", asset: "HOST-C", description: "logon by CORP\\jdoe", timestamp: "2026-05-20T12:00:00Z" }),
    );
    const paths = buildLateralPaths(s);
    expect(paths).toHaveLength(1);
    expect(paths[0].hostIds).toEqual(["host:host-a", "host:host-b", "host:host-c"]);
    expect(paths[0].hops.map((h) => h.rule)).toEqual(["shared-hash", "shared-account"]);
    expect(paths[0].confidence).toBe("medium"); // weakest link, not the first hop's "high"
  });

  it("does not stitch a hop that would move backward in time", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", sha256: HASH, timestamp: "2026-05-20T12:00:00Z" }),
      // A different account ties HOST-B back to HOST-C, but earlier than the hop that reached HOST-B.
      ev({ id: "e3", asset: "HOST-B", description: "logon by CORP\\jdoe", timestamp: "2026-05-20T08:00:00Z" }),
      ev({ id: "e4", asset: "HOST-C", description: "logon by CORP\\jdoe", timestamp: "2026-05-20T08:30:00Z" }),
    );
    const paths = buildLateralPaths(s);
    // The hash hop A→B stands alone; the account hop is a separate, earlier, unrelated root/chain.
    const hashPath = paths.find((p) => p.hostIds.includes("host:host-a"))!;
    expect(hashPath.hostIds).toEqual(["host:host-a", "host:host-b"]);
  });

  it("does not form a cycle back to an already-visited host", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
      // A second hash ties HOST-B back to HOST-A, later in time — would form a cycle if followed.
      ev({ id: "e3", asset: "HOST-B", sha256: HASH2, timestamp: "2026-05-20T11:00:00Z" }),
      ev({ id: "e4", asset: "HOST-A", sha256: HASH2, timestamp: "2026-05-20T12:00:00Z" }),
    );
    const paths = buildLateralPaths(s);
    for (const p of paths) {
      const unique = new Set(p.hostIds);
      expect(unique.size).toBe(p.hostIds.length); // no host repeats within a single path
    }
  });

  it("returns an empty array when there is no lateral signal", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev({ id: "e1", asset: "HOST-A", sha256: HASH }));
    expect(buildLateralPaths(s)).toEqual([]);
  });

  // Spread the same binary over three hosts from a given on-disk location.
  function estateWide(path: string, extra: Partial<ForensicEvent> = {}) {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WS-01", sha256: HASH, path, timestamp: "2026-05-20T09:00:00Z", ...extra }),
      ev({ id: "e2", asset: "WS-02", sha256: HASH, path, timestamp: "2026-05-20T10:00:00Z" }),
      ev({ id: "e3", asset: "WS-03", sha256: HASH, path, timestamp: "2026-05-20T11:00:00Z" }),
    );
    return s;
  }

  it("does NOT infer lateral movement from vendor software installed across the estate", () => {
    // chrome.exe / OUTLOOK.EXE / vpnui.exe share a hash on every workstation BY DESIGN. Treating
    // "same binary on two hosts" as high-confidence movement made ordinary software the longest,
    // top-sorted chain in a real case (10 hosts, entirely browsers, VPN clients and updaters).
    for (const path of [
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Windows\\System32\\svchost.exe",
      "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
      // Modern apps install per user — these are vendor install roots too, not attacker drops.
      "C:\\Users\\samuel.roth\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
      "C:\\Users\\grace.lin\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
      "C:\\Users\\grace.lin\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
    ]) {
      expect(buildLateralPaths(estateWide(path)), `${path} must not imply movement`).toEqual([]);
    }
  });

  it("suppresses vendor software at ANY spread, including just two hosts", () => {
    // Prevalence is not part of the test: System32 binaries paired across two hosts were the bulk
    // of the surviving noise, and a vendor binary on two hosts is the same non-event as on ten.
    const s = emptyState("c1");
    const path = "C:\\Windows\\System32\\dllhost.exe";
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WS-01", sha256: HASH, path, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "WS-02", sha256: HASH, path, timestamp: "2026-05-20T10:00:00Z" }),
    );
    expect(buildLateralPaths(s)).toEqual([]);
  });

  it("being flagged does NOT rescue vendor software (grading is not the discriminator)", () => {
    // The pipeline registers every observed binary hash as an IOC and puts MITRE techniques on
    // process events, so "is it flagged?" is true of chrome.exe too. If these rescued a binary the
    // filter would do nothing at all on real data — which is exactly what happened when tried.
    const withIoc = estateWide("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
    withIoc.iocs.push({ id: "i1", type: "hash", value: HASH, firstSeen: "2026-05-20T09:00:00Z" });
    expect(buildLateralPaths(withIoc)).toEqual([]);

    const withMitre = estateWide("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", { mitreTechniques: ["T1021"] });
    expect(buildLateralPaths(withMitre)).toEqual([]);
  });

  it("keeps a widespread binary running from a user-writable location", () => {
    // Provenance is the discriminator: vendor software lives under Windows/Program Files, attacker
    // tooling lands somewhere writable — and prevalence must never bury that.
    for (const path of [
      "C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost.exe",
      "C:\\ProgramData\\update\\tool.exe",
      "D:\\tools\\psexec.exe",
    ]) {
      const paths = buildLateralPaths(estateWide(path));
      expect(paths.length, `${path} must still imply movement`).toBeGreaterThan(0);
      expect(paths[0].hostIds).toEqual(["host:ws-01", "host:ws-02", "host:ws-03"]);
    }
  });

  it("keeps a trusted-directory binary that the content tagger graded High (LOLbin abuse)", () => {
    const paths = buildLateralPaths(estateWide("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", { severity: "High" }));
    expect(paths.length).toBeGreaterThan(0);
  });

  it("keeps a widespread binary whose on-disk path was never recorded (no provenance ⇒ no filtering)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WS-01", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "WS-02", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
      ev({ id: "e3", asset: "WS-03", sha256: HASH, timestamp: "2026-05-20T11:00:00Z" }),
    );
    expect(buildLateralPaths(s).length).toBeGreaterThan(0);
  });

  it("keeps a tool dropped in a writable location on only two hosts", () => {
    const s = emptyState("c1");
    const path = "C:\\Users\\jdoe\\Downloads\\psexec.exe";
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "WS-01", sha256: HASH, path, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "WS-02", sha256: HASH, path, timestamp: "2026-05-20T10:00:00Z" }),
    );
    expect(buildLateralPaths(s)).toHaveLength(1);
  });

  it("terminates on a densely connected host graph (no simple-path enumeration blow-up)", () => {
    // Real cases produce MANY parallel hops between the same hosts: 8 accounts each seen on the
    // same 10 hosts = 8 interchangeable choices at each of 9 steps, i.e. 8^9 ≈ 134M distinct
    // simple paths. Exploring every combination to find the longest tail pegs a core forever —
    // this hung the whole server on a real 12-host case. The chain must be derived without
    // enumerating combinations.
    const s = emptyState("c1");
    const base = Date.parse("2026-05-20T00:00:00Z");
    for (let a = 0; a < 8; a++) {
      for (let h = 0; h < 10; h++) {
        // Same per-host timestamp across every account, so all 8 accounts' hops are freely
        // interchangeable at each step — that is what creates the combinatorial fan-out.
        s.forensicTimeline.push(ev({
          id: `e-${a}-${h}`,
          asset: `HOST-${h}`,
          description: `logon by CORP\\user${a}`,
          timestamp: new Date(base + h * 3600_000).toISOString(),
        }));
      }
    }

    const t0 = Date.now();
    const paths = buildLateralPaths(s);
    const elapsed = Date.now() - t0;

    expect(elapsed).toBeLessThan(2000);
    // Still reconstructs the full 10-host chain — the fix must not cost correctness.
    expect(paths[0].hostIds).toEqual(Array.from({ length: 10 }, (_, h) => `host:host-${h}`));
  });

  it("does NOT treat truncated NT AUTHORITY pseudo-principals as a shared account", () => {
    // extractAccounts() splits "NT AUTHORITY\LOCAL SERVICE" on the space, yielding the truncated
    // pair AUTHORITY\LOCAL — which slipped past a filter listing only the untruncated
    // "nt authority" / "local service". Every Windows host runs these, so letting them through
    // chains unrelated hosts into a confident-looking attack path.
    for (const acct of ["NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE", "NT AUTHORITY\\ANONYMOUS LOGON", "NT SERVICE\\TrustedInstaller"]) {
      const s = emptyState("c1");
      s.forensicTimeline.push(
        ev({ id: "e1", asset: "HOST-A", description: `logon by ${acct}`, timestamp: "2026-05-20T09:00:00Z" }),
        ev({ id: "e2", asset: "HOST-B", description: `logon by ${acct}`, timestamp: "2026-05-20T10:00:00Z" }),
      );
      expect(buildLateralPaths(s), `${acct} must not produce a lateral path`).toEqual([]);
    }
  });

  it("still derives a path for a real account whose name merely resembles a service principal", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", description: "logon by CORP\\network.admin", timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", description: "logon by CORP\\network.admin", timestamp: "2026-05-20T10:00:00Z" }),
    );
    expect(buildLateralPaths(s)).toHaveLength(1);
  });

  it("every hop carries its two backing events (per-hop evidence)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
    );
    const paths = buildLateralPaths(s);
    expect(paths[0].hops[0].eventIds).toEqual(["e1", "e2"]);
  });

  it("respects the time window (#83), matching buildEvidenceGraph's scoping", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", sha256: HASH, timestamp: "2026-05-20T15:00:00Z" }),
    );
    const scoped = buildLateralPaths(s, { from: "2026-05-20T08:00:00Z", until: "2026-05-20T10:00:00Z" });
    expect(scoped).toEqual([]); // only e1 in range — below the ≥2-host threshold
  });

  it("never drops a forked destination host: both branches of a fork appear across the paths", () => {
    // Fork at HOST-B: a by-hash chain A→B→D AND a by-account hop B→C from a DIFFERENT group.
    // The greedy longest-tail walk keeps only ONE onward branch from B — before the path-cover
    // fix the other branch's destination vanished from EVERY returned path. Both must survive.
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "HOST-A", sha256: HASH, timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "HOST-B", sha256: HASH, timestamp: "2026-05-20T10:00:00Z" }),
      ev({ id: "e3", asset: "HOST-D", sha256: HASH, timestamp: "2026-05-20T12:00:00Z" }), // hash: A→B→D
      ev({ id: "e4", asset: "HOST-B", description: "logon by CORP\\jdoe", timestamp: "2026-05-20T10:30:00Z" }),
      ev({ id: "e5", asset: "HOST-C", description: "logon by CORP\\jdoe", timestamp: "2026-05-20T11:00:00Z" }), // account: B→C
    );
    const paths = buildLateralPaths(s);
    const reached = new Set(paths.flatMap((p) => p.hostIds));
    // Both forked destinations reached by the attacker must be present somewhere in the output.
    expect(reached.has("host:host-c")).toBe(true);
    expect(reached.has("host:host-d")).toBe(true);
    // The B→C and B→D hops are both represented (completeness: every hop covered).
    const hopPairs = paths.flatMap((p) => p.hops.map((h) => `${h.from}->${h.to}`));
    expect(hopPairs).toContain("host:host-b->host:host-c");
    expect(hopPairs).toContain("host:host-b->host:host-d");
  });
});

describe("buildEvidenceGraph — time window (#83)", () => {
  // A hash shared across two hosts — but each sighting is at a different time, so a window that
  // covers only one of them drops the pair below the ≥2-host threshold and no lateral edge forms.
  function seeded() {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "ALCLIENT07", sha256: HASH, severity: "Critical", timestamp: "2026-05-20T09:00:00Z" }),
      ev({ id: "e2", asset: "DC01", sha256: HASH, severity: "High", timestamp: "2026-05-20T15:00:00Z" }),
    );
    return s;
  }

  it("narrows the graph to events inside the window", () => {
    const scoped = buildEvidenceGraph(seeded(), { from: "2026-05-20T08:00:00Z", until: "2026-05-20T10:00:00Z" });
    // Only e1 is in range → the second host never appears → no lateral_move edge survives.
    expect(scoped.edges.filter((e) => e.type === "lateral_move")).toHaveLength(0);
    expect(scoped.nodes.some((n) => n.id === "host:dc01")).toBe(false);
  });

  it("an absent/empty window is identical to no window", () => {
    const full = buildEvidenceGraph(seeded());
    expect(full.edges.filter((e) => e.type === "lateral_move")).toHaveLength(1);   // both hosts in range
    expect(buildEvidenceGraph(seeded(), {})).toEqual(full);
    expect(buildEvidenceGraph(seeded(), { from: "", until: "" })).toEqual(full);
  });

  it("keeps events with an unparseable timestamp (mirrors the client filter)", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev({ id: "e1", asset: "H", parentName: "excel.exe", processName: "powershell.exe", timestamp: "" }),
    );
    const g = buildEvidenceGraph(s, { from: "2026-05-20T08:00:00Z", until: "2026-05-20T10:00:00Z" });
    expect(g.edges.filter((e) => e.type === "spawned")).toHaveLength(1);   // undated → kept
  });
});
