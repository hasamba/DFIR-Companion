import { describe, it, expect } from "vitest";
import {
  markLolbinChains,
  UNUSUAL_LAUNCHERS,
  normalizeProcessName,
} from "../../src/analysis/lolbinChains.js";
import type { EvidenceEdge, EvidenceNode } from "../../src/analysis/evidenceGraph.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

const HOST = "h1";
const nid = (name: string) => `proc:${HOST}:${name.toLowerCase()}`;
const node = (name: string, maxSeverity: Severity = "Low"): EvidenceNode => ({
  id: nid(name),
  kind: "process",
  label: name,
  asset: HOST,
  maxSeverity,
  eventIds: ["e"],
});
const spawn = (a: string, b: string): EvidenceEdge => ({
  id: `spawned|${nid(a)}|${nid(b)}`,
  type: "spawned",
  source: nid(a),
  target: nid(b),
  confidence: "high",
  rule: "process-parent-child",
  basis: `${a} -> ${b}`,
  eventIds: ["e"],
});
const flag = (nodes: EvidenceNode[], name: string) => nodes.find((n) => n.id === nid(name))?.lolbin;

describe("markLolbinChains", () => {
  it("marks a LOLBIN under an unusual launcher as a hit, flags the edge, and gives the launcher context", () => {
    const out = markLolbinChains(
      [node("winword.exe"), node("powershell.exe", "Low")],
      [spawn("winword.exe", "powershell.exe")],
    );
    expect(flag(out.nodes, "powershell.exe")).toBe("hit");
    expect(flag(out.nodes, "winword.exe")).toBe("context");
    expect(out.edges[0].launcher).toBe(true);
  });

  it.each([
    "WINWORD.EXE",
    "winword",
    "Excel",
    "powerpnt.exe",
    "OUTLOOK",
    "onenote",
    "msaccess",
    "chrome",
    "msedge",
    "firefox",
    "iexplore",
    "wmiprvse",
    "wscript",
    "cscript",
  ])("treats %s as an unusual launcher", (launcher) => {
    const out = markLolbinChains(
      [node(launcher), node("certutil.exe", "Low")],
      [spawn(launcher, "certutil.exe")],
    );
    expect(flag(out.nodes, "certutil.exe")).toBe("hit");
    expect(out.edges[0].launcher).toBe(true);
  });

  it("exposes the launcher list and name normaliser", () => {
    expect(UNUSUAL_LAUNCHERS.has("winword.exe")).toBe(true);
    expect(normalizeProcessName("C:\\Windows\\System32\\CMD")).toBe("cmd.exe");
  });

  it("marks a Medium-or-higher LOLBIN under an ordinary parent, but not a Low one", () => {
    for (const sev of ["Medium", "High", "Critical"] as Severity[]) {
      const out = markLolbinChains(
        [node("explorer.exe"), node("powershell.exe", sev)],
        [spawn("explorer.exe", "powershell.exe")],
      );
      expect(flag(out.nodes, "powershell.exe")).toBe("hit");
      expect(out.edges[0].launcher).toBeUndefined();
    }
    const low = markLolbinChains(
      [node("explorer.exe"), node("powershell.exe", "Low")],
      [spawn("explorer.exe", "powershell.exe")],
    );
    expect(low.nodes.every((n) => n.lolbin === undefined)).toBe(true);
  });

  it("does not flag a non-LOLBIN spawned by an unusual launcher", () => {
    const out = markLolbinChains(
      [node("winword.exe"), node("notepad.exe", "High")],
      [spawn("winword.exe", "notepad.exe")],
    );
    expect(out.nodes.every((n) => n.lolbin === undefined)).toBe(true);
    expect(out.edges[0].launcher).toBeUndefined();
  });

  it("marks ancestors to the root and direct children, but not grandchildren", () => {
    const chain = ["services.exe", "explorer.exe", "winword.exe", "powershell.exe", "whoami.exe", "x.exe"];
    const edges = chain.slice(1).map((c, i) => spawn(chain[i], c));
    const out = markLolbinChains(
      chain.map((c) => node(c)),
      edges,
    );
    expect(flag(out.nodes, "powershell.exe")).toBe("hit");
    for (const c of ["services.exe", "explorer.exe", "winword.exe", "whoami.exe"])
      expect(flag(out.nodes, c)).toBe("context");
    expect(flag(out.nodes, "x.exe")).toBeUndefined();
  });

  it("qualifies certutil (outside the Run-key subset)", () => {
    const out = markLolbinChains([node("certutil.exe", "Medium")], []);
    expect(flag(out.nodes, "certutil.exe")).toBe("hit");
  });

  it("keeps hit when a node is both a hit and context of another hit", () => {
    const out = markLolbinChains(
      [node("winword.exe"), node("cmd.exe", "Low"), node("powershell.exe", "Medium")],
      [spawn("winword.exe", "cmd.exe"), spawn("cmd.exe", "powershell.exe")],
    );
    expect(flag(out.nodes, "cmd.exe")).toBe("hit");
  });

  it("does not mutate its inputs", () => {
    const nodes = [node("winword.exe"), node("powershell.exe")];
    const edges = [spawn("winword.exe", "powershell.exe")];
    const before = JSON.stringify({ nodes, edges });
    markLolbinChains(nodes, edges);
    expect(JSON.stringify({ nodes, edges })).toBe(before);
  });

  it("terminates on spawn cycles", () => {
    const out = markLolbinChains(
      [node("a.exe"), node("b.exe"), node("powershell.exe", "High")],
      [spawn("a.exe", "b.exe"), spawn("b.exe", "a.exe"), spawn("b.exe", "powershell.exe")],
    );
    expect(flag(out.nodes, "powershell.exe")).toBe("hit");
    expect(flag(out.nodes, "a.exe")).toBe("context");
    expect(flag(out.nodes, "b.exe")).toBe("context");
  });
});
