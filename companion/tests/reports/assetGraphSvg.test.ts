import { describe, it, expect } from "vitest";
import { renderAssetGraphSvg } from "../../src/reports/assetGraphSvg.js";
import type { AssetGraph, GraphAsset, GraphIoc } from "../../src/analysis/assetGraph.js";

function host(id: string, name: string, compromised = false): GraphAsset {
  return { id, name, type: "host", compromised, iocIds: [], findingIds: [], eventCount: 1, maxSeverity: "Info" };
}
function ioc(id: string, value: string, type = "ip", verdict?: string): GraphIoc {
  return { id, type, value, verdict, assetIds: [] };
}
function makeGraph(partial: Partial<AssetGraph> = {}): AssetGraph {
  return { assets: [], iocs: [], edges: [], ...partial };
}

describe("renderAssetGraphSvg", () => {
  it("returns empty string when there are no assets", () => {
    expect(renderAssetGraphSvg(makeGraph())).toBe("");
    // IoCs without any assets still produce an empty string
    expect(renderAssetGraphSvg(makeGraph({ iocs: [ioc("i1", "1.2.3.4")] }))).toBe("");
  });

  it("produces a valid SVG element for a graph with assets", () => {
    const svg = renderAssetGraphSvg(makeGraph({ assets: [host("host:w1", "WIN-01")] }));
    expect(svg).toMatch(/^<svg /);
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
    expect(svg).toMatch(/<\/svg>\s*$/);
  });

  it("renders asset names and IoC values with column-header counts", () => {
    const graph: AssetGraph = {
      assets: [{ ...host("host:w1", "WIN-01", true), iocIds: ["i1"] }],
      iocs: [{ ...ioc("i1", "10.0.0.5"), assetIds: ["host:w1"] }],
      edges: [{ asset: "host:w1", ioc: "i1" }],
    };
    const svg = renderAssetGraphSvg(graph);
    expect(svg).toContain("WIN-01");
    expect(svg).toContain("10.0.0.5");
    expect(svg).toContain("Assets (1)");
    expect(svg).toContain("IoCs (1)");
    // Edge bezier curve present
    expect(svg).toContain('<path d="M');
  });

  it("draws an H badge for host assets and an A badge for account assets", () => {
    const graph: AssetGraph = {
      assets: [
        host("host:w1", "WIN-01"),
        { id: "account:jdoe", name: "CORP\\jdoe", type: "account", compromised: false, iocIds: [], findingIds: [], eventCount: 1, maxSeverity: "Info" },
      ],
      iocs: [],
      edges: [],
    };
    const svg = renderAssetGraphSvg(graph);
    // Both badge letters must appear
    const hIdx = svg.indexOf(">H<");
    const aIdx = svg.indexOf(">A<");
    expect(hIdx).toBeGreaterThan(-1);
    expect(aIdx).toBeGreaterThan(-1);
  });

  it("uses the IOC_BADGE label for known IoC types", () => {
    const graph: AssetGraph = {
      assets: [{ ...host("host:w1", "WIN-01"), iocIds: ["i1", "i2"] }],
      iocs: [
        { ...ioc("i1", "8.8.8.8", "ip"), assetIds: ["host:w1"] },
        { ...ioc("i2", "evil.com", "domain"), assetIds: ["host:w1"] },
      ],
      edges: [
        { asset: "host:w1", ioc: "i1" },
        { asset: "host:w1", ioc: "i2" },
      ],
    };
    const svg = renderAssetGraphSvg(graph);
    expect(svg).toContain(">IP<");
    expect(svg).toContain(">DO<");
  });

  it("escapes HTML special characters in asset names and IoC values", () => {
    const graph: AssetGraph = {
      assets: [host("host:x", "<CORP>&admin")],
      iocs: [],
      edges: [],
    };
    const svg = renderAssetGraphSvg(graph);
    expect(svg).not.toContain("<CORP>");
    expect(svg).toContain("&lt;CORP&gt;");
    expect(svg).toContain("&amp;admin");
  });

  it("truncates long asset names and IoC values with an ellipsis", () => {
    const longName = "A".repeat(50);
    const graph: AssetGraph = {
      assets: [host("host:x", longName)],
      iocs: [],
      edges: [],
    };
    const svg = renderAssetGraphSvg(graph);
    expect(svg).not.toContain(longName);
    expect(svg).toContain("…");
  });

  it("shows a truncation note when the graph exceeds the display cap", () => {
    const assets = Array.from({ length: 35 }, (_, i) =>
      host(`host:h${i}`, `HOST-${i}`),
    );
    const svg = renderAssetGraphSvg(makeGraph({ assets }));
    // Note mentions total asset count and refers to dashboard
    expect(svg).toContain("35");
    expect(svg).toContain("dashboard");
  });

  it("does not show a truncation note when the graph is within the cap", () => {
    const assets = Array.from({ length: 5 }, (_, i) => host(`host:h${i}`, `H${i}`));
    const svg = renderAssetGraphSvg(makeGraph({ assets }));
    expect(svg).not.toContain("dashboard");
  });

  it("excludes IoCs not connected to any displayed asset from the right column", () => {
    // i2 is connected to a non-displayed asset (beyond MAX_ITEMS cap); won't appear
    const assets = Array.from({ length: 31 }, (_, i) =>
      host(`host:h${i}`, `HOST-${i}`),
    );
    const iocs: GraphIoc[] = [
      { ...ioc("i1", "1.1.1.1"), assetIds: ["host:h0"] },
      { ...ioc("i2", "9.9.9.9"), assetIds: ["host:h30"] },  // h30 is index 30 — beyond cap of 30
    ];
    const svg = renderAssetGraphSvg({ assets, iocs, edges: [] });
    expect(svg).toContain("1.1.1.1");
    expect(svg).not.toContain("9.9.9.9");
  });
});
