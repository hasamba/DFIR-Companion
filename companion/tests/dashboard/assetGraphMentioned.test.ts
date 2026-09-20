import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { functionsOf, scriptFromSource } from "../helpers/dashboardAst.js";

// #1461. GET /cases/:id/asset-graph marks an IoC read out of free text `mentioned: true` and every
// edge from it `referenced: true`. The Cytoscape panel is a live DOM, so the contract is pinned at
// the source level, the way dashboardGeoClientReported.test.ts pins the Leaflet pin: the element
// builder carries both flags into the graph, the edge style dashes a referenced edge, and the node
// detail names the reference in the report's words.
const source = readFileSync(new URL("../../../public/js/dashboard-asset-graph.js", import.meta.url), "utf8");
const script = scriptFromSource("dashboard-asset-graph.js", source);

function bodyOf(name: string): string {
  const fn = functionsOf(script).find((f) => f.name === name);
  if (!fn) throw new Error(`dashboard-asset-graph.js no longer defines ${name}`);
  return fn.node.getText();
}

describe("dashboard-asset-graph.js draws a mentioned IoC as a reference (#1461)", () => {
  it("the element builder names the reference on the IoC node", () => {
    const body = bodyOf("assetBuildElements");
    expect(body).toMatch(/i\.mentioned\s*\?[^:]*referenced in free text; no network record/);
  });

  it("the element builder classes a referenced edge", () => {
    const body = bodyOf("assetBuildElements");
    expect(body).toMatch(/e\.referenced\s*\?\s*"referenced"/);
  });

  it("the stylesheet dashes the referenced edge", () => {
    expect(source).toMatch(/selector:\s*"edge\.referenced",\s*style:\s*\{[^}]*"line-style":\s*"dashed"/);
  });
});
