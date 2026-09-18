import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { functionsOf, scriptFromSource } from "../helpers/dashboardAst.js";

// public/js/dashboard-geo.js draws with Leaflet against a live DOM, so it has no vm-context
// behavioural harness. This pins the #1326 contract at the source level instead: the two places
// a marker is rendered for a human (the pin popup, the top-IP list) and the one place it is
// drawn (circleMarker options) all read the server's `clientReported` flag. If a refactor drops
// one, the marker silently vanishes with green CI — the invisibility #1326 was filed to fix.
const source = readFileSync(new URL("../../../public/js/dashboard-geo.js", import.meta.url), "utf8");
const script = scriptFromSource("dashboard-geo.js", source);

function bodyOf(name: string): string {
  const fn = functionsOf(script).find((f) => f.name === name);
  if (!fn) throw new Error(`dashboard-geo.js no longer defines ${name}`);
  return fn.node.getText();
}

describe("dashboard-geo.js says when a pin is client-reported (#1326)", () => {
  it("the popup and the drawn marker both read m.clientReported", () => {
    const body = bodyOf("renderGeoMarkers");
    expect(body).toContain("m.clientReported");
    expect(body).toContain("(client-reported)");
    // The de-emphasis is visible before any click, like `approximate`'s own dash.
    expect(body).toMatch(/if \(m\.clientReported\) \{[^}]*dashArray/);
  });

  it("the top-IP list reads m.clientReported and the legend names the styling", () => {
    const body = bodyOf("renderGeoView");
    expect(body).toContain("m.clientReported");
    expect(body).toContain("(client-reported)");
    expect(body).toContain("= client-reported");
  });
});
