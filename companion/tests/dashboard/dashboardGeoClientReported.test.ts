import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { functionsOf, scriptFromSource } from "../helpers/dashboardAst.js";

// The popup and top-IP list suffixes are behaviourally tested through the published geoIpFlags /
// geoPopupHtml (iocClientReportedLabel.test.ts). The drawn marker is Leaflet against a live DOM,
// so its de-emphasis is pinned at the source level: a client-reported pin is long-dashed and
// hollow BEFORE any click — a malicious verdict must not render it full-red beside sensor-observed
// peers — and the legend names that styling. Negative-controlled by renaming the flag.
const source = readFileSync(new URL("../../../public/js/dashboard-geo.js", import.meta.url), "utf8");
const script = scriptFromSource("dashboard-geo.js", source);

function bodyOf(name: string): string {
  const fn = functionsOf(script).find((f) => f.name === name);
  if (!fn) throw new Error(`dashboard-geo.js no longer defines ${name}`);
  return fn.node.getText();
}

describe("dashboard-geo.js de-emphasises a client-reported pin before any click (#1326 follow-up)", () => {
  it("the drawn marker reads m.clientReported and dashes/hollows it", () => {
    expect(bodyOf("renderGeoMarkers")).toMatch(/if \(m\.clientReported\) \{[^}]*dashArray[^}]*fillOpacity/);
  });

  it("the legend names the client-reported styling next to the approximate one", () => {
    const body = bodyOf("renderGeoView");
    expect(body).toContain("dashed = country-level (approx)");
    expect(body).toContain("= client-reported");
  });
});
