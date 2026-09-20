import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { functionsOf, scriptFromSource } from "../helpers/dashboardAst.js";

// #1461. GET /cases/:id/geo-map returns `mentioned: true` on a pin whose IP was read out of free
// text (a loader's `--reported-meterpreter-stage 91.191.209.46:12385`). The host was TOLD that
// address; nothing says it reached it. The popup and the Top IPs list say so with the report's
// own words, and the drawn pin is de-emphasised BEFORE any click — the same treatment a
// client-reported pin gets (#1326), with its own dash pattern so the two never look alike.

interface GeoApi {
  geoIpFlags(m: { falsePositive?: boolean; clientReported?: boolean; mentioned?: boolean }): string;
  geoPopupHtml(m: {
    ip: string;
    mentioned?: boolean;
    city?: string;
    country?: string;
    asn?: string;
    severity?: string;
    eventCount?: number;
  }): string;
}

const geo = loadDashboardModule<GeoApi>("dashboard-geo.js", ["dashboard-escape.js"]);
const NOTE = "referenced in free text; no network record";
const marker = {
  ip: "91.191.209.46",
  city: "Sofia",
  country: "BG",
  asn: "AS1",
  severity: "Medium",
  eventCount: 3,
};

describe("geo map — a mentioned IP is labelled as a reference (#1461)", () => {
  it("suffixes the popup with the report's wording", () => {
    expect(geo.geoPopupHtml({ ...marker, mentioned: true })).toContain(`<b>91.191.209.46</b> (${NOTE})`);
  });

  it("labels nothing on an ordinary sighting", () => {
    expect(geo.geoPopupHtml(marker)).not.toContain("no network record");
  });

  it("shares one flag string with the Top IPs list, after the other flags", () => {
    expect(geo.geoIpFlags({ mentioned: true })).toBe(` (${NOTE})`);
    expect(geo.geoIpFlags({ falsePositive: true, mentioned: true })).toBe(` (false positive) (${NOTE})`);
    expect(geo.geoIpFlags({})).toBe("");
  });
});

const source = readFileSync(new URL("../../../public/js/dashboard-geo.js", import.meta.url), "utf8");
const script = scriptFromSource("dashboard-geo.js", source);
function bodyOf(name: string): string {
  const fn = functionsOf(script).find((f) => f.name === name);
  if (!fn) throw new Error(`dashboard-geo.js no longer defines ${name}`);
  return fn.node.getText();
}

describe("dashboard-geo.js de-emphasises a mentioned pin before any click (#1461)", () => {
  it("the drawn marker reads m.mentioned and dots/hollows it", () => {
    expect(bodyOf("renderGeoMarkers")).toMatch(/if \(m\.mentioned\) \{[^}]*dashArray[^}]*fillOpacity/);
  });

  it("the legend names the mentioned styling beside the client-reported one", () => {
    const body = bodyOf("renderGeoView");
    expect(body).toContain("= client-reported");
    expect(body).toContain("= referenced in free text (no network record)");
  });
});
