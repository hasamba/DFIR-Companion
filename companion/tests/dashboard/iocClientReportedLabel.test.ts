import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { functionsOf, mainInlineScript } from "../helpers/dashboardAst.js";

// #1326. PR #1324 (#1266) stamps `IOC.provenance = "client-reported"` on an indicator the sender
// controlled (an X-Originating-IP header, a Received hop) and the markdown report suffixes it
// "(client-reported)". The dashboard had the same object in hand — DfirScope.project spreads the
// IOC, and GET /cases/:id/geo-map returns `clientReported: true` — and drew it like any other
// sighting. An analyst reading the IOC panel or the geo map saw a sender-controlled IP sitting
// beside sensor-observed peers at identical weight.
//
// NAMING: the page already says "provenance" for a DIFFERENT lens — detection-linked versus
// telemetry-only (dashboard-ioc-provenance.js, `ioc-prov-filter`). The chip therefore reads
// "client-reported", the same word the report uses, never "provenance".

interface GeoApi {
  geoIpFlags(m: { falsePositive?: boolean; clientReported?: boolean }): string;
  geoPopupHtml(m: {
    ip: string;
    falsePositive?: boolean;
    clientReported?: boolean;
    city?: string;
    country?: string;
    asn?: string;
    severity?: string;
    verdict?: string;
    eventCount?: number;
    approximate?: boolean;
  }): string;
}

const geo = loadDashboardModule<GeoApi>("dashboard-geo.js", ["dashboard-escape.js"]);

const marker = {
  ip: "203.0.113.9",
  city: "Oslo",
  country: "NO",
  asn: "AS1",
  severity: "High",
  eventCount: 3,
};

describe("geo map — client-reported IPs are labelled (#1326)", () => {
  it("suffixes the popup the way the report does, beside the existing false-positive suffix", () => {
    expect(geo.geoPopupHtml({ ...marker, clientReported: true })).toContain(
      "<b>203.0.113.9</b> (client-reported)",
    );
    expect(geo.geoPopupHtml({ ...marker, clientReported: true, falsePositive: true })).toContain(
      "<b>203.0.113.9</b> (false positive) (client-reported)",
    );
  });

  it("labels nothing on an ordinary sighting — absence is the default, not a third state", () => {
    const html = geo.geoPopupHtml(marker);
    expect(html).not.toContain("client-reported");
    expect(html).not.toContain("false positive");
  });

  // The Top IPs list and the popup share one flag string, so the two surfaces cannot drift.
  it("exposes the same flag string for the marker list", () => {
    expect(geo.geoIpFlags({ clientReported: true })).toBe(" (client-reported)");
    expect(geo.geoIpFlags({ falsePositive: true, clientReported: true })).toBe(
      " (false positive) (client-reported)",
    );
    expect(geo.geoIpFlags({})).toBe("");
  });
});

// renderIocs lives in the inline script and is exercised by the browser alone, so this pins the
// text of THAT function — not the whole page — to the strict compare the sentinel demands
// (stateTypes.ts: a future second literal must not be mistaken for this one) and to the chip
// wording. Scoping the assertion to the function is what stops a matching string elsewhere in
// 5,000 lines from satisfying it.
describe("IOC panel row — client-reported chip (#1326)", () => {
  const main = mainInlineScript();
  const renderIocs = functionsOf(main).find((f) => f.name === "renderIocs");
  const body = renderIocs?.node.getText(main.ast) ?? "";

  it("gates the chip on the exact provenance literal", () => {
    expect(renderIocs, "renderIocs must still live in the inline script").toBeDefined();
    expect(body).toContain('i.provenance === "client-reported"');
  });

  it("says client-reported, in the existing chip styling, and never a second 'provenance' badge", () => {
    expect(body).toMatch(/class="ioc-note-chip[^"]*"[^>]*>client-reported</);
    // The detection/telemetry badge is the ONE thing on this row allowed to be called provenance.
    const provenanceWords = body.match(/>provenance</gi) ?? [];
    expect(provenanceWords).toEqual([]);
  });
});
