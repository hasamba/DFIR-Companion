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

// The chip is rendered by dashboard-ioc-provenance.js (the module that owns the row's other
// badges) so the inline script — which sits at its size-ledger ceiling — only calls it. The
// module is exercised for real; renderIocs is pinned only to the call, scoped to that function so
// a matching string elsewhere in 5,000 lines cannot satisfy it.
interface ProvApi {
  iocClientReportedChip(ioc: { type?: string; provenance?: string }): string;
}
const prov = loadDashboardModule<ProvApi>("dashboard-ioc-provenance.js", ["dashboard-escape.js"]);

describe("IOC panel row — client-reported chip (#1326)", () => {
  it("gates the chip on the exact provenance literal", () => {
    expect(prov.iocClientReportedChip({ provenance: "client-reported" })).toMatch(
      /class="ioc-note-chip[^"]*"[^>]*>client-reported</,
    );
    expect(prov.iocClientReportedChip({})).toBe("");
    // A future second literal must not be mistaken for this one (stateTypes.ts sentinel).
    expect(prov.iocClientReportedChip({ provenance: "client-reported-ish" })).toBe("");
  });

  it("never calls itself a 'provenance' badge — that word is the detection/telemetry lens", () => {
    expect(prov.iocClientReportedChip({ provenance: "client-reported" })).not.toMatch(/>provenance</i);
  });

  // #1471 finding 6: the same chip function (renderIocs must keep its one call) also carries the
  // `mentioned` mark — the #1461 note for a network value, the #1459 note for a hash — so the
  // analyst's primary IOC list stops showing a free-text hash as an ordinary verified one.
  it("marks a mentioned network IOC with the #1461 note (#1471)", () => {
    const html = prov.iocClientReportedChip({ type: "ip", provenance: "mentioned" });
    expect(html).toMatch(/class="ioc-note-chip[^"]*"[^>]*>mentioned</);
    expect(html).toContain("no network record");
    expect(html).not.toContain("no file with this hash");
    expect(prov.iocClientReportedChip({ type: "domain", provenance: "mentioned" })).toContain(
      "no network record",
    );
    expect(prov.iocClientReportedChip({ type: "url", provenance: "mentioned" })).toContain(
      "no network record",
    );
  });

  it("marks a mentioned hash with the #1459 note, not the network one (#1471)", () => {
    const html = prov.iocClientReportedChip({ type: "hash", provenance: "mentioned" });
    expect(html).toMatch(/class="ioc-note-chip[^"]*"[^>]*>mentioned</);
    expect(html).toContain("no file with this hash");
    expect(html).not.toContain("no network record");
  });

  it("gates the mentioned chip on the exact literal and on a type that has wording", () => {
    expect(prov.iocClientReportedChip({ type: "ip", provenance: "mentioned-ish" })).toBe("");
    expect(prov.iocClientReportedChip({ type: "file", provenance: "mentioned" })).toBe("");
    expect(prov.iocClientReportedChip({ type: "ip" })).toBe("");
  });

  it("is what the inline IOC row actually renders", () => {
    const main = mainInlineScript();
    const renderIocs = functionsOf(main).find((f) => f.name === "renderIocs");
    expect(renderIocs, "renderIocs must still live in the inline script").toBeDefined();
    expect(renderIocs?.node.getText(main.ast) ?? "").toContain("${iocClientReportedChip(i)}");
  });
});
