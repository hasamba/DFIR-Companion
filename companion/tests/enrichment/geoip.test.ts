import { describe, it, expect } from "vitest";
import { GeoIpProvider } from "../../src/enrichment/geoip.js";

function mockFetch(body: unknown) {
  return async () =>
    ({ ok: true, status: 200, json: async () => body }) as unknown as Response;
}

describe("GeoIpProvider coordinates (#133)", () => {
  it("parses ipinfo loc 'lat,lon' and country/city", async () => {
    const p = new GeoIpProvider({ fetchFn: mockFetch({ city: "Mountain View", region: "California", country: "US", loc: "37.3860,-122.0838", org: "AS15169 Google LLC" }) });
    const r = await p.lookup("ip", "8.8.8.8");
    expect(r).not.toBeNull();
    expect(r!.lat).toBeCloseTo(37.386, 2);
    expect(r!.lon).toBeCloseTo(-122.0838, 3);
    expect(r!.city).toBe("Mountain View");
    expect(r!.country).toBe("US");
  });

  it("parses ip-api numeric lat/lon", async () => {
    const p = new GeoIpProvider({ fetchFn: mockFetch({ status: "success", country: "Germany", countryCode: "DE", city: "Berlin", lat: 52.52, lon: 13.405, as: "AS3320 Deutsche Telekom AG" }) });
    const r = await p.lookup("ip", "1.2.3.4");
    expect(r!.lat).toBeCloseTo(52.52, 2);
    expect(r!.lon).toBeCloseTo(13.405, 3);
    expect(r!.country).toBe("Germany");
    expect(r!.city).toBe("Berlin");
  });

  it("parses ipwho.is latitude/longitude", async () => {
    const p = new GeoIpProvider({ fetchFn: mockFetch({ success: true, country: "Japan", country_code: "JP", city: "Tokyo", latitude: 35.6895, longitude: 139.6917, connection: { asn: 2497, org: "IIJ" } }) });
    const r = await p.lookup("ip", "5.6.7.8");
    expect(r!.lat).toBeCloseTo(35.6895, 3);
    expect(r!.lon).toBeCloseTo(139.6917, 3);
  });

  it("rejects out-of-range / null-island coordinates", async () => {
    const p = new GeoIpProvider({ fetchFn: mockFetch({ country: "US", loc: "0,0" }) });
    const r = await p.lookup("ip", "9.9.9.9");
    expect(r!.lat).toBeUndefined();
    expect(r!.lon).toBeUndefined();
  });

  it("rejects out-of-range coordinates", async () => {
    const p = new GeoIpProvider({ fetchFn: mockFetch({ country: "US", loc: "200,1" }) });
    const r = await p.lookup("ip", "9.9.9.9");
    expect(r!.lat).toBeUndefined();
    expect(r!.lon).toBeUndefined();
  });

  it("rejects a partial loc string (no bogus lon=0)", async () => {
    const p = new GeoIpProvider({ fetchFn: mockFetch({ country: "US", loc: "37.4," }) });
    const r = await p.lookup("ip", "9.9.9.9");
    expect(r!.lat).toBeUndefined();
    expect(r!.lon).toBeUndefined();
  });
});
