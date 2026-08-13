import { describe, it, expect } from "vitest";
import { parseHindsight } from "../../src/analysis/hindsightImport.js";

function rec(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "url",
    timestamp: "2026-05-02T10:00:00Z",
    url: "https://intranet.example.invalid/reports",
    title: "Quarterly reports",
    interpretation: "",
    profile: "Default",
    source: "Chrome",
    ...over,
  };
}

describe("parseHindsight", () => {
  it("reports an empty result for empty input", () => {
    const r = parseHindsight("");
    expect(r.total).toBe(0);
    expect(r.format).toBe("empty");
  });

  it("maps a visited URL to an Info evidence row", () => {
    const r = parseHindsight(JSON.stringify([rec()]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("intranet.example.invalid");
    expect(r.events[0].sources).toContain("Hindsight");
  });

  it("records the visited domain as an IOC", () => {
    const r = parseHindsight(JSON.stringify([rec()]));
    expect(r.iocs.map((i) => i.value)).toContain("intranet.example.invalid");
  });

  it("keeps a download distinguishable from a plain visit", () => {
    const r = parseHindsight(
      JSON.stringify([
        rec({
          type: "download",
          url: "https://cdn.example.invalid/setup.exe",
          value: "C:\\Users\\jdoe\\Downloads\\setup.exe",
        }),
      ]),
    );
    expect(r.events[0].description.toLowerCase()).toContain("download");
    expect(r.events[0].description).toContain("setup.exe");
  });

  it("does not invent a verdict — a download is still Info evidence", () => {
    const r = parseHindsight(
      JSON.stringify([rec({ type: "download", url: "https://bad.example.invalid/x.exe" })]),
    );
    expect(r.events[0].severity).toBe("Info");
  });

  it("carries Hindsight's own interpretation when it has one", () => {
    const r = parseHindsight(
      JSON.stringify([rec({ interpretation: "Searched for 'how to disable defender'" })]),
    );
    expect(r.events[0].description).toContain("how to disable defender");
  });

  it("names the browser profile so multi-user hosts stay separable", () => {
    const r = parseHindsight(JSON.stringify([rec({ profile: "Profile 2" })]));
    expect(r.events[0].description).toContain("Profile 2");
  });

  it("reads Hindsight CSV export as well as JSON", () => {
    const csv = [
      "type,timestamp,url,title,interpretation,profile,source",
      "url,2026-05-02T10:00:00Z,https://intranet.example.invalid/reports,Quarterly reports,,Default,Chrome",
    ].join("\n");
    const r = parseHindsight(csv);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("intranet.example.invalid");
  });

  it("skips a row with no usable timestamp or url", () => {
    const r = parseHindsight(JSON.stringify([{ type: "cookie", name: "x" }]));
    expect(r.events).toHaveLength(0);
  });

  it("caps the IOC list", () => {
    const many = Array.from({ length: 40 }, (_, i) =>
      rec({ url: `https://host${i}.example.invalid/a`, timestamp: "2026-05-02T10:00:00Z" }),
    );
    const r = parseHindsight(JSON.stringify(many), { maxIocs: 5 });
    expect(r.iocs.length).toBeLessThanOrEqual(5);
  });
});
