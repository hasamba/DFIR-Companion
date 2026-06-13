import { describe, it, expect } from "vitest";
import {
  parseIrisCase, mapIrisEvent, mapIrisIoc, mapIrisAsset, type IrisCaseData,
} from "../../src/analysis/irisImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

// ── fixtures (rows as the IRIS REST list endpoints return them) ──

function timelineRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    event_id: 1,
    event_title: "C2 beacon to 185.220.101.5",
    event_content: "C2 beacon to 185.220.101.5\nAsset: DC01\nSHA256: " + "a".repeat(64) + "\nPath: C:\\Windows\\Temp\\evil.exe\nMITRE: T1071",
    event_date: "2026-06-04T13:00:00.123456",
    event_tz: "+00:00",
    event_color: "#f97316",   // High
    event_tags: "dfir-companion,high,T1071",
    ...over,
  };
}

function iocRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { ioc_id: 1, ioc_value: "185.220.101.5", ioc_type: { type_name: "ip-dst" }, ...over };
}

function assetRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { asset_id: 1, asset_name: "DC01", asset_compromise_status_id: 1, asset_ip: "10.0.0.5", ...over };
}

function data(over: Partial<IrisCaseData> = {}): IrisCaseData {
  return { assets: [], iocs: [], timeline: [], ...over };
}

// ── timeline event mapping ──

describe("mapIrisEvent", () => {
  it("reads severity from the event colour, MITRE from tags, and asset/hash/path from the content", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapIrisEvent(timelineRow(), sink);
    expect(e.severity).toBe("High");                 // from #f97316
    expect(e.mitre).toContain("T1071");
    expect(e.asset).toBe("DC01");
    expect(e.sha256).toBe("a".repeat(64));
    expect(e.path).toBe("C:\\Windows\\Temp\\evil.exe");
    expect(e.sources).toEqual(["DFIR-IRIS"]);
    // timestamp combined from event_date + event_tz, microseconds → milliseconds, UTC.
    expect(e.timestamp).toBe("2026-06-04T13:00:00.123Z");
    // the content hash + path are also harvested as IOCs.
    const vals = [...sink.values()].map((i) => i.value);
    expect(vals).toContain("a".repeat(64));
    expect(vals).toContain("C:\\Windows\\Temp\\evil.exe");
  });

  it("falls back to a severity word in the tags when no colour is present", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapIrisEvent(timelineRow({ event_color: "", event_tags: "Critical,native" }), sink);
    expect(e.severity).toBe("Critical");
  });

  it("defaults to Info when neither colour nor tag severity is present", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapIrisEvent(timelineRow({ event_color: "", event_tags: "native-iris" }), sink);
    expect(e.severity).toBe("Info");
  });

  it("converts a non-UTC event_tz to UTC", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapIrisEvent(timelineRow({ event_date: "2026-06-04T13:00:00", event_tz: "+02:00" }), sink);
    expect(e.timestamp).toBe("2026-06-04T11:00:00.000Z");
  });
});

// ── IOC mapping ──

describe("mapIrisIoc", () => {
  it("maps the IRIS ioc-type name to a coarse type", () => {
    const sink = new Map<string, SiemIoc>();
    mapIrisIoc(iocRow({ ioc_value: "8.8.8.8", ioc_type: { type_name: "ip-dst" } }), sink);
    mapIrisIoc(iocRow({ ioc_value: "evil.com", ioc_type: "domain" }), sink);
    mapIrisIoc(iocRow({ ioc_value: "http://evil.com/x", ioc_type: "url" }), sink);
    mapIrisIoc(iocRow({ ioc_value: "d41d8cd98f00b204e9800998ecf8427e", ioc_type: "md5" }), sink);
    const byVal = new Map([...sink.values()].map((i) => [i.value, i.type]));
    expect(byVal.get("8.8.8.8")).toBe("ip");
    expect(byVal.get("evil.com")).toBe("domain");
    expect(byVal.get("http://evil.com/x")).toBe("url");
    expect(byVal.get("d41d8cd98f00b204e9800998ecf8427e")).toBe("hash");
  });

  it("infers the type from the value shape when IRIS gives no usable type name", () => {
    const sink = new Map<string, SiemIoc>();
    mapIrisIoc({ ioc_value: "1.2.3.4" }, sink);
    mapIrisIoc({ ioc_value: "a".repeat(64) }, sink);
    mapIrisIoc({ ioc_value: "https://bad.example/p" }, sink);
    mapIrisIoc({ ioc_value: "bad.example.com" }, sink);
    mapIrisIoc({ ioc_value: "C:\\Users\\x\\evil.dll" }, sink);
    const byVal = new Map([...sink.values()].map((i) => [i.value, i.type]));
    expect(byVal.get("1.2.3.4")).toBe("ip");
    expect(byVal.get("a".repeat(64))).toBe("hash");
    expect(byVal.get("https://bad.example/p")).toBe("url");
    expect(byVal.get("bad.example.com")).toBe("domain");
    expect(byVal.get("C:\\Users\\x\\evil.dll")).toBe("file");
  });

  it("ignores a row with no ioc_value", () => {
    const sink = new Map<string, SiemIoc>();
    expect(mapIrisIoc({ ioc_id: 5 }, sink)).toBe(false);
    expect(sink.size).toBe(0);
  });
});

// ── asset mapping ──

describe("mapIrisAsset", () => {
  it("maps a compromised asset to a High evidence event carrying the asset name", () => {
    const e = mapIrisAsset(assetRow())!;
    expect(e.severity).toBe("High");                  // compromise status 1
    expect(e.asset).toBe("DC01");
    expect(e.description).toContain("COMPROMISED");
    expect(e.timestamp).toBe("");                     // assets are undated
  });

  it("maps an uncompromised asset to an Info event", () => {
    const e = mapIrisAsset(assetRow({ asset_compromise_status_id: 3 }))!;
    expect(e.severity).toBe("Info");
  });

  it("returns null for an asset with no name", () => {
    expect(mapIrisAsset({ asset_id: 1 })).toBeNull();
  });
});

// ── top-level parse ──

describe("parseIrisCase", () => {
  it("aggregates timeline + assets into events, dedupes IOCs, and reports counts", () => {
    const res = parseIrisCase(data({
      timeline: [timelineRow()],
      assets: [assetRow()],
      iocs: [iocRow(), iocRow({ ioc_id: 2, ioc_value: "evil.com", ioc_type: "domain" })],
      caseName: "Ransomware FS01",
      irisCaseId: 7,
    }));
    expect(res.timelineCount).toBe(1);
    expect(res.assetCount).toBe(1);
    expect(res.iocRecords).toBe(2);
    expect(res.kept).toBe(2);                          // one timeline event + one asset event
    expect(res.caseName).toBe("Ransomware FS01");
    expect(res.irisCaseId).toBe(7);
    // IOCs from the ioc list plus the hash/path harvested from the timeline content.
    const vals = res.iocs.map((i) => i.value);
    expect(vals).toContain("185.220.101.5");
    expect(vals).toContain("evil.com");
    expect(vals).toContain("a".repeat(64));
  });

  it("honors includeAssets:false (assets are not turned into events)", () => {
    const res = parseIrisCase(data({ timeline: [timelineRow()], assets: [assetRow()] }), { includeAssets: false });
    expect(res.kept).toBe(1);                          // only the timeline event
  });

  it("applies the minSeverity floor (drops Info asset events)", () => {
    const res = parseIrisCase(data({
      timeline: [timelineRow()],
      assets: [assetRow({ asset_compromise_status_id: 3 })],   // Info
    }), { minSeverity: "Medium" });
    expect(res.kept).toBe(1);                          // High timeline event kept, Info asset dropped
    expect(res.dropped).toBeGreaterThanOrEqual(1);
  });

  it("returns an empty result for an empty case", () => {
    const res = parseIrisCase(data());
    expect(res.kept).toBe(0);
    expect(res.events).toEqual([]);
    expect(res.iocs).toEqual([]);
  });
});
