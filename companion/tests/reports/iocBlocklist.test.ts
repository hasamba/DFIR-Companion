import { describe, it, expect } from "vitest";
import {
  filterBlocklistIocs,
  buildIocBlocklistTxt,
  buildIocBlocklistCsv,
  buildIocBlocklistStix,
} from "../../src/reports/iocBlocklist.js";
import { emptyState, type IOC, type IocEnrichment } from "../../src/analysis/stateTypes.js";

function ioc(overrides: Partial<IOC>): IOC {
  return { id: "i1", type: "ip", value: "1.2.3.4", firstSeen: "2026-06-13T09:00:00Z", ...overrides };
}

function enrich(verdict: IocEnrichment["verdict"], source = "VT", score?: string): IocEnrichment {
  return { source, verdict, ...(score ? { score } : {}), fetchedAt: "2026-06-13T09:00:00Z" };
}

// ── filterBlocklistIocs ───────────────────────────────────────────────────────

describe("filterBlocklistIocs", () => {
  it("includes ip, domain, url, hash by default; excludes file and process", () => {
    const iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "domain", value: "evil.com", enrichments: [enrich("suspicious")] }),
      ioc({ id: "i3", type: "url", value: "http://evil.com/x", enrichments: [enrich("malicious")] }),
      ioc({ id: "i4", type: "hash", value: "a".repeat(64), enrichments: [enrich("malicious")] }),
      ioc({ id: "i5", type: "file", value: "bad.exe", enrichments: [enrich("malicious")] }),
      ioc({ id: "i6", type: "process", value: "cmd.exe", enrichments: [enrich("malicious")] }),
    ];
    const result = filterBlocklistIocs(iocs, {});
    expect(result.map((r) => r.ioc.id).sort()).toEqual(["i1", "i2", "i3", "i4"]);
  });

  it("excludes IOCs below minSeverity (no enrichment → Info)", () => {
    const iocs = [
      ioc({ id: "i1", type: "ip", value: "10.0.0.1", enrichments: [enrich("malicious")] }),  // High
      ioc({ id: "i2", type: "ip", value: "10.0.0.2", enrichments: [enrich("suspicious")] }), // Medium
      ioc({ id: "i3", type: "ip", value: "10.0.0.3" }),                                       // Info (no enrichment)
    ];
    const med = filterBlocklistIocs(iocs, { minSeverity: "Medium" });
    expect(med.map((r) => r.ioc.id).sort()).toEqual(["i1", "i2"]);

    const high = filterBlocklistIocs(iocs, { minSeverity: "High" });
    expect(high.map((r) => r.ioc.id)).toEqual(["i1"]);

    const info = filterBlocklistIocs(iocs, { minSeverity: "Info" });
    expect(info.map((r) => r.ioc.id).sort()).toEqual(["i1", "i2", "i3"]);
  });

  it("harmless verdict maps to Low severity", () => {
    const iocs = [ioc({ id: "i1", type: "domain", value: "cdn.safe.com", enrichments: [enrich("harmless")] })];
    expect(filterBlocklistIocs(iocs, { minSeverity: "Low" })).toHaveLength(1);
    expect(filterBlocklistIocs(iocs, { minSeverity: "Medium" })).toHaveLength(0);
  });

  it("verdictOnly excludes IOCs without malicious/suspicious verdict", () => {
    const iocs = [
      ioc({ id: "i1", type: "domain", value: "evil.com", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "domain", value: "maybe.com", enrichments: [enrich("suspicious")] }),
      ioc({ id: "i3", type: "domain", value: "unknown.com", enrichments: [enrich("unknown")] }),
      ioc({ id: "i4", type: "domain", value: "plain.com" }),
    ];
    const result = filterBlocklistIocs(iocs, { minSeverity: "Info", verdictOnly: true });
    expect(result.map((r) => r.ioc.id).sort()).toEqual(["i1", "i2"]);
  });

  it("respects type selector — only the requested types are included", () => {
    const iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "domain", value: "evil.com", enrichments: [enrich("malicious")] }),
      ioc({ id: "i3", type: "hash", value: "a".repeat(64), enrichments: [enrich("malicious")] }),
    ];
    const result = filterBlocklistIocs(iocs, { types: ["ip", "hash"] });
    expect(result.map((r) => r.ioc.id).sort()).toEqual(["i1", "i3"]);
  });

  it("treats `other` IOC as email when the value matches an email address", () => {
    const iocs = [
      ioc({ id: "i1", type: "other", value: "attacker@evil.com", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "other", value: "not-an-email-thing", enrichments: [enrich("malicious")] }),
    ];
    const result = filterBlocklistIocs(iocs, { minSeverity: "Low", types: ["email"] });
    expect(result).toHaveLength(1);
    expect(result[0].ioc.id).toBe("i1");
    expect(result[0].effectiveType).toBe("email");
  });

  it("worst verdict wins when multiple enrichments exist", () => {
    const iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("harmless"), enrich("malicious", "TF")] }),
    ];
    // harmless alone → Low, but malicious also present → High
    expect(filterBlocklistIocs(iocs, { minSeverity: "High" })).toHaveLength(1);
  });
});

// ── buildIocBlocklistTxt ─────────────────────────────────────────────────────

describe("buildIocBlocklistTxt", () => {
  it("produces the standard header with case name and timestamp", () => {
    const state = emptyState("c1");
    const txt = buildIocBlocklistTxt(state, { caseName: "Ransomware 2026", generatedAt: "2026-06-13T10:00:00Z" });
    expect(txt).toContain("# DFIR Companion — IOC Block List");
    expect(txt).toContain("# Case: Ransomware 2026");
    expect(txt).toContain("# Generated: 2026-06-13T10:00:00Z");
  });

  it("falls back to caseId in the header when caseName is absent", () => {
    const state = emptyState("case-99");
    const txt = buildIocBlocklistTxt(state, { generatedAt: "2026-06-13T10:00:00Z" });
    expect(txt).toContain("# Case: case-99");
  });

  it("groups IOCs by type with section headers and counts", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "ip", value: "185.220.101.5", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "ip", value: "10.0.0.99", enrichments: [enrich("suspicious")] }),
      ioc({ id: "i3", type: "domain", value: "evil.com", enrichments: [enrich("suspicious")] }),
    ];
    const txt = buildIocBlocklistTxt(state, { generatedAt: "t" });
    expect(txt).toContain("# IP Addresses (2)");
    expect(txt).toContain("185.220.101.5");
    expect(txt).toContain("10.0.0.99");
    expect(txt).toContain("# Domains (1)");
    expect(txt).toContain("evil.com");
  });

  it("omits empty type sections", () => {
    const state = emptyState("c1");
    state.iocs = [ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] })];
    const txt = buildIocBlocklistTxt(state, { generatedAt: "t" });
    expect(txt).toContain("# IP Addresses");
    expect(txt).not.toContain("# Domains");
    expect(txt).not.toContain("# Hashes");
  });

  it("shows verdict-confirmed note in header when verdictOnly is set", () => {
    const state = emptyState("c1");
    const txt = buildIocBlocklistTxt(state, { verdictOnly: true, generatedAt: "t" });
    expect(txt).toContain("verdict-confirmed only");
  });

  it("returns only the header block when no IOCs pass the filter", () => {
    const state = emptyState("c1");
    const txt = buildIocBlocklistTxt(state, { generatedAt: "t" });
    expect(txt).toContain("# DFIR Companion — IOC Block List");
    expect(txt).not.toContain("# IP Addresses");
  });
});

// ── buildIocBlocklistCsv ─────────────────────────────────────────────────────

describe("buildIocBlocklistCsv", () => {
  it("outputs a header row followed by one row per matching IOC", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious", "VT", "52/73")] }),
    ];
    const csv = buildIocBlocklistCsv(state, { minSeverity: "Low" });
    const rows = csv.trim().split("\n");
    expect(rows[0]).toBe("type,value,severity,verdict,description");
    expect(rows[1]).toContain("ip");
    expect(rows[1]).toContain("1.2.3.4");
    expect(rows[1]).toContain("High");
    expect(rows[1]).toContain("malicious");
  });

  it("includes the enrichment summary in the description column", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious", "VT", "10/72")] }),
    ];
    const csv = buildIocBlocklistCsv(state, { minSeverity: "Low" });
    expect(csv).toContain("VT (10/72)");
  });

  it("CSV-escapes cells that contain commas", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({
        id: "i1", type: "ip", value: "1.2.3.4",
        enrichments: [enrich("malicious", "VirusTotal"), enrich("malicious", "ThreatFox")],
      }),
    ];
    const csv = buildIocBlocklistCsv(state, { minSeverity: "Low" });
    // Description "malicious — VirusTotal, ThreatFox" contains a comma → must be quoted.
    expect(csv).toContain('"malicious — VirusTotal, ThreatFox"');
  });

  it("CSV-escapes values that contain commas", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "url", value: "http://evil.com/a,b", enrichments: [enrich("suspicious")] }),
    ];
    const csv = buildIocBlocklistCsv(state, { minSeverity: "Low" });
    expect(csv).toContain('"http://evil.com/a,b"');
  });

  it("CSV-escapes double quotes inside cells", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "url", value: 'http://evil.com/"quoted"', enrichments: [enrich("malicious")] }),
    ];
    const csv = buildIocBlocklistCsv(state, { minSeverity: "Low" });
    expect(csv).toContain('"http://evil.com/""quoted"""');
  });

  it("returns only the header row when no IOCs match", () => {
    const state = emptyState("c1");
    const csv = buildIocBlocklistCsv(state);
    expect(csv.trim()).toBe("type,value,severity,verdict,description");
  });
});

// ── buildIocBlocklistStix ────────────────────────────────────────────────────

describe("buildIocBlocklistStix", () => {
  it("produces a bundle with only indicator objects", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "domain", value: "evil.com", enrichments: [enrich("suspicious")] }),
    ];
    const bundle = buildIocBlocklistStix(state, { minSeverity: "Low" });
    expect(bundle.type).toBe("bundle");
    expect(bundle.objects.every((o) => o.type === "indicator")).toBe(true);
    expect(bundle.objects).toHaveLength(2);
  });

  it("excludes IOCs below minSeverity (default Medium)", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "ip", value: "10.0.0.1" }), // no enrichment → Info → excluded
    ];
    const bundle = buildIocBlocklistStix(state);
    expect(bundle.objects).toHaveLength(1);
    expect((bundle.objects[0] as { name: string }).name).toBe("1.2.3.4");
  });

  it("produces a valid STIX 2.1 spec_version on every object", () => {
    const state = emptyState("c1");
    state.iocs = [ioc({ id: "i1", type: "ip", value: "5.5.5.5", enrichments: [enrich("malicious")] })];
    const bundle = buildIocBlocklistStix(state, { minSeverity: "Low" });
    for (const o of bundle.objects) expect(o.spec_version).toBe("2.1");
  });

  it("produces deterministic ids matching the full STIX bundle (same namespace + key)", () => {
    const state = emptyState("c1");
    state.iocs = [ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] })];
    const a = buildIocBlocklistStix(state, { minSeverity: "Low" });
    const b = buildIocBlocklistStix(state, { minSeverity: "Low" });
    expect(a.objects[0].id).toBe(b.objects[0].id);
    // bundle id differs from full-STIX bundle (uses "|ioc-blocklist" key)
    expect(a.id).not.toBe(b.objects[0].id);
    expect(a.id).toBe(b.id);
  });

  it("returns an empty bundle when no IOCs match", () => {
    const bundle = buildIocBlocklistStix(emptyState("c1"));
    expect(bundle.type).toBe("bundle");
    expect(bundle.objects).toHaveLength(0);
  });

  it("sets indicator_types from the worst verdict", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] }),
      ioc({ id: "i2", type: "domain", value: "evil.com", enrichments: [enrich("suspicious")] }),
      ioc({ id: "i3", type: "ip", value: "2.3.4.5" }),
    ];
    const bundle = buildIocBlocklistStix(state, { minSeverity: "Info" });
    const byName = Object.fromEntries(bundle.objects.map((o) => [(o as { name: string }).name, o]));
    expect((byName["1.2.3.4"].indicator_types as string[])).toContain("malicious-activity");
    expect((byName["evil.com"].indicator_types as string[])).toContain("anomalous-activity");
    expect((byName["2.3.4.5"].indicator_types as string[])).toContain("unknown");
  });
});
