import { describe, expect, it } from "vitest";
import {
  isPlausibleHuntQuery,
  languageHuntResponseSchema,
  sanitizeLanguageHunts,
  sanitizePlaybookLanguageHunts,
} from "../../src/analysis/languageHuntSuggest.js";

const raw = (over: Record<string, unknown>) =>
  languageHuntResponseSchema.parse({ suggestions: [{ title: "t", rationale: "r", ...over }] }).suggestions;

describe("isPlausibleHuntQuery (#2559)", () => {
  it("accepts each language's own shape", () => {
    expect(isPlausibleHuntQuery("cql", "#event_simpleName=ProcessRollup2 | ImageFileName=/rundll32/i")).toBe(
      true,
    );
    expect(isPlausibleHuntQuery("kql-device", 'DeviceProcessEvents\n| where FileName =~ "x.exe"')).toBe(true);
    expect(
      isPlausibleHuntQuery("kql-device", 'let h = dynamic(["a"]);\nDeviceFileEvents | where SHA256 in (h)'),
    ).toBe(true);
    expect(isPlausibleHuntQuery("kql-cloud", 'SigninLogs | where IPAddress == "1.2.3.4"')).toBe(true);
    expect(isPlausibleHuntQuery("esql", 'FROM logs-* | WHERE process.name == "x.exe"')).toBe(true);
    expect(isPlausibleHuntQuery("spl", 'index=* process_name="x.exe" | table _time host')).toBe(true);
  });

  it("reads the shape after leading comment lines, and lets SPL start with any search term", () => {
    expect(isPlausibleHuntQuery("kql-device", "// sweep\nDeviceProcessEvents | take 5")).toBe(true);
    expect(isPlausibleHuntQuery("esql", "// recent\nFROM logs-* | LIMIT 5")).toBe(true);
    expect(isPlausibleHuntQuery("spl", "(index=wineventlog OR index=sysmon) process_name=x.exe")).toBe(true);
    expect(isPlausibleHuntQuery("spl", "earliest=-7d index=* x")).toBe(true);
    expect(isPlausibleHuntQuery("spl", "DeviceProcessEvents | where FileName == 'x'")).toBe(false);
  });

  it("rejects a query written in the wrong language", () => {
    expect(isPlausibleHuntQuery("cql", "SELECT * FROM pslist()")).toBe(false);
    expect(isPlausibleHuntQuery("cql", 'index=* process_name="x"')).toBe(false);
    expect(isPlausibleHuntQuery("kql-device", "SELECT Name FROM pslist()")).toBe(false);
    expect(isPlausibleHuntQuery("kql-device", 'SigninLogs | where IPAddress == "1.2.3.4"')).toBe(false);
    expect(isPlausibleHuntQuery("kql-cloud", "DeviceProcessEvents | take 10")).toBe(false);
    expect(isPlausibleHuntQuery("esql", "index=* | table host")).toBe(false);
    expect(isPlausibleHuntQuery("spl", "FROM logs-* | LIMIT 10")).toBe(false);
    expect(isPlausibleHuntQuery("spl", "SELECT * FROM glob(globs='C:/x')")).toBe(false);
  });
});

describe("sanitizeLanguageHunts (#2559)", () => {
  it("keeps a valid hunt, stamps the assigned language and clamps fields", () => {
    const out = sanitizeLanguageHunts(
      raw({ query: 'DeviceProcessEvents | where FileName =~ "a.exe"', relatedFindingIds: ["f1", "f9"] }),
      "kql-device",
      { allowedFindingIds: new Set(["f1"]) },
    );
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ language: "kql-device", platform: "defender", relatedFindingIds: ["f1"] });
    expect(out[0]).not.toHaveProperty("vql");
  });

  it("drops empty, wrong-language and wrong-platform answers", () => {
    expect(sanitizeLanguageHunts(raw({ query: "" }), "spl", {})).toEqual([]);
    expect(sanitizeLanguageHunts(raw({ query: "SELECT * FROM pslist()" }), "spl", {})).toEqual([]);
    expect(sanitizeLanguageHunts(raw({ query: "index=* x", platform: "elastic" }), "spl", {})).toEqual([]);
    expect(sanitizeLanguageHunts(raw({ query: "index=* x", platform: "spl" }), "spl", {})).toHaveLength(1);
  });

  it("strips one surrounding markdown fence the model wrapped the query in", () => {
    const out = sanitizeLanguageHunts(raw({ query: "```esql\nFROM logs-* | LIMIT 5\n```" }), "esql", {});
    expect(out[0].query).toBe("FROM logs-* | LIMIT 5");
  });

  it("drops a re-suggested query when regenerating", () => {
    const q = "FROM logs-* | LIMIT 5";
    expect(sanitizeLanguageHunts(raw({ query: q }), "esql", { exclude: q })).toEqual([]);
  });

  it("caps the number of hunts", () => {
    const many = languageHuntResponseSchema.parse({
      suggestions: Array.from({ length: 20 }, (_, i) => ({ title: `t${i}`, query: `index=* n=${i}` })),
    }).suggestions;
    expect(sanitizeLanguageHunts(many, "spl", { max: 3 })).toHaveLength(3);
  });
});

describe("sanitizePlaybookLanguageHunts (#2559)", () => {
  it("keeps only answers for the tasks sent, marked relevant", () => {
    const sugs = languageHuntResponseSchema.parse({
      suggestions: [
        { taskId: "t1", relevant: true, title: "a", query: "#event_simpleName=DnsRequest | DomainName=x" },
        { taskId: "t2", relevant: true, title: "b", query: "#event_simpleName=DnsRequest" },
        { taskId: "t1", relevant: false, title: "c", query: "#event_simpleName=DnsRequest" },
      ],
    }).suggestions;
    const out = sanitizePlaybookLanguageHunts(sugs, "cql", new Set(["t1"]));
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ taskId: "t1", language: "cql", platform: "crowdstrike" });
  });
});
