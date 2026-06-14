import { describe, it, expect } from "vitest";
import {
  extractCveIds,
  parseKevJson,
  buildKevCatalog,
  matchKevEntries,
  buildKevDigest,
  type KevEntry,
} from "../../src/analysis/kev.js";

const ENTRY_A: KevEntry = {
  cveID: "CVE-2021-44228",
  vendorProject: "Apache",
  product: "Log4j2",
  vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
  dateAdded: "2021-12-10",
  shortDescription: "Apache Log4j2 contains a remote code execution vulnerability.",
  requiredAction: "Apply updates per vendor instructions.",
  dueDate: "2021-12-24",
  knownRansomwareCampaignUse: "Known",
};

const ENTRY_B: KevEntry = {
  cveID: "CVE-2024-38094",
  vendorProject: "Microsoft",
  product: "SharePoint Server",
  vulnerabilityName: "Microsoft SharePoint Server Deserialization Vulnerability",
  dateAdded: "2024-10-22",
  shortDescription: "SharePoint contains a deserialization vulnerability allowing RCE.",
  requiredAction: "Apply mitigations per vendor instructions.",
  dueDate: "2024-11-12",
  knownRansomwareCampaignUse: "Unknown",
};

describe("extractCveIds", () => {
  it("extracts a single CVE id", () => {
    expect(extractCveIds("Exploited CVE-2021-44228 via JNDI")).toEqual(["CVE-2021-44228"]);
  });

  it("extracts multiple CVE ids, deduplicating", () => {
    const ids = extractCveIds("CVE-2021-44228 and CVE-2024-38094 and CVE-2021-44228 again");
    expect(ids).toHaveLength(2);
    expect(ids).toContain("CVE-2021-44228");
    expect(ids).toContain("CVE-2024-38094");
  });

  it("normalises to upper-case", () => {
    expect(extractCveIds("cve-2021-44228")).toEqual(["CVE-2021-44228"]);
  });

  it("handles Shodan vuln: prefix", () => {
    expect(extractCveIds("vuln:CVE-2021-44228")).toEqual(["CVE-2021-44228"]);
  });

  it("returns [] for empty/CVE-free input", () => {
    expect(extractCveIds("")).toEqual([]);
    expect(extractCveIds("no vulnerabilities here")).toEqual([]);
  });

  it("rejects year < 1999 or > 2099", () => {
    expect(extractCveIds("CVE-1998-1234")).toEqual([]);
    expect(extractCveIds("CVE-2100-1234")).toEqual([]);
  });

  it("rejects sequences with fewer than 4 digits", () => {
    expect(extractCveIds("CVE-2021-123")).toEqual([]);
  });

  it("accepts 5-digit sequences", () => {
    expect(extractCveIds("CVE-2023-12345")).toEqual(["CVE-2023-12345"]);
  });
});

describe("parseKevJson", () => {
  const FEED = {
    title: "CISA Known Exploited Vulnerabilities Catalog",
    catalogVersion: "2024.11.01",
    dateReleased: "2024-11-01T00:00:00Z",
    count: 2,
    vulnerabilities: [ENTRY_A, ENTRY_B],
  };

  it("parses the full CISA feed object", () => {
    const entries = parseKevJson(FEED);
    expect(entries).toHaveLength(2);
    expect(entries[0].cveID).toBe("CVE-2021-44228");
    expect(entries[1].cveID).toBe("CVE-2024-38094");
  });

  it("parses a bare array of vulnerability objects", () => {
    const entries = parseKevJson([ENTRY_A]);
    expect(entries).toHaveLength(1);
    expect(entries[0].vendorProject).toBe("Apache");
  });

  it("normalises cveID to upper-case", () => {
    const entries = parseKevJson([{ ...ENTRY_A, cveID: "cve-2021-44228" }]);
    expect(entries[0].cveID).toBe("CVE-2021-44228");
  });

  it("skips entries without a valid CVE id", () => {
    const entries = parseKevJson([{ cveID: "NOT-A-CVE", product: "foo" }, ENTRY_B]);
    expect(entries).toHaveLength(1);
    expect(entries[0].cveID).toBe("CVE-2024-38094");
  });

  it("handles missing optional notes field", () => {
    const { notes: _, ...noNotes } = ENTRY_A;
    const entries = parseKevJson([noNotes]);
    expect(entries[0].notes).toBeUndefined();
  });

  it("returns [] for null / non-object input", () => {
    expect(parseKevJson(null)).toEqual([]);
    expect(parseKevJson("string")).toEqual([]);
    expect(parseKevJson(42)).toEqual([]);
  });
});

describe("buildKevCatalog + matchKevEntries", () => {
  const catalog = buildKevCatalog([ENTRY_A, ENTRY_B]);

  it("builds a Map keyed by upper-cased CVE id", () => {
    expect(catalog.size).toBe(2);
    expect(catalog.get("CVE-2021-44228")).toBe(ENTRY_A);
  });

  it("matches CVE ids against the catalog", () => {
    const matches = matchKevEntries(["CVE-2021-44228", "CVE-9999-0000"], catalog);
    expect(matches).toHaveLength(1);
    expect(matches[0].cveID).toBe("CVE-2021-44228");
  });

  it("is case-insensitive on input ids", () => {
    const matches = matchKevEntries(["cve-2021-44228"], catalog);
    expect(matches).toHaveLength(1);
  });

  it("deduplicates repeated ids in input", () => {
    const matches = matchKevEntries(["CVE-2021-44228", "CVE-2021-44228"], catalog);
    expect(matches).toHaveLength(1);
  });

  it("returns [] when catalog is empty", () => {
    const empty = buildKevCatalog([]);
    expect(matchKevEntries(["CVE-2021-44228"], empty)).toEqual([]);
  });
});

describe("buildKevDigest", () => {
  it("returns empty string for no matches", () => {
    expect(buildKevDigest([])).toBe("");
  });

  it("includes CVE id, vendor/product, and required action", () => {
    const digest = buildKevDigest([ENTRY_A]);
    expect(digest).toContain("CVE-2021-44228");
    expect(digest).toContain("Apache Log4j2");
    expect(digest).toContain("Apply updates per vendor instructions.");
  });

  it("flags ransomware-associated CVEs", () => {
    const digest = buildKevDigest([ENTRY_A]);
    expect(digest).toContain("[RANSOMWARE CAMPAIGN]");
  });

  it("does not flag Unknown ransomware use", () => {
    const digest = buildKevDigest([ENTRY_B]);
    expect(digest).not.toContain("[RANSOMWARE CAMPAIGN]");
  });

  it("lists multiple matches", () => {
    const digest = buildKevDigest([ENTRY_A, ENTRY_B]);
    expect(digest).toContain("CVE-2021-44228");
    expect(digest).toContain("CVE-2024-38094");
  });
});
