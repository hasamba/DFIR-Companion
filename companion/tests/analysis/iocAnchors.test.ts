import { describe, it, expect } from "vitest";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { rankConnectiveIocs, buildConnectiveIocDigest, looksSuspiciousDomain, isKnownHostAsset, shortHost } from "../../src/analysis/iocAnchors.js";

function ev(id: string, asset: string, sources: string[], description: string): any {
  return { id, timestamp: "2024-03-18T15:00:00Z", description, severity: "Medium", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset, sources };
}

function caseState(): ReturnType<typeof emptyState> {
  const s = emptyState("veridia");
  s.iocs.push(
    { id: "i1", type: "domain", value: "northlakeportal.com", firstSeen: "" }, // C2 — touches 2 hosts, 3 tools
    { id: "i2", type: "ip", value: "10.10.20.20", firstSeen: "" },             // internal, 1 host / 1 tool
    { id: "i3", type: "domain", value: "lookup-hopn4hi4.tk", firstSeen: "" },  // 1 host but risky TLD
  );
  s.forensicTimeline.push(
    ev("e1", "WS-DEV-01", ["Zeek", "ECAR"], "C2 tool download from northlakeportal.com (wdi-svc.exe)"),
    ev("e2", "DB-01", ["Snort"], "exfil POST to northlakeportal.com over HTTPS"),
    ev("e3", "WS-DEV-01", ["Sysmon"], "ssh connection to 10.10.20.20:22"),
    ev("e4", "WS-DEV-01", ["Zeek"], "DNS query for lookup-hopn4hi4.tk"),
  );
  return s;
}

describe("looksSuspiciousDomain — offline reputation heuristic (#200)", () => {
  it("flags risky TLDs and DGA-ish labels, not clean domains", () => {
    expect(looksSuspiciousDomain("lookup-hopn4hi4.tk")).toBe(true);  // risky TLD
    expect(looksSuspiciousDomain("kx7zqplmv.example.com")).toBe(true); // DGA-ish subdomain label
    expect(looksSuspiciousDomain("northlakeportal.com")).toBe(false);
    expect(looksSuspiciousDomain("google.com")).toBe(false);
    expect(looksSuspiciousDomain("10.10.20.20")).toBe(false);        // not a domain
  });
});

describe("rankConnectiveIocs (#200)", () => {
  it("ranks the cross-host / multi-tool C2 domain first", () => {
    const anchors = rankConnectiveIocs(caseState());
    expect(anchors[0].value).toBe("northlakeportal.com");
    expect(anchors[0].hosts).toEqual(["DB-01", "WS-DEV-01"]);
    expect(new Set(anchors[0].tools)).toEqual(new Set(["ECAR", "Snort", "Zeek"]));
  });

  it("excludes a single-host single-tool internal IP, but keeps a risky-TLD indicator", () => {
    const anchors = rankConnectiveIocs(caseState());
    const values = anchors.map((a) => a.value);
    expect(values).not.toContain("10.10.20.20");
    const risky = anchors.find((a) => a.value === "lookup-hopn4hi4.tk");
    expect(risky?.suspicious).toBe(true);
  });

  it("builds a digest that leads with the connective indicators", () => {
    const digest = buildConnectiveIocDigest(rankConnectiveIocs(caseState()));
    expect(digest).toContain("CONNECTIVE INDICATORS");
    expect(digest).toContain("northlakeportal.com");
    expect(digest).toMatch(/2 hosts: DB-01, WS-DEV-01/);
  });

  it("returns nothing when no indicator is connective or flagged", () => {
    const s = emptyState("c");
    s.iocs.push({ id: "i1", type: "ip", value: "10.0.0.9", firstSeen: "" });
    s.forensicTimeline.push(ev("e1", "H1", ["Sysmon"], "connection to 10.0.0.9"));
    expect(rankConnectiveIocs(s)).toHaveLength(0);
  });
});

describe("isKnownHostAsset / shortHost — internal-infra conflict detection", () => {
  it("matches on the bare hostname regardless of protocol/path/FQDN qualification", () => {
    const hosts = new Set(["db-01"]);
    expect(isKnownHostAsset("db-01.northpeaklabs.com", hosts)).toBe(true);
    expect(isKnownHostAsset("https://db-01/health", hosts)).toBe(true);
    expect(shortHost("DB-01.northpeaklabs.com")).toBe("db-01");
    expect(isKnownHostAsset("evil-external.tld", hosts)).toBe(false);
  });
});

describe("rankConnectiveIocs — internal-infra conflict dampener", () => {
  function stateWithInternalMaliciousDomain(): ReturnType<typeof emptyState> {
    const s = emptyState("c");
    // db-01 is the case's OWN shared internal server (widely touched — many hosts/accounts), and a
    // (possibly stale) threat-intel provider has marked it malicious.
    s.iocs.push({ id: "i1", type: "domain", value: "db-01.northpeaklabs.com", firstSeen: "",
      enrichments: [{ source: "OpenCTI", verdict: "suspicious", score: "", fetchedAt: "" }] });
    s.forensicTimeline.push(
      ev("e1", "db-01.northpeaklabs.com", ["SIEM"], "connection from grace.kim to db-01.northpeaklabs.com"),
      ev("e2", "db-01.northpeaklabs.com", ["SIEM"], "connection from priya.raman to db-01.northpeaklabs.com"),
      ev("e3", "WS-ENG-04", ["Zeek"], "connection to db-01.northpeaklabs.com"),
    );
    return s;
  }

  it("flags internalConflict and caps the malicious bump instead of anchoring it as a C2 backbone", () => {
    const anchors = rankConnectiveIocs(stateWithInternalMaliciousDomain());
    const db01 = anchors.find((a) => a.value === "db-01.northpeaklabs.com");
    expect(db01?.malicious).toBe(true);
    expect(db01?.internalConflict).toBe(true);
  });

  it("renders an explicit CONFLICT warning in the digest instead of a bare malicious flag", () => {
    const digest = buildConnectiveIocDigest(rankConnectiveIocs(stateWithInternalMaliciousDomain()));
    expect(digest).toContain("CONFLICT");
    expect(digest).toContain("ALSO one of the case's OWN host assets");
  });

  it("does NOT flag a genuine external indicator that happens to be malicious", () => {
    const s = emptyState("c");
    s.iocs.push({ id: "i1", type: "domain", value: "evil-c2.tld", firstSeen: "",
      enrichments: [{ source: "VirusTotal", verdict: "malicious", score: "60/73", fetchedAt: "" }] });
    s.forensicTimeline.push(
      ev("e1", "WS-01", ["Zeek"], "beacon to evil-c2.tld"),
      ev("e2", "WS-02", ["ECAR"], "beacon to evil-c2.tld"),
    );
    const anchors = rankConnectiveIocs(s);
    const c2 = anchors.find((a) => a.value === "evil-c2.tld");
    expect(c2?.internalConflict).toBe(false);
    expect(buildConnectiveIocDigest(anchors)).not.toContain("CONFLICT");
  });
});
