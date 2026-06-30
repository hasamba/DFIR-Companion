import { describe, it, expect } from "vitest";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { rankConnectiveIocs, buildConnectiveIocDigest, looksSuspiciousDomain } from "../../src/analysis/iocAnchors.js";

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
