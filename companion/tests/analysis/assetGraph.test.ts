import { describe, it, expect } from "vitest";
import { buildAssetGraph } from "../../src/analysis/assetGraph.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

describe("buildAssetGraph", () => {
  it("derives host assets from events and links IoCs by hash field, description, and findings", () => {
    const s = emptyState("c1");
    s.iocs.push(
      { id: "i1", type: "hash", value: HASH, firstSeen: "" },
      { id: "i2", type: "ip", value: "10.0.0.5", firstSeen: "" },
      { id: "i3", type: "domain", value: "evil.example.com", firstSeen: "" }, // never referenced
    );
    s.findings.push({ id: "f1", severity: "Critical", title: "Ransomware", description: "", relatedIocs: ["i1"],
      sourceScreenshots: [], mitreTechniques: [], firstSeen: "", lastUpdated: "", status: "confirmed" });
    s.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "encryptor executed", severity: "Critical",
        mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [], asset: "WIN-01", sha256: HASH },
      { id: "e2", timestamp: "2026-05-20T09:05:00Z", description: "beacon to 10.0.0.5", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WIN-01" },
    );

    const g = buildAssetGraph(s);
    const win = g.assets.find((a) => a.name === "WIN-01")!;
    expect(win.type).toBe("host");
    expect(win.compromised).toBe(true);                       // finding + Critical event
    expect(new Set(win.iocIds)).toEqual(new Set(["i1", "i2"])); // hash (field/finding) + ip (description)
    expect(g.iocs.find((i) => i.id === "i3")).toBeUndefined(); // unconnected IoC excluded
    expect(g.edges).toEqual(expect.arrayContaining([
      { asset: win.id, ioc: "i1" }, { asset: win.id, ioc: "i2" },
    ]));
  });

  it("extracts account assets (DOMAIN\\user, UPN) but not file-path segments", () => {
    const s = emptyState("c1");
    s.iocs.push({ id: "i1", type: "ip", value: "10.0.0.9", firstSeen: "" });
    s.forensicTimeline.push(
      { id: "e1", timestamp: "", description: "logon by ADATUMLAB\\jdoe from 10.0.0.9; file C:\\Users\\srv\\x.exe",
        severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "DC01" },
      { id: "e2", timestamp: "", description: "token for admin@adatumlab.local observed", severity: "Medium",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );

    const g = buildAssetGraph(s);
    const names = g.assets.map((a) => a.name);
    expect(names).toContain("ADATUMLAB\\jdoe");
    expect(names).toContain("admin@adatumlab.local");
    expect(names).toContain("DC01");
    expect(names.some((n) => /users\\srv/i.test(n))).toBe(false); // path segment must not become an account

    // Regression: a relative file path like Zip\7z.exe matches DOMAIN\user but is a FILE, not a user.
    s.forensicTimeline.push({
      id: "e3", description: "process execution from archive Zip\\7z.exe extracted Mimikatz",
      timestamp: "", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    });
    const g2 = buildAssetGraph(s);
    const names2 = g2.assets.map((a) => a.name);
    expect(names2.some((n) => /7z\.exe/i.test(n))).toBe(false);   // file path must not become an account
    // ...but a real username that happens to contain a dot is still extracted.
    s.forensicTimeline.push({
      id: "e4", description: "logon by CORP\\first.last succeeded", timestamp: "", severity: "Low",
      mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    });
    expect(buildAssetGraph(s).assets.map((a) => a.name)).toContain("CORP\\first.last");

    const acct = g.assets.find((a) => a.name === "ADATUMLAB\\jdoe")!;
    expect(acct.type).toBe("account");
    expect(acct.iocIds).toContain("i1");                      // account linked to the IP in its event
  });

  it("links an IP IoC referenced only in the description, with boundary-aware matching", () => {
    const s = emptyState("c1");
    s.iocs.push(
      { id: "i1", type: "ip", value: "192.168.1.1", firstSeen: "" },   // the gateway
      { id: "i2", type: "ip", value: "1.1.1.1", firstSeen: "" },        // shorter prefix of a longer IP
    );
    s.forensicTimeline.push(
      // i1 appears ONLY in free text (no structured field, no finding) → must still link.
      { id: "e1", timestamp: "", description: "outbound beacon to 192.168.1.1 observed",
        severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "HOST-A" },
      // Mentions 192.168.1.10 / 11.1.1.10 only — must NOT link i1 (192.168.1.1) or i2 (1.1.1.1).
      { id: "e2", timestamp: "", description: "scan from 192.168.1.10 and 11.1.1.10",
        severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "HOST-B" },
    );

    const g = buildAssetGraph(s);
    const a = g.assets.find((x) => x.name === "HOST-A")!;
    const b = g.assets.find((x) => x.name === "HOST-B")!;
    expect(a.iocIds).toContain("i1");                                   // (1) IP-only-in-description is linked
    expect(b.iocIds).not.toContain("i1");                              // (2) 192.168.1.1 NOT inside 192.168.1.10
    expect(b.iocIds).not.toContain("i2");                              //     1.1.1.1 NOT inside 11.1.1.10
  });

  it("connects one IoC to multiple assets", () => {
    const s = emptyState("c1");
    s.iocs.push({ id: "i1", type: "ip", value: "8.8.8.8", firstSeen: "" });
    s.forensicTimeline.push(
      { id: "e1", timestamp: "", description: "conn to 8.8.8.8", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "HOST-A" },
      { id: "e2", timestamp: "", description: "conn to 8.8.8.8", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "HOST-B" },
    );
    const g = buildAssetGraph(s);
    expect(g.iocs.find((i) => i.id === "i1")!.assetIds.length).toBe(2);
  });

  it("returns an empty graph for an empty case", () => {
    const g = buildAssetGraph(emptyState("c1"));
    expect(g).toEqual({ assets: [], iocs: [], edges: [] });
  });
});
