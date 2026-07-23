import { describe, it, expect } from "vitest";
import {
  groundAndScoreFindings,
  corroborationLabel,
  UNGROUNDED_CONFIDENCE_CAP,
  SINGLE_SOURCE_CONFIDENCE_CAP,
  HUNT_ARTIFACT_CONFIDENCE_CAP,
  CONTENT_MISMATCH_CONFIDENCE_CAP,
  CONTENT_MISMATCH_SEVERITY_FLOOR,
  LATERAL_UNCONFIRMED_CONFIDENCE_CAP,
  LATERAL_UNCONFIRMED_SEVERITY_FLOOR,
} from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent, IOC, Severity } from "../../src/analysis/stateTypes.js";

function f(p: Partial<Finding>): Finding {
  return {
    id: p.id ?? "f1", severity: p.severity ?? "High", title: p.title ?? "A finding", description: "",
    relatedIocs: p.relatedIocs ?? [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "", lastUpdated: "",
    status: "open", ...p,
  };
}
function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1", timestamp: "2026-01-01T00:00:00Z", description: "x", severity: p.severity ?? "High" as Severity,
    mitreTechniques: [], relatedFindingIds: p.relatedFindingIds ?? [], sourceScreenshots: [], ...p,
  };
}
function ioc(p: Partial<IOC>): IOC {
  return { id: p.id ?? "i1", type: p.type ?? "ip", value: p.value ?? "1.2.3.4", firstSeen: "", ...p };
}

describe("groundAndScoreFindings", () => {
  it("flags a finding with no cited in-scope evidence as ungrounded and caps confidence", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 95, relatedEventIds: ["missing"] })],
      scopedEvents: [ev({ id: "e1" })],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].ungrounded).toBe(true);
    expect(out[0].confidence).toBe(UNGROUNDED_CONFIDENCE_CAP);
    expect(out[0].confidenceReason).toMatch(/no cited evidence/i);
    expect(out[0].relatedEventIds).toEqual([]);
  });

  it("grounds a deterministic backfill finding via the REVERSE link (event.relatedFindingIds)", () => {
    // backfillHighSeverityFindings sets no forward relatedEventIds — only the event points back.
    const out = groundAndScoreFindings({
      findings: [f({ id: "f-auto-e1", confidence: 100, relatedEventIds: [] })],
      scopedEvents: [ev({ id: "e1", relatedFindingIds: ["f-auto-e1"], sources: ["Velociraptor", "THOR"], asset: "H1" })],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].ungrounded).toBeUndefined();
    expect(out[0].relatedEventIds).toEqual(["e1"]);
    expect(out[0].corroboration).toEqual({ distinctTools: 2, distinctHosts: 1, intelSources: 0, graphLinked: false, verdictFirst: true, huntArtifactOnly: false, kevLinked: false });
    expect(out[0].confidence).toBe(100); // corroborated by 2 tools → not capped
  });

  it("caps a grounded but single-tool/single-host/uncorroborated finding at 65", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].confidence).toBe(SINGLE_SOURCE_CONFIDENCE_CAP);
    expect(out[0].confidenceReason).toMatch(/single-source/i);
  });

  it("does not cap a single-tool finding that IS graph-linked", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [],
      graphLinkedEventIds: new Set(["e1"]),
    });
    expect(out[0].confidence).toBe(90);
    expect(out[0].corroboration?.graphLinked).toBe(true);
  });

  it("counts intel-flagged related IOCs and does not cap when intel backs a single-tool finding", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 88, relatedEventIds: ["e1"], relatedIocs: ["i1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [ioc({ id: "i1", enrichments: [{ source: "VT", verdict: "malicious", fetchedAt: "" }] })],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].corroboration?.intelSources).toBe(1);
    expect(out[0].confidence).toBe(88); // intel corroboration → not capped
  });

  it("never RAISES confidence and is idempotent", () => {
    const once = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 30, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(once[0].confidence).toBe(30); // already below the cap — unchanged
    const twice = groundAndScoreFindings({ findings: once, scopedEvents: [ev({ id: "e1", sources: ["OneTool"], asset: "H1" })], iocs: [], graphLinkedEventIds: new Set() });
    expect(twice[0].confidence).toBe(30);
    expect(twice[0].corroboration).toEqual(once[0].corroboration);
  });
});

describe("groundAndScoreFindings — content-mismatch (veridia-deep-pass false positive, 2026-07-22)", () => {
  it("floors severity and caps confidence when a High finding claims an IP absent from its cited events", () => {
    // Reproduces f13: claims RDP from 45.33.32.156 but cites three internal-IP logons that never mention it.
    const out = groundAndScoreFindings({
      findings: [f({
        id: "f13", severity: "High", confidence: 90,
        title: "External RDP logon from public IP address 45.33.32.156",
        description: "A logon consistent with RDP was observed against ws-dev-01 originating from 45.33.32.156.",
        relatedEventIds: ["40e39", "40e34", "40e2"],
      })],
      scopedEvents: [
        ev({ id: "40e39", asset: "WS-FIN-01", sources: ["Windows Event Log"], description: "Successful logon LogonType=3 IpAddress=10.10.10.51" }),
        ev({ id: "40e34", asset: "WS-FIN-01", sources: ["Windows Event Log"], description: "Successful logon LogonType=3 IpAddress=10.10.10.50" }),
        ev({ id: "40e2", asset: "WS-FIN-01", sources: ["Windows Event Log"], description: "Failed logon LogonType=2" }),
      ],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].contentMismatch).toBe(true);
    expect(out[0].severity).toBe(CONTENT_MISMATCH_SEVERITY_FLOOR);
    expect(out[0].confidence).toBe(CONTENT_MISMATCH_CONFIDENCE_CAP);
    expect(out[0].confidenceReason).toMatch(/45\.33\.32\.156/);
  });

  it("does not flag a High finding whose claimed IP DOES appear in its cited events", () => {
    const out = groundAndScoreFindings({
      findings: [f({
        id: "f1", severity: "High", confidence: 90,
        title: "External RDP logon from public IP address 45.33.32.156",
        description: "RDP from 45.33.32.156.", relatedEventIds: ["e1"],
      })],
      scopedEvents: [ev({ id: "e1", asset: "WS-FIN-01", sources: ["Windows Event Log"], description: "LogonType=10 IpAddress=45.33.32.156" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].contentMismatch).toBeUndefined();
    expect(out[0].severity).toBe("High");
  });

  it("does not apply the content-mismatch check to Medium/Low findings", () => {
    const out = groundAndScoreFindings({
      findings: [f({
        id: "f1", severity: "Medium", confidence: 90,
        title: "Possible external logon from 45.33.32.156", description: "",
        relatedEventIds: ["e1"],
      })],
      scopedEvents: [ev({ id: "e1", asset: "WS-FIN-01", sources: ["Windows Event Log"], description: "no IP here" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].contentMismatch).toBeUndefined();
    expect(out[0].severity).toBe("Medium");
  });
});

describe("groundAndScoreFindings — actor-provenance (lateral movement) gate", () => {
  // The meridian benchmark class: a lateral-movement claim to a host that has NO High/Critical event of
  // its own, resting only on a benign LogonType=3 by a reused account, must be floored — not left at the
  // deep pass's confidence 82.
  it("floors a High RDP-pivot finding whose destination host has no confirmed malicious activity", () => {
    const out = groundAndScoreFindings({
      findings: [f({
        id: "f5", severity: "High", confidence: 82,
        title: "Lateral movement via RDP from RDGW-01 to WS-17",
        description: "The attacker pivoted via RDP to WS-17, reusing the harvested credential to authenticate.",
        relatedEventIds: ["e-ws17-logon"],
      })],
      scopedEvents: [
        // WS-17 carries only a benign Low logon — no High/Critical event pins it to the attack.
        ev({ id: "e-ws17-logon", asset: "WS-17.meridiancpa.com", severity: "Low", sources: ["Windows Event Log"], description: "Successful logon (EID 4624) MERIDIANCPA\\kevin.obrien LogonType=3" }),
        // The real attack High events live on OTHER hosts.
        ev({ id: "e-rdgw", asset: "RDGW-01.meridiancpa.com", severity: "High", sources: ["Sysmon"], description: "comsvcs MiniDump LSASS" }),
      ],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].lateralUnconfirmed).toBe(true);
    expect(out[0].severity).toBe(LATERAL_UNCONFIRMED_SEVERITY_FLOOR);
    expect(out[0].confidence).toBe(LATERAL_UNCONFIRMED_CONFIDENCE_CAP);
    expect(out[0].confidenceReason).toMatch(/ws-17/i);
  });

  it("does NOT floor a pivot to a host that HAS its own confirmed High/Critical activity (real WS-12 spread)", () => {
    const out = groundAndScoreFindings({
      findings: [f({
        id: "f12", severity: "Critical", confidence: 90,
        title: "Ransomware spread laterally to WS-12",
        description: "The attacker pivoted to WS-12 and detonated the identical binary.",
        relatedEventIds: ["e-ws12-enc"],
      })],
      scopedEvents: [
        ev({ id: "e-ws12-enc", asset: "WS-12.meridiancpa.com", severity: "High", sources: ["Sysmon"], description: "msidxsvc.exe --enc" }),
      ],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].lateralUnconfirmed).toBeUndefined();
    expect(out[0].severity).toBe("Critical");
  });

  it("does NOT floor when the lateral finding's OWN cited evidence includes a High/Critical event", () => {
    const out = groundAndScoreFindings({
      findings: [f({
        id: "f1", severity: "High", confidence: 88,
        title: "Lateral movement via RDP to WS-33",
        description: "Pivot to WS-33 followed immediately by credential dumping.",
        relatedEventIds: ["e-high"],
      })],
      // WS-33 has no High event of its own in scope, BUT the finding cites a High event → defer to normal caps.
      scopedEvents: [ev({ id: "e-high", asset: "WS-33", severity: "High", sources: ["Sysmon"], description: "comsvcs MiniDump on WS-33" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].lateralUnconfirmed).toBeUndefined();
    expect(out[0].severity).toBe("High");
  });

  it("does NOT touch a non-lateral finding that merely names an uncompromised host", () => {
    const out = groundAndScoreFindings({
      findings: [f({
        id: "f1", severity: "High", confidence: 80,
        title: "LSASS credential dumping observed",
        description: "comsvcs MiniDump ran; note that WS-17 was also seen in baseline traffic.",
        relatedEventIds: ["e1"],
      })],
      scopedEvents: [ev({ id: "e1", asset: "RDGW-01", severity: "Low", sources: ["Sysmon"], description: "comsvcs MiniDump" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].lateralUnconfirmed).toBeUndefined();
  });
});

describe("corroborationLabel", () => {
  it("labels an ungrounded finding", () => {
    expect(corroborationLabel(f({ ungrounded: true }))).toMatch(/no cited evidence/i);
  });
  it("labels a multi-tool finding as corroborated (no warning)", () => {
    const label = corroborationLabel(f({ corroboration: { distinctTools: 2, distinctHosts: 3, intelSources: 1, graphLinked: false } }));
    expect(label).toContain("2 tools / 3 hosts / intel ✓");
    expect(label).not.toMatch(/uncorroborated/);
  });
  it("marks a single-tool finding uncorroborated", () => {
    expect(corroborationLabel(f({ corroboration: { distinctTools: 1, distinctHosts: 1, intelSources: 0, graphLinked: false } }))).toMatch(/uncorroborated/);
  });
  it("surfaces a KEV badge and an unconfirmed-lead caution", () => {
    expect(corroborationLabel(f({ corroboration: { distinctTools: 2, distinctHosts: 1, intelSources: 0, graphLinked: false, kevLinked: true } }))).toMatch(/KEV/);
    expect(corroborationLabel(f({ corroboration: { distinctTools: 1, distinctHosts: 1, intelSources: 0, graphLinked: false, huntArtifactOnly: true } }))).toMatch(/unconfirmed lead/i);
  });
});

describe("groundAndScoreFindings — verdict-first / hunt-artifact / KEV signals (issue #61)", () => {
  it("marks verdictFirst when a supporting event is graded (Low+), not hunt-artifact-only", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", severity: "High", sources: ["EDR"], asset: "H1" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].corroboration?.verdictFirst).toBe(true);
    expect(out[0].corroboration?.huntArtifactOnly).toBe(false);
  });

  it("marks huntArtifactOnly and caps at 55 when every supporting event is Info telemetry", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", severity: "Info", sources: ["Velociraptor"], asset: "H1", artifactName: "Windows.NTFS.MFT" })],
      iocs: [], graphLinkedEventIds: new Set(),
    });
    expect(out[0].corroboration?.huntArtifactOnly).toBe(true);
    expect(out[0].corroboration?.verdictFirst).toBe(false);
    expect(out[0].confidence).toBe(HUNT_ARTIFACT_CONFIDENCE_CAP);
    expect(out[0].confidenceReason).toMatch(/hunt-collection artifacts/i);
  });

  it("does NOT apply the hunt-artifact cap when intel or KEV backs it", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"], relatedIocs: ["i1"] })],
      scopedEvents: [ev({ id: "e1", severity: "Info", sources: ["Velociraptor"], asset: "H1" })],
      iocs: [ioc({ id: "i1", enrichments: [{ source: "VT", verdict: "malicious", fetchedAt: "" }] })],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].corroboration?.huntArtifactOnly).toBe(true);
    expect(out[0].confidence).toBe(90); // intel lifts it above the hunt-artifact cap
  });

  it("marks kevLinked and exempts a single-source finding from the 65 cap", () => {
    const out = groundAndScoreFindings({
      findings: [f({ id: "f1", confidence: 90, relatedEventIds: ["e1"], description: "exploitation of CVE-2024-38094" })],
      scopedEvents: [ev({ id: "e1", severity: "High", sources: ["OneTool"], asset: "H1" })],
      iocs: [], graphLinkedEventIds: new Set(),
      kevCveIds: new Set(["CVE-2024-38094"]),
    });
    expect(out[0].corroboration?.kevLinked).toBe(true);
    expect(out[0].confidence).toBe(90); // KEV is independent corroboration → not single-source-capped
  });

  it("kevLinked reads CVEs from a supporting event's message and related IOC values", () => {
    const viaEvent = groundAndScoreFindings({
      findings: [f({ id: "f1", relatedEventIds: ["e1"] })],
      scopedEvents: [ev({ id: "e1", severity: "High", message: "Suspected CVE-2023-1234 exploit", sources: ["T"], asset: "H" })],
      iocs: [], graphLinkedEventIds: new Set(), kevCveIds: new Set(["CVE-2023-1234"]),
    });
    expect(viaEvent[0].corroboration?.kevLinked).toBe(true);
    const notInKev = groundAndScoreFindings({
      findings: [f({ id: "f1", relatedEventIds: ["e1"], description: "CVE-2000-9999" })],
      scopedEvents: [ev({ id: "e1", severity: "High", sources: ["T"], asset: "H" })],
      iocs: [], graphLinkedEventIds: new Set(), kevCveIds: new Set(["CVE-2024-38094"]),
    });
    expect(notInKev[0].corroboration?.kevLinked).toBe(false);
  });
});
