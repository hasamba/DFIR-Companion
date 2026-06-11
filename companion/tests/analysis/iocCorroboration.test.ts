import { describe, it, expect } from "vitest";
import { deriveIocSources, corroboratedIocSources } from "../../src/analysis/iocCorroboration.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

const ioc = (id: string, type: IOC["type"], value: string): IOC => ({ id, type, value, firstSeen: "2026-01-01T00:00:00Z" });

const ev = (over: Partial<ForensicEvent> & Pick<ForensicEvent, "id" | "description">): ForensicEvent => ({
  timestamp: "2026-01-01T00:00:00Z", severity: "Medium", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over,
});

describe("deriveIocSources", () => {
  it("unions the distinct tools that observed the same hash across events", () => {
    const iocs = [ioc("i1", "hash", "ABCDEF123456")];
    const events = [
      ev({ id: "e1", description: "malware detected", sha256: "abcdef123456", sources: ["THOR"] }),
      ev({ id: "e2", description: "file flagged", sha256: "abcdef123456", sources: ["Velociraptor"] }),
      ev({ id: "e3", description: "unrelated", sha256: "0000", sources: ["Chainsaw"] }),
    ];
    expect(deriveIocSources(iocs, events)).toEqual({ i1: ["THOR", "Velociraptor"] });
  });

  it("matches an IP via structured fields and free-text, with exact-token boundaries", () => {
    const iocs = [ioc("ip1", "ip", "10.0.0.1")];
    const events = [
      ev({ id: "e1", description: "connection to host", dstIp: "10.0.0.1", sources: ["Suricata"] }),
      ev({ id: "e2", description: "beacon to 10.0.0.1 on 443", sources: ["Zeek"] }),
      // must NOT corroborate: 10.0.0.10 is a different address that contains "10.0.0.1"
      ev({ id: "e3", description: "traffic to 10.0.0.10", sources: ["EDR"] }),
    ];
    expect(deriveIocSources(iocs, events).ip1.sort()).toEqual(["Suricata", "Zeek"]);
  });

  it("matches a domain token in the description", () => {
    const iocs = [ioc("d1", "domain", "evil.com")];
    const events = [
      ev({ id: "e1", description: "DNS query for evil.com", sources: ["Zeek"] }),
      ev({ id: "e2", description: "C2 evil.com resolved", sources: ["THOR"] }),
      // notevil.com is a different domain — exact-token match must not corroborate
      ev({ id: "e3", description: "lookup notevil.com", sources: ["EDR"] }),
    ];
    expect(deriveIocSources(iocs, events).d1.sort()).toEqual(["THOR", "Zeek"]);
  });

  it("ignores 'unknown source' and events without sources", () => {
    const iocs = [ioc("i1", "hash", "deadbeef")];
    const events = [
      ev({ id: "e1", description: "x", sha256: "deadbeef", sources: ["unknown source"] }),
      ev({ id: "e2", description: "x", sha256: "deadbeef" }),                       // no sources
      ev({ id: "e3", description: "x", sha256: "deadbeef", sources: ["THOR"] }),
    ];
    expect(deriveIocSources(iocs, events)).toEqual({ i1: ["THOR"] });
  });

  it("omits IOCs that no sourced event references", () => {
    const iocs = [ioc("i1", "domain", "absent.example")];
    const events = [ev({ id: "e1", description: "nothing here", sources: ["THOR"] })];
    expect(deriveIocSources(iocs, events)).toEqual({});
  });

  it("returns {} for empty inputs", () => {
    expect(deriveIocSources([], [ev({ id: "e1", description: "x", sources: ["THOR"] })])).toEqual({});
    expect(deriveIocSources([ioc("i1", "ip", "1.2.3.4")], [])).toEqual({});
  });
});

describe("corroboratedIocSources", () => {
  it("keeps only IOCs confirmed by 2+ distinct tools", () => {
    const iocs = [ioc("i1", "hash", "deadbeef"), ioc("i2", "hash", "cafebabe")];
    const events = [
      ev({ id: "e1", description: "x", sha256: "deadbeef", sources: ["THOR"] }),
      ev({ id: "e2", description: "x", sha256: "deadbeef", sources: ["Velociraptor"] }),
      ev({ id: "e3", description: "x", sha256: "cafebabe", sources: ["THOR"] }),       // single tool → dropped
    ];
    const out = corroboratedIocSources(iocs, events);
    expect(out).toEqual({ i1: ["THOR", "Velociraptor"] });
    expect(out.i2).toBeUndefined();
  });
});
