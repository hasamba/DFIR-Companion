import { describe, it, expect } from "vitest";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { parseLoginEvent, displayAccountName, isNoiseAccount } from "../../src/analysis/loginGraph.js";

// Minimal ForensicEvent factory — only description/asset/timestamp vary per test.
export const ev = (over: Partial<ForensicEvent> & { description: string }): ForensicEvent => ({
  id: over.id ?? `id-${Math.abs(hash(over.description))}`,
  timestamp: "2026-06-10T12:00:00Z",
  severity: "Low",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});
function hash(s: string): number { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }

describe("parseLoginEvent", () => {
  it("parses a successful domain-account logon with type, source ip and workstation", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=10 - IpAddress=203.0.113.7 - WorkstationName=WKSTN-02 @ SRV-01 [RemoteInteractive/RDP from 203.0.113.7]",
      asset: "SRV-01",
    }));
    expect(p).toEqual({
      account: "CORP\\jdoe", host: "SRV-01", logonType: 10,
      typeName: "RemoteInteractive/RDP", outcome: "success",
      sourceIp: "203.0.113.7", workstation: "WKSTN-02",
    });
  });

  it("parses a failed logon (4625) as outcome failed", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Failed logon (EID 4625) - CORP\\admin - LogonType=3 - IpAddress=10.0.0.9 @ DC-01",
      asset: "DC-01",
    }));
    expect(p?.outcome).toBe("failed");
    expect(p?.typeName).toBe("Network");
  });

  it("parses NT AUTHORITY pseudo-accounts (space in domain)", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - NT AUTHORITY\\SYSTEM - LogonType=5 @ WKSTN-01",
      asset: "WKSTN-01",
    }));
    expect(p?.account).toBe("NT AUTHORITY\\SYSTEM");
    expect(p?.typeName).toBe("Service");
  });

  it("takes the FIRST account (the logon target) when subject account is also rendered", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe, CORP\\WKSTN-02$ - LogonType=3 @ SRV-01",
      asset: "SRV-01",
    }));
    expect(p?.account).toBe("CORP\\jdoe");
  });

  it("decodes an unknown numeric logon type as `type N` and a missing one as Unknown", () => {
    const withNum = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=13 @ SRV-01", asset: "SRV-01",
    }));
    expect(withNum?.typeName).toBe("type 13");
    const noType = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe @ SRV-01", asset: "SRV-01",
    }));
    expect(noType?.typeName).toBe("Unknown");
  });

  it("rejects a marker embedded in a field value (log-content injection)", () => {
    expect(parseLoginEvent(ev({
      description: "Sysmon Process create (EID 1) - CommandLine=echo Successful logon (EID 4624) - EVIL\\fake @ x - Image=C:\\evil.exe @ HOST1",
      asset: "HOST1",
    }))).toBeNull();
  });

  it("returns null for: non-logon rows, rows with no account segment, rows with no asset", () => {
    expect(parseLoginEvent(ev({ description: "Sysmon Process create (EID 1) - CommandLine=cmd.exe @ H1", asset: "H1" }))).toBeNull();
    expect(parseLoginEvent(ev({ description: "Windows Security Successful logon (EID 4624) - LogonType=3 @ H1", asset: "H1" }))).toBeNull();
    expect(parseLoginEvent(ev({ description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=3" }))).toBeNull();
  });
});

describe("displayAccountName", () => {
  it("shortens service domains, keeps real domains", () => {
    expect(displayAccountName("NT AUTHORITY\\SYSTEM")).toBe("SYSTEM");
    expect(displayAccountName("Window Manager\\DWM-1")).toBe("DWM-1");
    expect(displayAccountName("Font Driver Host\\UMFD-0")).toBe("UMFD-0");
    expect(displayAccountName("CORP\\jdoe")).toBe("CORP\\jdoe");
    expect(displayAccountName("jdoe@corp.example")).toBe("jdoe@corp.example");
  });
});

describe("isNoiseAccount", () => {
  it("flags machine accounts, window-manager accounts and ANONYMOUS LOGON", () => {
    expect(isNoiseAccount("CORP\\WKSTN-01$")).toBe(true);
    expect(isNoiseAccount("Window Manager\\DWM-1")).toBe(true);
    expect(isNoiseAccount("Font Driver Host\\UMFD-0")).toBe(true);
    expect(isNoiseAccount("NT AUTHORITY\\ANONYMOUS LOGON")).toBe(true);
    expect(isNoiseAccount("NT AUTHORITY\\SYSTEM")).toBe(false);   // meaningful, not noise
    expect(isNoiseAccount("CORP\\jdoe")).toBe(false);
  });
});
