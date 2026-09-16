import { describe, it, expect } from "vitest";
import { isPeSieveReport, parseMemoryPeSieve } from "../../src/analysis/pesieveImport.js";

function scan(entry: Record<string, unknown>): Record<string, unknown> {
  return entry;
}

function report(over: Record<string, unknown> = {}): object {
  return {
    pid: 1234,
    is_64_bit: 1,
    main_image_path: "C:\\Windows\\System32\\notepad.exe",
    scanned: {
      total: 10,
      skipped: 0,
      errors: 0,
      modified: {
        total: 0,
        patched: 0,
        iat_hooked: 0,
        replaced: 0,
        hdr_modified: 0,
        implanted_pe: 0,
        implanted_shc: 0,
        unreachable_file: 0,
        other: 0,
      },
    },
    scans: [],
    ...over,
  };
}

describe("isPeSieveReport", () => {
  it("recognizes a real PE-sieve report shape", () => {
    expect(isPeSieveReport(report())).toBe(true);
  });

  it("requires scanned to be an object, not an array — guards against isVolatilityMap-style shapes", () => {
    expect(isPeSieveReport({ pid: 1, scanned: [], scans: [] })).toBe(false);
  });

  it("requires pid to be present", () => {
    const { pid, ...rest } = report() as Record<string, unknown>;
    expect(isPeSieveReport(rest)).toBe(false);
  });

  it("requires scans to be an array", () => {
    expect(isPeSieveReport({ pid: 1, scanned: { total: 1 }, scans: {} })).toBe(false);
  });

  it("does not collide with a Volatility JSON row shape (PID/ImageFileName/PPID)", () => {
    expect(isPeSieveReport({ PID: 1, ImageFileName: "x", PPID: 0 })).toBe(false);
  });

  it("does not collide with a sandbox report shape (verdict/threat_score)", () => {
    expect(isPeSieveReport({ verdict: "malicious", threat_score: 90 })).toBe(false);
  });

  it("rejects an array root", () => {
    expect(isPeSieveReport([report()])).toBe(false);
  });
});

describe("parseMemoryPeSieve — summary event", () => {
  it("grades Info when nothing was flagged", () => {
    const r = parseMemoryPeSieve(JSON.stringify(report()), {});
    const summary = r.events.find((e) => e.description.includes("scanned"));
    expect(summary?.severity).toBe("Info");
  });

  it("grades Medium and discloses the full modified.* breakdown when something was flagged", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scanned: {
            total: 5,
            skipped: 1,
            errors: 1,
            modified: {
              total: 1,
              patched: 1,
              iat_hooked: 0,
              replaced: 0,
              hdr_modified: 0,
              implanted_pe: 0,
              implanted_shc: 0,
              unreachable_file: 0,
              other: 0,
            },
          },
        }),
      ),
      {},
    );
    const summary = r.events.find((e) => e.description.includes("scanned"));
    expect(summary?.severity).toBe("Medium");
    expect(summary?.description).toContain("1 skipped");
    expect(summary?.description).toContain("1 error");
    expect(summary?.description).toContain("patched");
  });
});

describe("parseMemoryPeSieve — code_scan", () => {
  it("grades High/T1055 when patches > 0", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ code_scan: { module: "75660000", module_file: "user32.dll", status: 1, patches: 2, scanned_sections: 1 } })],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("code_scan"));
    expect(e?.severity).toBe("High");
    expect(e?.mitreTechniques).toContain("T1055");
    expect(e?.description).toContain("2");
  });

  it("grades Medium/T1055 when status:1 but patches is absent or 0", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ code_scan: { module: "75660000", module_file: "user32.dll", status: 1 } })],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("code_scan"));
    expect(e?.severity).toBe("Medium");
    expect(e?.mitreTechniques).toContain("T1055");
  });

  it("says nothing for status:0", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ code_scan: { module: "75660000", module_file: "user32.dll", status: 0, patches: 0 } })],
        }),
      ),
      {},
    );
    expect(r.events.some((ev) => ev.description.includes("code_scan"))).toBe(false);
  });
});

describe("parseMemoryPeSieve — headers_scan", () => {
  it("grades High/T1055 for is_pe_replaced, distinct from an ordinary header diff", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [
            scan({
              headers_scan: {
                module: "1",
                module_file: "evil.dll",
                status: 1,
                is_pe_replaced: 1,
                dos_hdr_modified: 1,
              },
            }),
          ],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("headers_scan"));
    expect(e?.severity).toBe("High");
    expect(e?.mitreTechniques).toContain("T1055");
  });

  it("grades Low/no-MITRE for an ordinary header field modification, naming the field", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [
            scan({
              headers_scan: {
                module: "1",
                module_file: "ntdll.dll",
                status: 1,
                dos_hdr_modified: 1,
                nt_hdr_modified: 0,
              },
            }),
          ],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("headers_scan"));
    expect(e?.severity).toBe("Low");
    expect(e?.mitreTechniques ?? []).toHaveLength(0);
    expect(e?.description).toContain("dos_hdr_modified");
    expect(e?.description).not.toContain("nt_hdr_modified");
    expect(e?.description).toMatch(/does not establish|not.*malicious/i);
  });
});

describe("parseMemoryPeSieve — mapping_scan", () => {
  it("grades Medium/T1055, single grade, states mapped_file when present", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ mapping_scan: { module: "1", module_file: "svc.exe", mapped_file: "C:\\svc.exe", status: 1 } })],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("mapping_scan"));
    expect(e?.severity).toBe("Medium");
    expect(e?.mitreTechniques).toContain("T1055");
    expect(e?.description).toContain("C:\\svc.exe");
  });

  it("discloses an absent mapped_file honestly, never as 'deleted by malware'", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ mapping_scan: { module: "1", module_file: "svc.exe", mapped_file: "", status: 1 } })],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("mapping_scan"));
    expect(e?.description).not.toMatch(/deleted by malware/i);
    expect(e?.description).toMatch(/not resolved|unreachable|missing/i);
  });
});

describe("parseMemoryPeSieve — iat_scan", () => {
  it("grades Medium/T1055 by scan-type key alone", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ iat_scan: { module: "1", module_file: "ntdll.dll", status: 1 } })],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("iat_scan"));
    expect(e?.severity).toBe("Medium");
    expect(e?.mitreTechniques).toContain("T1055");
  });
});

describe("parseMemoryPeSieve — unrecognized scan type", () => {
  it("grades Low/no-MITRE, never crashes, never fabricates detail fields", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ workingset_scan: { module: "1", module_file: "x.dll", status: 1 } })],
        }),
      ),
      {},
    );
    const e = r.events.find((ev) => ev.description.includes("workingset_scan"));
    expect(e?.severity).toBe("Low");
    expect(e?.mitreTechniques ?? []).toHaveLength(0);
  });
});

describe("parseMemoryPeSieve — multiple scan types on the same module", () => {
  it("never merges — each flagged scan type is its own distinct event", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [
            scan({ code_scan: { module: "abc", module_file: "x.dll", status: 1, patches: 1 } }),
            scan({ headers_scan: { module: "abc", module_file: "x.dll", status: 1, dos_hdr_modified: 1 } }),
          ],
        }),
      ),
      {},
    );
    expect(r.events.some((e) => e.description.includes("code_scan"))).toBe(true);
    expect(r.events.some((e) => e.description.includes("headers_scan"))).toBe(true);
  });
});

describe("parseMemoryPeSieve — IOC promotion", () => {
  it("promotes the module's own file path as a file IOC regardless of severity", () => {
    const r = parseMemoryPeSieve(
      JSON.stringify(
        report({
          scans: [scan({ headers_scan: { module: "1", module_file: "C:\\Windows\\ntdll.dll", status: 1, dos_hdr_modified: 1 } })],
        }),
      ),
      {},
    );
    expect(r.iocs.some((i) => i.type === "file" && /ntdll\.dll/i.test(i.value))).toBe(true);
  });
});
