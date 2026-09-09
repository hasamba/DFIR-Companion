import { describe, it, expect } from "vitest";
import { malfindContext } from "../../src/analysis/malfindContext.js";
import { parseMemory } from "../../src/analysis/memoryImport.js";

describe("malfindContext — what the region actually shows", () => {
  it("corroborates when the region is private, RWX and starts with an image header", () => {
    const c = malfindContext({
      Protection: "PAGE_EXECUTE_READWRITE",
      Tag: "VadS",
      PrivateMemory: 1,
      Hexdump: "4d 5a 90 00 03 00 00 00",
    });
    expect(c.confidence).toBe("corroborated");
    expect(c.note).toContain("writable and executable");
    expect(c.note).toContain("private memory");
    expect(c.note).toContain("MZ image header");
  });

  it("treats a file-backed executable mapping as the weaker shape it is", () => {
    const c = malfindContext({
      Protection: "PAGE_EXECUTE_READ",
      Tag: "Vad",
      PrivateMemory: 0,
      Hexdump: "48 89 5c 24",
    });
    expect(c.confidence).toBe("uncorroborated");
    expect(c.note).toContain("file-backed");
  });

  // Volatility 3 emits BOTH a Tag and PrivateMemory on every malfind row. Gating the authoritative
  // field behind "no tag" meant it was never consulted on real output. VadS/VadF are pool tags cast
  // to the same short structure, so the tag alone cannot classify private versus file-backed.
  it("reads PrivateMemory even when a VAD tag is present", () => {
    const c = malfindContext({ Protection: "PAGE_EXECUTE_READWRITE", Tag: "VadS", PrivateMemory: 1 });
    expect(c.note).toContain("private memory");
    // Private + executable are malfind's SELECTION criteria — every row it returns has them, so
    // they set the baseline and cannot raise confidence. MsMpEng.exe has exactly this shape.
    expect(c.confidence).toBe("baseline");
  });

  it("does not infer private memory from the VAD tag alone", () => {
    const c = malfindContext({ Protection: "PAGE_EXECUTE_READWRITE", Tag: "VadS" });
    expect(c.note).not.toContain("private memory");
    expect(c.note).toContain("VAD tag VadS");
  });

  it("reads the tool's own Notes verdict when the hexdump did not survive the import", () => {
    const c = malfindContext({ Protection: "PAGE_EXECUTE_READWRITE", PrivateMemory: 1, Notes: "MZ header" });
    expect(c.note).toContain("MZ header");
    expect(c.note).not.toContain("no content preview");
  });

  it("matches an MZ header in an address-prefixed hexdump row", () => {
    const c = malfindContext({ Protection: "PAGE_EXECUTE_READWRITE", PrivateMemory: 1, Hexdump: "0x1f0000  4d 5a 90 00" });
    expect(c.note).toContain("MZ image header");
  });

  it("does not read a NOP-prefixed region as an image header", () => {
    const c = malfindContext({ Protection: "PAGE_EXECUTE_READWRITE", PrivateMemory: 1, Hexdump: "90 4d 5a 90" });
    expect(c.note).toContain("does not begin with an MZ header");
  });

  it("counts corroborating evidence from other tables in the same image", () => {
    const row = { Protection: "PAGE_EXECUTE_READ", PrivateMemory: 0, Hexdump: "48 89" };
    expect(malfindContext(row).confidence).toBe("uncorroborated");
    const withNet = malfindContext(row, { networkPid: true, suspiciousCommandLine: true });
    expect(withNet.confidence).toBe("corroborated");
    expect(withNet.note).toContain("network connection in this image");
  });
});

// The rule the module exists to protect. Absence of a positive indicator is not evidence of
// absence: malfind previews only the START of a region, and shellcode has no header.
describe("malfindContext — absence never reads as clean", () => {
  it("says a missing MZ header does not indicate the region is clean", () => {
    const c = malfindContext({ Protection: "PAGE_EXECUTE_READWRITE", PrivateMemory: 1, Hexdump: "90 90 90 90" });
    expect(c.note).toContain("does not indicate the region is clean");
    expect(c.note).not.toMatch(/\bis clean\b(?!,)/);
  });

  it("says an absent preview leaves the contents unknown, not clean", () => {
    const c = malfindContext({ Protection: "PAGE_EXECUTE_READWRITE", PrivateMemory: 1 });
    expect(c.note).toContain("contents are unknown");
  });

  it("says a non-executable protection does not corroborate, rather than clearing it", () => {
    const withPrivate = malfindContext({ Protection: "PAGE_READONLY", PrivateMemory: 1 });
    expect(withPrivate.note).toContain("does not corroborate injection");
    // With nothing corroborating at all, the closing has to say so in both directions at once.
    const nothing = malfindContext({ Protection: "PAGE_READONLY", PrivateMemory: 0 });
    expect(nothing.note).toContain("do not corroborate injection");
    expect(nothing.note).toContain("do not clear it");
  });

  it("never claims a region is clean, whatever is missing", () => {
    for (const row of [
      {},
      { Protection: "PAGE_READONLY" },
      { Protection: "PAGE_NOACCESS", PrivateMemory: 0, Hexdump: "" },
    ]) {
      const note = malfindContext(row).note;
      expect(note).not.toMatch(/region is clean\.|no injection|not injected|benign/i);
    }
  });

  it("records what was not captured rather than staying silent about it", () => {
    const c = malfindContext({});
    expect(c.note).toContain("protection was not recorded");
    expect(c.confidence).toBe("uncorroborated");
  });
});

describe("wired into the memory importer", () => {
  const rows = [
    {
      Process: "svchost.exe",
      PID: 1234,
      Protection: "PAGE_EXECUTE_READWRITE",
      Tag: "VadS",
      PrivateMemory: 1,
      "Start VPN": "0x1f0000",
      Hexdump: "4d 5a 90 00",
    },
  ];

  it("keeps the existing High severity and adds the interpretation", () => {
    const r = parseMemory(JSON.stringify({ "windows.malfind.Malfind": rows }));
    expect(r.events).toHaveLength(1);
    // The severity policy is deliberately unchanged — this item adds context, not a downgrade.
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1055");
    expect(r.events[0].description).toContain("private memory");
    expect(r.events[0].description).toContain("Confirm");
  });

  it("still names the region, so two regions do not merge into one row", () => {
    const two = [
      { ...rows[0], "Start VPN": "0x1f0000" },
      { ...rows[0], "Start VPN": "0x2a0000" },
    ];
    const r = parseMemory(JSON.stringify({ "windows.malfind.Malfind": two }));
    expect(r.events).toHaveLength(2);
    expect(r.events[0].description).toContain("0x1f0000");
    expect(r.events[1].description).toContain("0x2a0000");
  });
});
