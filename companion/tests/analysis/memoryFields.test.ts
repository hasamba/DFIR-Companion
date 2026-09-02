import { describe, it, expect } from "vitest";
import { filePathIoc, regionAddress, serviceImagePath } from "../../src/analysis/memoryFields.js";

describe("serviceImagePath", () => {
  it("unwraps a quoted ImagePath and drops the arguments after it", () => {
    expect(serviceImagePath('"C:\\ProgramData\\Defender\\MsMpEng.exe" -Service')).toBe(
      "C:\\ProgramData\\Defender\\MsMpEng.exe",
    );
  });

  it("cuts an unquoted ImagePath after its extension, not at the first space", () => {
    expect(serviceImagePath("C:\\WINDOWS\\system32\\svchost.exe -k RPCSS -p")).toBe(
      "C:\\WINDOWS\\system32\\svchost.exe",
    );
    // A path that legitimately contains spaces must survive whole.
    expect(serviceImagePath("C:\\Program Files\\Vendor App\\agent.exe --run")).toBe(
      "C:\\Program Files\\Vendor App\\agent.exe",
    );
  });

  it("refuses the placeholders Volatility prints for an absent value", () => {
    for (const junk of ["N/A", "n/a", "-", "", "   ", "none", "null"])
      expect(serviceImagePath(junk)).toBe("");
  });

  it("refuses a bare name with no path separator, as the importer always has", () => {
    expect(serviceImagePath("svchost.exe -k RPCSS")).toBe("");
  });

  it("leaves a driver path with no recognised extension alone", () => {
    expect(serviceImagePath("\\SystemRoot\\System32\\drivers\\thing")).toBe(
      "\\SystemRoot\\System32\\drivers\\thing",
    );
  });
});

describe("filePathIoc", () => {
  // The guard this replaced asked "does it contain a separator?" — and `N/A` contains a forward
  // slash, so every path-bearing mapper recorded the placeholder as a file indicator.
  it("refuses N/A, whose own slash passed the old separator test", () => {
    expect(/[\\/]/.test("N/A")).toBe(true); // why the bug existed
    expect(filePathIoc("N/A")).toBe("");
    expect(filePathIoc("n/a")).toBe("");
  });

  it("keeps a real path", () => {
    expect(filePathIoc("C:\\WINDOWS\\system32\\wininit.exe")).toBe("C:\\WINDOWS\\system32\\wininit.exe");
    expect(filePathIoc("/usr/bin/bash")).toBe("/usr/bin/bash");
  });

  it("refuses a bare name and the other placeholders", () => {
    for (const junk of ["wininit.exe", "-", "", "none", "unknown"]) expect(filePathIoc(junk)).toBe("");
  });
});

describe("regionAddress", () => {
  it("renders a decimal virtual address as hex", () => {
    expect(regionAddress("2178332819456")).toBe("0x1fb2ec10000");
  });

  it("keeps an address that is already hex, and anything that is not a number", () => {
    expect(regionAddress("0x2000000")).toBe("0x2000000");
    expect(regionAddress("")).toBe("");
    expect(regionAddress("VadS")).toBe("VadS");
  });

  it("stays exact past 2^53, where a double would round", () => {
    expect(regionAddress("18446744073709551615")).toBe("0xffffffffffffffff");
  });
});
