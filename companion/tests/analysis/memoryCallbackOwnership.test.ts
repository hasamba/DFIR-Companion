import { describe, it, expect } from "vitest";
import { callbackOwnershipFacts, KERNEL_UNIMPLEMENTED_IRP_SYMBOL } from "../../src/analysis/memoryCallbackOwnership.js";

describe("callbackOwnershipFacts — resolved rows never produce a per-row fact", () => {
  it("counts a resolved callbacks row into resolvedCount, no fact", () => {
    const rows = [{ Type: "CreateProcessNotifyRoutine", Callback: "0xfffff801`12345678", Module: "ntoskrnl.exe", Symbol: "PspCreateProcessNotifyRoutine", Detail: "" }];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(1);
  });

  it("counts a resolved ssdt row into resolvedCount, no fact", () => {
    const rows = [{ Index: "0", Address: "0xfffff801`00000000", Module: "ntoskrnl.exe", Symbol: "NtCreateFile" }];
    const r = callbackOwnershipFacts(rows, "ssdt");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(1);
  });

  it("counts a driverirp row whose names agree into resolvedCount, no fact", () => {
    const rows = [
      { Offset: "0x1000", "Driver Name": "\\Driver\\disk", IRP: "IRP_MJ_READ", Address: "0x2000", Module: "disk.sys", Symbol: "DiskReadWrite" },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(1);
  });
});

describe("callbackOwnershipFacts — unresolved", () => {
  it("grades Low, no MITRE, when Module/Symbol are placeholder", () => {
    const rows = [{ Type: "CreateProcessNotifyRoutine", Callback: "0x1000", Module: "N/A", Symbol: "N/A", Detail: "" }];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts).toHaveLength(1);
    expect(r.facts[0].kind).toBe("unresolved");
    expect(r.facts[0].severity).toBe("Low");
    expect(r.facts[0].mitre).toHaveLength(0);
    expect(r.facts[0].note).toMatch(/incomplete module listing|unavailable page|unsupported symbol|legitimate/i);
  });

  it("treats an empty-string Module the same as a placeholder", () => {
    const rows = [{ Index: "5", Address: "0x1000", Module: "", Symbol: "" }];
    const r = callbackOwnershipFacts(rows, "ssdt");
    expect(r.facts[0].kind).toBe("unresolved");
  });

  it("never claims a rootkit or a stronger conclusion than the hedge allows", () => {
    const rows = [{ Type: "x", Callback: "0x1", Module: "N/A", Symbol: "N/A", Detail: "" }];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts[0].note).not.toMatch(/rootkit/i);
  });
});

describe("callbackOwnershipFacts — driver-name-mismatch (driverirp only)", () => {
  it("flags a genuine mismatch between Driver Name and the resolved Module", () => {
    const rows = [
      { Offset: "0x1000", "Driver Name": "\\Driver\\evilrootkit", IRP: "IRP_MJ_READ", Address: "0x2000", Module: "disk.sys", Symbol: "DiskReadWrite" },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(1);
    expect(r.facts[0].kind).toBe("driver-name-mismatch");
    expect(r.facts[0].severity).toBe("Low");
    expect(r.facts[0].mitre).toHaveLength(0);
    expect(r.facts[0].note).not.toMatch(/is lying/i);
  });

  it("normalizes the DRIVER_OBJECT name (strips \\Driver\\ prefix, ignores the module's own extension) before comparing", () => {
    const rows = [
      { Offset: "0x1000", "Driver Name": "\\Driver\\Disk", IRP: "IRP_MJ_READ", Address: "0x2000", Module: "disk.sys", Symbol: "DiskReadWrite" },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(0); // "disk" (normalized) matches "disk" (module minus .sys) — no mismatch
    expect(r.resolvedCount).toBe(1);
  });

  it("excludes the kernel's own unimplemented-IRP-dispatch stub from mismatch checking", () => {
    const rows = [
      {
        Offset: "0x1000",
        "Driver Name": "\\Driver\\SomeVendorDriver",
        IRP: "IRP_MJ_FLUSH_BUFFERS",
        Address: "0xfffff801`00001000",
        Module: "ntoskrnl.exe",
        Symbol: KERNEL_UNIMPLEMENTED_IRP_SYMBOL,
      },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(0); // unimplemented IRP major — ordinary, not a mismatch
    expect(r.resolvedCount).toBe(1);
  });

  it("is never checked for callbacks/ssdt rows (no Driver Name field there)", () => {
    const rows = [{ Type: "x", Callback: "0x1", Module: "ntoskrnl.exe", Symbol: "PspCreateProcessNotifyRoutine", Detail: "" }];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts.some((f) => f.kind === "driver-name-mismatch")).toBe(false);
  });
});

describe("callbackOwnershipFacts — identity for aggregation", () => {
  it("uses driverirp's own Offset (unique per driver), not the shared stub Address", () => {
    const rows = [
      { Offset: "0xAAA", "Driver Name": "\\Driver\\one", IRP: "IRP_MJ_FLUSH_BUFFERS", Address: "0xSTUB", Module: "ntoskrnl.exe", Symbol: KERNEL_UNIMPLEMENTED_IRP_SYMBOL },
      { Offset: "0xBBB", "Driver Name": "\\Driver\\evil", IRP: "IRP_MJ_FLUSH_BUFFERS", Address: "0xSTUB", Module: "vendor.sys", Symbol: "VendorFlush" },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    // the second row is a genuine mismatch (evil vs vendor.sys); the first is the stub exclusion
    expect(r.facts).toHaveLength(1);
    expect(r.facts[0].identity).toBe("0xBBB");
  });

  it("uses Address for callbacks/ssdt", () => {
    const rows = [{ Type: "x", Callback: "0xCCC", Module: "N/A", Symbol: "N/A", Detail: "" }];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts[0].identity).toBe("0xCCC");
  });
});

describe("callbackOwnershipFacts — never crashes on malformed rows", () => {
  it("skips a row with no address/offset field at all", () => {
    const rows = [{ Type: "x", Module: "N/A", Symbol: "N/A" }];
    expect(() => callbackOwnershipFacts(rows, "callbacks")).not.toThrow();
  });

  it("handles an empty table", () => {
    const r = callbackOwnershipFacts([], "ssdt");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(0);
  });
});
