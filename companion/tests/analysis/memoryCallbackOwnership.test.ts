import { describe, it, expect } from "vitest";
import {
  callbackOwnershipFacts,
  kernelHookEvents,
  KERNEL_UNIMPLEMENTED_IRP_SYMBOL,
} from "../../src/analysis/memoryCallbackOwnership.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

describe("callbackOwnershipFacts — resolved rows never produce a per-row fact", () => {
  it("counts a resolved callbacks row into resolvedCount, no fact", () => {
    const rows = [
      {
        Type: "CreateProcessNotifyRoutine",
        Callback: "0xfffff801`12345678",
        Module: "ntoskrnl.exe",
        Symbol: "PspCreateProcessNotifyRoutine",
        Detail: "",
      },
    ];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(1);
  });

  it("counts a resolved ssdt row into resolvedCount, no fact", () => {
    const rows = [
      { Index: "0", Address: "0xfffff801`00000000", Module: "ntoskrnl.exe", Symbol: "NtCreateFile" },
    ];
    const r = callbackOwnershipFacts(rows, "ssdt");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(1);
  });

  it("counts a driverirp row whose names agree into resolvedCount, no fact", () => {
    const rows = [
      {
        Offset: "0x1000",
        "Driver Name": "\\Driver\\disk",
        IRP: "IRP_MJ_READ",
        Address: "0x2000",
        Module: "disk.sys",
        Symbol: "DiskReadWrite",
      },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(1);
  });
});

describe("callbackOwnershipFacts — unresolved", () => {
  it("grades Low, no MITRE, when Module/Symbol are placeholder", () => {
    const rows = [
      { Type: "CreateProcessNotifyRoutine", Callback: "0x1000", Module: "N/A", Symbol: "N/A", Detail: "" },
    ];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts).toHaveLength(1);
    expect(r.facts[0].kind).toBe("unresolved");
    expect(r.facts[0].severity).toBe("Low");
    expect(r.facts[0].mitre).toHaveLength(0);
    expect(r.facts[0].note).toMatch(
      /incomplete module listing|unavailable page|unsupported symbol|legitimate/i,
    );
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
      {
        Offset: "0x1000",
        "Driver Name": "\\Driver\\evilrootkit",
        IRP: "IRP_MJ_READ",
        Address: "0x2000",
        Module: "disk.sys",
        Symbol: "DiskReadWrite",
      },
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
      {
        Offset: "0x1000",
        "Driver Name": "\\Driver\\Disk",
        IRP: "IRP_MJ_READ",
        Address: "0x2000",
        Module: "disk.sys",
        Symbol: "DiskReadWrite",
      },
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
    const rows = [
      {
        Type: "x",
        Callback: "0x1",
        Module: "ntoskrnl.exe",
        Symbol: "PspCreateProcessNotifyRoutine",
        Detail: "",
      },
    ];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts.some((f) => f.kind === "driver-name-mismatch")).toBe(false);
  });
});

describe("callbackOwnershipFacts — identity for aggregation", () => {
  it("uses driverirp's own Offset (unique per driver), not the shared stub Address", () => {
    const rows = [
      {
        Offset: "0xAAA",
        "Driver Name": "\\Driver\\one",
        IRP: "IRP_MJ_FLUSH_BUFFERS",
        Address: "0xSTUB",
        Module: "ntoskrnl.exe",
        Symbol: KERNEL_UNIMPLEMENTED_IRP_SYMBOL,
      },
      {
        Offset: "0xBBB",
        "Driver Name": "\\Driver\\evil",
        IRP: "IRP_MJ_FLUSH_BUFFERS",
        Address: "0xSTUB",
        Module: "vendor.sys",
        Symbol: "VendorFlush",
      },
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

// Regressions from an Ollama code-review round.
describe("callbackOwnershipFacts — module resolved but symbol absent is NOT unresolved", () => {
  it("counts as resolved when Module is present, even if Symbol has no PDB-backed name", () => {
    const rows = [{ Type: "x", Callback: "0x1", Module: "ntoskrnl.exe", Symbol: "N/A", Detail: "" }];
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts).toHaveLength(0);
    expect(r.resolvedCount).toBe(1);
  });

  it("only Module absence triggers unresolved, never Symbol absence alone", () => {
    const rows = [{ Index: "0", Address: "0x1", Module: "hal.dll", Symbol: "" }];
    const r = callbackOwnershipFacts(rows, "ssdt");
    expect(r.facts).toHaveLength(0);
  });
});

describe("callbackOwnershipFacts — exact-equality name comparison, not substring", () => {
  it("flags a mismatch a substring check would have silently missed", () => {
    // "tcpip" (normalized Driver Name) is a SUBSTRING of "tcpip6" (normalized Module) — a naive
    // substring check would suppress this as "no mismatch"; exact equality correctly flags it.
    const rows = [
      {
        Offset: "0x1",
        "Driver Name": "\\Driver\\Tcpip",
        IRP: "IRP_MJ_READ",
        Address: "0x2",
        Module: "tcpip6.sys",
        Symbol: "SomeHandler",
      },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(1);
    expect(r.facts[0].kind).toBe("driver-name-mismatch");
  });

  it("still recognizes an exact match after normalization as no mismatch", () => {
    const rows = [
      {
        Offset: "0x1",
        "Driver Name": "\\Driver\\Tcpip",
        IRP: "IRP_MJ_READ",
        Address: "0x2",
        Module: "tcpip.sys",
        Symbol: "SomeHandler",
      },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(0);
  });

  it("names framework-driven dispatch as a possible benign cause in the note, since it is not excluded programmatically", () => {
    const rows = [
      {
        Offset: "0x1",
        "Driver Name": "\\Driver\\SomeKmdfDriver",
        IRP: "IRP_MJ_READ",
        Address: "0x2",
        Module: "Wdf01000.sys",
        Symbol: "FxIoQueueDispatch",
      },
    ];
    const r = callbackOwnershipFacts(rows, "driverirp");
    expect(r.facts).toHaveLength(1);
    expect(r.facts[0].note).toMatch(/framework|KMDF|minifilter|shared code/i);
  });
});

describe("callbackOwnershipFacts — bounded output", () => {
  it("caps facts at MAX_FACTS and discloses truncation", () => {
    const rows = Array.from({ length: 250 }, (_, i) => ({
      Type: "x",
      Callback: `0x${i}`,
      Module: "N/A",
      Symbol: "N/A",
      Detail: "",
    }));
    const r = callbackOwnershipFacts(rows, "callbacks");
    expect(r.facts.length).toBeLessThanOrEqual(200);
    expect(r.truncated).toBe(true);
  });
});

describe("kernelHookEvents — wiring", () => {
  it("promotes only the resolved module as a file IOC, never the driver object's own name", () => {
    const sink = new Map<string, SiemIoc>();
    const events = kernelHookEvents(
      [
        {
          pluginType: "driverirp",
          rows: [
            {
              Offset: "0x1",
              "Driver Name": "\\Driver\\evilrootkit",
              IRP: "IRP_MJ_READ",
              Address: "0x2",
              Module: "disk.sys",
              Symbol: "DiskReadWrite",
            },
          ],
        },
      ],
      "Volatility",
      sink,
    );
    expect(
      events.some(
        (e) => e.description.includes("driver-name-mismatch") || e.description.includes("does not match"),
      ),
    ).toBe(true);
    const iocValues = [...sink.values()].map((i) => i.value.toLowerCase());
    expect(iocValues.some((v) => v.includes("disk"))).toBe(true);
    expect(iocValues.some((v) => v.includes("evilrootkit"))).toBe(false);
  });

  it("does not collide the summary aggKey across two tables of the same plugin type", () => {
    const sink = new Map<string, SiemIoc>();
    const events = kernelHookEvents(
      [
        { pluginType: "ssdt", rows: [{ Index: "0", Address: "0x1", Module: "ntoskrnl.exe", Symbol: "NtA" }] },
        { pluginType: "ssdt", rows: [{ Index: "1", Address: "0x2", Module: "ntoskrnl.exe", Symbol: "NtB" }] },
      ],
      "Volatility",
      sink,
    );
    const summaries = events.filter((e) => e.description.includes("resolved to a known module"));
    expect(summaries).toHaveLength(2);
    expect(summaries[0].aggKey).not.toBe(summaries[1].aggKey);
  });
});
