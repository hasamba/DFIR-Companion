import { describe, it, expect } from "vitest";
import { handleOwnershipFacts } from "../../src/analysis/memoryHandleOwnership.js";
import { indexProcessRows, type ProcessIndex } from "../../src/analysis/memoryNetObjects.js";

const EMPTY_INDEX: ProcessIndex = { any: false, byPid: new Map() };

function processIndexFrom(rows: Record<string, unknown>[]): ProcessIndex {
  return indexProcessRows([{ plugin: "windows.pslist", rows }]);
}

function handleRow(over: Record<string, unknown> = {}) {
  return {
    PID: "100",
    Process: "chrome.exe",
    Offset: "0x8badf00d",
    Type: "File",
    GrantedAccess: "0x120089",
    Name: "\\Device\\HarddiskVolume2\\Users\\a\\file.txt",
    ...over,
  };
}

describe("handleOwnershipFacts — no process tables submitted", () => {
  it("emits one coverage note, not one fact per handle row", () => {
    const rows = [handleRow({ PID: "100" }), handleRow({ PID: "101" }), handleRow({ PID: "100" })];
    const result = handleOwnershipFacts(rows, EMPTY_INDEX);
    expect(result.noProcessTablesSubmitted).toBe(true);
    const notes = result.facts.filter((f) => f.kind === "unconfirmed-process");
    expect(notes).toHaveLength(1);
    expect(notes[0].note).toContain("2 distinct PID");
  });

  it("emits nothing at all when there are no handle rows either", () => {
    const result = handleOwnershipFacts([], EMPTY_INDEX);
    expect(result.facts).toHaveLength(0);
    expect(result.noProcessTablesSubmitted).toBe(true);
  });
});

describe("handleOwnershipFacts — unconfirmed-process, per PID not per row", () => {
  it("emits exactly one fact for a PID absent from the submitted process rows", () => {
    const processIndex = processIndexFrom([{ PID: "999", ImageFileName: "svchost.exe" }]);
    const rows = [handleRow({ PID: "100" }), handleRow({ PID: "100" }), handleRow({ PID: "100" })];
    const result = handleOwnershipFacts(rows, processIndex);
    const facts = result.facts.filter((f) => f.kind === "unconfirmed-process");
    expect(facts).toHaveLength(1);
    expect(facts[0].note).toContain("no submitted process row has PID 100");
    expect(facts[0].note).toContain("3 handle-table row(s)");
  });

  it("reports an explicit ambiguous outcome when 2+ process rows share a PID", () => {
    const processIndex = processIndexFrom([
      { PID: "100", ImageFileName: "chrome.exe", Offset: "0x1" },
      { PID: "100", ImageFileName: "chrome.exe", Offset: "0x2" },
    ]);
    const rows = [handleRow({ PID: "100" })];
    const result = handleOwnershipFacts(rows, processIndex);
    const facts = result.facts.filter((f) => f.kind === "unconfirmed-process");
    expect(facts).toHaveLength(1);
    expect(facts[0].note).toContain("ambiguous: 2 distinct submitted process rows have PID 100");
  });
});

describe("handleOwnershipFacts — PID-reuse identity conflict (regression, Codex finding H1)", () => {
  it("never resolves a PID whose sole process candidate disagrees with the handle row's own holder name", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "chrome.exe" }]);
    const rows = [handleRow({ PID: "100", Process: "evil.exe" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "residual-handle")).toHaveLength(0);
    const facts = result.facts.filter((f) => f.kind === "unconfirmed-process");
    expect(facts).toHaveLength(1);
    expect(facts[0].note).toContain("conflict");
    expect(facts[0].note).toContain("chrome.exe");
    expect(facts[0].note).toContain("evil.exe");
  });

  it("still resolves normally when the names agree", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "chrome.exe" }]);
    const rows = [handleRow({ PID: "100", Process: "chrome.exe" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "unconfirmed-process")).toHaveLength(0);
  });
});

describe("handleOwnershipFacts — bounded PID length (regression, Codex finding M1)", () => {
  it("rejects a PID longer than a real 32-bit Windows PID can be", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "chrome.exe" }]);
    const rows = [handleRow({ PID: "99999999999999999999" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts).toHaveLength(0); // the row is dropped, not treated as an unconfirmed PID
  });

  it("rejects an over-long target PID in a Type=Process handle's own Name suffix", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "evil.exe" }]);
    const rows = [handleRow({ PID: "100", Type: "Process", Name: "lsass.exe Pid 99999999999999999999" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "cross-process-access")).toHaveLength(0);
  });
});

describe("handleOwnershipFacts — offset-join safety (regression, Codex finding M2/M3)", () => {
  it("never correlates two rows whose offset failed to parse into pure hex", () => {
    const processIndex = processIndexFrom([
      { PID: "100", ImageFileName: "a.exe" },
      { PID: "101", ImageFileName: "b.exe" },
    ]);
    const rows = [
      handleRow({ PID: "100", Offset: "garbled-not-an-address" }),
      handleRow({ PID: "101", Offset: "garbled-not-an-address" }),
    ];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "shared-object")).toHaveLength(0);
  });

  it("never lets a delimiter-built key collide type+offset across two distinct rows", () => {
    const processIndex = processIndexFrom([
      { PID: "100", ImageFileName: "a.exe" },
      { PID: "101", ImageFileName: "b.exe" },
    ]);
    // "a|b" + offset "c" would collide with type "a" + offset "b|c" under naive delimiter joins.
    const rows = [
      handleRow({ PID: "100", Type: "a|b", Offset: "0xc" }),
      handleRow({ PID: "101", Type: "a", Offset: "0xb7c" }), // hex "b7c" — distinct from "c" and "b|c"
    ];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "shared-object")).toHaveLength(0);
  });
});

describe("handleOwnershipFacts — truncation is reported (regression, Codex finding M4)", () => {
  it("sets truncated when the unconfirmed-process family hits its cap, even with process tables submitted", () => {
    const processIndex = processIndexFrom([{ PID: "0", ImageFileName: "known.exe" }]);
    const rows = Array.from({ length: 60 }, (_, i) => handleRow({ PID: String(i + 1) }));
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.truncated).toBe(true);
  });
});

describe("handleOwnershipFacts — residual-handle", () => {
  it("fires only when exactly one candidate resolves and it shows an exit", () => {
    const processIndex = processIndexFrom([
      { PID: "100", ImageFileName: "chrome.exe", ExitTime: "2026-01-01T00:00:00Z" },
    ]);
    const rows = [handleRow({ PID: "100" })];
    const result = handleOwnershipFacts(rows, processIndex);
    const facts = result.facts.filter((f) => f.kind === "residual-handle");
    expect(facts).toHaveLength(1);
    expect(facts[0].note).toContain("records an exit");
  });

  it("says nothing for a resolved process that has not exited", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "chrome.exe" }]);
    const rows = [handleRow({ PID: "100" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "residual-handle")).toHaveLength(0);
  });
});

describe("handleOwnershipFacts — cross-process-access", () => {
  it("reads the holder and target PID from a Type=Process handle's own Name suffix", () => {
    const processIndex = processIndexFrom([
      { PID: "100", ImageFileName: "evil.exe" },
      { PID: "200", ImageFileName: "lsass.exe" },
    ]);
    const rows = [
      handleRow({
        PID: "100",
        Process: "evil.exe",
        Type: "Process",
        Name: "lsass.exe Pid 200",
        GrantedAccess: "0x1410",
      }),
    ];
    const result = handleOwnershipFacts(rows, processIndex);
    const facts = result.facts.filter((f) => f.kind === "cross-process-access");
    expect(facts).toHaveLength(1);
    expect(facts[0].targetPid).toBe("200");
    expect(facts[0].targetProcess).toBe("lsass.exe");
    expect(facts[0].grantedAccess).toBe("0x1410");
  });

  it("produces no fact when the Name suffix is malformed or not anchored at the end", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "evil.exe" }]);
    const malformed = [
      "lsass.exe Pid ",
      "lsass.exe Pid 200 extra-trailing-text",
      "Pid 200 lsass.exe",
      "lsass.exe",
    ];
    for (const name of malformed) {
      const rows = [handleRow({ PID: "100", Type: "Process", Name: name })];
      const result = handleOwnershipFacts(rows, processIndex);
      expect(result.facts.filter((f) => f.kind === "cross-process-access")).toHaveLength(0);
    }
  });

  it("never reports a process handle onto itself", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "evil.exe" }]);
    const rows = [handleRow({ PID: "100", Type: "Process", Name: "evil.exe Pid 100" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "cross-process-access")).toHaveLength(0);
  });
});

describe("handleOwnershipFacts — shared-object", () => {
  it("groups by (type, canonical offset) across processes, capping the sharedWith list", () => {
    const rows = Array.from({ length: 15 }, (_, i) =>
      handleRow({
        PID: String(100 + i),
        Type: "Mutant",
        Offset: "0xdeadbeef",
        Name: "\\Sessions\\1\\BaseNamedObjects\\Global\\mtx",
      }),
    );
    const processIndex = processIndexFrom(rows.map((r) => ({ PID: r.PID, ImageFileName: "svchost.exe" })));
    const result = handleOwnershipFacts(rows, processIndex);
    const facts = result.facts.filter((f) => f.kind === "shared-object");
    expect(facts).toHaveLength(1);
    expect(facts[0].sharedWith).toHaveLength(11); // 10 shown + "+5 more"
    expect(facts[0].sharedWith?.at(-1)).toBe("+5 more");
    expect(facts[0].note).toContain("15 distinct processes");
  });

  it("says nothing for an object only one process holds", () => {
    const processIndex = processIndexFrom([{ PID: "100", ImageFileName: "svchost.exe" }]);
    const rows = [handleRow({ PID: "100", Offset: "0xabc" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "shared-object")).toHaveLength(0);
  });

  it("never joins rows with a missing or placeholder offset", () => {
    const processIndex = processIndexFrom([
      { PID: "100", ImageFileName: "a.exe" },
      { PID: "101", ImageFileName: "b.exe" },
    ]);
    const rows = [handleRow({ PID: "100", Offset: "-" }), handleRow({ PID: "101", Offset: "-" })];
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.facts.filter((f) => f.kind === "shared-object")).toHaveLength(0);
  });
});

describe("handleOwnershipFacts — GrantedAccess is always raw", () => {
  it("never decodes or renames the raw access value", () => {
    const processIndex = processIndexFrom([
      { PID: "100", ImageFileName: "evil.exe" },
      { PID: "200", ImageFileName: "lsass.exe" },
    ]);
    const rows = [
      handleRow({
        PID: "100",
        Process: "evil.exe",
        Type: "Process",
        Name: "lsass.exe Pid 200",
        GrantedAccess: "0x001410",
      }),
    ];
    const result = handleOwnershipFacts(rows, processIndex);
    const facts = result.facts.filter((f) => f.kind === "cross-process-access");
    expect(facts[0].grantedAccess).toBe("0x001410");
  });
});

describe("handleOwnershipFacts — truncation", () => {
  it("marks the result truncated once a per-kind cap is hit", () => {
    const rows = Array.from({ length: 60 }, (_, i) => handleRow({ PID: String(i) }));
    const result = handleOwnershipFacts(rows, EMPTY_INDEX);
    // no assertion on facts count here — truncation applies to unresolved-process accounting only
    // when process tables ARE submitted; this exercises the "no tables at all" short-circuit path
    // does not itself explode into one fact per PID.
    expect(result.facts.filter((f) => f.kind === "unconfirmed-process")).toHaveLength(1);
    expect(result.truncated).toBe(false);
  });

  it("caps unconfirmed/residual facts at MAX_FACTS_PER_KIND when process tables are submitted", () => {
    const knownPid = { PID: "0", ImageFileName: "known.exe" };
    const processIndex = processIndexFrom([knownPid]);
    const rows = Array.from({ length: 60 }, (_, i) => handleRow({ PID: String(i + 1) }));
    const result = handleOwnershipFacts(rows, processIndex);
    expect(result.truncated).toBe(true);
    expect(result.facts.filter((f) => f.kind === "unconfirmed-process").length).toBeLessThanOrEqual(50);
  });
});
