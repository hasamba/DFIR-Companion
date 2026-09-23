import { describe, it, expect } from "vitest";
import { applyMftTimeHints, detectCopiedBinary } from "../../src/analysis/mftTimeHints.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

// The INC-2026-028 decoy: a renamed copy of cmd.exe. The copy's $SI Created and $FN Created record the
// drop; $SI LastModified is cmd.exe's own build date, carried over by the copy (#1422).
const SI_CREATED = "2026-09-19T11:28:24.4392589Z";
const SI_MODIFIED = "2025-12-05T02:54:10.1128473Z";

function mftRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    _Source: "DetectRaptor.Windows.Detection.MFT",
    Fqdn: "DESKTOP-16OJFO6.localdomain",
    Detection: { Name: "Suspicious Location", StringHit: "secretsdump.exe", Criticality: "High" },
    OSPath: "\\\\.\\C:\\Users\\Public\\Attacker\\share\\secretsdump.exe",
    InUse: true,
    IsDir: false,
    SITimestamps: {
      Created0x10: SI_CREATED,
      LastModified0x10: SI_MODIFIED,
      LastRecordChange0x10: "2026-09-19T11:28:24.4679154Z",
      LastAccess0x10: "2026-09-19T11:34:18.8651387Z",
    },
    FNTimestamps: {
      Created0x30: SI_CREATED,
      LastModified0x30: SI_CREATED,
      LastRecordChange0x30: SI_CREATED,
      LastAccess0x30: SI_CREATED,
    },
    ...over,
  };
}

function ev(): MappedEvent {
  return {
    timestamp: SI_CREATED,
    description: "DetectRaptor MFT detection: Suspicious Location — secretsdump.exe",
    severity: "High",
    mitre: [],
    aggKey: "k",
    sources: ["Velociraptor"],
  };
}

describe("detectCopiedBinary — $SI modified before $SI created is a copy", () => {
  it("fires on the decoy row and names both times", () => {
    const v = detectCopiedBinary(SI_CREATED, SI_MODIFIED);
    // The verdict leads, so a clipped note still says what it is (#1558).
    expect(v?.note).toMatch(
      /^copied file, not timestomp \(\$SI Created = \$FN Created; modified time inherited from the source\)/,
    );
    expect(v?.note).toContain("modified 2025-12-05T02:54:10Z");
    expect(v?.note).toContain("created 2026-09-19T11:28:24Z");
  });

  it("stays silent when modified is at or after created (a file that grew here)", () => {
    expect(detectCopiedBinary(SI_CREATED, SI_CREATED)).toBeNull();
    expect(detectCopiedBinary("2026-09-19T11:28:24Z", "2026-09-19T12:00:00Z")).toBeNull();
  });

  it("stays silent inside the threshold (clock jitter is not a copy)", () => {
    expect(detectCopiedBinary("2026-09-19T11:28:24Z", "2026-09-19T11:20:00Z")).toBeNull();
    expect(detectCopiedBinary("2026-09-19T11:28:24Z", "2026-09-19T11:20:00Z", 60_000)).not.toBeNull();
  });

  it("stays silent on an unparseable or missing time", () => {
    expect(detectCopiedBinary("", SI_MODIFIED)).toBeNull();
    expect(detectCopiedBinary(SI_CREATED, "not a time")).toBeNull();
  });
});

describe("applyMftTimeHints — description-only lead, no grade, no technique", () => {
  it("appends the copied-binary note and leaves severity and MITRE alone", () => {
    const m = ev();
    applyMftTimeHints(mftRow(), m);
    expect(m.description).toMatch(
      /— copied file, not timestomp \(.*\): modified 2025-12-05T02:54:10Z, created 2026-09-19T11:28:24Z/,
    );
    expect(m.severity).toBe("High");
    expect(m.mitre).toEqual([]);
  });

  it("reads top-level Created0x10 / LastModified0x10 as well as the nested form", () => {
    const m = ev();
    applyMftTimeHints(
      { IsDir: false, Created0x10: SI_CREATED, LastModified0x10: SI_MODIFIED, Created0x30: SI_CREATED },
      m,
    );
    expect(m.description).toContain("copied file");
  });

  it('without $FN it still records the copy, but makes no "not timestomp" claim (#1558)', () => {
    const m = ev();
    applyMftTimeHints({ IsDir: false, Created0x10: SI_CREATED, LastModified0x10: SI_MODIFIED }, m);
    expect(m.description).toContain("copied file ($FN not collected, timestomp not checked)");
    expect(m.description).not.toContain("not timestomp (");
  });

  it("skips directories and rows without $SI times", () => {
    const dir = ev();
    applyMftTimeHints(mftRow({ IsDir: true }), dir);
    expect(dir.description).not.toContain("copied file");
    const bare = ev();
    applyMftTimeHints({ OSPath: "C:\\x.exe" }, bare);
    expect(bare.description).not.toContain("copied file");
  });

  it("still flags $SI-before-$FN backdating as timestomping (moved, not changed)", () => {
    const m = ev();
    applyMftTimeHints(
      mftRow({
        SITimestamps: { Created0x10: "2021-01-01T00:00:00Z", LastModified0x10: "2021-01-01T00:00:00Z" },
        FNTimestamps: { Created0x30: SI_CREATED },
      }),
      m,
    );
    expect(m.description).toMatch(/timestomping/i);
    expect(m.mitre).toContain("T1070.006");
    expect(m.description).not.toContain("copied file");
  });

  it("through the Velociraptor importer: the DetectRaptor MFT row carries the note, keeps its grade", () => {
    const r = parseVelociraptorJson(JSON.stringify([mftRow()]));
    const hit = r.events.find((e) => /secretsdump\.exe/.test(e.description));
    expect(hit?.description).toContain("copied file, not timestomp");
    expect(hit?.timestamp.slice(0, 19)).toBe("2026-09-19T11:28:24");
    expect(hit?.mitreTechniques ?? []).not.toContain("T1070.006");
  });
});
