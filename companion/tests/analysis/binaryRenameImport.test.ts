// mapBinaryRename (DetectRaptor BinaryRename) — direct tests (#2170). The grade comes from what the
// file IS (its OriginalFilename), never from the name the attacker gave it.
import { describe, expect, it } from "vitest";
import { mapBinaryRename } from "../../src/analysis/binaryRenameImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";
import { splitDerivedNotes } from "../../src/analysis/derivedNote.js";

const SHA = "b".repeat(64);
const TS = "2026-01-01T00:00:00Z";

const renamedCmd = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  OSPath: "C:\\Program Files\\App\\java.exe",
  Name: "java.exe",
  VersionInformation: { OriginalFilename: "Cmd.Exe", CompanyName: "Microsoft Corporation" },
  Hash: { SHA256: SHA.toUpperCase(), MD5: "c".repeat(32) },
  ...over,
});

describe("mapBinaryRename — happy path", () => {
  it("grades a renamed system utility High with T1036.003 and names the real binary", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapBinaryRename(renamedCmd(), "HOST01", sink, TS);
    expect(e.severity).toBe("High");
    expect(e.mitre).toEqual(["T1036.003", "T1036"]);
    expect(e.description).toContain("Renamed binary — java.exe is really Cmd.Exe (Microsoft Corporation)");
    expect(e.description).toContain("[renamed system utility]");
    expect(e.path).toBe("C:\\Program Files\\App\\java.exe");
    expect(e.asset).toBe("HOST01");
    expect(e.sha256).toBe(SHA);
    expect(e.md5).toBe("c".repeat(32));
    expect(e.timestamp).toBe(TS);
    const iocs = [...sink.values()];
    expect(iocs.some((i) => i.type === "file")).toBe(true);
    expect(iocs.some((i) => i.type === "hash" && i.value === SHA)).toBe(true);
  });

  it("keeps the whole rename fact on the title line when a name or vendor contains ' - '", () => {
    // The dashboard splits a row's title from its details at the FIRST " - ". ProcDump's CompanyName
    // is "Sysinternals - www.sysinternals.com", which cut the title inside the parentheses.
    const e = mapBinaryRename(
      renamedCmd({
        OSPath: "C:\\Tools\\procdump64a - Copy.exe",
        Name: "procdump64a - Copy.exe",
        VersionInformation: {
          OriginalFilename: "procdump",
          CompanyName: "Sysinternals - www.sysinternals.com",
        },
      }),
      "HOST01",
      new Map<string, SiemIoc>(),
      TS,
    );
    const title = e.description.slice(0, e.description.indexOf(" - "));
    expect(title).toContain(
      "Renamed binary — procdump64a — Copy.exe is really procdump (Sysinternals — www.sysinternals.com)",
    );
    expect(e.description).toContain("at C:\\Tools\\procdump64a - Copy.exe"); // the path stays verbatim
    expect(e.path).toBe("C:\\Tools\\procdump64a - Copy.exe");
  });

  it("grades a renamed non-system binary Medium with plain T1036", () => {
    const r = renamedCmd({ VersionInformation: { OriginalFilename: "vendortool.exe" } });
    const e = mapBinaryRename(r, "H", new Map(), TS);
    expect(e.severity).toBe("Medium");
    expect(e.mitre).toEqual(["T1036"]);
  });

  it("does not call a file renamed when its name matches OriginalFilename (Info, no technique)", () => {
    const r = renamedCmd({ Name: "cmd.exe", VersionInformation: { OriginalFilename: "Cmd.Exe" } });
    const e = mapBinaryRename(r, "H", new Map(), TS);
    expect(e.severity).toBe("Info");
    expect(e.mitre).toEqual([]);
  });

  it("lets an explicit rule-pack severity win over the inferred grade", () => {
    const e = mapBinaryRename(renamedCmd({ Severity: "low" }), "H", new Map(), TS);
    expect(e.severity).toBe("Low");
  });

  it("prefers a later Btime over the picked timestamp (the copy's arrival on this host)", () => {
    const e = mapBinaryRename(renamedCmd({ Btime: "2026-06-01T12:00:00Z" }), "H", new Map(), TS);
    expect(e.timestamp).toBe("2026-06-01T12:00:00Z");
  });
});

describe("mapBinaryRename — malformed rows", () => {
  it("does not throw on an empty row and makes no rename claim", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapBinaryRename({}, "", sink, TS);
    expect(e.severity).toBe("Info");
    expect(e.mitre).toEqual([]);
    expect(e.path).toBeUndefined();
    expect(e.asset).toBeUndefined();
    expect(sink.size).toBe(0);
  });

  it("floors a binary with no version resource at Medium without claiming a rename", () => {
    const e = mapBinaryRename({ OSPath: "C:\\x\\tool.exe", Name: "tool.exe" }, "H", new Map(), TS);
    expect(e.severity).toBe("Medium");
    expect(e.mitre).toEqual([]);
    expect(e.description).toContain("carries no OriginalFilename to compare");
  });

  it.each([
    ["VersionInformation as a string", { Name: "a.exe", VersionInformation: "garbage" }],
    ["Hash as a number", { Name: "a.exe", Hash: 42 }],
    ["a non-hex SHA256", { Name: "a.exe", Hash: { SHA256: "x".repeat(64) } }],
    ["an unparseable Btime", { Name: "a.exe", Btime: "not a date" }],
  ])("does not throw on %s", (_name, r) => {
    const e = mapBinaryRename(r, "H", new Map(), TS);
    expect(e.sha256).toBeUndefined();
    expect(typeof e.description).toBe("string");
    expect(e.timestamp).toBe(TS);
  });
});

// #2885: the base text was capped AFTER the "@ HOST" suffix, so a row whose names, vendor and path
// all sat near their own caps left "… @ WORKSTATION-LA" — and past 600 dropped the host. The rename
// note goes on after the base, so the host is checked at the end of the base.
describe("mapBinaryRename — the host suffix survives the length cap", () => {
  const HOST = "WORKSTATION-LAB-0001";
  const STAGED = "C:\\Users\\a\\AppData\\Local\\Temp\\";

  it("keeps the '@ HOST' suffix whole at the end of the base however long the vendor is", () => {
    for (let n = 0; n <= 80; n++) {
      const row = {
        OSPath: `${STAGED}${"d".repeat(200 - STAGED.length - 4)}.exe`,
        Name: `${"n".repeat(116)}.exe`,
        VersionInformation: { OriginalFilename: `${"o".repeat(116)}.exe`, CompanyName: "v".repeat(n) },
      };
      const { base } = splitDerivedNotes(mapBinaryRename(row, HOST, new Map(), TS).description);
      expect(base.length).toBeLessThanOrEqual(600);
      expect(base.endsWith(`@ ${HOST}`)).toBe(true);
    }
  });
});
