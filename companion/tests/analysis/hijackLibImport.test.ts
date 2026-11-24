// mapHijackLib (DetectRaptor HijackLibsMFT) — direct tests (#2170). The signal is LOCATION: a DLL
// in its ExpectedLocation is Low, the same name elsewhere is a Medium side-load candidate.
import { describe, expect, it } from "vitest";
import { mapHijackLib } from "../../src/analysis/hijackLibImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

const ARTIFACT = "DetectRaptor.Windows.Detection.HijackLibsMFT";
const SHA = "a".repeat(64);

const row = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  OSPath: "C:\\Users\\Public\\Downloads\\version.dll",
  HijackLibInfo: {
    DllName: "version.dll",
    Vendor: "Microsoft",
    Type: "Sideloading",
    ExpectedLocation: "\\\\Windows\\\\System32",
    Url: "https://hijacklibs.net/entries/microsoft/built-in/version.html",
    ExecutableSHA256: SHA.toUpperCase(),
  },
  ...over,
});

describe("mapHijackLib — happy path", () => {
  it("grades a DLL outside its vendor location as a Medium side-load candidate", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapHijackLib(row(), ARTIFACT, "HOST01", sink);
    expect(e.severity).toBe("Medium");
    expect(e.mitre).toEqual(["T1574.002"]);
    expect(e.description).toContain(`Velociraptor [${ARTIFACT}]: hijackable DLL version.dll (Microsoft)`);
    expect(e.description).toContain("OUTSIDE its expected vendor location");
    expect(e.path).toBe("C:\\Users\\Public\\Downloads\\version.dll");
    expect(e.asset).toBe("HOST01");
    expect(e.sha256).toBe(SHA);
    expect(e.sources).toEqual(["Velociraptor"]);
    expect([...sink.values()].some((i) => i.type === "file")).toBe(true);
  });

  it("grades the same DLL inside its ExpectedLocation as Low", () => {
    const e = mapHijackLib(
      row({ OSPath: "C:\\Windows\\System32\\version.dll" }),
      ARTIFACT,
      "HOST01",
      new Map(),
    );
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("in its vendor location (likely legitimate)");
  });

  it("maps a search-order Type to T1574.001 and an unknown Type to the parent technique", () => {
    const so = row({ HijackLibInfo: { DllName: "x.dll", Type: "Search Order" } });
    expect(mapHijackLib(so, ARTIFACT, "H", new Map()).mitre).toEqual(["T1574.001"]);
    const other = row({ HijackLibInfo: { DllName: "x.dll", Type: "Environment Variable" } });
    expect(mapHijackLib(other, ARTIFACT, "H", new Map()).mitre).toEqual(["T1574"]);
  });

  it("treats a malformed ExpectedLocation regex as 'cannot confirm legitimate' (Medium)", () => {
    const bad = row({ HijackLibInfo: { DllName: "x.dll", ExpectedLocation: "([unclosed" } });
    expect(mapHijackLib(bad, ARTIFACT, "H", new Map()).severity).toBe("Medium");
  });
});

describe("mapHijackLib — malformed rows", () => {
  it.each([
    ["HijackLibInfo as a string", { OSPath: "C:\\x\\a.dll", HijackLibInfo: "not-an-object" }],
    ["HijackLibInfo as null", { OSPath: "C:\\x\\a.dll", HijackLibInfo: null }],
    ["an empty row", {}],
  ])("does not throw on %s and falls back to defaults", (_name, r) => {
    const e = mapHijackLib(r, ARTIFACT, "", new Map());
    expect(e.severity).toBe("Medium");
    expect(e.mitre).toEqual(["T1574"]);
    expect(e.sha256).toBeUndefined();
    expect(e.asset).toBeUndefined();
    expect(typeof e.description).toBe("string");
  });

  it("names the DLL 'a DLL' when neither DllName nor FileName is present", () => {
    expect(mapHijackLib({}, ARTIFACT, "", new Map()).description).toContain("hijackable DLL a DLL");
  });

  it("drops a SHA256 that is not 64 hex characters", () => {
    const r = row({ HijackLibInfo: { DllName: "x.dll", ExecutableSHA256: "zz-not-a-hash" } });
    expect(mapHijackLib(r, ARTIFACT, "H", new Map()).sha256).toBeUndefined();
  });
});

// The title (before the first " - ") is the DLL, vendor and where it sits. The verdict, the
// side-load type and the hijacklibs.net link are explanation and belong in the details.
describe("mapHijackLib — title vs details", () => {
  const split = (d: string): [string, string] => {
    const i = d.indexOf(" - ");
    return i < 0 ? [d, ""] : [d.slice(0, i), d.slice(i + 3)];
  };

  it("ends the title at the path and moves the explanation to the details", () => {
    const [title, rest] = split(mapHijackLib(row(), ARTIFACT, "HOST01", new Map()).description);
    expect(title).toBe(
      `Velociraptor [${ARTIFACT}]: hijackable DLL version.dll (Microsoft) at C:\\Users\\Public\\Downloads\\version.dll`,
    );
    expect(rest).toContain("OUTSIDE its expected vendor location — DLL side-load candidate [Sideloading]");
    expect(rest).toContain("https://hijacklibs.net/entries/microsoft/built-in/version.html");
  });

  it("keeps a ' - ' inside the path from cutting the title short", () => {
    const e = mapHijackLib(
      row({ OSPath: "C:\\Tools\\App - Portable\\version.dll" }),
      ARTIFACT,
      "HOST01",
      new Map(),
    );
    expect(split(e.description)[0]).toContain(
      "version.dll (Microsoft) at C:\\Tools\\App — Portable\\version.dll",
    );
    expect(e.path).toBe("C:\\Tools\\App - Portable\\version.dll");
  });

  it("does not leave a trailing ' -' when the row has no host", () => {
    const e = mapHijackLib(row(), ARTIFACT, "", new Map());
    expect(e.description.trimEnd().endsWith(" -")).toBe(false);
  });
});
