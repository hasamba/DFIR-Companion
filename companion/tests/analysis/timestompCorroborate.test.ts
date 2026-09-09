import { describe, it, expect } from "vitest";
import {
  sameFile,
  corroborateTimestomp,
  corroborateTimestompsOnTimeline,
  type TimeObservation,
} from "../../src/analysis/timestompCorroborate.js";

const mft = (over: Partial<TimeObservation> = {}): TimeObservation => ({
  source: "MFT",
  path: "C:\\Windows\\Temp\\evil.exe",
  created: "2019-01-01T00:00:00Z",
  modified: "2019-01-01T00:00:00Z",
  ...over,
});

describe("sameFile — a basename is not identity", () => {
  it("matches on a full path", () => {
    expect(sameFile(mft(), mft({ source: "ShimCache" }))).toBe(true);
  });

  it("matches case- and separator-insensitively", () => {
    expect(sameFile(mft(), mft({ source: "ShimCache", path: "c:/windows/temp/EVIL.EXE" }))).toBe(true);
  });

  // Every host has a dozen setup.exe. Pairing two of them invents a discrepancy from two unrelated
  // files, which is worse than missing one.
  it("refuses to match two bare filenames", () => {
    const a = mft({ path: "evil.exe" });
    const b = mft({ source: "ShimCache", path: "evil.exe" });
    expect(sameFile(a, b)).toBe(false);
  });

  it("refuses when only one side has a full path", () => {
    expect(sameFile(mft(), mft({ source: "ShimCache", path: "evil.exe" }))).toBe(false);
  });

  it("prefers a file reference over the path when both carry one", () => {
    const a = mft({ reference: "C:|100-1", path: "C:\\a\\x.exe" });
    const b = mft({ source: "ShimCache", reference: "C:|100-1", path: "C:\\b\\x.exe" });
    expect(sameFile(a, b)).toBe(true);
    const c = mft({ reference: "C:|999-1", path: "C:\\a\\x.exe" });
    expect(sameFile(a, c)).toBe(false);
  });

  it("does not match different files", () => {
    expect(sameFile(mft(), mft({ source: "ShimCache", path: "C:\\Windows\\other.exe" }))).toBe(false);
  });
});

describe("corroborateTimestomp", () => {
  const base = { severity: "Medium" as const, note: "$SI predates $FN." };

  it("raises to High when ShimCache disagrees with the MFT", () => {
    const shim: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\Temp\\evil.exe",
      modified: "2026-01-01T10:00:00Z",
    };
    const v = corroborateTimestomp(mft(), [shim], base);
    expect(v?.severity).toBe("High");
    expect(v?.mitre).toContain("T1070.006");
    expect(v?.corroborations[0].kind).toBe("shimcache-disagrees");
    expect(v?.note).toContain("independent of the MFT disagrees");
  });

  // DIRECTION is the discriminator. A backdated MFT is EARLIER than the historical record; the
  // opposite ordering is what an ordinary update at the same path produces, and a path match cannot
  // tell one file version from its successor.
  it("does not corroborate when ShimCache is OLDER than the MFT, which is an update", () => {
    const shim: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\Temp\\evil.exe",
      modified: "2015-01-01T00:00:00Z",
    };
    const v = corroborateTimestomp(mft(), [shim], base);
    expect(v?.severity).toBe("Medium");
    expect(v?.corroborations[0].kind).toBe("shimcache-newer-mft");
    expect(v?.note).toContain("updated or");
  });

  it("says nothing when the independent record agrees", () => {
    const shim: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\Temp\\evil.exe",
      modified: "2019-01-01T00:00:00Z",
    };
    expect(corroborateTimestomp(mft(), [shim], base)).toBeNull();
  });

  it("tolerates a small difference between two independently recorded times", () => {
    const shim: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\Temp\\evil.exe",
      modified: "2019-01-01T00:00:01Z",
    };
    expect(corroborateTimestomp(mft(), [shim], base)).toBeNull();
  });

  // The rule the issue calls out by name.
  it("never lets BASIC_INFO_CHANGE carry a verdict on its own", () => {
    const usn: TimeObservation = {
      source: "USN",
      path: "C:\\Windows\\Temp\\evil.exe",
      reasons: ["BASIC_INFO_CHANGE"],
    };
    // With no MFT-side signal there is nothing to report at all.
    expect(corroborateTimestomp(mft(), [usn], null)).toBeNull();
    // With one, it is context that does NOT raise to High.
    const v = corroborateTimestomp(mft(), [usn], base);
    expect(v?.severity).toBe("Medium");
    expect(v?.note).toContain("read-only, hidden, archive and system flags");
    expect(v?.note).toContain("remains a lead");
  });

  it("does not corroborate from a different file's record", () => {
    const shim: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\other.exe",
      modified: "2026-01-01T10:00:00Z",
    };
    expect(corroborateTimestomp(mft(), [shim], base)).toBeNull();
  });

  // Agreement is not exoneration: a thorough tool rewrites more than one place.
  it("never presents agreement as clearing the file", () => {
    const shim: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\Temp\\evil.exe",
      modified: "2026-01-01T10:00:00Z",
    };
    const v = corroborateTimestomp(mft(), [shim], base);
    expect(v?.note).toContain("would not clear the file");
  });

  it("can surface a discrepancy the single-row check could not see", () => {
    // No $SI/$FN signal at all, yet the historical record is later than the MFT now holds.
    const shim: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\Temp\\evil.exe",
      modified: "2026-01-01T10:00:00Z",
    };
    const v = corroborateTimestomp(mft(), [shim], null);
    expect(v?.severity).toBe("High");
  });

  it("returns nothing when there is neither a signal nor a corroborating record", () => {
    expect(corroborateTimestomp(mft(), [], null)).toBeNull();
    expect(corroborateTimestomp(mft(), [], base)).toBeNull();
  });
});

describe("corroborateTimestompsOnTimeline — the merge pass", () => {
  const mftEvent = (over: Record<string, unknown> = {}) => ({
    description: "MFT: C:\\Windows\\Temp\\evil.exe",
    severity: "Medium" as const,
    mitreTechniques: ["T1070.006"],
    path: "C:\\Windows\\Temp\\evil.exe",
    sources: ["MFT"],
    timestamp: "2019-01-01T00:00:00Z",
    fileModified: "2019-01-01T00:00:00Z",
    ...over,
  });
  const shimEvent = (over: Record<string, unknown> = {}) => ({
    description: "ShimCache: C:\\Windows\\Temp\\evil.exe",
    severity: "Info" as const,
    mitreTechniques: [] as string[],
    path: "C:\\Windows\\Temp\\evil.exe",
    sources: ["ShimCache"],
    timestamp: "2026-01-01T10:00:00Z",
    fileModified: "2026-01-01T10:00:00Z",
    ...over,
  });

  it("raises the MFT event when ShimCache disagrees", () => {
    const [e] = corroborateTimestompsOnTimeline([mftEvent(), shimEvent()]);
    expect(e.severity).toBe("High");
    expect(e.description).toContain("[timestomp corroboration:");
    expect(e.description).toContain("ShimCache recorded");
  });

  it("leaves the ShimCache event itself alone", () => {
    const [, s] = corroborateTimestompsOnTimeline([mftEvent(), shimEvent()]);
    expect(s.description).not.toContain("[timestomp corroboration:");
    expect(s.severity).toBe("Info");
  });

  it("does nothing when the two artifacts agree", () => {
    const [e] = corroborateTimestompsOnTimeline([
      mftEvent(),
      shimEvent({ fileModified: "2019-01-01T00:00:00Z" }),
    ]);
    expect(e.description).not.toContain("[timestomp corroboration:");
  });

  it("does not corroborate from a different file", () => {
    const [e] = corroborateTimestompsOnTimeline([mftEvent(), shimEvent({ path: "C:\\Windows\\other.exe" })]);
    expect(e.description).not.toContain("[timestomp corroboration:");
  });

  it("is idempotent", () => {
    const once = corroborateTimestompsOnTimeline([mftEvent(), shimEvent()]);
    const twice = corroborateTimestompsOnTimeline(once);
    expect(twice[0].description).toBe(once[0].description);
  });

  it("costs nothing when no timestomp signal exists in the case", () => {
    const plain = [shimEvent(), shimEvent({ path: "C:\\x\\y.exe" })];
    expect(corroborateTimestompsOnTimeline(plain)).toBe(plain);
  });

  it("never lowers a severity the event already had", () => {
    const [e] = corroborateTimestompsOnTimeline([
      mftEvent({ severity: "Critical" }),
      shimEvent({ fileModified: "2019-01-01T00:00:00Z" }),
    ]);
    expect(e.severity).toBe("Critical");
  });
});

// The two artifacts do not write paths the same way. This is the test that would have caught the
// feature silently never firing in production while every other test passed.
describe("path forms the real tools actually emit", () => {
  it("matches MFTECmd's volume-rooted path against ShimCache's drive-qualified one", () => {
    const mftEcmd: TimeObservation = {
      source: "MFT",
      path: ".\\Windows\\Temp\\evil.exe",
      modified: "2019-01-01T00:00:00Z",
    };
    const shimParser: TimeObservation = {
      source: "ShimCache",
      path: "C:\\Windows\\Temp\\evil.exe",
      modified: "2026-01-01T10:00:00Z",
    };
    expect(sameFile(mftEcmd, shimParser)).toBe(true);
    expect(corroborateTimestomp(mftEcmd, [shimParser], null)?.severity).toBe("High");
  });

  it("handles the long-path prefix", () => {
    const a: TimeObservation = { source: "MFT", path: "\\\\?\\C:\\Windows\\Temp\\x.exe" };
    const b: TimeObservation = { source: "ShimCache", path: "C:\\Windows\\Temp\\x.exe" };
    expect(sameFile(a, b)).toBe(true);
  });

  // Dropping the volume to make the forms comparable is also what makes this possible.
  it("refuses to match the same path on two different hosts", () => {
    const a: TimeObservation = { source: "MFT", path: ".\\Windows\\Temp\\x.exe", host: "HOST-A" };
    const b: TimeObservation = { source: "ShimCache", path: "C:\\Windows\\Temp\\x.exe", host: "HOST-B" };
    expect(sameFile(a, b)).toBe(false);
  });

  it("proceeds when neither observation records a host, the single-host import case", () => {
    const a: TimeObservation = { source: "MFT", path: ".\\Windows\\Temp\\x.exe" };
    const b: TimeObservation = { source: "ShimCache", path: "C:\\Windows\\Temp\\x.exe" };
    expect(sameFile(a, b)).toBe(true);
  });
});

// A known limitation, recorded rather than papered over: ShimCache rows arrive Info, and the
// default forensic floor demotes them to the super-timeline, which this pass does not read. So
// corroboration fires when both artifacts are in the forensic timeline — the analyst lowered the
// floor, or the content tagger promoted the ShimCache row — and not otherwise.
describe("what the pass can and cannot see", () => {
  it("finds nothing when the corroborating artifact is not in the timeline it reads", () => {
    const mftOnly = [
      {
        description: "MFT: C:\\Windows\\Temp\\evil.exe",
        severity: "Medium" as const,
        mitreTechniques: ["T1070.006"],
        path: "C:\\Windows\\Temp\\evil.exe",
        sources: ["MFT"],
        timestamp: "2019-01-01T00:00:00Z",
        fileModified: "2019-01-01T00:00:00Z",
      },
    ];
    const [e] = corroborateTimestompsOnTimeline(mftOnly);
    expect(e.description).not.toContain("[timestomp corroboration:");
    expect(e.severity).toBe("Medium");
  });
});
