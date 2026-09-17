import { describe, it, expect } from "vitest";
import { bamFields } from "../../src/analysis/bamRowMap.js";

const BAM_ROW = {
  SID: "S-1-5-21-111-222-333-1001",
  UserName: "alice",
  Binary: "\\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\tool.exe",
  Bam_time: "2026-05-02T10:00:00.000Z",
};
const CTX = { artifact: "Windows.Forensics.Bam", host: "DESKTOP-01" };

describe("bamFields — a BAM finding streamed through Velociraptor", () => {
  it("names the binary, last-run time and user in the title", () => {
    expect(bamFields(BAM_ROW, CTX)!.description).toBe(
      "Velociraptor BAM: tool.exe last run 2026-05-02T10:00:00.000Z (user alice)",
    );
  });

  it("falls back to the SID when UserName is absent", () => {
    const { UserName: _drop, ...row } = BAM_ROW;
    expect(bamFields(row, CTX)!.description).toContain("(user S-1-5-21-111-222-333-1001)");
  });

  it("carries no severity of its own — Info, like Prefetch", () => {
    expect(bamFields(BAM_ROW, CTX)!.severity).toBe("Info");
  });

  it("carries the raw Binary path as identity, no hash", () => {
    const f = bamFields(BAM_ROW, CTX)!;
    expect(f.path).toBe(BAM_ROW.Binary);
    expect(f.sha256).toBeUndefined();
    expect(f.md5).toBeUndefined();
  });

  it("aggKey excludes Bam_time — a later re-collection updates the same finding, not a new one", () => {
    const later = { ...BAM_ROW, Bam_time: "2026-06-01T00:00:00.000Z" };
    expect(bamFields(BAM_ROW, CTX)!.aggKey).toBe(bamFields(later, CTX)!.aggKey);
  });

  it("is undefined without all three of SID, Binary, Bam_time", () => {
    expect(bamFields({ ...BAM_ROW, SID: "" }, CTX)).toBeUndefined();
    expect(bamFields({ ...BAM_ROW, Binary: "" }, CTX)).toBeUndefined();
    expect(bamFields({ ...BAM_ROW, Bam_time: "" }, CTX)).toBeUndefined();
  });

  it("is undefined when the artifact does not name BAM, even with all three columns present", () => {
    // The columns alone (SID, Binary) are generic Windows names shared with other artifacts —
    // requires the artifact-name proof too, mirroring thorFields()'s own reasoning (#985 item 2/3).
    expect(
      bamFields(BAM_ROW, { artifact: "Windows.Forensics.SomeOtherArtifact", host: "H" }),
    ).toBeUndefined();
  });

  it("neutralizes ' - ' in a username so splitEventTitle never mis-splits the title", () => {
    const row = { ...BAM_ROW, UserName: "evil - admin" };
    expect(bamFields(row, CTX)!.description).not.toContain(" - admin)");
    expect(bamFields(row, CTX)!.description).toContain("evil — admin");
  });

  it("is undefined for a non-object row", () => {
    expect(bamFields(null, CTX)).toBeUndefined();
    expect(bamFields("not a row", CTX)).toBeUndefined();
  });
});
