import { describe, it, expect } from "vitest";
import { pickTime } from "../../src/analysis/veloRowTime.js";

// #1415. A copied binary keeps the SOURCE file's $SI LastModified — cmd.exe's build date survives the
// copy, while every Created stamp records the drop. Dating a nested MFT row from LastModified0x10
// placed each decoy in case INC-2026-028 at 2025-12-05 instead of the 2026-09-19 drop, and the AI
// synthesized a staging wave and a 264-day dwell out of it. The nested block must rank the streams the
// way the top-level block already does: $FN Created, then $SI Created, then the modified/changed times.
describe("pickTime — nested MFT timestamp containers", () => {
  // Verbatim shape of the DetectRaptor.Windows.Detection.MFT row that misdated the decoys.
  const copiedCmd = {
    OSPath: "C:\\Users\\Public\\svchost.exe",
    SITimestamps: {
      Created0x10: "2026-09-19T11:28:24Z",
      LastModified0x10: "2025-12-05T02:54:10Z",
      LastRecordChange0x10: "2026-09-19T11:28:24Z",
    },
    FNTimestamps: {
      Created0x30: "2026-09-19T11:28:24Z",
      LastModified0x30: "2026-09-19T11:28:24Z",
    },
    _ts: 1_790_000_000,
  };

  it("dates a copied binary at its $FN Created, not the source file's $SI LastModified", () => {
    expect(pickTime(copiedCmd)).toMatch(/^2026-09-19T11:28:24/);
  });

  it("prefers $FN Created over $SI Created when the two differ (hardest to timestomp)", () => {
    const row = {
      SITimestamps: { Created0x10: "2009-07-14T01:14:24Z", LastModified0x10: "2009-07-14T01:14:24Z" },
      FNTimestamps: { Created0x30: "2026-09-19T11:28:24Z" },
    };
    expect(pickTime(row)).toMatch(/^2026-09-19T11:28:24/);
  });

  it("with only SITimestamps, uses Created0x10 before LastModified0x10", () => {
    const row = {
      SITimestamps: {
        Created0x10: "2026-09-19T11:28:24Z",
        LastModified0x10: "2025-12-05T02:54:10Z",
        LastRecordChange0x10: "2026-09-19T11:28:25Z",
      },
    };
    expect(pickTime(row)).toMatch(/^2026-09-19T11:28:24/);
  });

  it("still falls through to LastModified0x10, then LastRecordChange0x10, when no Created is present", () => {
    expect(
      pickTime({
        SITimestamps: {
          LastModified0x10: "2026-08-30T15:03:17Z",
          LastRecordChange0x10: "2026-08-31T00:00:00Z",
        },
      }),
    ).toMatch(/^2026-08-30T15:03:17/);
    expect(pickTime({ SITimestamps: { LastRecordChange0x10: "2026-08-31T00:00:00Z" } })).toMatch(
      /^2026-08-31T00:00:00/,
    );
  });

  it("keeps the same order for the top-level (un-nested) MFT columns", () => {
    const row = {
      Created0x10: "2026-09-19T11:28:24Z",
      LastModified0x10: "2025-12-05T02:54:10Z",
      Created0x30: "2026-09-19T11:28:25Z",
    };
    expect(pickTime(row)).toMatch(/^2026-09-19T11:28:25/);
  });
});
