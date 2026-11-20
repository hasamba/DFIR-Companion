import { describe, it, expect } from "vitest";
import { remediationChecksSection } from "../../src/reports/remediationSection.js";
import { emptyState, type RemediationBoundaryView } from "../../src/analysis/stateTypes.js";

// #2763: an artifact value or a host spelling holding a backtick closed the hand-written single
// backtick code span early, so the rest of the value rendered as live Markdown / raw HTML.
function boundary(value: string, spelling: string): RemediationBoundaryView {
  return {
    id: "rb-1",
    host: "WS01",
    artifact: { kind: "file", value },
    remediatedAt: "2026-01-01T00:00:00Z",
    windowHours: 24,
    status: "checked-not-observed",
    statusReceiptId: "rc-1",
    evidence: [],
    receipts: [
      {
        id: "rc-1",
        at: "2026-01-02T00:00:00Z",
        spellings: [spelling, "ws01"],
        window: { from: "2026-01-01T00:00:00Z", to: "2026-01-02T00:00:00Z", open: false },
        coverage: [],
        families: [],
        hitTotal: 0,
        hitsByClass: {},
        truncated: false,
        undated: 0,
        coverageGapped: false,
        inconsistent: false,
      },
    ],
  };
}

function render(value: string, spelling: string): string[] {
  const state = { ...emptyState("c1"), remediationBoundaries: [boundary(value, spelling)] };
  const lines: string[] = [];
  remediationChecksSection(state, lines);
  return lines;
}

describe("remediationChecksSection code spans (#2763)", () => {
  it("fences an artifact value holding a backtick with a longer fence", () => {
    const lines = render("a`<img src=x onerror=1>`b", "WS01");
    const heading = lines.find((l) => l.startsWith("### "));
    expect(heading).toBe("### file `` a`<img src=x onerror=1>`b `` on WS01");
  });

  it("fences a host spelling holding a backtick with a longer fence", () => {
    const lines = render("evil.exe", "h`ost`<b>x</b>");
    const check = lines.find((l) => l.startsWith("- Check "));
    expect(check).toContain("host spellings `` h`ost`<b>x</b> ``, ` ws01 `;");
  });

  it("still renders a plain value as a code span", () => {
    const heading = render("evil.exe", "WS01").find((l) => l.startsWith("### "));
    expect(heading).toBe("### file ` evil.exe ` on WS01");
  });
});
