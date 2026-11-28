import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #3085, report §4.8: the From/To "Lateral movement" table and the paths table carry only directed
// hops; hosts that merely share a binary or account get their own table and never a From/To row.

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-20T08:00:00Z",
    description: "",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const HASH = "cd".repeat(32);
const logonFrom = (id: string, source: string, target: string, timestamp: string) =>
  ev({
    id,
    asset: target,
    timestamp,
    description: `Windows Security Successful logon (EID 4624) - CORP\\ops - LogonType=3 - WorkstationName=${source} @ ${target} [Network]`,
  });

function report(): string {
  const s = emptyState("c1");
  s.forensicTimeline.push(
    ev({ id: "s0", asset: "HOST-SRC", description: "PsExec.exe started" }),
    logonFrom("la", "HOST-SRC", "HOST-A", "2026-05-20T09:00:00Z"),
    logonFrom("lb", "HOST-SRC", "HOST-B", "2026-05-20T09:30:00Z"),
    ev({
      id: "h1",
      asset: "HOST-A",
      sha256: HASH,
      path: "D:\\drop\\to|ol.exe",
      timestamp: "2026-05-20T10:00:00Z",
    }),
    ev({
      id: "h2",
      asset: "HOST-B",
      sha256: HASH,
      path: "D:\\drop\\to|ol.exe",
      timestamp: "2026-05-20T10:05:00Z",
    }),
  );
  return renderMarkdownReport(s);
}

const section = (md: string, heading: string) => {
  const start = md.indexOf(heading);
  expect(start, heading).toBeGreaterThan(-1);
  const rest = md.slice(start + heading.length);
  const end = rest.search(/\n\*\*|\n#/);
  return end === -1 ? rest : rest.slice(0, end);
};

describe("report §4.8 — directed lateral movement vs shared links (#3085)", () => {
  it("lists only directed hops in the From/To table", () => {
    const rows = section(report(), "**Lateral movement**\n")
      .split("\n")
      .filter((l) => l.startsWith("| HOST"));
    expect(
      rows.map((r) =>
        r
          .split("|")
          .slice(1, 3)
          .map((c) => c.trim()),
      ),
    ).toEqual([
      ["HOST-SRC", "HOST-A"],
      ["HOST-SRC", "HOST-B"],
    ]);
  });

  it("shows the fan-out as two paths, never HOST-A → HOST-B", () => {
    const paths = section(report(), "**Lateral movement paths**");
    expect(paths).toContain("HOST-SRC → HOST-A");
    expect(paths).toContain("HOST-SRC → HOST-B");
    expect(paths).not.toContain("HOST-A → HOST-B");
  });

  it("puts the shared binary in its own table, with the cell escaped", () => {
    const shared = section(report(), "**Hosts that share a binary or account**");
    expect(shared).toContain("It does not say which host moved to which.");
    expect(shared).toMatch(/\| HOST-A, HOST-B \| to\\\|ol\.exe \| binary \|/);
  });
});
