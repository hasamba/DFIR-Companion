import { describe, it, expect } from "vitest";
import { renderSwimlaneSvg } from "../../src/reports/swimlaneSvg.js";
import { buildSwimlaneData } from "../../src/analysis/swimlane.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SwimlaneData } from "../../src/analysis/swimlane.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("renderSwimlaneSvg", () => {
  it("returns an empty string when there are no dated events", () => {
    expect(renderSwimlaneSvg(buildSwimlaneData([]))).toBe("");
    expect(renderSwimlaneSvg(buildSwimlaneData([ev("e1", ""), ev("e2", "nope")]))).toBe("");
  });

  it("renders an SVG with lane labels and one dot per event", () => {
    const data = buildSwimlaneData([
      ev("e1", "2026-05-01T10:00:00Z", { asset: "WIN-01", severity: "Critical" }),
      ev("e2", "2026-05-01T11:00:00Z", { asset: "WIN-01", severity: "High" }),
      ev("e3", "2026-05-01T12:00:00Z", { asset: "SRV-02", severity: "Low" }),
    ]);
    const svg = renderSwimlaneSvg(data);
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain("</svg>");
    expect(svg).toContain("WIN-01");
    expect(svg).toContain("SRV-02");
    // one <circle> per dated event
    expect(svg.match(/<circle/g)?.length).toBe(3);
    // severity colors present (Critical + High + Low)
    expect(svg).toContain("#d64545");
    expect(svg).toContain("#e0852b");
    expect(svg).toContain("#3f9c54");
    // header reflects the dated-event count
    expect(svg).toContain("3 dated events");
  });

  it("plots a single-instant timeline without dividing by zero", () => {
    const data = buildSwimlaneData([
      ev("e1", "2026-05-01T10:00:00Z", { asset: "WIN-01" }),
    ]);
    const svg = renderSwimlaneSvg(data);
    expect(svg).toContain("<circle");
    expect(svg).not.toContain("NaN");
    expect(svg).not.toContain("Infinity");
  });

  it("caps lanes and adds a truncation note when there are more than 40", () => {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 50; i++) {
      events.push(ev(`e${i}`, `2026-05-01T10:${String(i % 60).padStart(2, "0")}:00Z`, { asset: `HOST-${String(i).padStart(2, "0")}` }));
    }
    const svg = renderSwimlaneSvg(buildSwimlaneData(events));
    expect(svg).toContain("Showing 40/50 lanes");
  });

  it("never emits NaN coordinates for a well-formed dataset", () => {
    const data: SwimlaneData = buildSwimlaneData([
      ev("e1", "2026-05-01T10:00:00Z", { severity: "Critical" }),
      ev("e2", "2026-05-02T10:00:00Z", { severity: "Info" }),
    ], "severity");
    const svg = renderSwimlaneSvg(data);
    expect(svg).not.toContain("NaN");
  });
});
