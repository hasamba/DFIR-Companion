// The review caption accounts for the collector's own footprint it set aside (#1949): graded +
// already analysed + build window + collector footprint = read.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  jevCaptionHtml(
    result: Record<string, unknown>,
    counts: { shown: number; kept: number; drawn: number },
  ): string;
}
const api = () => loadDashboardModule<Api>("dashboard-jev-review-format.js", ["dashboard-escape.js"]);
const counts = { shown: 0, kept: 0, drawn: 0 };
const text = (html: string) => html.replace(/<[^>]+>/g, "");

describe("the review caption and the collector footprint (#1949)", () => {
  it("names the collector rows set aside and closes the sum on every row that matched", () => {
    const line = text(
      api().jevCaptionHtml(
        {
          matched: 100,
          read: 100,
          alreadyAnalyzed: 40,
          buildWindow: 10,
          collectorFootprint: 12,
          graded: 38,
          rows: [],
        },
        counts,
      ),
    );
    expect(line).toMatch(/Graded 38 archive row/);
    expect(line).toMatch(/12 were set aside because they are the collector's own footprint/);
    expect(line).toMatch(/accounts for all 100 row\(s\) that matched/);
  });

  it("says nothing was left to grade when every candidate was the collector's", () => {
    const line = text(
      api().jevCaptionHtml(
        { matched: 12, read: 12, alreadyAnalyzed: 0, collectorFootprint: 12, graded: 0, rows: [] },
        counts,
      ),
    );
    expect(line).toMatch(/Graded 0 archive row/);
    expect(line).toMatch(/Nothing was left for this review to grade/);
  });

  it("says nothing about the collector when an older server sends no count", () => {
    const line = text(
      api().jevCaptionHtml({ matched: 10, read: 10, alreadyAnalyzed: 0, graded: 10, rows: [] }, counts),
    );
    expect(line).not.toMatch(/collector/);
  });
});
