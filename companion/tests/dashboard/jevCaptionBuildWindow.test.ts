// The review caption accounts for build-window rows it set aside (#1700), and its sum closes on the
// rows it READ when a cap held some back (Codex review of #1700): graded + already analysed + build
// window = read; read + unread = matched.
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

describe("the review caption and the build window (#1700)", () => {
  it("names the rows set aside as the host's build, and closes the sum on every row that matched", () => {
    const line = text(
      api().jevCaptionHtml(
        { matched: 300, read: 300, alreadyAnalyzed: 60, buildWindow: 216, graded: 24, rows: [] },
        counts,
      ),
    );
    expect(line).toMatch(/Graded 24 archive row/);
    expect(line).toMatch(/216 were set aside because they sit inside the host's own build window/);
    expect(line).toMatch(/60 were skipped because the case has already analysed them/);
    expect(line).toMatch(/accounts for all 300 row\(s\) that matched/);
  });

  it("closes the sum on the rows READ when the cap held rows back", () => {
    const line = text(
      api().jevCaptionHtml(
        {
          matched: 500,
          read: 300,
          alreadyAnalyzed: 60,
          buildWindow: 216,
          graded: 24,
          capped: true,
          cap: 300,
          rows: [],
        },
        counts,
      ),
    );
    expect(line).toMatch(/accounts for all 300 row\(s\) read/);
    expect(line).not.toMatch(/accounts for all 500/);
    expect(line).toMatch(/200 matching row\(s\) were never read/);
  });

  it("says nothing was left to grade when every candidate was build-window activity", () => {
    const line = text(
      api().jevCaptionHtml(
        { matched: 216, read: 216, alreadyAnalyzed: 0, buildWindow: 216, graded: 0, rows: [] },
        counts,
      ),
    );
    expect(line).toMatch(/Graded 0 archive row/);
    expect(line).toMatch(/Nothing was left for this review to grade/);
  });

  it("keeps the old wording when nothing was set aside", () => {
    const line = text(
      api().jevCaptionHtml({ matched: 10, read: 10, alreadyAnalyzed: 0, graded: 10, rows: [] }, counts),
    );
    expect(line).toMatch(/That is every row that matched, out of 10/);
    expect(line).not.toMatch(/build window/);
  });
});
