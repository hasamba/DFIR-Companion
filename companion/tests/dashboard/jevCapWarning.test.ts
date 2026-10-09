// The capped-review warning (#2077): when the default row cap stops a missed-evidence review, the
// panel says how much of the archive it read, how many rows it never reached, and what a full read
// would cost — prominently when the capped run found nothing above Info, because that is when an
// analyst is most likely to stop. Plus the full-read estimate it shows, which scales by rows GRADED.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Plan {
  known: boolean;
  matched: number;
  unread: number;
  costLow: number | null;
  costHigh: number | null;
}
interface Api {
  jevCapWarningHtml(result: Record<string, unknown> | null, opts: { foundNothing: boolean }): string;
  jevFullReadPlan(result: Record<string, unknown> | null): Plan;
  jevFullReadConfirmHtml(plan: Plan): string;
}
const api = () => loadDashboardModule<Api>("dashboard-jev-review-format.js", ["dashboard-escape.js"]);
// What the analyst reads: tags stripped, the escaper's entities decoded ("<1%" is sent as "&lt;1%").
const text = (html: string) =>
  html
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");

const infoRows = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `r${i}`, grade: "Info" }));
// The issue's case: 81,385 matched, the 2,000-row cap read 2,000, 62 of them were graded.
const issueCase = (over: Record<string, unknown> = {}) => ({
  matched: 81385,
  read: 2000,
  alreadyAnalyzed: 1938,
  graded: 62,
  capped: true,
  cap: 2000,
  rows: infoRows(62),
  usage: { costUSD: 0.0031 },
  ...over,
});

describe("the capped-review warning (#2077)", () => {
  it("is a prominent status block when the capped review found nothing above Info", () => {
    const html = api().jevCapWarningHtml(issueCase(), { foundNothing: true });
    expect(html).toMatch(/class="jev-cap-warn"/);
    expect(html).toMatch(/role="status"/);
    expect(html).toMatch(/id="jevOfferAll"/);
    const t = text(html);
    expect(t).toMatch(/Reviewed 2,000 of 81,385 archive rows \(2%\)/);
    expect(t).toMatch(/79,385 archive rows were not read/);
    expect(t).toMatch(/An empty result here is not evidence that nothing was missed\./);
    expect(t).toMatch(/\$0\.13 to \$3\.97/);
  });

  it("is an inline offer, not a block, when the capped review found something", () => {
    const html = api().jevCapWarningHtml(issueCase(), { foundNothing: false });
    expect(html).not.toMatch(/jev-cap-warn/);
    expect(html).toMatch(/class="jev-offer"/);
    expect(html).toMatch(/id="jevOfferAll"/);
    const t = text(html);
    expect(t).toMatch(/Reviewed 2,000 of 81,385 archive rows \(2%\)/);
    expect(t).toMatch(/79,385 archive rows were not read/);
    expect(t).toMatch(/\$0\.13 to \$3\.97/);
    expect(t).not.toMatch(/not evidence that nothing was missed/);
  });

  it("says nothing when the cap did not hold rows back, even with rows unread (#1540)", () => {
    const html = api().jevCapWarningHtml(issueCase({ capped: false, readAll: true }), { foundNothing: true });
    expect(html).toBe("");
  });

  it("says nothing when the run was capped but nothing went unread", () => {
    const html = api().jevCapWarningHtml(issueCase({ matched: 2000 }), { foundNothing: true });
    expect(html).toBe("");
    expect(api().jevCapWarningHtml(null, { foundNothing: true })).toBe("");
  });

  it("prints no dollar figure when the run reported no cost", () => {
    const t = text(api().jevCapWarningHtml(issueCase({ usage: {} }), { foundNothing: true }));
    expect(t).not.toMatch(/\$/);
    expect(t).not.toMatch(/about/);
    expect(t).toMatch(/Read every row/);
  });

  it("floors the share at <1%, never 0%", () => {
    const t = text(api().jevCapWarningHtml(issueCase({ read: 50, matched: 100000 }), { foundNothing: true }));
    expect(t).toMatch(/\(<1%\)/);
    expect(t).not.toMatch(/\(0%\)/);
  });

  it("never rounds a partial read up to 100%", () => {
    const t = text(api().jevCapWarningHtml(issueCase({ read: 999, matched: 1000 }), { foundNothing: true }));
    expect(t).toMatch(/\(>99%\)/);
  });

  it("never claims a count of rows that have never been graded", () => {
    const t = text(api().jevCapWarningHtml(issueCase(), { foundNothing: true }));
    expect(t).not.toMatch(/never been graded/);
  });

  it("renders a non-numeric count as 0, never as markup", () => {
    const html = api().jevCapWarningHtml(issueCase({ read: "<img>", cap: "<img>" }), { foundNothing: true });
    expect(html).not.toMatch(/<img>/);
  });
});

describe("the full-read cost estimate scales by rows graded, not rows read (#2077)", () => {
  it("brackets the cost between the read sample's grading rate and grading every unread row", () => {
    const plan = api().jevFullReadPlan(issueCase());
    // $0.0031 bought 62 graded rows: $0.00005 a row.
    // Low: the unread rows are graded as often as the rows read (62 / 2,000) → 2,522.9 rows ≈ $0.126.
    // High: every unread row needs grading → 62 + 79,385 = 79,447 rows ≈ $3.97.
    expect(plan.costLow).toBeCloseTo((0.0031 / 62) * (62 + (79385 * 62) / 2000), 6);
    expect(plan.costHigh).toBeCloseTo((0.0031 / 62) * (62 + 79385), 6);
  });

  it("has no estimate when the run graded nothing, because nothing priced a graded row", () => {
    const plan = api().jevFullReadPlan(issueCase({ graded: 0, rows: [], usage: { costUSD: 0 } }));
    expect(plan.costLow).toBeNull();
    expect(plan.costHigh).toBeNull();
  });

  it("does not let skipped rows inflate the per-row price", () => {
    // 10 graded rows cost $1; 990 read rows were skipped. A row-read basis would price a row at
    // $0.001; the graded basis prices it at $0.10.
    const plan = api().jevFullReadPlan({
      matched: 1100,
      read: 1000,
      graded: 10,
      capped: true,
      usage: { costUSD: 1 },
    });
    expect(plan.costHigh).toBeCloseTo(0.1 * (10 + 100), 6);
    expect(plan.costLow).toBeCloseTo(0.1 * (10 + 1), 6);
  });

  it("shows the same range in the confirmation step", () => {
    const t = text(api().jevFullReadConfirmHtml(api().jevFullReadPlan(issueCase())));
    expect(t).toMatch(/\$0\.13 to \$3\.97/);
    expect(t).toMatch(/an estimate, not a quote/);
  });
});
