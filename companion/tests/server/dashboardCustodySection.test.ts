import { describe, it, expect, beforeAll } from "vitest";
import { dashboardClientSource } from "../helpers/dashboardModule.js";

// The dashboard is a single hand-written HTML file with inline JS and no DOM test harness in this
// repo, so behaviour cannot be asserted here. What CAN be asserted is the wiring — the three
// mistakes that make a new section silently dead: markup with no loader, a loader never called on
// case open, or a section missing from the visibility registry so it can never be toggled.
// This is a smoke test for those, not a substitute for looking at the page.

let html: string;

beforeAll(async () => {
  html = dashboardClientSource();
});

// Reads the whole CLIENT SOURCE, not dashboard.html alone: #415 moved this behaviour into
// public/js/dashboard-*.js, and the question these assertions ask is "does the dashboard do
// this", not "is this string in that file". Markup assertions still hold — the HTML is the
// first thing dashboardClientSource() concatenates.
describe("Chain of Custody dashboard section (#231)", () => {
  it("has its own section element", () => {
    expect(html).toContain('<section id="sec-custody"');
    expect(html).toContain('id="custodyPanel"');
  });

  it("is registered in the section-visibility list, so it can be hidden like any other", () => {
    expect(html).toMatch(/\{\s*id:\s*"sec-custody",\s*label:\s*"Chain of Custody"\s*\}/);
  });

  it("loads its records when a case is opened", () => {
    // Loaded from the case-load panel table (it was a bare call before the progress bar landed).
    expect(html).toContain('["custody", () => loadCustody(caseId)]');
    expect(html).toContain("/custody`");
  });

  it("offers verification and the signed manifest", () => {
    expect(html).toContain('id="custodyVerifyBtn"');
    expect(html).toContain('id="custodyManifestLink"');
    expect(html).toContain("/custody/verify`");
    expect(html).toContain("/custody/manifest`");
  });

  it("escapes every custody field it renders, since paths and sources are attacker-influenced", () => {
    // A capture's source is a page URL and an artifact path carries a filename — both reach this
    // panel from outside, so neither may be interpolated raw.
    const panel = html.slice(html.indexOf("function renderCustody()"), html.indexOf("function loadCustody("));
    expect(panel).not.toMatch(/\$\{r\.(source|collectedBy|trigger|event|sha256)\}/);
    expect(panel).not.toMatch(/\$\{(path|name)\}/);
    expect(panel).toContain("esc(r.source)");
    expect(panel).toContain("escAttr(path)");
  });
});
