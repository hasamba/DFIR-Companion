import { describe, it, expect } from "vitest";
import { BUILT_IN_DASHBOARD_VIEWS, DASHBOARD_SECTION_IDS } from "../../src/analysis/dashboardViews.js";

// The page re-applies the section order on load. Playbook Match sat 7th in that order, beside
// Playbook, while Adversary Hints sat beside MITRE far below, so the two read as unrelated panels
// scattered down the page. The markup, the Settings list and now every ordering list keep Playbook
// Match directly after Adversary Hints.

const lists: Array<[string, readonly string[]]> = [
  ["the canonical section order", DASHBOARD_SECTION_IDS],
  ...BUILT_IN_DASHBOARD_VIEWS.map((v): [string, readonly string[]] => [`the ${v.name} view`, v.sections]),
];

describe("Adversary Hints and Playbook Match are one after the other", () => {
  it.each(lists.filter(([, ids]) => ids.includes("sec-playbook-match")))(
    "%s puts Playbook Match directly after Adversary Hints",
    (_name, ids) => {
      const adversary = ids.indexOf("sec-adversary");
      expect(adversary).toBeGreaterThanOrEqual(0);
      expect(ids.indexOf("sec-playbook-match")).toBe(adversary + 1);
    },
  );

  it("lists Playbook Match exactly once in each ordering", () => {
    for (const [, ids] of lists) {
      expect(ids.filter((id) => id === "sec-playbook-match").length).toBeLessThanOrEqual(1);
    }
  });
});
