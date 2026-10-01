// #1765-#1768 (and the sweep: Narrative Timeline, Findings, Forensic Timeline): on a new case the
// panels showed a bare "—", which reads as "broken". render() has no behavioural DOM harness (see
// dashboardRenderOriginLens.test.ts), so this pins the source: every one of those fallbacks is a
// sentence now, and the two traps the triage named stay closed.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const read = (p: string) => readFileSync(new URL(`../../../public/${p}`, import.meta.url), "utf8");
const RENDER = read("js/dashboard-render.js");
const HTML = read("dashboard.html");
const MATRIX = read("js/dashboard-mitre-matrix.js");

describe("render() empty states", () => {
  it("has no bare-dash fallback left, except the narrative editor's sentinel", () => {
    const dashes = RENDER.match(/(\|\||:|\?)\s*"—"/g) ?? [];
    expect(dashes).toEqual(['|| "—"']);
    expect(RENDER).toContain('const narrative = state.narrativeTimeline || "—";');
  });

  it("names what each empty panel is waiting for", () => {
    for (const sentence of [
      "No attack path yet — run Synthesize.",
      "No findings yet.",
      "No findings match the current filters.",
      "No imports or AI notes yet.",
      "No techniques yet — import evidence or run Synthesize.",
      "No techniques in the current scope.",
    ])
      expect(RENDER).toContain(sentence);
  });

  // Trap 1: attackPathHtml() parses its input into steps. The placeholder must go around it.
  it("never passes a placeholder through attackPathHtml", () => {
    expect(RENDER).toMatch(/state\.attackerPath\s*\?\s*attackPathHtml\(state\.attackerPath,/);
    expect(RENDER).not.toMatch(/attackPathHtml\(\s*state\.attackerPath\s*\|\|/);
  });

  // Trap 2: data-raw is what the editor loads. The sentence lives only in the rendered view.
  it("keeps the sentence out of the narrative's data-raw", () => {
    expect(RENDER).toContain("narrativeView.dataset.raw = narrative;");
    expect(RENDER).toContain(
      "narrativeView.innerHTML = narrativeViewHtml(narrative, state.forensicTimeline);",
    );
  });

  it("hands the Matrix view the same empty line, only when there are no techniques", () => {
    expect(RENDER).toContain('emptyHtml: mitreRows.length ? "" : mitreEmptyHtml(),');
    expect(MATRIX).toContain(
      'host.innerHTML = (mmLast.emptyHtml || "") + matrixHtml(model, hits, mmExpanded);',
    );
  });
});

describe("Forensic Timeline empty state", () => {
  it("renders through timelineEmptyHtml instead of a dash", () => {
    expect(HTML).toContain(
      // #1916: the filtered-empty branch also draws the Load more bar, so unloaded events stay reachable.
      'No events match the current filters.</div>" + (typeof timelineMoreMatchesBar === "function" ? timelineMoreMatchesBar() : "") : timelineEmptyHtml(((DfirState.lastState() || {}).forensicTimeline || []).length);',
    );
  });
});
