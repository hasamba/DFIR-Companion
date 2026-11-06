import { describe, expect, it } from "vitest";
import { collectionStatus } from "../../src/integrations/cloudCollect/collectEngine.js";
import { sourceCoverage, withPageDisclosure } from "../../src/integrations/cloudCollect/collectCoverage.js";
import type { SubWindowStatus } from "../../src/integrations/cloudCollect/collectTypes.js";

// #2314: a page can carry a note for the result and say its completeness is unverified (a GCS sink
// delivers best effort). The engine discloses the note and never reports such a source "complete".

const WINDOW = { start: "2026-11-01T00:00:00.000Z", end: "2026-11-02T00:00:00.000Z" };
const done = (over: Partial<SubWindowStatus> = {}): SubWindowStatus => ({
  id: "s:0",
  source: "s",
  window: WINDOW,
  state: "done",
  pages: 1,
  records: 1,
  restarts: 0,
  firstRetrievedAt: "2026-11-05T00:00:00.000Z",
  ...over,
});

describe("page disclosure (#2314)", () => {
  it("keeps each note once and remembers an unverified page", () => {
    let sw = withPageDisclosure(done(), { note: "n1", unverified: true });
    sw = withPageDisclosure(sw, { note: "n1" });
    sw = withPageDisclosure(sw, {});
    expect(sw.notes).toEqual(["n1"]);
    expect(sw.unverified).toBe(true);
    expect(withPageDisclosure(done(), {})).toEqual(done());
  });

  it("reports an all-done collection with an unverified page as partial, never complete", () => {
    expect(collectionStatus([done()], 1)).toBe("complete");
    expect(collectionStatus([done({ unverified: true })], 1)).toBe("partial");
  });

  it("puts the pages' notes in the source's coverage", () => {
    const [cov] = sourceCoverage(
      [done({ notes: ["sink note"] })],
      [{ id: "s", label: "S", streamKind: "cloud" }],
      {
        sources: ["s"],
        window: WINDOW,
        startedAt: "2026-11-05T00:00:00.000Z",
      },
    );
    expect(cov.notes).toContain("sink note");
  });
});
