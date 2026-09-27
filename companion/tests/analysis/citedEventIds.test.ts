import { describe, expect, it } from "vitest";
import { deltaSchema, resolveCitedEventId, resolveCitedEventIds } from "../../src/analysis/responseSchema.js";

/**
 * #1693 — a model-decorated event id (`e_cld-e1`, `~cld-e1`, `[cld-e1]`, `CLD-E1`) resolves to the
 * event it names, but only when exactly one known event fits. An id that exists is never rewritten,
 * and an id that fits nothing — or fits two events — stays as the model sent it.
 */

const known = (...ids: string[]): ReadonlySet<string> => new Set(ids);

describe("resolveCitedEventId (#1693)", () => {
  it.each([
    ["e_cld-e1", "cld-e1"],
    ["~cld-e1", "cld-e1"],
    ["[cld-e1]", "cld-e1"],
    ["~[cld-e1]", "cld-e1"],
    ["[~cld-e1]", "cld-e1"],
    ["  [cld-e1] ", "cld-e1"],
    ["CLD-E1", "cld-e1"],
    ["E_CLD-E1", "cld-e1"],
    ["evt-cld-e1", "cld-e1"],
    ["evt_cld-e1", "cld-e1"],
    ["event_cld-e1", "cld-e1"],
    ["event-cld-e1", "cld-e1"],
    ["~[e_cld-e1]", "cld-e1"],
  ])("resolves %s to %s", (cited, expected) => {
    expect(resolveCitedEventId(cited, known("cld-e1", "cld-e2"))).toBe(expected);
  });

  it.each(["m3e12", "e1", "e_x", "evt-7", "cloud-metadata-coverage"])(
    "leaves the real id %s unchanged even when a stripped form also exists",
    (id) => {
      const ids = known("m3e12", "e1", "e_x", "x", "evt-7", "7", "cloud-metadata-coverage");
      expect(resolveCitedEventId(id, ids)).toBe(id);
    },
  );

  it("keeps the model's exact id inside prompt punctuation over a prefix-stripped guess", () => {
    expect(resolveCitedEventId("~[e_x]", known("e_x", "x"))).toBe("e_x");
  });

  it("refuses to guess when case-folding and prefix-stripping name different events", () => {
    expect(resolveCitedEventId("E_X", known("e_x", "x"))).toBe("E_X");
    expect(resolveCitedEventId("EVT_7", known("evt_7", "7"))).toBe("EVT_7");
  });

  it("refuses to guess between two events that differ only by case", () => {
    expect(resolveCitedEventId("Ab", known("AB", "ab"))).toBe("Ab");
  });

  it.each(["e_nope", "e-1", "", "[]", "~"])("leaves the unresolvable id %j as sent", (id) => {
    expect(resolveCitedEventId(id, known("e1", "cld-e1"))).toBe(id);
  });
});

const delta = (extra: Record<string, unknown>) =>
  deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
    ...extra,
  });

const finding = (id: string, relatedEventIds?: string[]) => ({
  id,
  severity: "High",
  title: "t",
  description: "d",
  relatedIocs: [],
  mitreTechniques: [],
  status: "open",
  ...(relatedEventIds ? { relatedEventIds } : {}),
});

describe("resolveCitedEventIds (#1693)", () => {
  const ids = known("cld-e1", "cld-e2", "e1");

  it("rewrites finding citations in order and drops the duplicates a rewrite creates", () => {
    const d = delta({ findings: [finding("f1", ["e_cld-e1", "cld-e2", "~[cld-e1]", "CLD-E2", "e_nope"])] });
    expect(resolveCitedEventIds(d, ids).findings[0].relatedEventIds).toEqual(["cld-e1", "cld-e2", "e_nope"]);
  });

  it("rewrites both hypothesis citation lists", () => {
    const d = delta({
      hypotheses: [{ title: "h", relatedEventIds: ["e_cld-e1"], contradictingEventIds: ["[cld-e2]"] }],
    });
    const out = resolveCitedEventIds(d, ids).hypotheses?.[0];
    expect(out?.relatedEventIds).toEqual(["cld-e1"]);
    expect(out?.contradictingEventIds).toEqual(["cld-e2"]);
  });

  it("returns the same delta when nothing needs resolving", () => {
    const d = delta({
      findings: [finding("f1", ["cld-e1", "e_nope"]), finding("f2")],
      hypotheses: [{ title: "h", relatedEventIds: ["e1"] }],
    });
    expect(resolveCitedEventIds(d, ids)).toBe(d);
  });

  it("does not mutate the input delta", () => {
    const d = delta({ findings: [finding("f1", ["e_cld-e1"])] });
    resolveCitedEventIds(d, ids);
    expect(d.findings[0].relatedEventIds).toEqual(["e_cld-e1"]);
  });

  it("leaves a finding with no citations without the field", () => {
    const d = delta({ findings: [finding("f1"), finding("f2", ["e_cld-e1"])] });
    expect(resolveCitedEventIds(d, ids).findings[0]).not.toHaveProperty("relatedEventIds");
  });
});
