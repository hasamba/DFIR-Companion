import { describe, it, expect } from "vitest";
import { superOriginOf, dedupeAppend, capEvents, querySuper } from "../../src/analysis/superTimeline.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string; timestamp: string }): ForensicEvent {
  return { description: "d", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

describe("superOriginOf", () => {
  it("prefers artifactName, then sources[0], then Unknown", () => {
    expect(superOriginOf(ev({ id: "a", timestamp: "t", artifactName: "Windows.NTFS.MFT", sources: ["Velociraptor"] }))).toBe("Windows.NTFS.MFT");
    expect(superOriginOf(ev({ id: "a", timestamp: "t", sources: ["Cisco ASA"] }))).toBe("Cisco ASA");
    expect(superOriginOf(ev({ id: "a", timestamp: "t" }))).toBe("Unknown");
  });
});

describe("dedupeAppend", () => {
  it("appends new events and drops incoming whose id already exists", () => {
    const existing = [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" })];
    const incoming = [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" }), ev({ id: "e2", timestamp: "2026-06-02T00:00:00Z" })];
    const out = dedupeAppend(existing, incoming);
    expect(out.map((e) => e.id)).toEqual(["e1", "e2"]);
  });
});

describe("capEvents", () => {
  it("keeps the newest N by timestamp when over the cap", () => {
    const events = [
      ev({ id: "old", timestamp: "2026-06-01T00:00:00Z" }),
      ev({ id: "mid", timestamp: "2026-06-02T00:00:00Z" }),
      ev({ id: "new", timestamp: "2026-06-03T00:00:00Z" }),
    ];
    const out = capEvents(events, 2);
    expect(new Set(out.map((e) => e.id))).toEqual(new Set(["mid", "new"]));
  });
  it("returns all when under the cap", () => {
    const events = [ev({ id: "a", timestamp: "2026-06-01T00:00:00Z" })];
    expect(capEvents(events, 10)).toHaveLength(1);
  });
});

describe("querySuper", () => {
  const events = [
    ev({ id: "before", timestamp: "2026-05-01T00:00:00Z", artifactName: "Windows.NTFS.MFT" }),
    ev({ id: "in1", timestamp: "2026-06-01T09:00:00Z", artifactName: "Windows.NTFS.MFT" }),
    ev({ id: "in2", timestamp: "2026-06-01T10:00:00Z", artifactName: "Windows.Detection.Sigma" }),
    ev({ id: "after", timestamp: "2026-07-01T00:00:00Z", artifactName: "Windows.NTFS.MFT" }),
  ];
  const labels = { in2: ["reviewed"] };

  it("filters by time range and returns chronological page + total + facets", () => {
    const r = querySuper(events, labels, { from: "2026-06-01T00:00:00Z", to: "2026-06-02T00:00:00Z" });
    expect(r.events.map((e) => e.id)).toEqual(["in1", "in2"]);
    expect(r.total).toBe(2);
    expect(r.origins).toEqual(["Windows.Detection.Sigma", "Windows.NTFS.MFT"]);
    expect(r.labelsAvailable).toEqual(["reviewed"]);
  });

  it("filters by origin", () => {
    const r = querySuper(events, labels, { origins: ["Windows.Detection.Sigma"] });
    expect(r.events.map((e) => e.id)).toEqual(["in2"]);
  });

  it("excludes the given origins (the dashboard's unchecked boxes)", () => {
    const r = querySuper(events, labels, { exclude: ["Windows.NTFS.MFT"] });
    expect(r.events.map((e) => e.id)).toEqual(["in2"]);   // MFT rows hidden, Sigma kept
  });

  it("excluding EVERY origin yields zero events (unchecking all = show nothing)", () => {
    const r = querySuper(events, labels, { exclude: ["Windows.NTFS.MFT", "Windows.Detection.Sigma"] });
    expect(r.events).toEqual([]);
    expect(r.total).toBe(0);
    expect(r.origins).toEqual(["Windows.Detection.Sigma", "Windows.NTFS.MFT"]);   // facet still complete so boxes can be re-checked
  });

  it("keeps the FULL origin facet when filtering by origin (so the checklist stays complete)", () => {
    // Filtering to MFT still lists Sigma as an available origin — the deselected origin must remain in
    // the checklist so it can be re-checked. (Regression: facets were computed off the filtered set.)
    const r = querySuper(events, labels, { origins: ["Windows.NTFS.MFT"] });
    expect(r.events.map((e) => e.id)).toEqual(["before", "in1", "after"]);          // MFT-only results
    expect(r.origins).toEqual(["Windows.Detection.Sigma", "Windows.NTFS.MFT"]);      // full facet, incl. deselected Sigma
  });

  it("filters by label (via the sidecar map)", () => {
    const r = querySuper(events, labels, { labels: ["reviewed"] });
    expect(r.events.map((e) => e.id)).toEqual(["in2"]);
  });

  it("keeps the FULL label facet when filtering by label", () => {
    const twoLabels = { in1: ["mine"], in2: ["reviewed"] };
    const r = querySuper(events, twoLabels, { labels: ["reviewed"] });
    expect(r.events.map((e) => e.id)).toEqual(["in2"]);
    expect(r.labelsAvailable).toEqual(["mine", "reviewed"]);                          // full facet, incl. the unselected "mine"
  });

  it("origin facet still respects the TIME window (only the window bounds what's available)", () => {
    // Narrowing the time window to June leaves out the May/July MFT rows but keeps in1(MFT)+in2(Sigma).
    const r = querySuper(events, labels, { from: "2026-06-01T00:00:00Z", to: "2026-06-02T00:00:00Z" });
    expect(r.origins).toEqual(["Windows.Detection.Sigma", "Windows.NTFS.MFT"]);
  });

  it("taggedOnly keeps only events carrying at least one label/tag", () => {
    const r = querySuper(events, labels, { taggedOnly: true });
    expect(r.events.map((e) => e.id)).toEqual(["in2"]);   // only in2 has a label
    expect(r.total).toBe(1);
    // Facets are unaffected by taggedOnly (they reflect the whole time window).
    expect(r.origins).toEqual(["Windows.Detection.Sigma", "Windows.NTFS.MFT"]);
    expect(r.labelsAvailable).toEqual(["reviewed"]);
  });

  it("taggedOnly with no tagged events yields zero", () => {
    const r = querySuper(events, {}, { taggedOnly: true });
    expect(r.events).toEqual([]);
    expect(r.total).toBe(0);
  });

  it("returns a host facet across the time window, including the (no host) pseudo-facet", () => {
    const withHosts = [
      ev({ id: "h1", timestamp: "2026-06-01T09:00:00Z", asset: "HOST-A" }),
      ev({ id: "h2", timestamp: "2026-06-01T10:00:00Z", asset: "HOST-B" }),
      ev({ id: "h3", timestamp: "2026-06-01T11:00:00Z" }),   // no asset → (no host)
    ];
    const r = querySuper(withHosts, {}, {});
    expect(r.hosts).toEqual(["(no host)", "HOST-A", "HOST-B"]);
  });

  it("excludes the given hosts (the dashboard's unchecked host boxes), keeping the facet complete", () => {
    const withHosts = [
      ev({ id: "h1", timestamp: "2026-06-01T09:00:00Z", asset: "HOST-A" }),
      ev({ id: "h2", timestamp: "2026-06-01T10:00:00Z", asset: "HOST-B" }),
    ];
    const r = querySuper(withHosts, {}, { excludeHosts: ["HOST-A"] });
    expect(r.events.map((e) => e.id)).toEqual(["h2"]);
    expect(r.hosts).toEqual(["HOST-A", "HOST-B"]);   // deselected host stays in the facet so it can be re-checked
  });

  it("excludeHosts with the (no host) facet hides host-less events", () => {
    const withHosts = [
      ev({ id: "h1", timestamp: "2026-06-01T09:00:00Z", asset: "HOST-A" }),
      ev({ id: "h2", timestamp: "2026-06-01T10:00:00Z" }),   // no asset
    ];
    const r = querySuper(withHosts, {}, { excludeHosts: ["(no host)"] });
    expect(r.events.map((e) => e.id)).toEqual(["h1"]);
  });

  it("paginates with offset/limit while total reflects the full match count", () => {
    const r = querySuper(events, labels, { offset: 1, limit: 1 });
    expect(r.total).toBe(4);
    expect(r.events).toHaveLength(1);
  });

  it("search narrows to events matching the main dashboard filter's free-text term (#see searchFilter.ts)", () => {
    const withDesc = [
      ev({ id: "s1", timestamp: "2026-06-01T09:00:00Z", description: "mimikatz observed on host" }),
      ev({ id: "s2", timestamp: "2026-06-01T10:00:00Z", description: "benign login" }),
    ];
    const r = querySuper(withDesc, {}, { search: "mimikatz" });
    expect(r.events.map((e) => e.id)).toEqual(["s1"]);
    expect(r.total).toBe(1);
  });

  it("excludeText hides events matching any exclude term, same semantics as the forensic timeline", () => {
    const withDesc = [
      ev({ id: "s1", timestamp: "2026-06-01T09:00:00Z", description: "noisy heartbeat" }),
      ev({ id: "s2", timestamp: "2026-06-01T10:00:00Z", description: "suspicious login" }),
    ];
    const r = querySuper(withDesc, {}, { excludeText: ["heartbeat"] });
    expect(r.events.map((e) => e.id)).toEqual(["s2"]);
  });

  it("search and excludeText compose with time/origin filters", () => {
    const r = querySuper(events, labels, { from: "2026-06-01T00:00:00Z", to: "2026-06-02T00:00:00Z", search: "d" });
    expect(r.events.map((e) => e.id)).toEqual(["in1", "in2"]);   // all fixture events share description "d"
    const none = querySuper(events, labels, { from: "2026-06-01T00:00:00Z", to: "2026-06-02T00:00:00Z", search: "nomatch" });
    expect(none.events).toEqual([]);
  });
});
