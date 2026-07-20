import { describe, it, expect } from "vitest";
import {
  lateralPathKey,
  filterDismissedPaths,
  annotateDismissedPaths,
  type LateralPathDismissal,
} from "../../src/analysis/lateralPathDismiss.js";
import type { LateralPath } from "../../src/analysis/evidenceGraph.js";

// A lateral path is DERIVED on every read and never stored, so a dismissal cannot key on the
// path's id — those are positional (lateral-path:0, :1) and shift the moment the data changes.
// It keys on the ordered host sequence instead: that IS the claim the analyst is rejecting
// ("the attacker did NOT go A → B → C"), and it survives the same chain being rebuilt from
// different underlying evidence.

function path(id: string, hostIds: string[]): LateralPath {
  return {
    id,
    hostIds,
    hops: [],
    confidence: "medium",
    startTime: "2026-05-20T09:00:00Z",
    endTime: "2026-05-20T11:00:00Z",
  };
}

function dismissal(hostIds: string[]): LateralPathDismissal {
  return {
    id: `d-${hostIds.join("-")}`,
    key: lateralPathKey(hostIds),
    hostIds,
    note: "",
    dismissedAt: "2026-05-21T00:00:00Z",
  };
}

describe("lateralPathKey", () => {
  it("is the ordered host sequence, so order is part of the identity", () => {
    expect(lateralPathKey(["host:a", "host:b"])).not.toBe(lateralPathKey(["host:b", "host:a"]));
  });

  it("is stable regardless of which evidence produced the chain", () => {
    // Same route, rebuilt from different hops after a re-import — still one claim.
    expect(lateralPathKey(["host:a", "host:b", "host:c"])).toBe(lateralPathKey(["host:a", "host:b", "host:c"]));
  });

  it("ignores case and surrounding whitespace in host ids", () => {
    expect(lateralPathKey([" HOST:A ", "host:B"])).toBe(lateralPathKey(["host:a", "host:b"]));
  });
});

describe("filterDismissedPaths", () => {
  const paths = [
    path("lateral-path:0", ["host:a", "host:b", "host:c"]),
    path("lateral-path:1", ["host:x", "host:y"]),
  ];

  it("removes exactly the dismissed route and leaves the rest", () => {
    const kept = filterDismissedPaths(paths, [dismissal(["host:a", "host:b", "host:c"])]);
    expect(kept.map((p) => p.hostIds)).toEqual([["host:x", "host:y"]]);
  });

  it("still removes the route when it comes back with a different path id", () => {
    // Re-derivation renumbers the paths; the dismissal must not be defeated by that.
    const renumbered = [path("lateral-path:7", ["host:a", "host:b", "host:c"])];
    expect(filterDismissedPaths(renumbered, [dismissal(["host:a", "host:b", "host:c"])])).toEqual([]);
  });

  it("does NOT remove a longer chain that merely contains the dismissed route", () => {
    // A → B → C → D is a DIFFERENT claim than A → B → C: the attacker reached one more host.
    // Silently hiding it would suppress a finding the analyst never rejected.
    const longer = [path("lateral-path:0", ["host:a", "host:b", "host:c", "host:d"])];
    expect(filterDismissedPaths(longer, [dismissal(["host:a", "host:b", "host:c"])])).toHaveLength(1);
  });

  it("does NOT remove the same hosts in a different order", () => {
    const reversed = [path("lateral-path:0", ["host:c", "host:b", "host:a"])];
    expect(filterDismissedPaths(reversed, [dismissal(["host:a", "host:b", "host:c"])])).toHaveLength(1);
  });

  it("returns everything when nothing is dismissed", () => {
    expect(filterDismissedPaths(paths, [])).toHaveLength(2);
  });
});

describe("annotateDismissedPaths", () => {
  it("keeps every path but flags the dismissed ones, for the review/undo view", () => {
    const annotated = annotateDismissedPaths(
      [path("lateral-path:0", ["host:a", "host:b"]), path("lateral-path:1", ["host:x", "host:y"])],
      [dismissal(["host:a", "host:b"])],
    );
    expect(annotated).toHaveLength(2);
    expect(annotated[0].dismissed).toBe(true);
    expect(annotated[1].dismissed).toBe(false);
  });

  it("carries the dismissal note so the analyst can see why it was rejected", () => {
    const d = { ...dismissal(["host:a", "host:b"]), note: "scheduled backup job, not an attacker" };
    const annotated = annotateDismissedPaths([path("lateral-path:0", ["host:a", "host:b"])], [d]);
    expect(annotated[0].dismissalNote).toBe("scheduled backup job, not an attacker");
  });
});
