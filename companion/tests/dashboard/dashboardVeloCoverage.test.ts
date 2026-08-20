import { describe, expect, it } from "vitest";
import type { VeloCoverageApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-coverage.js — the per-artifact accounting line under a collected hunt.
//
// Three outcomes have to stay distinguishable, or "+3 events" next to a 40-artifact bundle reads as
// "only one artifact worked": an artifact that FAILED to collect, one that returned NOTHING, and one
// that returned rows but was CUT SHORT at the row cap. The third is the dangerous one — it looks
// exactly like success, which is how a THOR scan's 40 warnings went missing behind a green job.
const cov = loadDashboardModule<VeloCoverageApi>("dashboard-velo-coverage.js", ["dashboard-escape.js"]);

const imported = (extra: Record<string, unknown> = {}) => ({
  status: "imported",
  artifacts: ["A.one", "A.two", "A.three"],
  ...extra,
});

describe("veloCoverageHtml", () => {
  it("counts artifacts that returned results, had nothing, and failed", () => {
    const html = cov.veloCoverageHtml(
      imported({ emptyArtifacts: ["A.two"], skippedArtifacts: [{ name: "A.three", error: "too big" }] }),
    );
    expect(html).toContain("1/3 artifact(s) returned results");
    expect(html).toContain("1 had no findings");
    expect(html).toContain("1 failed to collect");
    expect(html).toContain("A.three: too big");
  });

  it("calls out an artifact cut short at the row cap, and names the knob that lifts it", () => {
    const html = cov.veloCoverageHtml(
      imported({ truncatedArtifacts: [{ name: "Generic.Scanner.ThorZIP", kept: 1000, total: 1001 }] }),
    );
    expect(html).toContain("cut short");
    expect(html).toContain("Generic.Scanner.ThorZIP");
    expect(html).toContain("1000");
    expect(html).toContain("DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS");
  });

  // The bug this module was extracted to fix: the old inline version only rendered for a bundle of
  // MORE than one artifact, so a single-artifact THOR hunt that was cut short showed a green job and
  // no warning at all.
  it("warns on a SINGLE-artifact hunt that was cut short", () => {
    const html = cov.veloCoverageHtml({
      status: "imported",
      artifacts: ["Generic.Scanner.ThorZIP"],
      truncatedArtifacts: [{ name: "Generic.Scanner.ThorZIP", kept: 1000, total: 1001 }],
    });
    expect(html).toContain("cut short");
    expect(html).toContain("DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS");
  });

  it("stays quiet for a clean single-artifact hunt, and for a job still running", () => {
    expect(cov.veloCoverageHtml({ status: "imported", artifacts: ["A.one"] })).toBe("");
    expect(cov.veloCoverageHtml({ status: "running", artifacts: ["A.one", "A.two"] })).toBe("");
  });

  it("escapes artifact names and errors", () => {
    const html = cov.veloCoverageHtml(
      imported({ skippedArtifacts: [{ name: "<img src=x>", error: "<script>" }] }),
    );
    expect(html).not.toContain("<img src=x>");
    expect(html).toContain("&lt;img src=x&gt;");
  });
});
