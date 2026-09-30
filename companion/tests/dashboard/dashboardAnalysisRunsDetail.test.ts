// #1887: an import receipt lists what the import added and removed plus the entity counts, not every
// id the case held. The manifest detail shows that shape, and still shows an older manifest's list.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface RunsApi {
  openAnalysisRuns: () => Promise<unknown>;
}

const LISTED = {
  id: "run-1",
  kind: "import",
  startedAt: "2026-09-30T08:00:00Z",
  durationMs: 10,
  input: {},
  output: {},
};
const MANIFEST = {
  ...LISTED,
  status: "completed",
  sequence: 1,
  finishedAt: "2026-09-30T08:00:01Z",
  manifestHash: "a".repeat(64),
  previousManifestHash: null,
  versions: { application: "1.0.0" },
  execution: { retries: 0, warnings: [] },
};

async function detailOf(run: object): Promise<string> {
  const viewButton = { getAttribute: () => "run-1", onclick: null as null | (() => Promise<void>) };
  const elements: Record<string, Record<string, unknown>> = {};
  const get = (id: string) =>
    (elements[id] ??= {
      textContent: "",
      innerHTML: "",
      value: id === "caseId" ? "case-1" : "",
      style: {},
      classList: { add: () => {}, remove: () => {} },
      querySelectorAll: (sel: string) => (id === "arList" && sel === "[data-ar-view]" ? [viewButton] : []),
      querySelector: () => ({ onclick: null }),
    });
  const answer = (url: string) => {
    if (url.endsWith("/analysis-runs")) return [LISTED];
    if (url.endsWith("/integrity")) return { ok: true, manifests: 1 };
    return run;
  };
  const api = loadDashboardModule<RunsApi>("dashboard-analysis-runs.js", ["dashboard-escape.js"], {
    document: { getElementById: get },
    fetch: async (url: string) => ({ ok: true, status: 200, json: async () => answer(url) }),
    setTimeout,
    clearTimeout,
    AbortController,
    analysisRunLabel: (r: { id: string }) => r.id,
  });
  await api.openAnalysisRuns();
  await viewButton.onclick?.();
  return String(get("arDetail").innerHTML);
}

describe("the run manifest detail (#1887)", () => {
  it("shows an import receipt's counts and the ids it added and removed, escaped", async () => {
    const html = await detailOf({
      ...MANIFEST,
      input: { artifacts: [], eventIds: [], entityIds: [], entityCount: 5 },
      output: {
        entityIds: ["e6", "<img src=x onerror=alert(1)>"],
        removedEntityIds: ["e1"],
        entityCount: 6,
        hashes: [],
        claims: [],
      },
    });
    expect(html).toContain("Entities before: 5");
    expect(html).toContain("Added (2)");
    expect(html).toContain("e6, &lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("<img");
    expect(html).toContain("Removed (1)");
    expect(html).toContain("Entities after: 6");
    expect(html).not.toContain("Input entities");
  });

  it("shows an older manifest's full input list", async () => {
    const html = await detailOf({
      ...MANIFEST,
      input: { artifacts: [], eventIds: [], entityIds: ["e1", "i1"] },
      output: { entityIds: ["e1", "i1", "e2"], hashes: [], claims: [] },
    });
    expect(html).toContain("Input entities (2)");
    expect(html).toContain("e1, i1");
    expect(html).not.toContain("Entities before");
  });
});
