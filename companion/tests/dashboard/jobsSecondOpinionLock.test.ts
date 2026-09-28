// #1753: every jobs push re-applies the heavy-AI button lock, and that lock used to re-enable the
// Second opinion button the click had just disabled — so a second click mid-run started an
// overlapping run whose result replaced the first. A running or queued second-opinion job now keeps
// the button disabled, and the lock releases when the job ends.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface JobsApi {
  scheduleJobUiRefresh: (caseId: string, jobs?: unknown) => void;
}

const PRELOAD = ["dashboard-escape.js", "dashboard-values.js", "dashboard-fragments.js"];

function button() {
  return {
    disabled: false,
    title: "",
    removeAttribute(name: string) {
      if (name === "title") this.title = "";
    },
  };
}

function harness() {
  const so = button();
  const synth = button();
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    jobsBadge: { textContent: "", style: { display: "none" }, addEventListener: () => {} },
    jobsMenu: { innerHTML: "", style: { display: "none" }, querySelectorAll: () => [] },
    status: { textContent: "" },
    secondOpinion: so,
    synthesize: synth,
  };
  const api = loadDashboardModule<JobsApi>("dashboard-jobs.js", PRELOAD, {
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
    fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ jobs: [] }) }),
    deepPassBusy: () => false,
    deepPassJob: () => null,
    applyDeepPassGate: () => {},
    loadCockpit: () => Promise.resolve(),
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id: unknown) => globalThis.clearTimeout(id as number),
  });
  return { api, so, synth };
}

const soJob = (status: string) => [
  { id: "job_so", caseId: "INC-1", kind: "second-opinion", status, label: "second opinion" },
];

describe("the Second opinion button stays locked while its job runs (#1753)", () => {
  for (const status of ["running", "queued"]) {
    it(`a ${status} second-opinion job keeps the button disabled across a jobs push`, () => {
      const { api, so, synth } = harness();
      so.disabled = true; // the click disabled it
      api.scheduleJobUiRefresh("INC-1", soJob(status));
      expect(so.disabled).toBe(true);
      expect(synth.disabled).toBe(false); // Re-synthesize queues behind it server-side
    });
  }

  it("the button is released once the job ends", () => {
    const { api, so } = harness();
    api.scheduleJobUiRefresh("INC-1", soJob("running"));
    api.scheduleJobUiRefresh("INC-1", soJob("succeeded"));
    expect(so.disabled).toBe(false);
  });
});
