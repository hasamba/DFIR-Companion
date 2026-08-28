// A failed /api/jobs must not be drawn as "no jobs".
//
// Reported alongside a header pill stuck on "AI: synthesizing…": "no jobs chip at all". The jobs
// badge is the one surface that would have named the run the pill was claiming — and it had hidden
// itself. loadJobs mapped any non-ok response to `{ jobs: [] }`, so a 401 from an expired session,
// a 500, or a request the server dropped while it was overloaded emptied the cache and rendered the
// case as idle. That is the opposite of the truth: the badge is hidden exactly when the analyst
// most needs it, and there is then no Cancel button for the run that is still going.
//
// refreshAiState already gets this right ("a failed correction must not invent a state" — see
// js/dashboard-ai-status.js). This pins the same rule for the badge: on a failed read, keep the
// last known answer.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface JobsApi {
  loadJobs: () => Promise<void>;
  runningJob: (kind: string) => unknown;
}

const RUNNING = [{ id: "synth-1", kind: "synthesis", status: "running", cancellable: true }];

const PRELOAD = ["dashboard-escape.js", "dashboard-values.js", "dashboard-fragments.js"];

/** The page, plus a fetch whose answer the test swaps between calls. */
function harness(answers: { ok: boolean; jobs?: unknown[] }[]) {
  const menu = {
    innerHTML: "",
    style: { display: "none" },
    querySelectorAll: () => [] as unknown[],
  };
  const badge = { textContent: "", style: { display: "" }, addEventListener: () => {} };
  const caseIdInput = { value: "INC-1" };
  const elements: Record<string, unknown> = {
    caseId: caseIdInput,
    jobsBadge: badge,
    jobsMenu: menu,
    status: { textContent: "" },
  };
  let call = 0;
  const globals = {
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      addEventListener: () => {},
    },
    fetch: () => {
      const answer = answers[Math.min(call++, answers.length - 1)];
      return Promise.resolve({
        ok: answer.ok,
        status: answer.ok ? 200 : 401,
        json: () => Promise.resolve({ jobs: answer.jobs ?? [] }),
      });
    },
    deepPassBusy: () => false,
    deepPassJob: () => null,
    applyDeepPassGate: () => {},
    loadCockpit: () => Promise.resolve(),
  };
  return {
    badge,
    menu,
    caseIdInput,
    api: loadDashboardModule<JobsApi>("dashboard-jobs.js", PRELOAD, globals),
  };
}

describe("the background-jobs badge", () => {
  it("keeps the last known jobs when the read fails, instead of reporting none", async () => {
    const { api, badge } = harness([
      { ok: true, jobs: RUNNING },
      { ok: false }, // the session expired, or the server dropped it under load
    ]);

    await api.loadJobs();
    expect(badge.textContent).toBe("⚙ 1 job");
    expect(badge.style.display).toBe("");

    await api.loadJobs();
    expect(badge.textContent).toBe("⚙ 1 job"); // still the truth we last had, not "no jobs"
    expect(badge.style.display).toBe("");
  });

  it("still hides itself when the server genuinely answers with no jobs", async () => {
    const { api, badge } = harness([
      { ok: true, jobs: RUNNING },
      { ok: true, jobs: [] },
    ]);

    await api.loadJobs();
    await api.loadJobs();

    expect(badge.style.display).toBe("none");
  });

  // "Keep the last known answer" is only true for the case that answer describes. The cache is one
  // module-level array, so keeping it across a case switch would draw case A's running jobs under
  // case B — and every Cancel button in that popover POSTs A's job id, killing work in a case the
  // analyst is no longer even looking at.
  it("does not carry one case's jobs over to the next when the new case's read fails", async () => {
    const { api, badge, menu, caseIdInput } = harness([{ ok: true, jobs: RUNNING }, { ok: false }]);

    await api.loadJobs();
    expect(badge.textContent).toBe("⚙ 1 job");

    caseIdInput.value = "INC-2"; // the analyst switches case; INC-2's jobs never load
    await api.loadJobs();

    expect(badge.style.display).toBe("none");
    expect(menu.innerHTML).not.toContain("synth-1");
    expect(api.runningJob("synthesis")).toBeUndefined(); // and the deep-pass lock agrees
  });
});
