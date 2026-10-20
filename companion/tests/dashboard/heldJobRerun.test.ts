// A held job is final on the server: a Presidio or duplicate-host gate ended it before a prompt
// was sent, and it never resumes. Reported as "after clearing presidio findings, there is no
// resume button, the job still says held". Once no gate holds the case, the newest held run of a
// kind the dashboard can start offers Re-run, which presses the same control the analyst would.
//
// Drives the real module in a vm context (see helpers/dashboardModule.ts), the way jobsMenu.test.ts
// does. renderJobs is private, so the test reaches it through loadJobs() and setJobsGateCleared().
import { describe, it, expect, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface JobsApi {
  loadJobs: () => Promise<void>;
  setJobsGateCleared: (caseId: string, cleared: boolean) => void;
}

type StubJob = {
  id: string;
  kind: string;
  status: string;
  failure?: { code: string; retryable: boolean };
  parameters?: Record<string, unknown>;
};

type StubButton = { dataset: { job: string }; disabled: boolean; listeners: (() => void)[] };

const held = (id: string, kind: string, parameters?: Record<string, unknown>): StubJob => ({
  id,
  kind,
  status: "cancelled",
  failure: { code: "held_for_analyst", retryable: false },
  ...(parameters ? { parameters } : {}),
});

function setup(jobs: StubJob[]) {
  let rerunButtons: StubButton[] = [];
  const menu = {
    _html: "",
    get innerHTML() {
      return this._html;
    },
    set innerHTML(html: string) {
      this._html = html;
      rerunButtons = [...html.matchAll(/class="job-rerun" data-job="([^"]+)"/g)].map((m) => ({
        dataset: { job: m[1] },
        disabled: false,
        listeners: [],
      }));
    },
    style: { display: "none" },
    querySelectorAll: (sel: string) =>
      sel === ".job-rerun"
        ? rerunButtons.map((b) => ({
            ...b,
            addEventListener: (_e: string, fn: () => void) => b.listeners.push(fn),
          }))
        : [],
  };
  const control = () => ({
    disabled: false,
    title: "",
    click: vi.fn(),
    setAttribute: () => {},
    removeAttribute: () => {},
  });
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    jobsBadge: { textContent: "", style: { display: "" }, addEventListener: () => {} },
    jobsMenu: menu,
    status: { textContent: "" },
    synthesize: control(),
    secondOpinion: control(),
    deepPassBtn: control(),
  };
  const runDeepPass = vi.fn();
  const api = loadDashboardModule<JobsApi>(
    "dashboard-jobs.js",
    ["dashboard-escape.js", "dashboard-time.js", "dashboard-values.js", "dashboard-fragments.js"],
    {
      document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
      fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({ jobs }) }),
      deepPassBusy: () => false,
      deepPassJob: () => null,
      applyDeepPassGate: () => {},
      loadCockpit: () => Promise.resolve(),
      runDeepPass,
    },
  );
  const click = (id: string) => {
    const b = rerunButtons.find((x) => x.dataset.job === id);
    if (!b) throw new Error(`no Re-run button on ${id}`);
    b.listeners.forEach((fn) => fn());
  };
  return { api, menu, elements, runDeepPass, click, rerunIds: () => rerunButtons.map((b) => b.dataset.job) };
}

describe("Re-run on a held job", () => {
  it("is not offered while the gate still holds the case", async () => {
    const t = setup([held("s1", "synthesis")]);
    await t.api.loadJobs();
    expect(t.menu.innerHTML).toContain("held for analyst");
    expect(t.rerunIds()).toEqual([]);
  });

  it("is offered once the gate clears, and the row says the gate cleared", async () => {
    const t = setup([held("s1", "synthesis")]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-1", true);
    expect(t.menu.innerHTML).toContain("was held — gate cleared");
    expect(t.rerunIds()).toEqual(["s1"]);
  });

  it("is withdrawn when a gate holds the case again", async () => {
    const t = setup([held("s1", "synthesis")]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-1", true);
    t.api.setJobsGateCleared("INC-1", false);
    expect(t.rerunIds()).toEqual([]);
  });

  it("ignores a cleared gate reported for another case", async () => {
    const t = setup([held("s1", "synthesis")]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-2", true);
    expect(t.rerunIds()).toEqual([]);
  });

  it("is offered only on the newest job of each kind", async () => {
    // Newest first, as GET /api/jobs returns them.
    const t = setup([
      { id: "s2", kind: "synthesis", status: "succeeded" },
      held("s1", "synthesis"),
      held("d1", "deep-pass", { minSeverity: "Medium" }),
    ]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-1", true);
    expect(t.rerunIds()).toEqual(["d1"]);
  });

  it("presses AI Re-synthesize for a held synthesis", async () => {
    const t = setup([held("s1", "synthesis")]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-1", true);
    t.click("s1");
    expect((t.elements.synthesize as { click: () => void }).click).toHaveBeenCalledOnce();
  });

  it("presses 2nd opinion for a held second opinion", async () => {
    const t = setup([held("o1", "second-opinion")]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-1", true);
    t.click("o1");
    expect((t.elements.secondOpinion as { click: () => void }).click).toHaveBeenCalledOnce();
  });

  it("runs a held deep pass again at the floor it was held at, with its panel open", async () => {
    const t = setup([held("d1", "deep-pass", { minSeverity: "Medium" })]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-1", true);
    t.click("d1");
    expect((t.elements.deepPassBtn as { click: () => void }).click).toHaveBeenCalledOnce();
    expect(t.runDeepPass).toHaveBeenCalledWith("Medium");
  });

  it("says why, and starts nothing, when the control is locked", async () => {
    const t = setup([held("s1", "synthesis")]);
    await t.api.loadJobs();
    t.api.setJobsGateCleared("INC-1", true);
    // Set after the render: the heavy-job lock re-derives the button's state on every render.
    Object.assign(t.elements.synthesize as object, { disabled: true, title: "A deep pass is running" });
    t.click("s1");
    expect((t.elements.synthesize as { click: () => void }).click).not.toHaveBeenCalled();
    expect((t.elements.status as { textContent: string }).textContent).toContain("A deep pass is running");
  });
});
