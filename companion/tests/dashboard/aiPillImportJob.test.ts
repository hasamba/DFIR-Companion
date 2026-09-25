// A running IMPORT job is not the AI working (#1525).
//
// A Velociraptor hunt collect holds the case's import slot as a background job labelled
// "velociraptor: hunt H.X (N row(s), M upload(s))". /ai-state reports any running job as
// "analyzing", and the pill painted every derived "analyzing" with an "AI:" prefix — so an analyst
// with live analysis paused read "AI: velociraptor: hunt …" in the amber colour and concluded the
// AI was synthesizing. It was not: the server log showed only the import. The pushed-event path
// already relabels ingest as "deterministic import — not AI"; the derived path did not.
//
// And it stayed there. The hunt pushes `idle` BEFORE it releases the slot; the client answers
// `idle` by re-reading /ai-state, which still sees the running slot and repaints the pill. The slot
// release then pushes a jobs update — and the jobs handler never re-derived the pill, so nothing
// cleared it. The second suite pins that a jobs push leaving the case with no active job re-derives.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface AiStatusApi {
  refreshAiState: (caseId: string) => Promise<void>;
}

interface JobsApi {
  scheduleJobUiRefresh: (caseId: string, jobs?: unknown[]) => void;
}

/** The pill element plus the module, with /ai-state answering `state`. */
function pillHarness(state: Record<string, unknown>) {
  const pill = { className: "", textContent: "", title: "" };
  const globals = {
    document: { getElementById: (id: string) => (id === "aiStatus" ? pill : null) },
    fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve(state) }),
    // setAi is dashboard-presidio.js's; same two lines, because the assertion is about what the
    // status module hands it, and loading presidio drags in a page's worth of markup.
    setAi: (kind: string, text: string) => {
      pill.className = "ai-" + kind;
      pill.textContent = "AI: " + text;
      pill.title = "AI: " + text;
    },
    showImportProgress: () => {},
    hideImportProgress: () => {},
    fmtTime: () => "",
    aiEnabled: false,
    activeCaseId: "INC-1",
    loadHostDuplicates: () => {},
    loadRelatedCases: () => {},
    loadPresidioPending: () => {},
    ws: null,
  };
  return { pill, api: loadDashboardModule<AiStatusApi>("dashboard-ai-status.js", [], globals) };
}

describe("the derived pill and a running import job (#1525)", () => {
  it("paints an import-kind job without the AI prefix, and says it is not AI", async () => {
    const label = "velociraptor: hunt H.X (328 row(s), 0 upload(s))";
    const { pill, api } = pillHarness({
      state: "analyzing",
      detail: label,
      holds: [],
      running: [{ kind: "import", label }],
      livePaused: true,
    });
    await api.refreshAiState("INC-1");
    expect(pill.className).toBe("ai-analyzing"); // still work in flight — still amber
    expect(pill.textContent).toBe(label);
    expect(pill.textContent).not.toMatch(/^AI:/);
    expect(pill.title).toContain("not AI");
  });

  it("still names genuine AI work with the prefix", async () => {
    const { pill, api } = pillHarness({
      state: "analyzing",
      detail: "synthesis",
      holds: [],
      running: [{ kind: "synthesis", label: "synthesis" }],
      livePaused: false,
    });
    await api.refreshAiState("INC-1");
    expect(pill.textContent).toBe("AI: synthesis");
  });

  it("keeps a hold visible beside an import, without the prefix", async () => {
    const { pill, api } = pillHarness({
      state: "analyzing",
      detail: "evtx import",
      holds: [{ kind: "presidio", count: 1, detail: "1 Presidio finding awaiting approval" }],
      running: [{ kind: "import", label: "evtx import" }],
      livePaused: false,
    });
    await api.refreshAiState("INC-1");
    expect(pill.textContent).toBe("evtx import (analysis on hold)");
  });
});

/** The jobs module with a recording refreshAiState, fed job lists over the push path. */
function jobsHarness() {
  const refreshed: string[] = [];
  const badge = { textContent: "", style: { display: "" }, addEventListener: () => {} };
  const menu = { innerHTML: "", style: { display: "none" }, querySelectorAll: () => [] as unknown[] };
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    jobsBadge: badge,
    jobsMenu: menu,
    status: { textContent: "" },
  };
  const globals = {
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
    fetch: () => Promise.reject(new Error("not expected: the push carries the list")),
    setTimeout: () => 0, // the timed cockpit refresh the push also schedules; not under test
    clearTimeout: () => {},
    deepPassBusy: () => false,
    deepPassJob: () => null,
    applyDeepPassGate: () => {},
    loadCockpit: () => Promise.resolve(),
    refreshAiState: (caseId: string) => {
      refreshed.push(caseId);
      return Promise.resolve();
    },
  };
  const preload = ["dashboard-escape.js", "dashboard-values.js", "dashboard-fragments.js"];
  return { refreshed, api: loadDashboardModule<JobsApi>("dashboard-jobs.js", preload, globals) };
}

const running = (id: string) => ({ id, kind: "import", status: "running", cancellable: false });
const done = (id: string) => ({ id, kind: "import", status: "done", endedAt: "2026-09-22T09:34:43Z" });

describe("the pill re-derives when the last job ends (#1525)", () => {
  it("re-reads /ai-state on the jobs push that leaves the case with no active job", () => {
    const { refreshed, api } = jobsHarness();
    api.scheduleJobUiRefresh("INC-1", [running("slot-1")]);
    expect(refreshed).toEqual([]); // a job starting is announced by its own status push
    api.scheduleJobUiRefresh("INC-1", [done("slot-1")]);
    expect(refreshed).toEqual(["INC-1"]);
  });

  it("does not re-read while a job is still running — the pushed detail is richer", () => {
    const { refreshed, api } = jobsHarness();
    api.scheduleJobUiRefresh("INC-1", [done("slot-1"), running("slot-2")]);
    expect(refreshed).toEqual([]);
  });

  it("ignores a push for the case the analyst just left", () => {
    const { refreshed, api } = jobsHarness();
    api.scheduleJobUiRefresh("INC-2", [done("slot-1")]);
    expect(refreshed).toEqual([]);
  });
});

// #1599: dismissing a finding, changing the scope or clearing the Presidio gate starts no synthesis.
// The pill must not paint the green "up to date" over conclusions the case no longer supports.
describe("the derived pill when the conclusions are out of date (#1599)", () => {
  it("paints the stale class with the server's wording", async () => {
    const { pill, api } = pillHarness({
      state: "idle",
      detail: "conclusions out of date — press Re-synthesize",
      holds: [],
      running: [],
      livePaused: false,
      outOfDate: true,
    });
    await api.refreshAiState("INC-1");
    expect(pill.className).toBe("ai-stale");
    expect(pill.textContent).toBe("AI: conclusions out of date — press Re-synthesize");
  });

  it("keeps the green idle when nothing is out of date", async () => {
    const { pill, api } = pillHarness({
      state: "idle",
      detail: "up to date",
      holds: [],
      running: [],
      livePaused: false,
      outOfDate: false,
    });
    await api.refreshAiState("INC-1");
    expect(pill.className).toBe("ai-idle");
  });
});
