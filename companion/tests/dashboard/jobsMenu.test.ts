// The jobs popover must show every job its badge counts.
//
// Reported as "the chip says ⚙ 3 jobs, and none of them are in the list". The popover renders a
// bounded number of rows, newest first, and it took them straight off the top of the cache — so a
// burst of finished rows (a multi-file import mints one per file) filled the whole budget and
// pushed the still-queued work off the end. The badge counted the whole cache and the list showed
// twelve rows of history, and the two flatly contradicted each other.
//
// This drives the real module in a vm context, the way the browser loads it (see
// helpers/dashboardModule.ts). renderJobs is private, so the test reaches it through loadJobs() —
// the same path the WS refresh takes.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface JobsApi {
  loadJobs: () => Promise<void>;
}

type StubJob = {
  id: string;
  kind: string;
  status: string;
  cancellable?: boolean;
  resumable?: boolean;
  failure?: { retryable: boolean };
};

/** Minimal stand-ins for the page: one input, one badge, one menu, and inert everything else. */
function pageStubs(jobs: StubJob[]) {
  const menu = {
    innerHTML: "",
    style: { display: "none" },
    querySelectorAll: () => [] as unknown[],
  };
  const badge = { textContent: "", style: { display: "" }, addEventListener: () => {} };
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    jobsBadge: badge,
    jobsMenu: menu,
    status: { textContent: "" },
  };
  return {
    menu,
    badge,
    globals: {
      document: {
        getElementById: (id: string) => elements[id] ?? null,
        addEventListener: () => {},
      },
      fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({ jobs }) }),
      // The deep-pass lock renderJobs ends on. Not the subject here; kept inert so it cannot
      // decide the outcome.
      deepPassBusy: () => false,
      deepPassJob: () => null,
      applyDeepPassGate: () => {},
      loadCockpit: () => Promise.resolve(),
    },
  };
}

const PRELOAD = ["dashboard-escape.js", "dashboard-values.js", "dashboard-fragments.js"];

async function renderedRows(jobs: StubJob[]): Promise<{ ids: string[]; badge: string }> {
  const stubs = pageStubs(jobs);
  const api = loadDashboardModule<JobsApi>("dashboard-jobs.js", PRELOAD, stubs.globals);
  await api.loadJobs();
  const ids = [...stubs.menu.innerHTML.matchAll(/data-job-id="([^"]+)"/g)].map((m) => m[1]);
  return { ids, badge: stubs.badge.textContent };
}

const finished = (n: number): StubJob[] =>
  Array.from({ length: n }, (_unused, i) => ({
    id: `done-${i}`,
    kind: "synthesis",
    status: "succeeded",
  }));

describe("the background-jobs popover", () => {
  it("shows every running or queued job the badge counts, however much history precedes it", async () => {
    // Newest first, as GET /api/jobs returns them: twenty finished rows ahead of the queued work.
    const { ids, badge } = await renderedRows([
      ...finished(20),
      { id: "queued-1", kind: "import", status: "queued", cancellable: true },
      { id: "queued-2", kind: "import", status: "queued", cancellable: true },
      { id: "running-1", kind: "import", status: "running", cancellable: true },
    ]);

    expect(badge).toBe("⚙ 3 jobs");
    expect(ids).toEqual(expect.arrayContaining(["queued-1", "queued-2", "running-1"]));
  });

  it("still fills the rest of the popover with recent history, newest first", async () => {
    const { ids } = await renderedRows([
      ...finished(20),
      { id: "queued-1", kind: "import", status: "queued", cancellable: true },
    ]);

    // The active row plus enough history to fill the budget — and in cache order, not reshuffled
    // with the active rows hoisted to the top: the popover reads as a timeline.
    expect(ids.length).toBeGreaterThan(1);
    expect(ids[0]).toBe("done-0");
    expect(ids).toContain("queued-1");
    expect(ids.indexOf("queued-1")).toBe(ids.length - 1);
  });

  it("keeps a resumable interrupted job visible behind a wall of history", async () => {
    const { ids, badge } = await renderedRows([
      ...finished(20),
      { id: "stalled", kind: "import", status: "interrupted", resumable: true },
    ]);

    expect(badge).toBe("⚠ 1 job need attention");
    expect(ids).toContain("stalled");
  });
});
