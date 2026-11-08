// #2400: an abandoned jobs read must never freeze the jobs chip or its refresh.
//
// The case load and the reconnect catch-up hand an ABANDONED request a promise that never settles.
// loadJobs shared its in-flight promise with every caller for the same case until it settled, so a
// cancelled load followed by a retry of the same case handed back the dead promise for ever — and
// runJobUiRefresh, awaiting it, held its running flag on, so no job_changed push refreshed anything.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface JobsApi {
  loadJobs: () => Promise<void>;
  scheduleJobUiRefresh: (caseId?: string, jobs?: unknown[]) => void;
}

const ABANDONED = "dfir:panel-requests-abandoned";
const PRELOAD = ["dashboard-escape.js", "dashboard-values.js", "dashboard-fragments.js"];
const RUNNING = [{ id: "j1", kind: "synthesis", status: "running", cancellable: true }];

function harness() {
  const badge = { textContent: "", style: { display: "" }, addEventListener: () => {} };
  const menu = { innerHTML: "", style: { display: "none" }, querySelectorAll: () => [] as unknown[] };
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    jobsBadge: badge,
    jobsMenu: menu,
    status: { textContent: "" },
  };
  const urls: string[] = [];
  const answers: Array<(jobs: unknown[]) => void> = [];
  const listeners: Record<string, Array<() => void>> = {};
  const timers = new Map<number, () => void>();
  let nextTimer = 0;
  let cockpitReads = 0;
  const api = loadDashboardModule<JobsApi>("dashboard-jobs.js", PRELOAD, {
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
    addEventListener: (type: string, fn: () => void) => {
      (listeners[type] ||= []).push(fn);
    },
    setTimeout: (fn: () => void) => {
      timers.set(++nextTimer, fn);
      return nextTimer;
    },
    clearTimeout: (id: number) => void timers.delete(id),
    fetch: (url: string) => {
      urls.push(url);
      return new Promise((resolve) =>
        answers.push((jobs) => resolve({ ok: true, status: 200, json: () => Promise.resolve({ jobs }) })),
      );
    },
    deepPassBusy: () => false,
    deepPassJob: () => null,
    applyDeepPassGate: () => {},
    loadCockpit: () => {
      cockpitReads++;
      return Promise.resolve();
    },
  });
  const abandon = () => (listeners[ABANDONED] || []).forEach((fn) => fn());
  const fireTimers = () => {
    const due = [...timers.values()];
    timers.clear();
    due.forEach((fn) => fn());
  };
  return { api, badge, urls, answers, abandon, fireTimers, cockpit: () => cockpitReads };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe("jobs after an abandoned load (#2400)", () => {
  it("a retry of the same case issues a fresh read instead of reusing the dead one", async () => {
    const h = harness();
    void h.api.loadJobs(); // abandoned: never settles
    h.abandon();
    const retry = h.api.loadJobs();
    expect(h.urls).toHaveLength(2);
    h.answers[1](RUNNING);
    await retry;
    expect(h.badge.textContent).toBe("⚙ 1 job");
  });

  it("an older answer that settles late does not overwrite the newer one", async () => {
    const h = harness();
    void h.api.loadJobs();
    h.abandon();
    const retry = h.api.loadJobs();
    h.answers[1](RUNNING); // the replacement answers first
    await retry;
    h.answers[0]([]); // the old read, answered late, says "no jobs"
    await settle();
    expect(h.badge.textContent).toBe("⚙ 1 job");
  });

  it("a job refresh stuck on the dead read is released, and later pushes refresh again", async () => {
    const h = harness();
    h.api.scheduleJobUiRefresh("INC-1");
    h.fireTimers(); // runJobUiRefresh starts; its loadJobs() never settles
    await settle();
    expect(h.cockpit()).toBe(1);
    h.abandon();
    h.api.scheduleJobUiRefresh("INC-1");
    h.fireTimers();
    await settle();
    expect(h.cockpit()).toBe(2);
  });

  it("an abandonment drops a refresh that was still waiting on its timer", async () => {
    const h = harness();
    h.api.scheduleJobUiRefresh("INC-1");
    h.abandon(); // e.g. the analyst cancelled the case load
    h.fireTimers(); // a timer that still fires must not read jobs for the cancelled case
    await settle();
    expect(h.cockpit()).toBe(0);
    expect(h.urls).toHaveLength(0);
  });
});
