// #1447: the jobs refresh is the moment the dashboard learns an import has finished, so it is
// the hand-off that lets the parked IOC-provenance reloads fire. Pinned from the jobs side.
import { describe, it, expect, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface JobsApi {
  scheduleJobUiRefresh: (caseId: string) => void;
}

const PRELOAD = ["dashboard-escape.js", "dashboard-values.js", "dashboard-fragments.js"];

function harness(withFlush: boolean) {
  const flushed: number[] = [];
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    jobsBadge: { textContent: "", style: { display: "" }, addEventListener: () => {} },
    jobsMenu: { innerHTML: "", style: { display: "none" }, querySelectorAll: () => [] },
    status: { textContent: "" },
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
    ...(withFlush ? { flushDeferredIocProvenanceReloads: () => flushed.push(1) } : {}),
  });
  return { api, flushed };
}

describe("the jobs refresh flushes parked IOC-provenance reloads (#1447)", () => {
  it("calls the flush once per refresh, after the jobs cache has been reloaded", async () => {
    vi.useFakeTimers();
    const { api, flushed } = harness(true);
    api.scheduleJobUiRefresh("INC-1");
    expect(flushed).toEqual([]);
    await vi.advanceTimersByTimeAsync(1000);
    expect(flushed).toEqual([1]);
    vi.useRealTimers();
  });

  it("is a no-op when the provenance module is not loaded", async () => {
    vi.useFakeTimers();
    const { api } = harness(false);
    const errors: unknown[] = [];
    process.on("unhandledRejection", (e) => errors.push(e));
    api.scheduleJobUiRefresh("INC-1");
    await vi.advanceTimersByTimeAsync(1000);
    expect(errors).toEqual([]);
    vi.useRealTimers();
  });
});
