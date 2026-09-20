// #1453: the jobs chip renders from the job list the `job_changed` push carries. The HTTP read it
// used to depend on never left the browser during a big import — every lane was held by a panel
// read waiting on the case worker — so the chip stayed hidden while the header pill said
// "importing". The socket is its own connection; a push that carries the list needs no lane.
import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface JobsApi {
  scheduleJobUiRefresh: (caseId: string, jobs?: unknown) => void;
  runningJob: (kind: string) => { id: string } | undefined;
}

const PRELOAD = ["dashboard-escape.js", "dashboard-values.js", "dashboard-fragments.js"];

function harness() {
  const fetched: string[] = [];
  const flushed: number[] = [];
  const badge = { textContent: "", style: { display: "none" }, addEventListener: () => {} };
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    jobsBadge: badge,
    jobsMenu: { innerHTML: "", style: { display: "none" }, querySelectorAll: () => [] },
    status: { textContent: "" },
  };
  const api = loadDashboardModule<JobsApi>("dashboard-jobs.js", PRELOAD, {
    document: { getElementById: (id: string) => elements[id] ?? null, addEventListener: () => {} },
    fetch: (url: string) => {
      fetched.push(url);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ jobs: [] }) });
    },
    deepPassBusy: () => false,
    deepPassJob: () => null,
    applyDeepPassGate: () => {},
    loadCockpit: () => Promise.resolve(),
    flushDeferredIocProvenanceReloads: () => flushed.push(1),
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id: unknown) => globalThis.clearTimeout(id as number),
  });
  return { api, badge, fetched, flushed };
}

const RUNNING_IMPORT = [{ id: "job_1", caseId: "INC-1", kind: "import", status: "running", label: "x" }];

describe("the jobs chip renders from the job_changed push (#1453)", () => {
  it("draws the chip synchronously from the pushed list and skips the HTTP read", async () => {
    vi.useFakeTimers();
    const { api, badge, fetched, flushed } = harness();
    api.scheduleJobUiRefresh("INC-1", RUNNING_IMPORT);
    expect(badge.style.display).toBe("");
    expect(badge.textContent).toBe("⚙ 1 job");
    expect(api.runningJob("import")?.id).toBe("job_1");
    expect(flushed).toEqual([1]); // the provenance hand-off sees the new job set at once
    await vi.advanceTimersByTimeAsync(1000);
    expect(fetched.filter((u) => u.startsWith("/api/jobs"))).toEqual([]);
    vi.useRealTimers();
  });

  it("hides the chip again when a push says the import is gone", () => {
    const { api, badge } = harness();
    api.scheduleJobUiRefresh("INC-1", RUNNING_IMPORT);
    api.scheduleJobUiRefresh("INC-1", [{ ...RUNNING_IMPORT[0], status: "succeeded" }]);
    expect(badge.style.display).toBe("none");
    expect(api.runningJob("import")).toBeUndefined();
  });

  it("ignores a push for a case that is not on screen", () => {
    const { api, badge } = harness();
    api.scheduleJobUiRefresh("INC-2", [{ ...RUNNING_IMPORT[0], caseId: "INC-2" }]);
    expect(badge.style.display).toBe("none");
    expect(api.runningJob("import")).toBeUndefined();
  });

  it("still reads over HTTP when the push carries no list (an older server)", async () => {
    vi.useFakeTimers();
    const { api, fetched } = harness();
    api.scheduleJobUiRefresh("INC-1");
    await vi.advanceTimersByTimeAsync(1000);
    expect(fetched.filter((u) => u.startsWith("/api/jobs"))).toHaveLength(1);
    vi.useRealTimers();
  });
});

describe("the connect fan-out loads jobs before the panels #1447 parks (#1453)", () => {
  it("lists the jobs loader ahead of the IOC-provenance loaders", () => {
    const src = readFileSync(
      new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
      "utf8",
    );
    const jobs = src.indexOf('["jobs", () => loadJobs(caseId)]');
    const provenance = src.indexOf('["iocProvenance"');
    expect(jobs).toBeGreaterThan(-1);
    expect(provenance).toBeGreaterThan(-1);
    expect(jobs).toBeLessThan(provenance);
  });

  it("hands the pushed job list to the jobs module", () => {
    const src = readFileSync(
      new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
      "utf8",
    );
    expect(src).toMatch(/msg\.type === "job_changed"\)\s*scheduleJobUiRefresh\(caseId, msg\.jobs\)/);
  });
});
