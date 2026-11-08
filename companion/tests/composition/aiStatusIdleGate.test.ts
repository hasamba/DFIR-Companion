import { describe, it, expect, vi } from "vitest";
import { createAiStatusHandler } from "../../src/composition/aiStatusHandler.js";
import { caseJobRest, type CaseJobRest } from "../../src/composition/aiStatusIdleGate.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import type { AiStatusEvent } from "../../src/composition/appOptions.js";
import type { Logger } from "../../src/logging/logger.js";

// #2406: "idle" reaches the dashboard only once the case has no job running.

const AT = "2026-11-08T00:00:00.000Z";
const LATER = "2026-11-08T00:05:00.000Z";
const idle = (detail?: string): AiStatusEvent => ({ status: "idle", at: AT, ...(detail ? { detail } : {}) });
const analyzing = (detail: string): AiStatusEvent => ({
  status: "analyzing",
  phase: "extracting",
  at: AT,
  detail,
});
const error = (detail: string): AiStatusEvent => ({ status: "error", at: AT, detail });

const logger: Logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  getLevel: () => "info",
  setLevel: () => {},
  close: async () => {},
};

function harness() {
  const rest = new Map<string, CaseJobRest>();
  const listeners: Array<(caseId: string) => void> = [];
  const broadcast = vi.fn();
  const handler = createAiStatusHandler({
    broadcast,
    logger,
    redact: (e) => e,
    jobs: {
      jobsAtRest: (caseId) => rest.get(caseId) ?? "other",
      subscribeJobs: (l) => listeners.push(l),
      now: () => LATER,
    },
  });
  const jobsChange = (caseId: string, state: CaseJobRest) => {
    rest.set(caseId, state);
    for (const l of listeners) l(caseId);
  };
  return { handler, broadcast, rest, jobsChange };
}

const sent = (b: ReturnType<typeof vi.fn>) =>
  b.mock.calls.map(([c, e]) => `${c}:${(e as AiStatusEvent).status}`);

describe("AI status idle gate (#2406)", () => {
  it("holds an idle while a job is running and releases it when the last job succeeds", () => {
    const { handler, broadcast, rest, jobsChange } = harness();
    rest.set("c1", "active");
    handler("c1", analyzing("thor import — 1/2"));
    handler("c1", idle()); // the first of two imports finished
    expect(sent(broadcast)).toEqual(["c1:analyzing"]);
    handler("c1", analyzing("siem import — 1/3")); // the other import's progress keeps the held idle
    jobsChange("c1", "active"); // still something running
    expect(sent(broadcast)).toEqual(["c1:analyzing", "c1:analyzing"]);
    jobsChange("c1", "succeeded");
    expect(sent(broadcast)).toEqual(["c1:analyzing", "c1:analyzing", "c1:idle"]);
    expect(broadcast.mock.calls[2][1]).toMatchObject({ status: "idle", at: LATER });
    jobsChange("c1", "succeeded"); // released once only
    expect(broadcast).toHaveBeenCalledTimes(3);
  });

  it("drops a held idle when the last job failed, so 'up to date' never flashes before the error", () => {
    const { handler, broadcast, rest, jobsChange } = harness();
    rest.set("c1", "active");
    handler("c1", idle()); // generic import's early idle, before settle
    jobsChange("c1", "other"); // jobManager.fail
    handler("c1", error("settle failed"));
    expect(sent(broadcast)).toEqual(["c1:error"]);
  });

  it("drops a held idle at rest when the last broadcast was an error or a hold", () => {
    const { handler, broadcast, rest, jobsChange } = harness();
    rest.set("c1", "active");
    handler("c1", error("import B failed"));
    handler("c1", idle());
    jobsChange("c1", "succeeded");
    expect(sent(broadcast)).toEqual(["c1:error"]);
  });

  it("passes an idle straight through when nothing is running, and keeps cases apart", () => {
    const { handler, broadcast, rest, jobsChange } = harness();
    rest.set("c1", "active");
    handler("c1", idle());
    handler("c2", idle("other case"));
    expect(sent(broadcast)).toEqual(["c2:idle"]);
    jobsChange("c2", "succeeded"); // a job change in c2 does not release c1's idle
    expect(sent(broadcast)).toEqual(["c2:idle"]);
  });

  it("a later idle replaces the held one; a job change with nothing held broadcasts nothing", () => {
    const { handler, broadcast, rest, jobsChange } = harness();
    jobsChange("c1", "succeeded");
    expect(broadcast).not.toHaveBeenCalled();
    rest.set("c1", "active");
    handler("c1", idle("first"));
    handler("c1", idle("import processing cancelled; stored evidence retained"));
    jobsChange("c1", "succeeded");
    expect(broadcast.mock.calls[0][1]).toMatchObject({
      detail: "import processing cancelled; stored evidence retained",
    });
  });

  it("without job wiring every event broadcasts as before", () => {
    const broadcast = vi.fn();
    const handler = createAiStatusHandler({ broadcast, logger, redact: (e) => e });
    handler("c1", idle());
    expect(broadcast).toHaveBeenCalledWith("c1", idle());
  });
});

describe("caseJobRest", () => {
  it("is active while a job is queued or running, else the last-ended job's outcome", async () => {
    const m = new JobManager();
    const a = m.register({ caseId: "c1", kind: "import" });
    expect(caseJobRest(m.list("c1"))).toBe("active");
    await m.fail(a.jobId, new Error("x"));
    expect(caseJobRest(m.list("c1"))).toBe("other");
    expect(caseJobRest([])).toBe("other");
    const ended = [
      {
        status: "failed" as const,
        endedAt: "2026-11-08T00:00:01.000Z",
        updatedAt: "2026-11-08T00:00:01.000Z",
      },
      {
        status: "succeeded" as const,
        endedAt: "2026-11-08T00:00:02.000Z",
        updatedAt: "2026-11-08T00:00:02.000Z",
      },
    ];
    expect(caseJobRest(ended)).toBe("succeeded");
    expect(caseJobRest([...ended].reverse())).toBe("succeeded");
  });

  it("wired to a real job manager, an early idle reaches the dashboard only after finish()", async () => {
    const listeners: Array<(caseId: string) => void> = [];
    const broadcast = vi.fn();
    const m: JobManager = new JobManager({
      onJob: (caseId) => caseId && listeners.forEach((l) => l(caseId)),
    });
    const handler = createAiStatusHandler({
      broadcast,
      logger,
      redact: (e) => e,
      jobs: { jobsAtRest: (c) => caseJobRest(m.list(c)), subscribeJobs: (l) => listeners.push(l) },
    });
    const first = m.register({ caseId: "c1", kind: "import" });
    const second = m.register({ caseId: "c1", kind: "import" });
    handler("c1", idle()); // import.ts pushes idle before settle and before finish
    await m.finish(first.jobId);
    expect(broadcast).not.toHaveBeenCalled(); // the second import is still running
    await m.finish(second.jobId);
    expect(sent(broadcast)).toEqual(["c1:idle"]);
  });
});
