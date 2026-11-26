// AI Agent Forensics run status (#2898): the run card says, in plain English, whether the run is still
// going or done, read live from the Velociraptor hunt's own client counts.
import { describe, expect, it } from "vitest";
import { describeAiAgentRunStatus } from "../../../src/integrations/velociraptor/aiAgentRunStatus.js";

const hunt = (state: string, scheduled: number, completed: number, errors = 0) => ({
  state,
  clients: { scheduled, completed, errors },
});

describe("describeAiAgentRunStatus", () => {
  it("is running while fewer endpoints finished than were picked", () => {
    expect(describeAiAgentRunStatus(hunt("PAUSED", 2, 1), 2)).toEqual({
      state: "running",
      total: 2,
      finished: 1,
      errors: 0,
      summary: "Running — 1 of 2 endpoint(s) finished",
    });
  });

  it("is finished when every picked endpoint finished", () => {
    const s = describeAiAgentRunStatus(hunt("PAUSED", 1, 1), 1);
    expect(s.state).toBe("finished");
    expect(s.summary).toBe("Finished — 1 of 1 endpoint(s) done");
  });

  it("counts the endpoints picked even before Velociraptor scheduled them all", () => {
    const s = describeAiAgentRunStatus(hunt("PAUSED", 0, 0), 3);
    expect(s).toMatchObject({ state: "running", total: 3, finished: 0 });
  });

  it("names endpoints that reported an error", () => {
    expect(describeAiAgentRunStatus(hunt("PAUSED", 2, 2, 1), 2).summary).toBe(
      "Finished — 2 of 2 endpoint(s) done; 1 reported an error",
    );
  });

  it("says a hunt stopped in Velociraptor before every endpoint finished", () => {
    const s = describeAiAgentRunStatus(hunt("STOPPED", 2, 1), 2);
    expect(s.state).toBe("stopped");
    expect(s.summary).toBe("Stopped in Velociraptor — 1 of 2 endpoint(s) finished");
  });

  it("is unknown when Velociraptor has no record of the hunt, or no progress counts", () => {
    expect(describeAiAgentRunStatus(null, 1)).toMatchObject({
      state: "unknown",
      summary: "Unknown — Velociraptor has no record of this run",
    });
    expect(describeAiAgentRunStatus({ state: "PAUSED" }, 1)).toMatchObject({
      state: "unknown",
      summary: "Unknown — Velociraptor did not report this run's progress",
    });
  });
});
