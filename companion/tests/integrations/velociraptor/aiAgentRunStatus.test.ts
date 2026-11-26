// AI Agent Forensics run status (#2898): the run card says, in plain English, whether the run is still
// going or done. It reads each endpoint's own collection (`hunt_flows()`), not the hunt's summary
// counters: on a real paused hunt the counters still said 0 rows while the endpoint's collection had
// 1,172 rows and was IN_PROGRESS — they lag, and a status built on them could stick at "0 finished".
import { describe, expect, it } from "vitest";
import {
  describeAiAgentRunStatus,
  huntFlowsVql,
  parseHuntFlows,
} from "../../../src/integrations/velociraptor/aiAgentRunStatus.js";

const flow = (clientId: string, state: string, rows = 0, status = "") => ({ clientId, state, rows, status });

describe("parseHuntFlows", () => {
  it("reads each endpoint's collection state and row count", () => {
    expect(
      parseHuntFlows([
        { ClientId: "C.a1", State: "IN_PROGRESS", Rows: 1172, Status: "" },
        { ClientId: "C.b2", State: "FINISHED" },
      ]),
    ).toEqual([flow("C.a1", "IN_PROGRESS", 1172), flow("C.b2", "FINISHED")]);
  });

  it("voids the whole list on a row it cannot read, so progress is never guessed", () => {
    expect(parseHuntFlows([{ ClientId: "not-an-id", State: "FINISHED" }])).toBeUndefined();
    expect(parseHuntFlows([{ ClientId: "C.a1" }])).toBeUndefined();
    expect(parseHuntFlows("nope")).toBeUndefined();
  });

  it("asks hunt_flows for one validated hunt", () => {
    expect(huntFlowsVql("H.ABC123")).toContain("FROM hunt_flows(hunt_id='H.ABC123')");
    expect(() => huntFlowsVql("H.x'; DROP")).toThrow();
  });
});

describe("describeAiAgentRunStatus", () => {
  it("is running while an endpoint's collection is in progress, with rows so far", () => {
    expect(describeAiAgentRunStatus("PAUSED", [flow("C.a1", "IN_PROGRESS", 1172)], 1)).toEqual({
      state: "running",
      total: 1,
      finished: 0,
      errors: 0,
      summary: "Running — 0 of 1 endpoint(s) finished; 1,172 rows collected so far",
    });
  });

  it("is finished when every endpoint's collection finished", () => {
    const s = describeAiAgentRunStatus(
      "PAUSED",
      [flow("C.a1", "FINISHED", 10), flow("C.b2", "FINISHED", 5)],
      2,
    );
    expect(s.state).toBe("finished");
    expect(s.summary).toBe("Finished — 2 of 2 endpoint(s) done");
  });

  it("counts a collection that ended in an error as done, and names it", () => {
    const s = describeAiAgentRunStatus(
      "PAUSED",
      [flow("C.a1", "FINISHED"), flow("C.b2", "ERROR", 0, "timeout")],
      2,
    );
    expect(s).toMatchObject({ state: "finished", finished: 2, errors: 1 });
    expect(s.summary).toBe("Finished — 2 of 2 endpoint(s) done; 1 ended with an error");
  });

  it("names picked endpoints Velociraptor has not reached yet", () => {
    const s = describeAiAgentRunStatus("PAUSED", [flow("C.a1", "FINISHED")], 3);
    expect(s).toMatchObject({ state: "running", total: 3, finished: 1 });
    expect(s.summary).toBe("Running — 1 of 3 endpoint(s) finished; 2 not started yet (offline?)");
  });

  it("says a hunt stopped in Velociraptor before every endpoint finished", () => {
    const s = describeAiAgentRunStatus("STOPPED", [flow("C.a1", "FINISHED"), flow("C.b2", "IN_PROGRESS")], 2);
    expect(s.state).toBe("stopped");
    expect(s.summary).toBe("Stopped in Velociraptor — 1 of 2 endpoint(s) finished");
  });

  it("is unknown when Velociraptor has no record of the hunt, or its collections cannot be read", () => {
    expect(describeAiAgentRunStatus(null, [], 1)).toMatchObject({
      state: "unknown",
      summary: "Unknown — Velociraptor has no record of this run",
    });
    expect(describeAiAgentRunStatus("PAUSED", undefined, 1)).toMatchObject({
      state: "unknown",
      summary: "Unknown — could not read this run's collections from Velociraptor",
    });
  });
});
