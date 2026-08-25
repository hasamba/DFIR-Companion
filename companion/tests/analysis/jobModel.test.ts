// Which model is running this job (#633 follow-up).
//
// The jobs popover listed "SYNTHESIS synthesis running" and nothing else. Three synthesis rows in a
// row had each timed out after 180s, and the panel could not say whether they were all the same
// model — so the analyst could not tell "my synth model is too slow" from "one run was unlucky".
// The model an LLM-driven job runs is part of what the job IS, so it lives on the job record and
// survives the ledger round-trip like every other field.
import { describe, it, expect } from "vitest";
import { createJob, emptyJobTable, getJob, jobSchema } from "../../src/analysis/jobRegistry.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { jobModelResolver } from "../../src/composition/jobModel.js";

const T0 = "2026-08-25T00:00:00.000Z";

describe("job model", () => {
  it("createJob keeps the model it was given", () => {
    const table = createJob(emptyJobTable(), {
      id: "job_1",
      caseId: "c1",
      kind: "synthesis",
      model: "anthropic/claude-sonnet-4",
      now: T0,
    });
    expect(getJob(table, "job_1")!.model).toBe("anthropic/claude-sonnet-4");
  });

  it("leaves the model unset for a job no model runs", () => {
    const table = createJob(emptyJobTable(), { id: "job_1", caseId: "c1", kind: "enrichment", now: T0 });
    expect(getJob(table, "job_1")!.model).toBeUndefined();
  });

  // The ledger persists a job by JSON round-tripping it through this schema. A field the schema
  // does not know is dropped on the way back in, so the model would vanish on a server restart.
  it("survives the ledger schema round-trip", () => {
    const table = createJob(emptyJobTable(), {
      id: "job_1",
      caseId: "c1",
      kind: "deep-pass",
      model: "gpt-4o",
      now: T0,
    });
    const parsed = jobSchema.parse(JSON.parse(JSON.stringify(getJob(table, "job_1"))));
    expect(parsed.model).toBe("gpt-4o");
  });

  it("register asks the installed resolver, once, at queue time", () => {
    const manager = new JobManager({ now: () => T0 });
    manager.useModelResolver(() => "llama3.1:8b");
    const { jobId } = manager.register({ caseId: "c1", kind: "synthesis" });
    expect(manager.get(jobId)!.model).toBe("llama3.1:8b");
  });

  // A minimal wiring (and every test that builds a bare manager) installs no resolver. That must
  // mean "this row names no model", never a crash on the registration path.
  it("registers fine with no resolver installed", () => {
    const manager = new JobManager({ now: () => T0 });
    const { jobId } = manager.register({ caseId: "c1", kind: "synthesis" });
    expect(manager.get(jobId)!.model).toBeUndefined();
  });
});

describe("jobModelResolver", () => {
  const pipeline = { analysisTextProviderModel: () => ({ provider: "openrouter", model: "sonnet" }) };

  it("names the text model for synthesis and for a deep pass", () => {
    const resolve = jobModelResolver(pipeline);
    expect(resolve({ kind: "synthesis" })).toBe("sonnet");
    expect(resolve({ kind: "deep-pass" })).toBe("sonnet");
  });

  it("names it for a csv/log import, which runs the model to extract", () => {
    const resolve = jobModelResolver(pipeline);
    expect(resolve({ kind: "import", parameters: { kind: "csv" } })).toBe("sonnet");
    expect(resolve({ kind: "import", parameters: { kind: "log" } })).toBe("sonnet");
  });

  // A deterministic import parses locally, and the Velociraptor collect that borrows an import slot
  // registers no parameters at all. Neither may claim the synthesis model.
  it("leaves a deterministic import and a bare import slot unnamed", () => {
    const resolve = jobModelResolver(pipeline);
    expect(resolve({ kind: "import", parameters: { kind: "evtx" } })).toBeUndefined();
    expect(resolve({ kind: "import" })).toBeUndefined();
  });

  it("leaves enrichment and MCP unnamed — no model of ours runs them", () => {
    const resolve = jobModelResolver(pipeline);
    expect(resolve({ kind: "enrichment" })).toBeUndefined();
    expect(resolve({ kind: "mcp" })).toBeUndefined();
  });

  it("names nothing when no AI is configured", () => {
    expect(jobModelResolver(undefined)({ kind: "synthesis" })).toBeUndefined();
    expect(
      jobModelResolver({ analysisTextProviderModel: () => null })({ kind: "synthesis" }),
    ).toBeUndefined();
  });
});
