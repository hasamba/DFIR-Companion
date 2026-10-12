import { readdirSync, readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

// EVERY WORKFLOW JOB RUNS WITH AN EXPLICIT TOKEN SCOPE (#2159).
//
// A job with no `permissions:` block, at workflow level or on the job itself, inherits the
// repository's default GITHUB_TOKEN scope. That default is read-only today, but it is a setting
// outside this repo: if it is ever flipped to read-write, every uncovered job — including
// PR-triggered secret scans that run third-party actions — silently gets a writable token.
//
// The rule: a workflow declares a top-level `permissions:` block, OR every one of its jobs
// declares its own. Both styles are in use (ci.yml relies on the workflow-level block,
// claude.yml on job-level blocks), so either satisfies it. `write-all` is never acceptable.
//
// The directory is read with readdirSync, so a new workflow is covered the moment it is added.
const workflowsDir = new URL("../../../.github/workflows/", import.meta.url);

interface Workflow {
  permissions?: unknown;
  jobs?: Record<string, { permissions?: unknown } | null>;
}

const workflowFiles = readdirSync(workflowsDir)
  .filter((name) => /\.ya?ml$/i.test(name))
  .sort();

function loadWorkflow(name: string): Workflow {
  return (parseYaml(readFileSync(new URL(name, workflowsDir), "utf8")) ?? {}) as Workflow;
}

function jobsWithoutPermissions(wf: Workflow): string[] {
  return Object.entries(wf.jobs ?? {})
    .filter(([, job]) => job?.permissions === undefined)
    .map(([id]) => id);
}

describe("GitHub workflow token permissions", () => {
  it("finds the workflow files to check", () => {
    expect(workflowFiles.length).toBeGreaterThan(0);
  });

  it("every job is covered by a workflow-level or job-level permissions block", () => {
    const uncovered = workflowFiles.flatMap((name) => {
      const wf = loadWorkflow(name);
      if (wf.permissions !== undefined) return [];
      const missing = jobsWithoutPermissions(wf);
      return missing.length > 0 ? [`${name}: ${missing.join(", ")}`] : [];
    });
    expect(uncovered).toEqual([]);
  });

  it("no workflow grants write-all at the top level", () => {
    const writeAll = workflowFiles.filter((name) => loadWorkflow(name).permissions === "write-all");
    expect(writeAll).toEqual([]);
  });
});
