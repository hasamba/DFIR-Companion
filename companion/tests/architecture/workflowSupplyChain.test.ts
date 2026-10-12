import { readdirSync, readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

// THIRD-PARTY ACTIONS RUN FROM A COMMIT, AND RELEASE JOBS WRITE ONLY WHERE THEY MUST (#2156).
//
// A tag like `@v2` or even `@v5.0.0` is a mutable ref: whoever controls the upstream repo can
// move it, and the next run executes the new code with the job's GITHUB_TOKEN and every secret
// passed to the step (Chrome Web Store refresh token, OIDC token, GHCR push). The repo policy
// (#817) is that every action outside `actions/*` is pinned to a 40-hex commit SHA. `actions/*`
// stays on major tags by decision (#1192).
//
// release-artifacts.yml used to grant `contents: write` to all seven jobs. Only `release`
// (creates the GitHub Release) and `chocolatey` (attaches the .nupkg to it) write release
// assets; every other job — including the store-upload jobs holding third-party secrets — runs
// with `contents: read`.
//
// The workflow-level-or-every-job permissions rule lives in workflowPermissions.test.ts (#2159).
const workflowsDir = new URL("../../../.github/workflows/", import.meta.url);

interface Step {
  uses?: string;
}
interface Job {
  permissions?: unknown;
  uses?: string;
  steps?: Step[];
}
interface Workflow {
  permissions?: unknown;
  jobs?: Record<string, Job | null>;
}

const workflowFiles = readdirSync(workflowsDir)
  .filter((name) => /\.ya?ml$/i.test(name))
  .sort();

function loadWorkflow(name: string): Workflow {
  return (parseYaml(readFileSync(new URL(name, workflowsDir), "utf8")) ?? {}) as Workflow;
}

const PINNED = /@[0-9a-f]{40}$/;

function isFirstParty(ref: string): boolean {
  return ref.startsWith("actions/") || ref.startsWith("./") || ref.startsWith("docker://");
}

function unpinnedUses(name: string): string[] {
  return Object.entries(loadWorkflow(name).jobs ?? {}).flatMap(([jobId, job]) => {
    const refs = [job?.uses, ...(job?.steps ?? []).map((s) => s?.uses)].filter(
      (u): u is string => typeof u === "string",
    );
    return refs
      .filter((ref) => !isFirstParty(ref) && !PINNED.test(ref.trim()))
      .map((ref) => `${name} › ${jobId} › ${ref}`);
  });
}

function grantsWrite(permissions: unknown, scope?: string): boolean {
  if (permissions === "write-all") return true;
  if (permissions === null || typeof permissions !== "object") return false;
  return Object.entries(permissions as Record<string, unknown>).some(
    ([key, value]) => value === "write" && (scope === undefined || key === scope),
  );
}

describe("GitHub workflow supply chain", () => {
  it("finds the workflow files to check", () => {
    expect(workflowFiles.length).toBeGreaterThan(0);
  });

  it("every third-party action is pinned to a 40-hex commit SHA", () => {
    expect(workflowFiles.flatMap(unpinnedUses)).toEqual([]);
  });

  describe("release-artifacts.yml", () => {
    const wf = loadWorkflow("release-artifacts.yml");

    it("grants no write scope at the workflow level", () => {
      expect(wf.permissions).toBeDefined();
      expect(grantsWrite(wf.permissions)).toBe(false);
    });

    it("only the release and chocolatey jobs get contents: write", () => {
      const writers = Object.entries(wf.jobs ?? {})
        .filter(([, job]) => grantsWrite(job?.permissions, "contents"))
        .map(([id]) => id)
        .sort();
      expect(writers).toEqual(["chocolatey", "release"]);
    });

    it("no job grants any write scope other than contents", () => {
      const extra = Object.entries(wf.jobs ?? {}).flatMap(([id, job]) => {
        const perms = job?.permissions;
        if (perms === "write-all") return [`${id}: write-all`];
        if (perms === null || typeof perms !== "object") return [];
        return Object.entries(perms as Record<string, unknown>)
          .filter(([key, value]) => value === "write" && key !== "contents")
          .map(([key]) => `${id}: ${key}`);
      });
      expect(extra).toEqual([]);
    });
  });
});
