import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

// THE AMO SUBMISSION JOB'S FOUR WAYS TO FAIL SILENTLY.
//
// Publishing to Mozilla Add-ons is tag-driven, runs a handful of times a year, and every one of
// its failure modes surfaces hours later on a release nobody can redo. None of them is caught by
// running the workflow on a branch, because the job is gated on a tag.
//
// Each assertion below is one of those failures:
//
//   1. Signing the CHROME package. Both jobs hang off the same `extension-zip` job, which uploads
//      two artifacts whose names differ by one word. The Chrome manifest has no
//      browser_specific_settings, no data_collection_permissions, and a service_worker key
//      Firefox does not support — AMO would reject it, or worse, accept a broken add-on.
//   2. Submitting with no source archive. The shipped bundles are minified; AMO requires readable
//      source with EVERY version, not just the first. Without --upload-source-code the submission
//      is rejected after upload.
//   3. Waiting for approval. A listed version goes to human review, which takes hours to days.
//      Without --approval-timeout 0 web-ext blocks until the job's own timeout kills it, turning
//      a successful submission into a red release.
//   4. Trusting the exit code. web-ext exiting 0 is not proof AMO holds the version, which is the
//      same lesson the Chrome job's verify step already encodes.
const root = new URL("../../../", import.meta.url);
const workflow = parseYaml(
  readFileSync(new URL(".github/workflows/release-artifacts.yml", root), "utf8"),
) as {
  jobs: Record<
    string,
    {
      needs?: string | string[];
      if?: string;
      steps: { name?: string; uses?: string; run?: string; with?: Record<string, unknown> }[];
    }
  >;
};

const job = workflow.jobs["amo-listing"];
const stepText = (): string => JSON.stringify(job.steps);

describe("the AMO submission job", () => {
  it("exists and hangs off the job that builds the package", () => {
    expect(job, "amo-listing job missing from release-artifacts.yml").toBeDefined();
    const needs = Array.isArray(job.needs) ? job.needs : [job.needs];
    expect(needs).toContain("extension-zip");
  });

  it("only runs for a tag, like every other publishing job", () => {
    // A branch push must never submit to Mozilla. Version numbers are single-use on AMO: one
    // accidental submission burns the number for the real release.
    expect(job.if).toContain("refs/tags/");
  });

  it("downloads the Firefox artifact, never the Chrome one", () => {
    const download = job.steps.find((s) => s.uses?.startsWith("actions/download-artifact"));
    expect(download, "no download-artifact step").toBeDefined();
    expect(download!.with?.name).toBe("extension-firefox-zip");
  });

  it("uploads the human-readable source with the submission", () => {
    expect(stepText()).toContain("--upload-source-code");
  });

  it("does not wait for human approval", () => {
    expect(stepText()).toContain("--approval-timeout 0");
  });

  it("verifies against AMO instead of trusting web-ext's exit code", () => {
    const verify = job.steps.find((s) => s.name?.startsWith("Verify AMO"));
    expect(verify, "no verification step — web-ext exiting 0 is not proof").toBeDefined();
    expect(verify!.run).toContain("addons.mozilla.org/api/v5");
    // The failure branch must actually fail. A verify step that only echoes is decoration.
    expect(verify!.run).toMatch(/exit 1/);
  });

  it("submits the add-on ID the manifest transform pins", async () => {
    // If these two ever disagree the job verifies a DIFFERENT add-on and reports success while
    // the real one received nothing.
    const { GECKO_ID } = (await import(new URL("extension/scripts/manifest-firefox.mjs", root).href)) as {
      GECKO_ID: string;
    };
    const verify = job.steps.find((s) => s.name?.startsWith("Verify AMO"));
    expect(verify!.run).toContain(GECKO_ID);
  });

  it("no-ops cleanly when the credentials are absent", () => {
    // The job merges before the secrets exist. It must skip, not fail, or every release until
    // someone adds them is red for a reason that is not a defect.
    const check = job.steps.find((s) => s.name?.startsWith("Check for AMO credentials"));
    expect(check, "no credential check step").toBeDefined();
    expect(check!.run).toContain("configured=false");
    for (const step of job.steps.filter((s) => s !== check)) {
      expect(JSON.stringify(step), `step "${step.name}" runs even without credentials`).toContain(
        "steps.creds.outputs.configured == 'true'",
      );
    }
  });
});
