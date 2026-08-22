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
      steps: {
        name?: string;
        id?: string;
        if?: string;
        uses?: string;
        run?: string;
        with?: Record<string, unknown>;
      }[];
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
    expect(verify!.run).toContain("amoApi.mjs has-version");
    // The failure branch must actually fail. A verify step that only echoes is decoration.
    expect(verify!.run).toMatch(/exit 1/);
  });

  it("is safe to re-run, which a release workflow has to be", () => {
    // Re-running a release after one job fails is routine, and AMO refuses a version it already
    // holds. Without the pre-flight, the second run turns a good submission into a red release
    // and the only way back to green is burning a version number.
    const preflight = job.steps.find((s) => s.id === "existing");
    expect(preflight, "no step checking whether AMO already has this version").toBeDefined();
    expect(preflight!.run).toContain("amoApi.mjs has-version");

    const submit = job.steps.find((s) => s.name === "Submit to AMO");
    expect(submit!.if, "Submit runs unconditionally — a re-run would duplicate the version").toContain(
      "steps.existing.outputs.skip != 'true'",
    );
  });

  it("still verifies on the skipped path", () => {
    // A re-run that skips the upload must not report success without checking. The verify step is
    // gated only on credentials, never on the pre-flight's answer.
    const verify = job.steps.find((s) => s.name?.startsWith("Verify AMO"));
    expect(verify!.if).not.toContain("steps.existing");
  });

  it("refuses to submit source that does not match the package", () => {
    // The failure is mundane: a workflow_dispatch naming a tag while the checkout resolves to a
    // branch. Shipping Mozilla source that does not correspond to the binary is a policy
    // violation, so this compares the two versions and stops.
    const match = job.steps.find((s) => s.name === "Check the source matches the package");
    expect(match, "nothing checks the source against the package").toBeDefined();
    expect(match!.run).toMatch(/exit 1/);
  });

  it("does not pin the checkout to a ref, which would desynchronise it from the build", () => {
    // Counter-intuitive on purpose: the source must match the binary, and the binary is built by
    // extension-zip from ITS refless checkout. Pinning only this one to the tag is what CREATES
    // the mismatch the step above catches.
    const checkout = job.steps.find((s) => s.uses?.startsWith("actions/checkout"));
    expect(checkout!.with?.ref).toBeUndefined();
  });

  it("validates the package version with the tested module, not a shell glob", () => {
    // The glob this replaced — [0-9]*.[0-9]* — accepted 0abc.9xyz, 2.01, 1.2-beta and
    // `1.2 && curl evil.example`. A validator nobody can unit-test is how that survives.
    const unpack = job.steps.find((s) => s.name?.startsWith("Unpack"));
    expect(unpack!.run).toContain("amoApi.mjs check-version");
    expect(unpack!.run).not.toMatch(/case "\$VERSION" in/);
  });

  it("pins web-ext to an exact version", () => {
    // A publishing path that installs whatever is newest today is not reproducible: the run that
    // ships a release should behave like the run that tested it.
    const submit = job.steps.find((s) => s.name === "Submit to AMO");
    expect(submit!.run).toMatch(/web-ext@\d+\.\d+\.\d+ /);
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

  it("requires BOTH credentials, and says so when only one is set", () => {
    // Checking only the issuer let a half-configured pair report itself as configured and then die
    // further down inside mintJwt or web-ext — neither the documented no-op nor a legible error.
    const check = job.steps.find((s) => s.name?.startsWith("Check for AMO credentials"));
    expect(Object.keys(check!.env ?? {})).toEqual(
      expect.arrayContaining(["AMO_JWT_ISSUER", "AMO_JWT_SECRET"]),
    );
    expect(check!.run).toContain('[ -n "$AMO_JWT_ISSUER" ] && [ -n "$AMO_JWT_SECRET" ]');
    // Exactly one present means somebody meant to publish and the setup is broken. Skipping that
    // silently would drop a release from AMO with only a green tick to show for it.
    expect(check!.run).toMatch(/only one of AMO_JWT_ISSUER/);
    expect(check!.run).toMatch(/exit 1/);
  });

  it("checks the source archive without a pipeline that can SIGPIPE", () => {
    // `unzip -l | grep -q` reported "BUILD.md missing" on an archive containing it, 20 runs out of
    // 20: grep -q exits on first match, unzip takes SIGPIPE and exits 141, and pipefail turns that
    // into a failed guard. It blocked every credentialed submission before the upload.
    const build = job.steps.find((s) => s.name?.startsWith("Build the human-readable"));
    // Comments stripped first: the step explains this very bug in prose, and a gate that reads
    // prose as code fails on its own documentation.
    const code = build!
      .run!.split("\n")
      .filter((line) => !line.trim().startsWith("#"))
      .join("\n");
    expect(code).not.toMatch(/unzip[^\n]*\|[^\n]*grep/);
    expect(code).toContain("grep -qx");
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
