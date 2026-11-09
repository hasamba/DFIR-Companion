// #2486: the cloud row wording, and the older wording mapped to it for the Sigma re-grade.
import { describe, expect, it } from "vitest";
import { currentCloudWording, shortGcpMethod } from "../../src/analysis/cloudRowWording.js";

describe("shortGcpMethod", () => {
  it.each([
    ["google.iam.admin.v1.CreateServiceAccount", "CreateServiceAccount"],
    ["google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy", "OrgPolicy.DeletePolicy"],
    ["google.logging.v2.ConfigServiceV2.DeleteBucket", "ConfigServiceV2.DeleteBucket"],
    ["google.cloud.securitycenter.v1beta1.SecurityCenter.SetMute", "SecurityCenter.SetMute"],
    ["storage.buckets.create", "storage.buckets.create"],
    ["SetIamPolicy", "SetIamPolicy"],
    ["google.longrunning.Operations.GetOperation", "google.longrunning.Operations.GetOperation"],
    ["google.iam.admin.v1.", "google.iam.admin.v1."],
  ])("%s → %s", (method, short) => {
    expect(shortGcpMethod(method)).toBe(short);
  });
});

describe("currentCloudWording", () => {
  it("rewrites a pre-#2486 GCP head and leaves the rest of the row alone", () => {
    expect(
      currentCloudWording("GCP google.iam.admin.v1.UpdateRole (iam) by a@example.com on google.x.v1.y"),
    ).toBe("GCP UpdateRole (iam) by a@example.com on google.x.v1.y");
  });

  it("rewrites a pre-#2486 hidden-risk marker", () => {
    expect(currentCloudWording("Entra sign-in: u@example.com [risk: hidden] [ua: x]")).toBe(
      "Entra sign-in: u@example.com [risk level not visible (no Entra ID P2)] [ua: x]",
    );
  });

  it("is a no-op on text already in the current wording", () => {
    for (const t of [
      "GCP UpdateRole (iam) by a",
      "Entra sign-in: u [risk: high]",
      "AWS StopLogging (cloudtrail) by alice",
    ])
      expect(currentCloudWording(t)).toBe(t);
  });
});
