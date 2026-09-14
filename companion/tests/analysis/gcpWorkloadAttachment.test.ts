// #1065 (second half of #931 item 12): the workload-attachment method matrix — GCE
// insert/setServiceAccount, Cloud Functions v1/v2 create/update (mask-gated), Cloud Run v1/v2
// create/replace/update (mask-gated) — runtime/build/trigger identities kept apart, never
// synthesised when the request omits the field.
import { describe, expect, it } from "vitest";
import { decodeGcpWorkloadAttachment, maskCovers } from "../../src/analysis/gcpWorkloadAttachment.js";

type Row = Record<string, unknown>;
const pp = (method: string, service: string, request: Row = {}, resourceName = ""): Row => ({
  methodName: method,
  serviceName: service,
  resourceName,
  request,
});

describe("maskCovers", () => {
  it("a comma-separated string names the field", () => {
    expect(maskCovers("serviceAccountEmail,labels", "serviceAccountEmail")).toBe(true);
    expect(maskCovers("labels", "serviceAccountEmail")).toBe(false);
  });
  it("a {paths:[...]} array names the field", () => {
    expect(maskCovers({ paths: ["serviceConfig.serviceAccountEmail"] }, "serviceConfig.serviceAccountEmail")).toBe(
      true,
    );
  });
  it("snake_case and lowerCamelCase compare equal", () => {
    expect(maskCovers("service_account_email", "serviceAccountEmail")).toBe(true);
  });
  it("a parent path covers its child", () => {
    expect(maskCovers("serviceConfig", "serviceConfig.serviceAccountEmail")).toBe(true);
    expect(maskCovers("template", "template.serviceAccount")).toBe(true);
  });
  it("* covers everything", () => {
    expect(maskCovers("*", "anything.at.all")).toBe(true);
  });
  it("no mask covers nothing", () => {
    expect(maskCovers(undefined, "serviceAccountEmail")).toBe(false);
  });
});

describe("decodeGcpWorkloadAttachment — GCE", () => {
  it("instances.insert with two service accounts: two readings, runtime, never a default synthesised", () => {
    const r = decodeGcpWorkloadAttachment(
      pp(
        "v1.compute.instances.insert",
        "compute.googleapis.com",
        { serviceAccounts: [{ email: "a@p.iam.gserviceaccount.com" }, { email: "b@p.iam.gserviceaccount.com" }] },
        "projects/p/zones/z/instances/vm1",
      ),
      "compute.googleapis.com",
      "v1.compute.instances.insert",
    );
    expect(r).toHaveLength(2);
    expect(r[0].attachment).toMatchObject({
      workloadKind: "gce-instance",
      identityRole: "runtime",
      serviceAccountEmail: "a@p.iam.gserviceaccount.com",
      fromUpdateMask: false,
    });
    expect(r[0].posture).toContain("attachment (actAs), not credential minting");
  });

  it("insert with no serviceAccounts field: no reading, no synthesised default", () => {
    const r = decodeGcpWorkloadAttachment(
      pp("v1.compute.instances.insert", "compute.googleapis.com", {}),
      "compute.googleapis.com",
      "v1.compute.instances.insert",
    );
    expect(r).toHaveLength(0);
  });

  it("setServiceAccount reads request.email, not request.serviceAccount.email", () => {
    const r = decodeGcpWorkloadAttachment(
      pp("v1.compute.instances.setServiceAccount", "compute.googleapis.com", {
        email: "c@p.iam.gserviceaccount.com",
        scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      }),
      "compute.googleapis.com",
      "v1.compute.instances.setServiceAccount",
    );
    expect(r).toHaveLength(1);
    expect(r[0].attachment.serviceAccountEmail).toBe("c@p.iam.gserviceaccount.com");
    const wrongShape = decodeGcpWorkloadAttachment(
      pp("v1.compute.instances.setServiceAccount", "compute.googleapis.com", {
        serviceAccount: { email: "wrong-field@p.iam.gserviceaccount.com" },
      }),
      "compute.googleapis.com",
      "v1.compute.instances.setServiceAccount",
    );
    expect(wrongShape).toHaveLength(0);
  });
});

describe("decodeGcpWorkloadAttachment — Cloud Functions", () => {
  it("v1 CreateFunction always reads the field", () => {
    const r = decodeGcpWorkloadAttachment(
      pp("google.cloud.functions.v1.CloudFunctionsService.CreateFunction", "cloudfunctions.googleapis.com", {
        function: { name: "projects/p/locations/l/functions/f1", serviceAccountEmail: "fn@p.iam.gserviceaccount.com" },
      }),
      "cloudfunctions.googleapis.com",
      "google.cloud.functions.v1.CloudFunctionsService.CreateFunction",
    );
    expect(r).toHaveLength(1);
    expect(r[0].attachment).toMatchObject({ workloadKind: "cloud-function", workloadVersion: "v1", identityRole: "runtime" });
  });

  it("v1 UpdateFunction reads the field only when the mask names it", () => {
    const withMask = decodeGcpWorkloadAttachment(
      pp("google.cloud.functions.v1.CloudFunctionsService.UpdateFunction", "cloudfunctions.googleapis.com", {
        function: { name: "f1", serviceAccountEmail: "fn@p.iam.gserviceaccount.com" },
        updateMask: "serviceAccountEmail",
      }),
      "cloudfunctions.googleapis.com",
      "google.cloud.functions.v1.CloudFunctionsService.UpdateFunction",
    );
    expect(withMask).toHaveLength(1);
    expect(withMask[0].attachment.fromUpdateMask).toBe(true);
    const withoutMask = decodeGcpWorkloadAttachment(
      pp("google.cloud.functions.v1.CloudFunctionsService.UpdateFunction", "cloudfunctions.googleapis.com", {
        function: { name: "f1", serviceAccountEmail: "fn@p.iam.gserviceaccount.com" },
        updateMask: "labels",
      }),
      "cloudfunctions.googleapis.com",
      "google.cloud.functions.v1.CloudFunctionsService.UpdateFunction",
    );
    expect(withoutMask).toHaveLength(0);
  });

  it("v2 CreateFunction: runtime, build and trigger are three separate readings, never merged", () => {
    const r = decodeGcpWorkloadAttachment(
      pp("google.cloud.functions.v2.FunctionService.CreateFunction", "cloudfunctions.googleapis.com", {
        function: {
          name: "projects/p/locations/l/functions/f2",
          serviceConfig: { serviceAccountEmail: "runtime@p.iam.gserviceaccount.com" },
          buildConfig: { serviceAccount: "projects/p/serviceAccounts/build@p.iam.gserviceaccount.com" },
          eventTrigger: { serviceAccountEmail: "trigger@p.iam.gserviceaccount.com" },
        },
      }),
      "cloudfunctions.googleapis.com",
      "google.cloud.functions.v2.FunctionService.CreateFunction",
    );
    expect(r).toHaveLength(3);
    const roles = r.map((x) => x.attachment.identityRole).sort();
    expect(roles).toEqual(["build", "runtime", "trigger"]);
    const build = r.find((x) => x.attachment.identityRole === "build")!;
    expect(build.attachment.serviceAccountEmail).toBe("build@p.iam.gserviceaccount.com");
  });

  it("v2 UpdateFunction gates each of the three fields independently by its own mask entry", () => {
    const r = decodeGcpWorkloadAttachment(
      pp("google.cloud.functions.v2.FunctionService.UpdateFunction", "cloudfunctions.googleapis.com", {
        function: {
          name: "f2",
          serviceConfig: { serviceAccountEmail: "runtime@p.iam.gserviceaccount.com" },
          buildConfig: { serviceAccount: "projects/p/serviceAccounts/build@p.iam.gserviceaccount.com" },
          eventTrigger: { serviceAccountEmail: "trigger@p.iam.gserviceaccount.com" },
        },
        updateMask: { paths: ["serviceConfig.serviceAccountEmail"] },
      }),
      "cloudfunctions.googleapis.com",
      "google.cloud.functions.v2.FunctionService.UpdateFunction",
    );
    expect(r).toHaveLength(1);
    expect(r[0].attachment.identityRole).toBe("runtime");
  });
});

describe("decodeGcpWorkloadAttachment — Cloud Run", () => {
  it("v1 CreateService/ReplaceService always read (no field mask concept in v1)", () => {
    const body = {
      service: { spec: { template: { spec: { serviceAccountName: "run@p.iam.gserviceaccount.com" } } } },
    };
    const create = decodeGcpWorkloadAttachment(
      pp("google.cloud.run.v1.Services.CreateService", "run.googleapis.com", body),
      "run.googleapis.com",
      "google.cloud.run.v1.Services.CreateService",
    );
    const replace = decodeGcpWorkloadAttachment(
      pp("google.cloud.run.v1.Services.ReplaceService", "run.googleapis.com", body),
      "run.googleapis.com",
      "google.cloud.run.v1.Services.ReplaceService",
    );
    expect(create).toHaveLength(1);
    expect(replace).toHaveLength(1);
    expect(create[0].attachment.workloadVersion).toBe("v1");
  });

  it("v2 CreateService always reads; v2 UpdateService only when the mask names the field", () => {
    const body = { service: { template: { serviceAccount: "run2@p.iam.gserviceaccount.com" } } };
    const create = decodeGcpWorkloadAttachment(
      pp("google.cloud.run.v2.Services.CreateService", "run.googleapis.com", body),
      "run.googleapis.com",
      "google.cloud.run.v2.Services.CreateService",
    );
    expect(create).toHaveLength(1);
    const updateWith = decodeGcpWorkloadAttachment(
      pp("google.cloud.run.v2.Services.UpdateService", "run.googleapis.com", {
        ...body,
        updateMask: "template.serviceAccount",
      }),
      "run.googleapis.com",
      "google.cloud.run.v2.Services.UpdateService",
    );
    expect(updateWith).toHaveLength(1);
    const updateWithout = decodeGcpWorkloadAttachment(
      pp("google.cloud.run.v2.Services.UpdateService", "run.googleapis.com", { ...body, updateMask: "template.image" }),
      "run.googleapis.com",
      "google.cloud.run.v2.Services.UpdateService",
    );
    expect(updateWithout).toHaveLength(0);
  });
});

it("an unrelated method under the same service never decodes", () => {
  const r = decodeGcpWorkloadAttachment(
    pp("v1.compute.firewalls.insert", "compute.googleapis.com", { serviceAccounts: [{ email: "x@p.iam.gserviceaccount.com" }] }),
    "compute.googleapis.com",
    "v1.compute.firewalls.insert",
  );
  expect(r).toHaveLength(0);
});
