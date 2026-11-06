// GCP custom-role changes (#2358). The importer's role entry `(create|update).*\brole\b` never matched
// a real method (`google.iam.admin.v1.updaterole` has no word boundary before `role`), so custom-role
// changes fell to the generic Low floor.
import { describe, it, expect } from "vitest";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { matchGcpRule } from "../../src/analysis/gcpSeverityRules.js";

function gcp(method: string, serviceName = "iam.googleapis.com"): object {
  return {
    logName: "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
    timestamp: "2023-07-01T10:00:00Z",
    resource: { type: "iam_role" },
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
      serviceName,
      methodName: method,
      authenticationInfo: { principalEmail: "alice@acme.com" },
      requestMetadata: { callerIp: "203.0.113.11" },
      resourceName: "projects/acme/roles/custom1",
      status: {},
    },
  };
}

const grade = (method: string, service?: string) =>
  parseCloudActivity(JSON.stringify([gcp(method, service)])).events[0];

describe("GCP custom-role changes (#2358)", () => {
  for (const method of [
    "google.iam.admin.v1.CreateRole",
    "google.iam.admin.v1.UpdateRole",
    "google.iam.admin.v1.UndeleteRole",
    "UpdateRole",
  ]) {
    it(`grades ${method} Medium with T1098.003`, () => {
      const e = grade(method);
      expect(e.severity).toBe("Medium");
      expect(e.mitreTechniques).toContain("T1098.003");
    });
  }

  it("does not grade DeleteRole as a role grant (it keeps the generic floor)", () => {
    expect(matchGcpRule("google.iam.admin.v1.DeleteRole")).toBeNull();
  });

  it("leaves reads and look-alike methods to other rules", () => {
    for (const method of [
      "google.iam.admin.v1.GetRole",
      "google.iam.admin.v1.ListRoles",
      "google.cloud.foo.v1.UpdateRoleBinding",
      "io.k8s.authorization.rbac.v1.roles.update",
      "io.k8s.authorization.rbac.v1.clusterroles.create",
      "google.iam.admin.v1.CreateRoleX",
    ]) {
      expect(matchGcpRule(method)?.mitre ?? [], method).not.toContain("T1098.003");
    }
  });
});
