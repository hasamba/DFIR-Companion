import { describe, it, expect } from "vitest";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";

// ── GCP Cloud Audit Log entries (Cloud Logging LogEntry shape) ──────────────
function gcp(method: string, over: object = {}): object {
  return {
    logName: "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
    timestamp: "2023-07-01T10:00:00.123456789Z",
    resource: { type: "service_account" },
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
      serviceName: "iam.googleapis.com",
      methodName: method,
      authenticationInfo: { principalEmail: "attacker@acme.com" },
      requestMetadata: { callerIp: "203.0.113.11" },
      resourceName: "projects/acme/serviceAccounts/svc@acme.iam.gserviceaccount.com",
      status: {},
      ...over,
    },
  };
}

// ── Azure Activity Log entries (native az/REST camelCase) ───────────────────
function azure(op: string, over: object = {}): object {
  return {
    eventTimestamp: "2023-07-01T11:00:00Z",
    operationName: { value: op, localizedValue: op },
    category: { value: "Administrative" },
    level: "Informational",
    status: { value: "Succeeded" },
    caller: "admin@acme.com",
    resourceId: "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
    httpRequest: { clientIpAddress: "203.0.113.22" },
    ...over,
  };
}

describe("parseCloudActivity — GCP", () => {
  it("derives High for CreateServiceAccountKey and extracts principal + caller IP", () => {
    const r = parseCloudActivity(JSON.stringify([gcp("google.iam.admin.v1.CreateServiceAccountKey")]));
    expect(r.format).toBe("gcp");
    const e = r.events[0];
    expect(e.description).toContain("GCP google.iam.admin.v1.CreateServiceAccountKey (iam)");
    expect(e.description).toContain("by attacker@acme.com");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1098.001");
    expect(e.sources).toEqual(["GCP Audit"]);
    expect(e.timestamp).toBe("2023-07-01T10:00:00.123456789Z");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.11");
  });

  it("setIamPolicy on storage maps to data-exposure (T1530)", () => {
    const r = parseCloudActivity(JSON.stringify([gcp("storage.setIamPermissions", { serviceName: "storage.googleapis.com" })]));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1530");
  });

  it("a non-OK status code bumps severity to at least Medium", () => {
    const r = parseCloudActivity(JSON.stringify([gcp("storage.objects.get", { serviceName: "storage.googleapis.com", status: { code: 7, message: "PERMISSION_DENIED" } })]));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[DENIED");
  });
});

describe("parseCloudActivity — Azure", () => {
  it("derives High for a role assignment write (priv-esc)", () => {
    const r = parseCloudActivity(JSON.stringify([azure("Microsoft.Authorization/roleAssignments/write")]));
    expect(r.format).toBe("azure");
    const e = r.events[0];
    expect(e.description).toContain("Azure Microsoft.Authorization/roleAssignments/write");
    expect(e.description).toContain("by admin@acme.com");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1098.003");
    expect(e.sources).toEqual(["Azure Activity"]);
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.22");
  });

  it("High for deleting a diagnostic setting (disable logging)", () => {
    const r = parseCloudActivity(JSON.stringify([azure("Microsoft.Insights/diagnosticSettings/delete")]));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1562.008");
  });

  it("a Failed status bumps severity to Medium", () => {
    const r = parseCloudActivity(JSON.stringify([azure("Microsoft.Resources/deployments/read", { status: { value: "Failed" } })]));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[Failed]");
  });

  it("reads the flat Log-Analytics PascalCase shape", () => {
    const la = {
      TimeGenerated: "2023-07-01T12:00:00Z",
      OperationNameValue: "Microsoft.Storage/storageAccounts/listKeys/action",
      Caller: "sp@acme.com", CallerIpAddress: "203.0.113.33", ActivityStatusValue: "Success",
      ResourceId: "/subscriptions/abc/.../storageAccounts/sa1", Type: "AzureActivity",
    };
    const r = parseCloudActivity(JSON.stringify([la]));
    expect(r.format).toBe("azure");
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1552.001");
  });
});

describe("parseCloudActivity — inputs, floor & edges", () => {
  it("reads NDJSON and reports 'mixed' when both clouds appear", () => {
    const text = [gcp("google.iam.admin.v1.CreateServiceAccountKey"), azure("Microsoft.Authorization/roleAssignments/write")]
      .map((o) => JSON.stringify(o)).join("\n");
    const r = parseCloudActivity(text);
    expect(r.format).toBe("mixed");
    expect(r.events).toHaveLength(2);
  });

  it("applies a severity floor", () => {
    const text = JSON.stringify([
      gcp("google.iam.admin.v1.CreateServiceAccountKey"),                 // High
      gcp("storage.objects.get", { serviceName: "storage.googleapis.com" }), // Info
    ]);
    const r = parseCloudActivity(text, { minSeverity: "Medium" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
  });

  it("reports empty for a non-cloud file", () => {
    const r = parseCloudActivity(JSON.stringify([{ foo: "bar" }]));
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});
