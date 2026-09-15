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

describe("parseCloudActivity — coverage (#1063)", () => {
  it("GCP coverage reads the CloudAudit log type and the project scope", () => {
    const r = parseCloudActivity(JSON.stringify([gcp("google.iam.admin.v1.CreateServiceAccountKey")]));
    const gcpCov = r.coverage.find((c) => c.provider === "gcp")!;
    expect(gcpCov.scope).toEqual({ kind: "projects", value: "acme" });
    expect(gcpCov.categories.map((c) => c.name)).toEqual(["activity"]);
  });

  it("Azure coverage reads the category and the subscription parsed from resourceId", () => {
    const r = parseCloudActivity(JSON.stringify([azure("Microsoft.Compute/virtualMachines/write")]));
    const azureCov = r.coverage.find((c) => c.provider === "azure")!;
    expect(azureCov.scope).toEqual({ kind: "subscription", value: "abc" });
    expect(azureCov.categories.map((c) => c.name)).toEqual(["Administrative"]);
  });
});

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
    const r = parseCloudActivity(
      JSON.stringify([gcp("storage.setIamPermissions", { serviceName: "storage.googleapis.com" })]),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1530");
  });

  it("a non-OK status code bumps severity to at least Medium", () => {
    const r = parseCloudActivity(
      JSON.stringify([
        gcp("storage.objects.get", {
          serviceName: "storage.googleapis.com",
          status: { code: 7, message: "PERMISSION_DENIED" },
        }),
      ]),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[DENIED");
  });

  // #1081: a GCP logging-configuration call is classified denied / not-found / an honest
  // unclassified "failed", never collapsed to one outcome — and the head text (built before the
  // inner reading runs) must never contradict what the inner reading concludes.
  describe("a GCP logging-configuration call — three distinct outcomes, head text never contradicts the reading (#1081)", () => {
    const sinkDelete = (status: object) =>
      gcp("google.logging.v2.ConfigServiceV2.DeleteSink", {
        serviceName: "logging.googleapis.com",
        status,
        request: { sinkName: "my-sink" },
      });

    it("code 5 (NOT_FOUND) is not-found: Low, head has no stale [DENIED] bracket, posture says target not found", () => {
      const r = parseCloudActivity(JSON.stringify([sinkDelete({ code: 5, message: "NOT_FOUND" })]));
      const e = r.events[0];
      expect(e.severity).toBe("Low");
      expect(e.description).not.toContain("[DENIED");
      expect(e.description).toContain("requested (target not found):");
      expect(e.canonical?.loggingChange?.failure).toBe("not-found");
      expect(e.canonical?.loggingChange?.denied).toBe(false);
    });

    it("code 7 (PERMISSION_DENIED) stays denied: Medium, posture says denied — the head's own redundant bracket is stripped for EVERY logging outcome, not only when it would disagree", () => {
      const r = parseCloudActivity(JSON.stringify([sinkDelete({ code: 7, message: "PERMISSION_DENIED" })]));
      const e = r.events[0];
      expect(e.severity).toBe("Medium");
      expect(e.description).not.toContain("[DENIED");
      expect(e.description).toContain("requested (denied):");
      expect(e.canonical?.loggingChange?.failure).toBe("denied");
      expect(e.canonical?.loggingChange?.denied).toBe(true);
    });

    it("code 3 (INVALID_ARGUMENT) is the neutral 'failed': Medium, head has no stale [DENIED] bracket, posture says failed", () => {
      const r = parseCloudActivity(JSON.stringify([sinkDelete({ code: 3, message: "INVALID_ARGUMENT" })]));
      const e = r.events[0];
      expect(e.severity).toBe("Medium");
      expect(e.description).not.toContain("[DENIED");
      expect(e.description).toContain("requested (failed):");
      expect(e.canonical?.loggingChange?.failure).toBe("failed");
      expect(e.canonical?.loggingChange?.denied).toBe(false);
    });

    it("a NON-logging GCP row's own head bracket is unaffected — still says [DENIED] for any non-zero code", () => {
      // Regression guard: the head-bracket strip in gcpRow.ts is scoped to logging readings only.
      const r = parseCloudActivity(
        JSON.stringify([
          gcp("storage.objects.get", {
            serviceName: "storage.googleapis.com",
            status: { code: 5, message: "NOT_FOUND" },
          }),
        ]),
      );
      expect(r.events[0].description).toContain("[DENIED");
    });

    it("a long resource name (head > 300 chars pre-bracket) never leaves a mangled '[DENIED: …' fragment beside a not-found posture (#1081, Codex code review) — the bracket is decided BEFORE any truncation, never baked into a head that gets truncated separately", () => {
      const longResource = "r".repeat(340);
      const r = parseCloudActivity(
        JSON.stringify([
          gcp("google.logging.v2.ConfigServiceV2.DeleteSink", {
            serviceName: "logging.googleapis.com",
            resourceName: longResource,
            status: { code: 5, message: "NOT_FOUND" },
            request: { sinkName: "my-sink" },
          }),
        ]),
      );
      const e = r.events[0];
      expect(e.description).not.toMatch(/\[DENIED/);
      expect(e.description).toContain("requested (target not found):");
      expect(e.canonical?.loggingChange?.failure).toBe("not-found");
    });
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

  // #1081: Azure has no per-call error code threaded to the reading — a failed diagnostic-setting
  // call is the neutral "failed" outcome, never "denied" (that would claim evidence this record
  // does not carry). Azure's own not-found detection stays out of scope (#1096).
  it("a failed diagnostic-setting delete is the neutral 'failed', never 'denied'", () => {
    const r = parseCloudActivity(
      JSON.stringify([
        azure("Microsoft.Insights/diagnosticSettings/delete", { status: { value: "Failed" } }),
      ]),
    );
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain("requested (failed):");
    expect(e.description).not.toContain("requested (denied)");
    expect(e.canonical?.loggingChange?.failure).toBe("failed");
    expect(e.canonical?.loggingChange?.denied).toBe(false);
  });

  it("a Failed status bumps severity to Medium", () => {
    const r = parseCloudActivity(
      JSON.stringify([azure("Microsoft.Resources/deployments/read", { status: { value: "Failed" } })]),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[Failed]");
  });

  it("reads the flat Log-Analytics PascalCase shape", () => {
    const la = {
      TimeGenerated: "2023-07-01T12:00:00Z",
      OperationNameValue: "Microsoft.Storage/storageAccounts/listKeys/action",
      Caller: "sp@acme.com",
      CallerIpAddress: "203.0.113.33",
      ActivityStatusValue: "Success",
      ResourceId: "/subscriptions/abc/.../storageAccounts/sa1",
      Type: "AzureActivity",
    };
    const r = parseCloudActivity(JSON.stringify([la]));
    expect(r.format).toBe("azure");
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1552.001");
  });

  // #931 item 4: the key→read correlator needs a structured canonical envelope on the listKeys
  // row, not just prose — this row carried none before.
  it("stamps a canonical envelope on a storage key listing", () => {
    const r = parseCloudActivity(
      JSON.stringify([
        azure("Microsoft.Storage/storageAccounts/listKeys/action", {
          resourceId: "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
        }),
      ]),
    );
    const e = r.events[0];
    expect(e.canonical?.event.category).toBe("cloud");
    expect(e.canonical?.event.type).toBe("storage-key-list");
    expect(e.canonical?.event.outcome).toBe("success");
    expect(e.canonical?.cloud?.resource).toContain("storageAccounts/sa1");
  });

  // Codex review (P1, #931 item 2): without the resource in the aggKey, listings of two DIFFERENT
  // accounts by the same caller/IP collapsed into one row and the key→read correlator could only
  // ever see the first account.
  it("keeps listKeys on two different storage accounts as two distinct events", () => {
    const r = parseCloudActivity(
      JSON.stringify([
        azure("Microsoft.Storage/storageAccounts/listKeys/action", {
          resourceId: "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
        }),
        azure("Microsoft.Storage/storageAccounts/listKeys/action", {
          resourceId: "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa2",
        }),
      ]),
    );
    expect(r.events).toHaveLength(2);
    const resources = r.events.map((e) => e.canonical?.cloud?.resource);
    expect(resources.some((r) => r?.includes("sa1"))).toBe(true);
    expect(resources.some((r) => r?.includes("sa2"))).toBe(true);
  });
});

describe("parseCloudActivity — inputs, floor & edges", () => {
  it("reads NDJSON and reports 'mixed' when both clouds appear", () => {
    const text = [
      gcp("google.iam.admin.v1.CreateServiceAccountKey"),
      azure("Microsoft.Authorization/roleAssignments/write"),
    ]
      .map((o) => JSON.stringify(o))
      .join("\n");
    const r = parseCloudActivity(text);
    expect(r.format).toBe("mixed");
    // +1: the #1065 per-service-account join adds one summary row for the key's service account.
    expect(r.events).toHaveLength(3);
  });

  it("applies a severity floor", () => {
    const text = JSON.stringify([
      gcp("google.iam.admin.v1.CreateServiceAccountKey"), // High
      gcp("storage.objects.get", { serviceName: "storage.googleapis.com" }), // Info
    ]);
    const r = parseCloudActivity(text, { minSeverity: "Medium" });
    // +1: the #1065 join's own summary row for the key's service account, also High.
    expect(r.events).toHaveLength(2);
    expect(r.events[0].severity).toBe("High");
    expect(r.events[1].severity).toBe("High");
  });

  it("reports empty for a non-cloud file", () => {
    const r = parseCloudActivity(JSON.stringify([{ foo: "bar" }]));
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});

// #931 item 7 — Azure remote execution as a family: the action form, the managed form, scale sets.
describe("parseCloudActivity — Azure remote execution", () => {
  const VM = "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1";
  it("names the target VM, grades High with T1651, and says the script body is not in the log", () => {
    const r = parseCloudActivity(
      JSON.stringify([azure("Microsoft.Compute/virtualMachines/runCommand/action")]),
    );
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toEqual(expect.arrayContaining(["T1651", "T1059"]));
    expect(e.description).toContain("→ vm1 — the script body is not in the Activity Log");
  });
  it("the managed form targets the parent VM, not the runCommands child, and shares the target with the action form", () => {
    const managed = azure("Microsoft.Compute/virtualMachines/runCommands/write", {
      resourceId: `${VM}/runCommands/RunPowerShellScript`,
    });
    const action = azure("Microsoft.Compute/virtualMachines/runCommand/action", { resourceId: VM });
    const r = parseCloudActivity(JSON.stringify([managed, action]));
    // #1066: a compute-lifecycle summary row for vm1 is also appended (the VM has a
    // remote-access-request fact) — excluded here since this test is about the per-record rows.
    const perRecord = r.events.filter((e) => !e.description.startsWith("Azure compute lifecycle:"));
    for (const e of perRecord) expect(e.description).toContain("→ vm1 —");
    expect(perRecord.every((e) => e.severity === "High")).toBe(true);
  });
  it("a scale-set instance is identified by set and instance; two VMs by one caller are two rows", () => {
    const vmss = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", {
      resourceId:
        "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/web/virtualMachines/0",
    });
    const other = azure("Microsoft.Compute/virtualMachines/runCommand/action", {
      resourceId: VM.replace("vm1", "vm2"),
    });
    const r = parseCloudActivity(
      JSON.stringify([vmss, other, azure("Microsoft.Compute/virtualMachines/runCommand/action")]),
    );
    // 3 per-record rows + 2 standalone compute-lifecycle summary rows (#1066: vm1 and vm2 each
    // have a remote-access-request fact) + 1 VMSS compute-lifecycle summary row (#1078: the
    // Uniform-mode member web/0 has a remote-access-request fact too, now that #1078 tracks it).
    expect(r.events).toHaveLength(6);
    expect(r.events.some((e) => e.description.includes("→ web/0 —"))).toBe(true);
    expect(
      r.events.some((e) => e.description.startsWith("Azure VMSS compute lifecycle: 0 (scale set web")),
    ).toBe(true);
  });
  it("two executions with no resource id stay two rows, keyed on their record ids", () => {
    const a = azure("Microsoft.Compute/virtualMachines/runCommand/action", {
      resourceId: "",
      eventDataId: "ev-1",
    });
    const b = azure("Microsoft.Compute/virtualMachines/runCommand/action", {
      resourceId: "",
      eventDataId: "ev-2",
    });
    expect(parseCloudActivity(JSON.stringify([a, b])).events).toHaveLength(2);
  });

  it("leaves an unrelated write ungraded as remote execution", () => {
    const r = parseCloudActivity(JSON.stringify([azure("Microsoft.Compute/virtualMachines/write")]));
    expect(r.events[0].mitreTechniques).not.toContain("T1651");
    expect(r.events[0].description).not.toContain("→");
  });
});

describe("parseCloudActivity — compute-lifecycle wiring (#1066)", () => {
  it("an Azure VM write appends an azure-compute-lifecycle row after the per-record rows", () => {
    const r = parseCloudActivity(JSON.stringify([azure("Microsoft.Compute/virtualMachines/write")]));
    expect(r.events.some((e) => e.description.startsWith("Azure compute lifecycle:"))).toBe(true);
  });

  it("a GCP instances.insert appends a gcp-compute-lifecycle row after the per-record rows", () => {
    const r = parseCloudActivity(
      JSON.stringify([
        gcp("v1.compute.instances.insert", {
          serviceName: "compute.googleapis.com",
          resourceName: "projects/acme/zones/us-central1-a/instances/vm1",
        }),
      ]),
    );
    expect(r.events.some((e) => e.description.startsWith("GCP compute lifecycle:"))).toBe(true);
  });

  it("no Azure records in the upload -> no azure-compute-lifecycle row appended", () => {
    const r = parseCloudActivity(
      JSON.stringify([
        gcp("v1.compute.instances.insert", {
          serviceName: "compute.googleapis.com",
          resourceName: "projects/acme/zones/us-central1-a/instances/vm1",
        }),
      ]),
    );
    expect(r.events.some((e) => e.description.startsWith("Azure compute lifecycle:"))).toBe(false);
  });

  it("no GCP records in the upload -> no gcp-compute-lifecycle row appended", () => {
    const r = parseCloudActivity(JSON.stringify([azure("Microsoft.Compute/virtualMachines/write")]));
    expect(r.events.some((e) => e.description.startsWith("GCP compute lifecycle:"))).toBe(false);
  });

  it("the same uploadId (sourceArtifactHash of the raw text) threads through both new joins", () => {
    const text = JSON.stringify([
      azure("Microsoft.Compute/virtualMachines/write"),
      gcp("v1.compute.instances.insert", {
        serviceName: "compute.googleapis.com",
        resourceName: "projects/acme/zones/us-central1-a/instances/vm1",
      }),
    ]);
    const r1 = parseCloudActivity(text);
    const r2 = parseCloudActivity(text);
    const azureRow1 = r1.events.find((e) => e.description.startsWith("Azure compute lifecycle:"));
    const azureRow2 = r2.events.find((e) => e.description.startsWith("Azure compute lifecycle:"));
    expect(azureRow1?.aggKey).toBe(azureRow2?.aggKey);
  });

  // Regression test for Codex code-round-1 finding #3 (RECOMMENDATION-1066.md): each join must
  // cite the record's position in the ORIGINAL upload, never in a provider-filtered array — an
  // Azure-before-GCP upload must not make the GCP row cite the Azure record's index.
  it("#3 evidence locators reflect the ORIGINAL record position, never a provider-filtered array's position", () => {
    const r = parseCloudActivity(
      JSON.stringify([
        azure("Microsoft.Compute/virtualMachines/write"), // record:0
        gcp("v1.compute.instances.insert", {
          // record:1
          serviceName: "compute.googleapis.com",
          resourceName: "projects/acme/zones/us-central1-a/instances/vm1",
        }),
      ]),
    );
    const gcpRow = r.events.find((e) => e.description.startsWith("GCP compute lifecycle:"));
    const azureRow = r.events.find((e) => e.description.startsWith("Azure compute lifecycle:"));
    expect(gcpRow?.canonical?.evidence?.rawRecords.map((rr) => rr.locator)).toContain("record:1");
    expect(azureRow?.canonical?.evidence?.rawRecords.map((rr) => rr.locator)).toContain("record:0");
  });
});
