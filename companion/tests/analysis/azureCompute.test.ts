// #1066 (931.8 second half, Azure half): the standalone-VM compute lifecycle built over one
// Activity Log upload — the launch facts as the write's request body states them, every later
// recorded operation, an identity-assigned fact, a remote-access request, and nothing the records
// do not say. No network-security-group join is made (#1073).
import { describe, expect, it } from "vitest";
import { azureComputeLifecycles, AZURE_COMPUTE_MAX } from "../../src/analysis/azureCompute.js";
import { parseAzureVmResourceId } from "../../src/analysis/azureComputeState.js";

const SUB = "11111111-1111-1111-1111-111111111111";
const RG = "rg-prod";
const VM = "web-1";
const VM_ID = `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/${VM}`;
const T = "2024-05-01T09:00:00Z";
const at = (s: number): string => new Date(Date.parse(T) + s * 1000).toISOString();

const azure = (op: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  operationName: { value: op },
  eventTimestamp: T,
  caller: "alice@example.com",
  status: { value: "Succeeded" },
  resourceId: VM_ID,
  ...over,
});

describe("parseAzureVmResourceId", () => {
  it("parses a standalone VM's subscription/resourceGroup/vmName", () => {
    expect(parseAzureVmResourceId(VM_ID)).toEqual({ subscriptionId: SUB, resourceGroup: RG, vmName: VM });
  });
  it("returns null for a VM scale-set member (out of scope, #1073)", () => {
    expect(
      parseAzureVmResourceId(
        `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachineScaleSets/set1/virtualMachines/2`,
      ),
    ).toBeNull();
  });
  it("returns null for an unrelated resource id", () => {
    expect(
      parseAzureVmResourceId(
        `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/sa1`,
      ),
    ).toBeNull();
  });
});

describe("azureComputeLifecycles", () => {
  it("reads the launch facts from the write's request body, never the admin password", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", {
      properties: {
        requestbody: {
          properties: {
            hardwareProfile: { vmSize: "Standard_D2s_v3" },
            storageProfile: { imageReference: { publisher: "Canonical", offer: "0001", sku: "22_04-lts" } },
            osProfile: { adminUsername: "azureuser", adminPassword: "hunter2" },
            networkProfile: { networkInterfaces: [{ id: `${VM_ID}/nic1` }] },
          },
        },
      },
    });
    const [row] = azureComputeLifecycles([write], "u1");
    expect(row.description).toContain("Standard_D2s_v3");
    expect(row.description).toContain("Canonical:0001:22_04-lts");
    expect(row.description).toContain("azureuser");
    expect(row.description).not.toContain("hunter2");
    expect(row.canonical?.azureCompute?.launch?.by).toBe("alice@example.com");
    expect(row.severity).toBe("Low");
  });

  it("a request body as a JSON string decodes the same as an object", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", {
      properties: {
        requestbody: JSON.stringify({ properties: { hardwareProfile: { vmSize: "Standard_B1s" } } }),
      },
    });
    const [row] = azureComputeLifecycles([write], "u1");
    expect(row.description).toContain("Standard_B1s");
  });

  it("identity-assigned fires from identity.type, a sibling of properties (not nested under it)", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", {
      properties: {
        requestbody: {
          identity: { type: "SystemAssigned" },
          properties: { hardwareProfile: { vmSize: "Standard_B1s" } },
        },
      },
    });
    const [row] = azureComputeLifecycles([write], "u1");
    expect(row.canonical?.azureCompute?.facts).toContain("identity-assigned");
    expect(row.severity).toBe("Medium");
  });

  it("a failed write is not the launch and is counted as not-succeeded", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", { status: { value: "Failed" } });
    const rows = azureComputeLifecycles([write], "u1");
    expect(rows).toHaveLength(0);
  });

  it("start/deallocate/delete are recorded operations, never a fabricated transition", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", { eventTimestamp: at(0) });
    const start = azure("Microsoft.Compute/virtualMachines/start/action", { eventTimestamp: at(10) });
    const dealloc = azure("Microsoft.Compute/virtualMachines/deallocate/action", { eventTimestamp: at(20) });
    const [row] = azureComputeLifecycles([write, start, dealloc], "u1");
    expect(row.description).toContain("recorded: started");
    expect(row.description).toContain("recorded: deallocated");
    expect(row.canonical?.azureCompute?.operations.map((o) => o.kind)).toEqual(["start", "deallocate"]);
  });

  it("a non-succeeded status (e.g. Accepted, mid-flight) is an attempt, never a joined operation", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", { eventTimestamp: at(0) });
    const started = azure("Microsoft.Compute/virtualMachines/start/action", {
      eventTimestamp: at(10),
      status: { value: "Accepted" },
    });
    const dealloc = azure("Microsoft.Compute/virtualMachines/deallocate/action", { eventTimestamp: at(20) });
    const [row] = azureComputeLifecycles([write, started, dealloc], "u1");
    expect(row.canonical?.azureCompute?.operations.map((o) => o.kind)).toEqual(["deallocate"]);
    expect(row.canonical?.azureCompute?.attempts.notSucceeded).toBe(1);
  });

  it("a Run Command action targeting this VM is a remote-access-request fact", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", { eventTimestamp: at(0) });
    const run = azure("Microsoft.Compute/virtualMachines/runCommand/action", { eventTimestamp: at(5) });
    const [row] = azureComputeLifecycles([write, run], "u1");
    expect(row.canonical?.azureCompute?.facts).toContain("remote-access-request");
  });

  it("the managed Run Command form (resourceId names a runCommands child) still targets the parent VM", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", { eventTimestamp: at(0) });
    const run = azure("Microsoft.Compute/virtualMachines/runCommands/write", {
      eventTimestamp: at(5),
      resourceId: `${VM_ID}/runCommands/RunPowerShellScript`,
    });
    const [row] = azureComputeLifecycles([write, run], "u1");
    expect(row.canonical?.azureCompute?.facts).toContain("remote-access-request");
  });

  it("grades two distinct fact kinds High, one Medium, none Low (write-only)", () => {
    const writeOnly = azure("Microsoft.Compute/virtualMachines/write", { eventTimestamp: at(0) });
    expect(azureComputeLifecycles([writeOnly], "u1")[0].severity).toBe("Low");

    const withIdentity = azure("Microsoft.Compute/virtualMachines/write", {
      eventTimestamp: at(0),
      properties: { requestbody: { identity: { type: "SystemAssigned" } } },
    });
    expect(azureComputeLifecycles([withIdentity], "u1")[0].severity).toBe("Medium");

    const run = azure("Microsoft.Compute/virtualMachines/runCommand/action", { eventTimestamp: at(5) });
    expect(azureComputeLifecycles([withIdentity, run], "u1")[0].severity).toBe("High");
  });

  it("a VM with no launch and fewer than 2 operations and no facts is not reported", () => {
    const start = azure("Microsoft.Compute/virtualMachines/start/action", { eventTimestamp: at(0) });
    expect(azureComputeLifecycles([start], "u1")).toHaveLength(0);
  });

  it("a VM with 2+ operations and no launch IS reported, even with a Low grade", () => {
    const start = azure("Microsoft.Compute/virtualMachines/start/action", { eventTimestamp: at(0) });
    const dealloc = azure("Microsoft.Compute/virtualMachines/deallocate/action", { eventTimestamp: at(10) });
    const rows = azureComputeLifecycles([start, dealloc], "u1");
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe("Low");
  });

  it("two VMs by resourceId are two separate rows", () => {
    const vm2 = `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/web-2`;
    const w1 = azure("Microsoft.Compute/virtualMachines/write", { resourceId: VM_ID });
    const w2 = azure("Microsoft.Compute/virtualMachines/write", { resourceId: vm2 });
    const rows = azureComputeLifecycles([w1, w2], "u1");
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.canonical?.azureCompute?.vmName))).toEqual(new Set(["web-1", "web-2"]));
  });

  it("a VM scale-set member is never tracked (out of scope, #1073)", () => {
    const vmss = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", {
      resourceId: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachineScaleSets/set1/virtualMachines/2`,
    });
    expect(azureComputeLifecycles([vmss], "u1")).toHaveLength(0);
  });

  it("caps rows at AZURE_COMPUTE_MAX and reports an omitted row for the rest", () => {
    const records = Array.from({ length: AZURE_COMPUTE_MAX + 3 }, (_, i) =>
      azure("Microsoft.Compute/virtualMachines/write", {
        resourceId: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/vm-${i}`,
        eventTimestamp: at(i),
      }),
    );
    const rows = azureComputeLifecycles(records, "u1");
    expect(rows).toHaveLength(AZURE_COMPUTE_MAX + 1);
    expect(rows[rows.length - 1].description).toContain("3 further VM");
  });

  // Regression test for Codex code-round-1 finding #2 (RECOMMENDATION-1066.md): remote-access
  // requests must be bounded during scanning, or a 9th genuinely valid request would throw a
  // ZodError at canonical-envelope construction (the schema itself is capped at 8).
  it("#2 remote requests beyond REMOTE_MAX are counted, never pushed past the schema's own bound", () => {
    const write = azure("Microsoft.Compute/virtualMachines/write", { eventTimestamp: at(0) });
    const records = [write];
    for (let i = 0; i < 9; i++)
      records.push(
        azure("Microsoft.Compute/virtualMachines/runCommand/action", { eventTimestamp: at(10 + i) }),
      );
    expect(() => azureComputeLifecycles(records, "u1")).not.toThrow();
    const [row] = azureComputeLifecycles(records, "u1");
    expect(row.canonical?.azureCompute?.remote.length).toBeLessThanOrEqual(8);
    expect(row.canonical?.azureCompute?.remoteBeyond).toBeGreaterThan(0);
  });
});
