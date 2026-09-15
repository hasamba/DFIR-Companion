// #931 item 8, #1078: the Uniform-mode VMSS-member compute lifecycle built over one Activity Log
// upload — parity with #1066's own standalone-VM feature set (launch, operations,
// identity-assigned, remote-access-request), via a discriminated 4-tuple identity and
// generation-splitting (OBSERVED lifecycle epochs, never proven physical machines) for
// Uniform-mode instance-id reuse after delete. Flexible-mode members (their own record carries
// virtualMachineResourceId) are skipped entirely — see the "Flexible-mode" describe block.
import { describe, expect, it } from "vitest";
import { azureVmssComputeLifecycles, VMSS_COMPUTE_MAX } from "../../src/analysis/azureVmssCompute.js";
import {
  parseAzureVmssMemberResourceId,
  VMSS_MEMBER_RESOURCE_ID,
  VMSS_EPOCHS_PER_MEMBER_MAX,
} from "../../src/analysis/azureVmssComputeState.js";
import { parseAzureVmResourceId } from "../../src/analysis/azureComputeState.js";
import { azureRemoteExecutionTarget } from "../../src/analysis/cloudActivityImport.js";
import {
  canonicalConformanceIssues,
  canonicalEventEnvelopeSchema,
} from "../../src/analysis/canonicalEvent.js";

const SUB = "11111111-1111-1111-1111-111111111111";
const RG = "rg-prod";
const SET = "web";
const INST = "0";
const MEMBER_ID = `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachineScaleSets/${SET}/virtualMachines/${INST}`;
const T = "2024-05-01T09:00:00Z";
const at = (s: number): string => new Date(Date.parse(T) + s * 1000).toISOString();

const azure = (op: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  operationName: { value: op },
  eventTimestamp: T,
  caller: "alice@example.com",
  status: { value: "Succeeded" },
  resourceId: MEMBER_ID,
  ...over,
});
const env = (e: { canonical?: unknown }) => canonicalEventEnvelopeSchema.parse(e.canonical);

describe("parseAzureVmssMemberResourceId", () => {
  it("parses a VMSS member's subscription/resourceGroup/setName/instanceId", () => {
    expect(parseAzureVmssMemberResourceId(MEMBER_ID)).toEqual({
      subscriptionId: SUB,
      resourceGroup: RG,
      setName: SET,
      instanceId: INST,
    });
  });
  it("returns null for a standalone VM (out of scope for this parser)", () => {
    expect(
      parseAzureVmssMemberResourceId(
        `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/vm1`,
      ),
    ).toBeNull();
  });
  it("the standalone parser rejects a VMSS member's own resourceId, and vice versa (no collision)", () => {
    expect(parseAzureVmResourceId(MEMBER_ID)).toBeNull();
    expect(
      parseAzureVmssMemberResourceId(
        `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/vm1`,
      ),
    ).toBeNull();
  });
  it("also matches a Run Command child form, not end-anchored, mirroring the standalone parser's own convention", () => {
    expect(parseAzureVmssMemberResourceId(`${MEMBER_ID}/runCommands/RunPowerShellScript`)).toEqual({
      subscriptionId: SUB,
      resourceGroup: RG,
      setName: SET,
      instanceId: INST,
    });
  });
});

describe("cloudActivityImport.ts's azureRemoteExecutionTarget shares the SAME VMSS regex (#1078, design round 1, finding M1)", () => {
  it("targets a VMSS member by set/instance, using VMSS_MEMBER_RESOURCE_ID directly", () => {
    const target = azureRemoteExecutionTarget(
      "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action",
      MEMBER_ID,
    );
    expect(target?.display).toBe(`${SET}/${INST}`);
    expect(VMSS_MEMBER_RESOURCE_ID.test(MEMBER_ID)).toBe(true);
  });
});

describe("azureVmssComputeLifecycles", () => {
  it("reads the launch facts from the member's own write request body, never the admin password", () => {
    const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      properties: {
        requestbody: {
          properties: {
            hardwareProfile: { vmSize: "Standard_D2s_v3" },
            storageProfile: { imageReference: { publisher: "Canonical", offer: "0001", sku: "22_04-lts" } },
            osProfile: { adminUsername: "azureuser", adminPassword: "hunter2" },
            networkProfile: {
              networkInterfaces: [
                {
                  id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkInterfaces/nic1`,
                },
              ],
            },
          },
        },
      },
    });
    const [row] = azureVmssComputeLifecycles([write], "u1");
    expect(row.description).toContain("Standard_D2s_v3");
    expect(row.description).toContain("Canonical:0001:22_04-lts");
    expect(row.description).toContain("azureuser");
    expect(row.description).not.toContain("hunter2");
    expect(row.description).toContain("[epoch 1]");
    expect(row.canonical?.azureVmssCompute?.epoch).toBe(1);
    expect(row.canonical?.azureVmssCompute?.setName).toBe(SET);
    expect(row.canonical?.azureVmssCompute?.instanceId).toBe(INST);
    expect(row.severity).toBe("Low");
    expect(canonicalConformanceIssues(env(row))).toEqual([]);
  });

  it("#M2 a networkProfileConfiguration.networkInterfaceConfigurations[] entry's own id is NEVER read as a NIC id", () => {
    const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      properties: {
        requestbody: {
          properties: {
            networkProfileConfiguration: {
              networkInterfaceConfigurations: [{ name: "nic-template", id: "not-a-real-nic-id" }],
            },
          },
        },
      },
    });
    const [row] = azureVmssComputeLifecycles([write], "u1");
    expect(row.canonical?.azureVmssCompute?.launch?.networkInterfaces).toEqual([]);
    expect(row.description).not.toContain("not-a-real-nic-id");
  });

  it("a malformed NIC entry (no id, or an id that doesn't parse as a NIC resourceId) is never accepted", () => {
    const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      properties: {
        requestbody: {
          properties: { networkProfile: { networkInterfaces: [{ id: "not-a-nic-resource-id" }, {}] } },
        },
      },
    });
    const [row] = azureVmssComputeLifecycles([write], "u1");
    expect(row.canonical?.azureVmssCompute?.launch?.networkInterfaces).toEqual([]);
  });

  it("identity-assigned fires from identity.type, a sibling of properties", () => {
    const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      properties: {
        requestbody: {
          identity: { type: "SystemAssigned" },
          properties: { hardwareProfile: { vmSize: "Standard_B1s" } },
        },
      },
    });
    const [row] = azureVmssComputeLifecycles([write], "u1");
    expect(row.canonical?.azureVmssCompute?.facts).toContain("identity-assigned");
    expect(row.severity).toBe("Medium");
  });

  it("a failed write is not the launch and is counted as not-succeeded", () => {
    const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      status: { value: "Failed" },
    });
    expect(azureVmssComputeLifecycles([write], "u1")).toHaveLength(0);
  });

  it("start/deallocate/delete are recorded operations, never a fabricated transition", () => {
    const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      eventTimestamp: at(0),
    });
    const start = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/start/action", {
      eventTimestamp: at(10),
    });
    const dealloc = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/deallocate/action", {
      eventTimestamp: at(20),
    });
    const [row] = azureVmssComputeLifecycles([write, start, dealloc], "u1");
    expect(row.description).toContain("recorded: started");
    expect(row.description).toContain("recorded: deallocated");
    expect(row.canonical?.azureVmssCompute?.operations.map((o) => o.kind)).toEqual(["start", "deallocate"]);
  });

  it("a Run Command action targeting this member is a remote-access-request fact", () => {
    const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      eventTimestamp: at(0),
    });
    const run = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", {
      eventTimestamp: at(5),
    });
    const [row] = azureVmssComputeLifecycles([write, run], "u1");
    expect(row.canonical?.azureVmssCompute?.facts).toContain("remote-access-request");
  });

  describe("Flexible-mode members are skipped entirely (#1078, design round 1, finding M3)", () => {
    it("a write carrying properties.virtualMachineResourceId is never tracked", () => {
      const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        properties: {
          requestbody: {
            properties: {
              virtualMachineResourceId: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/${SET}${INST}`,
              hardwareProfile: { vmSize: "Standard_B1s" },
            },
          },
        },
      });
      expect(azureVmssComputeLifecycles([write], "u1")).toHaveLength(0);
    });

    it("once flagged Flexible from an earlier write, a later record for the SAME member is also skipped", () => {
      const flexWrite = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        eventTimestamp: at(0),
        properties: {
          requestbody: {
            properties: {
              virtualMachineResourceId: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/${SET}${INST}`,
            },
          },
        },
      });
      const laterRun = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", {
        eventTimestamp: at(10),
      });
      expect(azureVmssComputeLifecycles([flexWrite, laterRun], "u1")).toHaveLength(0);
    });
  });

  describe("epoch rule — observed lifecycle epochs, never proven physical machines (#1078, design round 1, finding H1)", () => {
    it("a delete-first record creates and immediately closes a placeholder epoch, retaining the boundary", () => {
      const del = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/delete", {
        eventTimestamp: at(0),
      });
      const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        eventTimestamp: at(10),
      });
      const rows = azureVmssComputeLifecycles([del, write], "u1");
      // The delete-first placeholder epoch has only 1 operation (< 2) and no launch/facts, so it
      // is not itself reported — only epoch 2 (the later write) is.
      expect(rows).toHaveLength(1);
      expect(rows[0].canonical?.azureVmssCompute?.epoch).toBe(2);
    });

    it("a delete then a later successful write for the same id starts a NEW epoch — facts never merge across the boundary", () => {
      const write1 = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        eventTimestamp: at(0),
        properties: {
          requestbody: { identity: { type: "SystemAssigned" }, properties: { hardwareProfile: {} } },
        },
      });
      const del = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/delete", {
        eventTimestamp: at(10),
      });
      const write2 = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        eventTimestamp: at(20),
      });
      const run2 = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", {
        eventTimestamp: at(30),
      });
      const rows = azureVmssComputeLifecycles([write1, del, write2, run2], "u1");
      const byEpoch = new Map(rows.map((r) => [r.canonical?.azureVmssCompute?.epoch, r]));
      expect(byEpoch.get(1)?.canonical?.azureVmssCompute?.facts).toContain("identity-assigned");
      expect(byEpoch.get(1)?.canonical?.azureVmssCompute?.facts).not.toContain("remote-access-request");
      expect(byEpoch.get(2)?.canonical?.azureVmssCompute?.facts).not.toContain("identity-assigned");
      expect(byEpoch.get(2)?.canonical?.azureVmssCompute?.facts).toContain("remote-access-request");
    });

    it("a repeated successful delete while already closed stays on the closed epoch, never opens a new one", () => {
      const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        eventTimestamp: at(0),
      });
      const del1 = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/delete", {
        eventTimestamp: at(10),
      });
      const del2 = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/delete", {
        eventTimestamp: at(20),
      });
      const rows = azureVmssComputeLifecycles([write, del1, del2], "u1");
      const epochs = new Set(rows.map((r) => r.canonical?.azureVmssCompute?.epoch));
      expect(epochs).toEqual(new Set([1]));
      expect(rows[0].canonical?.azureVmssCompute?.operations.map((o) => o.kind)).toEqual([
        "delete",
        "delete",
      ]);
    });

    it("a failed/non-terminal record after a close never opens a new epoch — it is a post-closure attempt only", () => {
      const write = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        eventTimestamp: at(0),
      });
      const del = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/delete", {
        eventTimestamp: at(10),
      });
      const failedRun = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", {
        eventTimestamp: at(20),
        status: { value: "Failed" },
      });
      const rows = azureVmssComputeLifecycles([write, del, failedRun], "u1");
      // Only epoch 1 (write + delete) is reported; the failed run never opened epoch 2.
      expect(rows).toHaveLength(1);
      expect(rows[0].canonical?.azureVmssCompute?.epoch).toBe(1);
    });

    it("VMSS_EPOCHS_PER_MEMBER_MAX bounds epochs retained per member — further ones counted, never tracked", () => {
      const records: Record<string, unknown>[] = [];
      for (let i = 0; i < VMSS_EPOCHS_PER_MEMBER_MAX + 3; i++) {
        records.push(
          azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
            eventTimestamp: at(i * 10),
            properties: {
              requestbody: { identity: { type: "SystemAssigned" }, properties: { hardwareProfile: {} } },
            },
          }),
        );
        records.push(
          azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/delete", {
            eventTimestamp: at(i * 10 + 5),
          }),
        );
      }
      expect(() => azureVmssComputeLifecycles(records, "u1")).not.toThrow();
      const rows = azureVmssComputeLifecycles(records, "u1");
      const perEpoch = rows.filter((r) => r.description.startsWith("Azure VMSS compute lifecycle:"));
      const epochs = new Set(perEpoch.map((r) => r.canonical?.azureVmssCompute?.epoch));
      expect(epochs.size).toBeLessThanOrEqual(VMSS_EPOCHS_PER_MEMBER_MAX);
      const omitted = rows.find((r) => r.description.startsWith("Azure VMSS compute lifecycle —"));
      expect(omitted?.description).toContain("epoch");
    });
  });

  it("grades two distinct fact kinds High, one Medium, none Low (write-only)", () => {
    const writeOnly = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      eventTimestamp: at(0),
    });
    expect(azureVmssComputeLifecycles([writeOnly], "u1")[0].severity).toBe("Low");

    const withIdentity = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      eventTimestamp: at(0),
      properties: { requestbody: { identity: { type: "SystemAssigned" } } },
    });
    expect(azureVmssComputeLifecycles([withIdentity], "u1")[0].severity).toBe("Medium");
  });

  it("two members by (set, instance) are two separate rows", () => {
    const other = MEMBER_ID.replace(/virtualMachines\/0$/, "virtualMachines/1");
    const w1 = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      resourceId: MEMBER_ID,
    });
    const w2 = azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
      resourceId: other,
    });
    const rows = azureVmssComputeLifecycles([w1, w2], "u1");
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.canonical?.azureVmssCompute?.instanceId))).toEqual(new Set(["0", "1"]));
  });

  it("caps rows at VMSS_COMPUTE_MAX and reports an omitted row for the rest", () => {
    const records = Array.from({ length: VMSS_COMPUTE_MAX + 2 }, (_, i) =>
      azure("Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write", {
        resourceId: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachineScaleSets/${SET}/virtualMachines/${i}`,
        eventTimestamp: at(i),
      }),
    );
    const rows = azureVmssComputeLifecycles(records, "u1");
    expect(rows).toHaveLength(VMSS_COMPUTE_MAX + 1);
    expect(rows[rows.length - 1].description).toContain("2 further epoch");
  });
});
