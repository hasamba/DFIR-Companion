// #1066 (931.8 second half, Azure half): the standalone-VM compute lifecycle built over one
// Activity Log upload — the launch facts as the write's request body states them, every later
// recorded operation, an identity-assigned fact, a remote-access request, and nothing the records
// do not say. #1077 adds the network-security-group join — see the "NSG join" describe block
// below for its own test matrix.
import { describe, expect, it } from "vitest";
import { azureComputeLifecycles, AZURE_COMPUTE_MAX } from "../../src/analysis/azureCompute.js";
import {
  parseAzureVmResourceId,
  resolveAt,
  EdgeBuffer,
  type NicState,
  type WithTombstone,
} from "../../src/analysis/azureComputeState.js";

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
/** Every tracked NIC/Subnet/NSG id is stored lowercased — pre-lowering test fixtures' own resource
 * ids keeps assertions on the resulting canonical fields predictable regardless of case. */
const lowerId = (id: string): string => id.toLowerCase();

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

describe("resolveAt — the helper that fixes groupsAt()'s unsoundness (#1077)", () => {
  const q = (time: number, locator: string) => ({ time, locator });
  it("returns null when the query predates every retained statement", () => {
    const buf = new EdgeBuffer<NicState>(4, 2);
    buf.push({ time: 1000, locator: "record:5", nsgId: "a", subnetId: null });
    expect(resolveAt(buf, q(500, "record:0"))).toBeNull();
  });
  it("resolves exactly to a statement the query lands on, never a manufactured gap", () => {
    const buf = new EdgeBuffer<NicState>(1, 1);
    buf.push({ time: 1000, locator: "record:1", nsgId: "a", subnetId: null });
    buf.push({ time: 2000, locator: "record:2", nsgId: "b", subnetId: null });
    buf.push({ time: 3000, locator: "record:3", nsgId: "c", subnetId: null }); // overflow: 1 discarded
    expect(buf.beyond).toBe(1);
    // record:1 is early's own last entry — an exact-position query still resolves to it.
    const hit = resolveAt(buf, q(1000, "record:1"));
    expect(hit).not.toBe("gap");
    expect((hit as NicState).nsgId).toBe("a");
  });
  it("returns 'gap' for a query strictly after early's last entry but before late's first, when something was discarded", () => {
    const buf = new EdgeBuffer<NicState>(1, 1);
    buf.push({ time: 1000, locator: "record:1", nsgId: "a", subnetId: null });
    buf.push({ time: 2000, locator: "record:2", nsgId: "b", subnetId: null });
    buf.push({ time: 3000, locator: "record:3", nsgId: "c", subnetId: null });
    // early=[1000], late=[2000,3000] with lateMax=1 -> late=[3000], beyond=1 (2000 discarded).
    expect(resolveAt(buf, q(1500, "record:1.5"))).toBe("gap");
  });
  it("resolves definitely once the query reaches late's own first entry, regardless of an earlier discard", () => {
    const buf = new EdgeBuffer<NicState>(1, 2);
    buf.push({ time: 1000, locator: "record:1", nsgId: "a", subnetId: null });
    buf.push({ time: 2000, locator: "record:2", nsgId: "b", subnetId: null });
    buf.push({ time: 3000, locator: "record:3", nsgId: "c", subnetId: null });
    // early=[1000] (cap 1), late=[2000,3000] (cap 2, nothing discarded here) -> beyond=0.
    expect(buf.beyond).toBe(0);
    const hit = resolveAt(buf, q(2500, "record:2.5"));
    expect(hit).not.toBe("gap");
    expect((hit as NicState).nsgId).toBe("b");
  });
  it("treats a resolved tombstone as a gap, never a positive statement", () => {
    const buf = new EdgeBuffer<WithTombstone<NicState>>(4, 2);
    buf.push({ time: 1000, locator: "record:1", nsgId: "a", subnetId: null });
    buf.push({ time: 2000, locator: "record:2", deleted: true });
    expect(resolveAt(buf, q(2500, "record:9"))).toBe("gap");
  });
});

describe("azureComputeLifecycles — the NSG join (#1077)", () => {
  const NIC_ID = lowerId(
    `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkInterfaces/nic1`,
  );
  const NSG_ID = lowerId(
    `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkSecurityGroups/nsg1`,
  );
  const VNET_ID = lowerId(
    `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/virtualNetworks/vnet1`,
  );
  const SUBNET_ID = `${VNET_ID}/subnets/subnet1`;

  const vmWriteWithNic = (nicId: string, at_ = at(0)): Record<string, unknown> =>
    azure("Microsoft.Compute/virtualMachines/write", {
      eventTimestamp: at_,
      properties: { requestbody: { properties: { networkProfile: { networkInterfaces: [{ id: nicId }] } } } },
    });

  const nicWrite = (
    opts: { nsgId?: string; subnetId?: string } = {},
    at_ = at(5),
    resourceId = NIC_ID,
  ): Record<string, unknown> =>
    azure("Microsoft.Network/networkInterfaces/write", {
      resourceId,
      eventTimestamp: at_,
      properties: {
        requestbody: {
          properties: {
            ...(opts.nsgId !== undefined ? { networkSecurityGroup: { id: opts.nsgId } } : {}),
            ...(opts.subnetId !== undefined
              ? { ipConfigurations: [{ properties: { subnet: { id: opts.subnetId } } }] }
              : {}),
          },
        },
      },
    });

  const subnetWrite = (nsgId: string | undefined, at_ = at(5)): Record<string, unknown> =>
    azure("Microsoft.Network/virtualNetworks/subnets/write", {
      resourceId: SUBNET_ID,
      eventTimestamp: at_,
      properties: { requestbody: { properties: nsgId ? { networkSecurityGroup: { id: nsgId } } : {} } },
    });

  const allowAnyRule = (over: Record<string, unknown> = {}) => ({
    direction: "Inbound",
    access: "Allow",
    sourceAddressPrefix: "*",
    ...over,
  });

  const nsgParentWrite = (rules: Record<string, unknown>[], at_ = at(10)): Record<string, unknown> =>
    azure("Microsoft.Network/networkSecurityGroups/write", {
      resourceId: NSG_ID,
      eventTimestamp: at_,
      properties: { requestbody: { properties: { securityRules: rules } } },
    });

  const nsgChildRuleWrite = (rule: Record<string, unknown>, at_ = at(10)): Record<string, unknown> =>
    azure("Microsoft.Network/networkSecurityGroups/securityRules/write", {
      resourceId: `${NSG_ID}/securityRules/allow-ssh`,
      eventTimestamp: at_,
      properties: { requestbody: { properties: rule } },
    });

  it("a direct NIC->NSG match (parent rule form) fires the fact", () => {
    const rows = azureComputeLifecycles(
      [vmWriteWithNic(NIC_ID), nicWrite({ nsgId: NSG_ID }), nsgParentWrite([allowAnyRule()])],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).toContain("any-address-nsg-rule");
    expect(rows[0].canonical?.azureCompute?.nsgObservation?.path).toBe("direct");
    expect(rows[0].canonical?.azureCompute?.nsgObservation?.token).toBe("*");
  });

  it("a via-subnet match (child rule form) fires the fact", () => {
    const rows = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ subnetId: SUBNET_ID }),
        subnetWrite(NSG_ID),
        nsgChildRuleWrite(allowAnyRule({ sourceAddressPrefix: "0.0.0.0/0" })),
      ],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).toContain("any-address-nsg-rule");
    expect(rows[0].canonical?.azureCompute?.nsgObservation?.path).toBe("via-subnet");
    expect(rows[0].canonical?.azureCompute?.nsgObservation?.token).toBe("0.0.0.0/0");
  });

  it("a rule naming a different NSG never fires", () => {
    const otherNsg = lowerId(
      `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-other`,
    );
    const rows = azureComputeLifecycles(
      [vmWriteWithNic(NIC_ID), nicWrite({ nsgId: otherNsg }), nsgParentWrite([allowAnyRule()])],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("Azure's own auto-provisioned defaultSecurityRules[] is never read", () => {
    const nsg = azure("Microsoft.Network/networkSecurityGroups/write", {
      resourceId: NSG_ID,
      eventTimestamp: at(10),
      properties: {
        requestbody: { properties: { defaultSecurityRules: [allowAnyRule()], securityRules: [] } },
      },
    });
    const rows = azureComputeLifecycles([vmWriteWithNic(NIC_ID), nicWrite({ nsgId: NSG_ID }), nsg], "u1");
    expect(rows[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("a rule scoped to a specific CIDR (not */0.0.0.0/0/::/0/Internet) never fires", () => {
    const rows = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ nsgId: NSG_ID }),
        nsgParentWrite([allowAnyRule({ sourceAddressPrefix: "10.0.0.0/8" })]),
      ],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("a deny rule and a disabled/outbound rule never fire", () => {
    const deny = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ nsgId: NSG_ID }),
        nsgParentWrite([allowAnyRule({ access: "Deny" })]),
      ],
      "u1",
    );
    expect(deny[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
    const outbound = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ nsgId: NSG_ID }),
        nsgParentWrite([allowAnyRule({ direction: "Outbound" })]),
      ],
      "u1",
    );
    expect(outbound[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("::/0 and Internet each produce their own distinct token, never collapsed into one 'any source' phrase", () => {
    const ipv6 = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ nsgId: NSG_ID }),
        nsgParentWrite([allowAnyRule({ sourceAddressPrefix: "::/0" })]),
      ],
      "u1",
    );
    expect(ipv6[0].canonical?.azureCompute?.nsgObservation?.token).toBe("::/0");
    const internet = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ nsgId: NSG_ID }),
        nsgParentWrite([allowAnyRule({ sourceAddressPrefix: "Internet" })]),
      ],
      "u1",
    );
    expect(internet[0].canonical?.azureCompute?.nsgObservation?.token).toBe("internet");
    expect(internet[0].description).toContain("Azure's Internet service tag");
  });

  it("#H1 an unrelated VM PATCH omitting networkProfile preserves the prior NIC-set observation, never a false empty set", () => {
    const secondWrite = azure("Microsoft.Compute/virtualMachines/write", {
      eventTimestamp: at(6),
      properties: { requestbody: { properties: { osProfile: { adminUsername: "azureuser" } } } },
    });
    const rows = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        secondWrite,
        nicWrite({ nsgId: NSG_ID }),
        nsgParentWrite([allowAnyRule()], at(20)),
      ],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).toContain("any-address-nsg-rule");
  });

  it("#H2 a VM delete stops a later join from resolving through it", () => {
    const del = azure("Microsoft.Compute/virtualMachines/delete", { eventTimestamp: at(6) });
    const rows = azureComputeLifecycles(
      [vmWriteWithNic(NIC_ID), del, nicWrite({ nsgId: NSG_ID }), nsgParentWrite([allowAnyRule()], at(20))],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("#H2 a NIC delete stops a later join from resolving through it", () => {
    const nicDel = azure("Microsoft.Network/networkInterfaces/delete", {
      resourceId: NIC_ID,
      eventTimestamp: at(6),
    });
    const rows = azureComputeLifecycles(
      [vmWriteWithNic(NIC_ID), nicWrite({ nsgId: NSG_ID }), nicDel, nsgParentWrite([allowAnyRule()], at(20))],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("#H2 a parent VNet write invalidates a stale child-subnet state — no false positive survives it", () => {
    const vnetWrite = azure("Microsoft.Network/virtualNetworks/write", {
      resourceId: VNET_ID,
      eventTimestamp: at(6),
      properties: { requestbody: { properties: {} } },
    });
    const rows = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ subnetId: SUBNET_ID }),
        subnetWrite(NSG_ID),
        vnetWrite,
        nsgChildRuleWrite(allowAnyRule(), at(20)),
      ],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("a VM whose NIC changes resolves against the CORRECT NIC-at-that-time, not the launch-time NIC", () => {
    const otherNic = lowerId(
      `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkInterfaces/nic2`,
    );
    const otherNsg = lowerId(
      `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-other`,
    );
    const swap = azure("Microsoft.Compute/virtualMachines/write", {
      eventTimestamp: at(8),
      properties: {
        requestbody: { properties: { networkProfile: { networkInterfaces: [{ id: otherNic }] } } },
      },
    });
    const rows = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ nsgId: NSG_ID }),
        swap,
        nicWrite({ nsgId: otherNsg }, at(9), otherNic),
        nsgParentWrite([allowAnyRule()], at(20)), // matches NSG_ID, not otherNsg — should NOT fire
      ],
      "u1",
    );
    expect(rows[0].canonical?.azureCompute?.facts).not.toContain("any-address-nsg-rule");
  });

  it("decisive attachment-chain locators (rule, NIC, subnet writes) survive the raw-evidence cap", () => {
    const rows = azureComputeLifecycles(
      [
        vmWriteWithNic(NIC_ID),
        nicWrite({ subnetId: SUBNET_ID }),
        subnetWrite(NSG_ID),
        nsgChildRuleWrite(allowAnyRule()),
      ],
      "u1",
    );
    const obs = rows[0].canonical?.azureCompute?.nsgObservation;
    const cited = rows[0].canonical?.evidence?.rawRecords.map((r) => r.locator) ?? [];
    expect(obs).toBeDefined();
    expect(cited).toContain(obs!.ruleLocator);
    expect(cited).toContain(obs!.nicLocator);
    expect(cited).toContain(obs!.subnetLocator);
  });

  it("the NSG-rule-records-examined bound is honored and disclosed", () => {
    const write = vmWriteWithNic(NIC_ID);
    const nic = nicWrite({ nsgId: NSG_ID });
    const records: Record<string, unknown>[] = [write, nic];
    for (let i = 0; i < 260; i++)
      records.push(
        azure("Microsoft.Network/networkSecurityGroups/write", {
          resourceId: lowerId(
            `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-${i}`,
          ),
          eventTimestamp: at(10 + i),
          properties: { requestbody: { properties: { securityRules: [allowAnyRule()] } } },
        }),
      );
    const rows = azureComputeLifecycles(records, "u1");
    const omitted = rows.find((r) => r.description.startsWith("Azure compute lifecycle —"));
    expect(omitted?.description).toContain("NSG-rule record");
  });
});
