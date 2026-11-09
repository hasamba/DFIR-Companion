import { describe, expect, it } from "vitest";
import {
  GCP_ENTRIES_LIST_URL,
  gcpCheckFilter,
  runGcpReadCheck,
} from "../../../src/integrations/cloudCheck/gcpReadCheck.js";
import { checkSummary } from "../../../src/integrations/cloudCheck/readCheckWording.js";
import { gcpDenied, mockGcp } from "./readCheckMocks.js";

// #2309: the GCP check lists one entry of each selected audit log family with entries:list.

const NOW = new Date("2026-11-06T00:00:00.000Z");
const input = (sources: ("audit-logs" | "data-access-logs")[] = ["audit-logs", "data-access-logs"]) => ({
  projectId: "test-project-01",
  sources,
  secrets: [],
  now: NOW,
});

describe("gcpCheckFilter", () => {
  it("names the project's audit logs and looks back 30 days", () => {
    expect(gcpCheckFilter("p1", "audit-logs", NOW)).toBe(
      'logName=("projects/p1/logs/cloudaudit.googleapis.com%2Factivity" OR ' +
        '"projects/p1/logs/cloudaudit.googleapis.com%2Fsystem_event" OR ' +
        '"projects/p1/logs/cloudaudit.googleapis.com%2Fpolicy") AND timestamp>="2026-10-07T00:00:00.000Z"',
    );
    expect(gcpCheckFilter("p1", "data-access-logs", NOW)).toContain(
      "cloudaudit.googleapis.com%2Fdata_access",
    );
  });
});

describe("runGcpReadCheck", () => {
  it("reports both families read when entries come back", async () => {
    const { client, calls } = mockGcp(() => ({ entries: [{}] }));
    const results = await runGcpReadCheck(client, input());
    expect(results.map((r) => r.status)).toEqual(["succeeded", "succeeded"]);
    expect(calls[0]).toMatchObject({ method: "POST", url: GCP_ENTRIES_LIST_URL });
    expect(calls[0].data).toMatchObject({ resourceNames: ["projects/test-project-01"], pageSize: 1 });
    expect(checkSummary(results)).toBe(
      "Tested reads succeeded for: GCP Admin Activity, System Event and Policy audit logs, GCP Data Access audit logs. " +
        "Failed: none. The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("reports a partial result when Data Access is denied", async () => {
    const { client } = mockGcp((f) =>
      f.includes("data_access") ? gcpDenied("needs privateLogViewer") : { entries: [] },
    );
    const results = await runGcpReadCheck(client, input());
    expect(checkSummary(results)).toBe(
      "Tested reads succeeded for: GCP Admin Activity, System Event and Policy audit logs. " +
        "Failed: GCP Data Access audit logs (HTTP 403 PERMISSION_DENIED: needs privateLogViewer). " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("fails every source when every call is denied", async () => {
    const { client } = mockGcp(() => gcpDenied());
    const results = await runGcpReadCheck(client, input());
    expect(results.map((r) => r.status)).toEqual(["failed", "failed"]);
  });

  it("does not claim Data Access was read from an empty page", async () => {
    const { client } = mockGcp(() => ({}));
    const results = await runGcpReadCheck(client, input(["data-access-logs"]));
    expect(results[0]).toMatchObject({
      status: "not-tested",
      detail: "the last 30 days hold no Data Access entry, so reading them could not be proven",
    });
  });

  // #2450: an account without Private Logs Viewer gets an EMPTY Data Access answer, not a 403.
  it("fails Data Access, naming the role, when the empty answer comes from a missing permission", async () => {
    const { client, calls } = mockGcp(
      () => ({}),
      () => ({}),
    );
    const results = await runGcpReadCheck(client, input(["data-access-logs"]));
    expect(results[0]).toMatchObject({
      status: "failed",
      detail: expect.stringContaining("lacks the Private Logs Viewer role (roles/logging.privateLogViewer)"),
    });
    expect(calls[1]).toMatchObject({
      method: "POST",
      url: "https://cloudresourcemanager.googleapis.com/v1/projects/test-project-01:testIamPermissions",
      data: { permissions: ["logging.privateLogEntries.list"] },
    });
  });

  it("stays not tested, saying the role may be missing, when the permission test fails", async () => {
    const { client } = mockGcp(
      () => ({}),
      () => gcpDenied("The caller does not have permission"),
    );
    const results = await runGcpReadCheck(client, input(["data-access-logs"]));
    expect(results[0].status).toBe("not-tested");
    expect(results[0].detail).toContain("HTTP 403 PERMISSION_DENIED: The caller does not have permission");
    expect(results[0].detail).toContain("Google hides Data Access logs instead of refusing them");
  });

  // Lab run: the project had the Resource Manager API off, and the 200-character cap cut Google's
  // console link in half. That answer is worded plainly, with a whole link.
  it("says plainly that the Cloud Resource Manager API is off, with a whole enable link", async () => {
    const off = Object.assign(new Error("Request failed with status code 403"), {
      name: "GaxiosError",
      response: {
        status: 403,
        data: {
          error: {
            status: "PERMISSION_DENIED",
            message:
              "Cloud Resource Manager API has not been used in project 123456789012 before or it is disabled. " +
              "Enable it by visiting https://console.developers.google.com/apis/api/cloudresourcemanager.googleapis.com/overview?project=123456789012 then retry.",
            details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "SERVICE_DISABLED" }],
          },
        },
      },
    });
    const { client } = mockGcp(
      () => ({}),
      () => off,
    );
    const results = await runGcpReadCheck(client, input(["data-access-logs"]));
    expect(results[0].status).toBe("not-tested");
    expect(results[0].detail).toContain(
      "the Cloud Resource Manager API is off in this project; enable it at " +
        "https://console.cloud.google.com/apis/library/cloudresourcemanager.googleapis.com?project=test-project-01",
    );
    expect(results[0].detail).not.toContain("console.developers.google.com");
  });

  it("does not test the permission when Data Access entries came back", async () => {
    const { client, calls } = mockGcp(() => ({ entries: [{}] }));
    await runGcpReadCheck(client, input(["data-access-logs"]));
    expect(calls.map((c) => c.url)).toEqual([GCP_ENTRIES_LIST_URL]);
  });

  it("only ever calls entries:list", async () => {
    const { client, calls } = mockGcp(() => ({ entries: [{}] }));
    await runGcpReadCheck(client, input());
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `POST ${GCP_ENTRIES_LIST_URL}`,
      `POST ${GCP_ENTRIES_LIST_URL}`,
    ]);
  });
});
