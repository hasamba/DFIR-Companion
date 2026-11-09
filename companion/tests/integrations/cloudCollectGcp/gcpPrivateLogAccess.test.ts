import { describe, expect, it } from "vitest";
import {
  GCP_AUDIT_SOURCE,
  gcpCollectSession,
  testPrivateLogAccess,
} from "../../../src/integrations/cloudCollectGcp/gcpCollectProvider.js";
import {
  dataAccessNote,
  privateLogAccessFrom,
  testIamPermissionsUrl,
} from "../../../src/integrations/cloudTransport/googlePrivateLogs.js";
import { gcpAuditEntry, googleError, mockWire, PROJECT } from "./gcpCollectMocks.js";

// #2450: without the Private Logs Viewer role, Google leaves Data Access out of entries:list with no
// error (measured in the #2314 lab run). The collector asks Google once per session whether the
// account holds the permission, and says so on every page that covers Data Access.

const WINDOW = { start: "2026-11-01T00:00:00.000Z", end: "2026-11-02T00:00:00.000Z" };
const SETTINGS = {
  projectId: PROJECT,
  authMode: "service-account-key" as const,
  clientEmail: `collector@${PROJECT}.iam.gserviceaccount.com`,
};
const page = (logName?: string) => ({
  source: GCP_AUDIT_SOURCE,
  subWindowId: "s:0",
  window: WINDOW,
  ...(logName ? { partition: { logName } } : {}),
});
const entries = () => ({ body: { entries: [gcpAuditEntry(1)] } });

describe("privateLogAccessFrom", () => {
  it("is granted only when Google lists the permission", () => {
    expect(privateLogAccessFrom({ permissions: ["logging.privateLogEntries.list"] })).toEqual({
      state: "granted",
    });
    expect(privateLogAccessFrom({})).toEqual({ state: "missing" });
    expect(privateLogAccessFrom({ permissions: ["logging.logEntries.list"] })).toEqual({ state: "missing" });
    expect(privateLogAccessFrom(null)).toEqual({ state: "missing" });
  });
});

describe("the collector's Data Access permission test", () => {
  it("marks a Data Access page unverified, with a note naming the role, when the permission is missing", async () => {
    const { wire, iamCalls } = mockWire(entries, () => ({ body: {} }));
    const got = await gcpCollectSession({ wire, settings: SETTINGS }).fetchPage(page("data_access"));
    expect(got.unverified).toBe(true);
    expect(got.note).toContain("Data Access logs were not collected");
    expect(got.note).toContain("roles/logging.privateLogViewer");
    expect(got.requestParams).toMatchObject({ privateLogAccess: "missing" });
    expect(iamCalls).toHaveLength(1);
    expect(iamCalls[0]).toMatchObject({ method: "POST", url: testIamPermissionsUrl(PROJECT) });
    expect(JSON.parse(String(iamCalls[0].body))).toEqual({ permissions: ["logging.privateLogEntries.list"] });
  });

  it("also covers a request for all four logs, which includes Data Access", async () => {
    const { wire } = mockWire(entries, () => ({ body: {} }));
    const got = await gcpCollectSession({ wire, settings: SETTINGS }).fetchPage(page());
    expect(got.unverified).toBe(true);
  });

  it("adds nothing but the recorded answer when the permission is held", async () => {
    const { wire } = mockWire(entries);
    const got = await gcpCollectSession({ wire, settings: SETTINGS }).fetchPage(page("data_access"));
    expect(got.note).toBeUndefined();
    expect(got.unverified).toBeUndefined();
    expect(got.requestParams).toMatchObject({ privateLogAccess: "granted" });
  });

  it("never asks for a request that does not cover Data Access", async () => {
    const { wire, iamCalls } = mockWire(entries, () => ({ body: {} }));
    const got = await gcpCollectSession({ wire, settings: SETTINGS }).fetchPage(page("activity"));
    expect(iamCalls).toEqual([]);
    expect(got.note).toBeUndefined();
    expect(got.requestParams).not.toHaveProperty("privateLogAccess");
  });

  it("asks once per session, however many pages follow", async () => {
    const { wire, iamCalls } = mockWire(entries, () => ({ body: {} }));
    const session = gcpCollectSession({ wire, settings: SETTINGS });
    await session.fetchPage(page("data_access"));
    await session.fetchPage({ ...page("data_access"), pageToken: "tok-1" });
    await session.fetchPage(page());
    expect(iamCalls).toHaveLength(1);
  });

  it("notes, without marking unverified, when the permission test itself fails", async () => {
    const { wire } = mockWire(entries, () => ({
      status: 403,
      body: googleError(403, "PERMISSION_DENIED", "Cloud Resource Manager API has not been used in project"),
    }));
    const got = await gcpCollectSession({ wire, settings: SETTINGS }).fetchPage(page("data_access"));
    expect(got.unverified).toBeUndefined();
    expect(got.note).toContain(
      "could not be tested (the permission test answered HTTP 403 PERMISSION_DENIED: Cloud Resource Manager API",
    );
    expect(got.requestParams).toMatchObject({ privateLogAccess: "unknown" });
  });

  it("words a transport error as fixed text, never the error's own message", async () => {
    const wire = async () => {
      throw new Error("connect ECONNREFUSED proxy.example:3128 (proxy password: secret-pw)");
    };
    const access = await testPrivateLogAccess(wire, PROJECT);
    expect(access).toEqual({ state: "unknown", reason: "the permission test got no answer" });
    expect(dataAccessNote(access)).not.toContain("secret-pw");
  });

  it("rethrows when the request was aborted, and asks again on the next request", async () => {
    let iamAsked = 0;
    const ctl = new AbortController();
    const { wire: inner } = mockWire(entries);
    const wire: typeof inner = async (req) => {
      if (req.url.endsWith(":testIamPermissions")) {
        iamAsked += 1;
        if (iamAsked === 1) {
          ctl.abort();
          throw new DOMException("aborted", "AbortError");
        }
      }
      return inner(req);
    };
    const session = gcpCollectSession({ wire, settings: SETTINGS });
    await expect(session.fetchPage({ ...page("data_access"), signal: ctl.signal })).rejects.toThrow(
      "aborted",
    );
    const got = await session.fetchPage(page("data_access"));
    expect(iamAsked).toBe(2);
    expect(got.requestParams).toMatchObject({ privateLogAccess: "granted" });
  });
});
