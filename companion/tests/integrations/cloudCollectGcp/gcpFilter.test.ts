import { describe, expect, it } from "vitest";
import {
  GCP_AUDIT_LOGS,
  entriesListBody,
  gcpAuditFilter,
  logsFor,
} from "../../../src/integrations/cloudCollectGcp/gcpFilter.js";
import { CursorExpiredError, RateLimitedError } from "../../../src/integrations/cloudCollect/collectTypes.js";
import { rateLimitOf } from "../../../src/integrations/cloudCollect/collectRateLimit.js";
import { throwForStatus, GcpHttpError } from "../../../src/integrations/cloudCollectGcp/gcpErrors.js";

// #2314: the exact Logging filter, the request body, and how a Google error becomes an engine error.

const WINDOW = { start: "2026-11-01T00:00:00.000Z", end: "2026-11-02T00:00:00.000Z" };

describe("gcpAuditFilter", () => {
  it("is the issue's exact filter: four audit logs, start inclusive, end exclusive", () => {
    expect(gcpAuditFilter("p1", WINDOW, GCP_AUDIT_LOGS)).toBe(
      'logName=("projects/p1/logs/cloudaudit.googleapis.com%2Factivity" OR ' +
        '"projects/p1/logs/cloudaudit.googleapis.com%2Fdata_access" OR ' +
        '"projects/p1/logs/cloudaudit.googleapis.com%2Fsystem_event" OR ' +
        '"projects/p1/logs/cloudaudit.googleapis.com%2Fpolicy") AND ' +
        'timestamp>="2026-11-01T00:00:00.000Z" AND timestamp<"2026-11-02T00:00:00.000Z"',
    );
  });

  it("narrows to one log for a logName partition", () => {
    expect(logsFor({ logName: "data_access" })).toEqual(["data_access"]);
    expect(logsFor(undefined)).toEqual(GCP_AUDIT_LOGS);
    expect(() => logsFor({ logName: "../etc" })).toThrow(/not a GCP audit log/);
    expect(gcpAuditFilter("p1", WINDOW, logsFor({ logName: "policy" }))).toBe(
      'logName=("projects/p1/logs/cloudaudit.googleapis.com%2Fpolicy") AND ' +
        'timestamp>="2026-11-01T00:00:00.000Z" AND timestamp<"2026-11-02T00:00:00.000Z"',
    );
  });

  it("builds the entries:list body: one project, page size 1000, oldest first, the token when given", () => {
    expect(entriesListBody("p1", "F", undefined)).toEqual({
      resourceNames: ["projects/p1"],
      filter: "F",
      orderBy: "timestamp asc",
      pageSize: 1000,
    });
    expect(entriesListBody("p1", "F", "tok")).toMatchObject({ pageToken: "tok" });
  });
});

const res = (status: number, body: unknown, headers: Record<string, string> = {}) => ({
  status,
  headers: new Headers(headers),
  body: new Uint8Array(Buffer.from(JSON.stringify(body))),
});

describe("throwForStatus", () => {
  it("passes a 200", () => {
    expect(() => throwForStatus(res(200, {}), { hadPageToken: false })).not.toThrow();
  });

  it("turns 429 and RESOURCE_EXHAUSTED into RateLimitedError with the Retry-After", () => {
    const thrown = (() => {
      try {
        throwForStatus(
          res(429, { error: { status: "RESOURCE_EXHAUSTED", message: "Quota" } }, { "retry-after": "7" }),
          {
            hadPageToken: true,
          },
        );
      } catch (err) {
        return err;
      }
    })();
    expect(thrown).toBeInstanceOf(RateLimitedError);
    expect(rateLimitOf(thrown, 0)).toEqual({ retryAfterMs: 7000 });
    expect(() =>
      throwForStatus(res(403, { error: { code: 403, status: "RESOURCE_EXHAUSTED", message: "q" } }), {
        hadPageToken: false,
      }),
    ).toThrow(RateLimitedError);
  });

  it("turns a rejected page token into CursorExpiredError — only when a token was sent", () => {
    const expired = res(400, {
      error: { code: 400, status: "INVALID_ARGUMENT", message: "page_token has expired; request a new one" },
    });
    expect(() => throwForStatus(expired, { hadPageToken: true })).toThrow(CursorExpiredError);
    expect(() => throwForStatus(expired, { hadPageToken: false })).toThrow(GcpHttpError);
    const invalid = res(400, {
      error: { code: 400, status: "INVALID_ARGUMENT", message: "Invalid page token" },
    });
    expect(() => throwForStatus(invalid, { hadPageToken: true })).toThrow(CursorExpiredError);
  });

  it("names the HTTP status and Google's status for anything else, cut short", () => {
    expect(() =>
      throwForStatus(
        res(403, { error: { code: 403, status: "PERMISSION_DENIED", message: "no logging.viewer" } }),
        {
          hadPageToken: false,
        },
      ),
    ).toThrow("HTTP 403 PERMISSION_DENIED: no logging.viewer");
    expect(() =>
      throwForStatus(
        { status: 502, headers: new Headers(), body: new Uint8Array(Buffer.from("<html>")) },
        {
          hadPageToken: false,
        },
      ),
    ).toThrow("HTTP 502");
  });
});
