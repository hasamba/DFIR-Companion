import { describe, expect, it } from "vitest";
import { sourceResult } from "../../../src/integrations/cloudCheck/readCheckTypes.js";
import { checkFailureReason, checkSummary } from "../../../src/integrations/cloudCheck/readCheckWording.js";

// #2309: the check's summary has one fixed form, and a failure reason never carries a secret.

describe("checkSummary", () => {
  it("lists every succeeded source and says writes were not tested", () => {
    const text = checkSummary([
      sourceResult("cloudtrail-lookup", "succeeded"),
      sourceResult("s3-trail", "succeeded"),
    ]);
    expect(text).toBe(
      "Tested reads succeeded for: CloudTrail event history, CloudTrail S3 bucket. Failed: none. " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("names each failed source with its reason", () => {
    const text = checkSummary([
      sourceResult("entra-signins", "succeeded"),
      sourceResult("entra-directory-audits", "failed", "HTTP 403 Authorization_RequestDenied"),
    ]);
    expect(text).toBe(
      "Tested reads succeeded for: Entra sign-in logs. " +
        "Failed: Entra directory audit logs (HTTP 403 Authorization_RequestDenied). " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("says none succeeded when every read failed", () => {
    const text = checkSummary([sourceResult("audit-logs", "failed", "HTTP 403 PERMISSION_DENIED")]);
    expect(text.startsWith("Tested reads succeeded for: none. Failed: GCP Admin Activity")).toBe(true);
  });

  it("adds a Not tested sentence only when a source was skipped", () => {
    const text = checkSummary([
      sourceResult("cloudtrail-lookup", "succeeded"),
      sourceResult("s3-trail", "not-tested", "name the trail bucket to test it"),
    ]);
    expect(text).toBe(
      "Tested reads succeeded for: CloudTrail event history. Failed: none. " +
        "Not tested: CloudTrail S3 bucket (name the trail bucket to test it). " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("never claims the account is read-only or verified", () => {
    const all = checkSummary([
      sourceResult("audit-logs", "succeeded"),
      sourceResult("data-access-logs", "succeeded"),
    ]);
    expect(all).not.toMatch(/read-only|verified/i);
  });
});

describe("checkFailureReason", () => {
  it("builds the reason from an AWS SDK error", () => {
    const err = Object.assign(new Error("User is not authorized to perform: cloudtrail:LookupEvents"), {
      name: "AccessDeniedException",
      $metadata: { httpStatusCode: 400 },
    });
    expect(checkFailureReason(err, [])).toBe(
      "HTTP 400 AccessDeniedException: User is not authorized to perform: cloudtrail:LookupEvents",
    );
  });

  it("builds the reason from a Google API error", () => {
    const err = Object.assign(new Error("Request failed"), {
      name: "GaxiosError",
      response: { status: 403, data: { error: { status: "PERMISSION_DENIED", message: "denied" } } },
    });
    expect(checkFailureReason(err, [])).toBe("HTTP 403 PERMISSION_DENIED: denied");
  });

  it("cuts every secret out, longest first", () => {
    const secret = "s3cr3t-value-9f8e7d";
    const err = new Error(`bad credential ${secret} and ${secret.slice(0, 8)}`);
    const reason = checkFailureReason(err, [secret, secret.slice(0, 8)]);
    expect(reason).not.toContain(secret);
    expect(reason).not.toContain(secret.slice(0, 8));
    expect(reason).toBe("bad credential [redacted] and [redacted]");
  });

  it("does not quote a JSON parse error, which quotes its input", () => {
    expect(checkFailureReason(new SyntaxError('Unexpected token "x" in "private"'), [])).toBe(
      "the stored credential could not be read",
    );
  });

  it("says a timed-out call got no answer in time, and caps long text", () => {
    expect(checkFailureReason(Object.assign(new Error("x"), { name: "TimeoutError" }), [])).toBe(
      "no answer in time",
    );
    expect(checkFailureReason(new Error("y".repeat(1000)), []).length).toBeLessThanOrEqual(300);
  });
});
