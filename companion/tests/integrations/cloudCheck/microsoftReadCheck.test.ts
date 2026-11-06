import { describe, expect, it } from "vitest";
import {
  GRAPH_CHECK_URLS,
  runMicrosoftReadCheck,
} from "../../../src/integrations/cloudCheck/microsoftReadCheck.js";
import { checkSummary } from "../../../src/integrations/cloudCheck/readCheckWording.js";
import { mockGraph } from "./readCheckMocks.js";

// #2309: the Microsoft check gets a Graph token, then GETs one page of each selected log.

const SIGNINS = "/v1.0/auditLogs/signIns";
const AUDITS = "/v1.0/auditLogs/directoryAudits";
const BOTH = { sources: ["entra-signins", "entra-directory-audits"] as const, secrets: [] };
const input = () => ({ ...BOTH, sources: [...BOTH.sources] });

describe("runMicrosoftReadCheck", () => {
  it("reports both logs read when Graph answers 200", async () => {
    const { clients, calls } = mockGraph({ [SIGNINS]: { status: 200 }, [AUDITS]: { status: 200 } });
    const results = await runMicrosoftReadCheck(clients, input());
    expect(results.map((r) => r.status)).toEqual(["succeeded", "succeeded"]);
    expect(calls).toEqual([
      { method: "GET", url: new URL(GRAPH_CHECK_URLS["entra-signins"]).href },
      { method: "GET", url: new URL(GRAPH_CHECK_URLS["entra-directory-audits"]).href },
    ]);
    expect(checkSummary(results)).toBe(
      "Tested reads succeeded for: Entra sign-in logs, Entra directory audit logs. Failed: none. " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("reports a partial result with Graph's own error code", async () => {
    const { clients } = mockGraph({ [AUDITS]: { status: 200 } });
    const results = await runMicrosoftReadCheck(clients, input());
    expect(checkSummary(results)).toBe(
      "Tested reads succeeded for: Entra directory audit logs. " +
        "Failed: Entra sign-in logs (HTTP 403 Authorization_RequestDenied: Insufficient privileges). " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("fails every source when the sign-in fails, and calls Graph not at all", async () => {
    const { clients, calls } = mockGraph({}, new Error("AADSTS700027: certificate is not registered"));
    const results = await runMicrosoftReadCheck(clients, input());
    expect(results.every((r) => r.status === "failed")).toBe(true);
    expect(results[0].detail).toBe("sign-in failed: AADSTS700027: certificate is not registered");
    expect(calls).toEqual([]);
  });

  it("does not count a token alone as a success", async () => {
    const { clients } = mockGraph({});
    const results = await runMicrosoftReadCheck(clients, input());
    expect(checkSummary(results).startsWith("Tested reads succeeded for: none.")).toBe(true);
  });

  it("never sends anything but GET to the two log endpoints", async () => {
    const { clients, calls } = mockGraph({ [SIGNINS]: { status: 200 } });
    await runMicrosoftReadCheck(clients, input());
    for (const call of calls) {
      expect(call.method).toBe("GET");
      expect([SIGNINS, AUDITS]).toContain(new URL(call.url).pathname);
    }
  });

  it("keeps the token and the account's secrets out of an error", async () => {
    const secret = "pem-body-line-sentinel-77";
    const { clients } = mockGraph({
      [SIGNINS]: {
        status: 401,
        body: { error: { code: "InvalidAuthenticationToken", message: `x graph-token-abc ${secret}` } },
      },
    });
    const results = await runMicrosoftReadCheck(clients, { sources: ["entra-signins"], secrets: [secret] });
    expect(results[0].detail).toBe("HTTP 401 InvalidAuthenticationToken: x [redacted] [redacted]");
  });
});
