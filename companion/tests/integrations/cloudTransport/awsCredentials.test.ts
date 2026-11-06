import { describe, expect, it } from "vitest";
import { onePerSession } from "../../../src/integrations/cloudTransport/awsCredentials.js";

// #2313: the role is assumed once per session, and again before it expires — a collection can run
// for hours, longer than one role session.

describe("onePerSession", () => {
  it("shares one call, forgets a failure, and refreshes credentials close to expiry", async () => {
    let t = 0;
    let calls = 0;
    let fail = true;
    const provider = onePerSession(
      async () => {
        calls++;
        if (fail) throw new Error("denied");
        return { expiration: new Date(t + 60 * 60_000) };
      },
      () => t,
    );
    await expect(provider()).rejects.toThrow("denied");
    fail = false;
    await Promise.all([provider(), provider()]);
    expect(calls).toBe(2);
    t += 50 * 60_000; // ten minutes left: still good
    await provider();
    expect(calls).toBe(2);
    t += 6 * 60_000; // four minutes left: refreshed
    await provider();
    expect(calls).toBe(3);
  });
});
