import { describe, expect, it } from "vitest";
import { createHmac } from "node:crypto";

import { mintJwt, findVersion, versionsUrl } from "../scripts/amoApi.mjs";

describe("mintJwt", () => {
  it("produces a verifiable HS256 JWT", async () => {
    const token = await mintJwt("user:1:2", "s3cret", { now: 1_700_000_000, jti: "fixed" });
    const [head, body, sig] = token.split(".");
    expect(JSON.parse(Buffer.from(head, "base64url").toString())).toEqual({ alg: "HS256", typ: "JWT" });
    expect(JSON.parse(Buffer.from(body, "base64url").toString())).toEqual({
      iss: "user:1:2",
      jti: "fixed",
      iat: 1_700_000_000,
      exp: 1_700_000_240,
    });
    // The signature must actually verify. A JWT that merely LOOKS right fails at AMO, on a release.
    expect(sig).toBe(createHmac("sha256", "s3cret").update(`${head}.${body}`).digest("base64url"));
  });

  it("gives every request a distinct jti", async () => {
    // AMO rejects a replayed jti. Two calls in the same second must still differ.
    const a = await mintJwt("i", "s", { now: 1 });
    const b = await mintJwt("i", "s", { now: 1 });
    expect(a).not.toBe(b);
  });

  it("refuses to mint without credentials", async () => {
    await expect(mintJwt("", "s")).rejects.toThrow(/issuer and a secret/);
    await expect(mintJwt("i", "")).rejects.toThrow(/issuer and a secret/);
  });
});

describe("findVersion", () => {
  it("finds a version that is present", () => {
    const body = JSON.stringify({ results: [{ version: "0.36.0" }, { version: "0.35.1" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "yes" });
  });

  it("reports a genuine absence as no, and says what it did see", () => {
    const body = JSON.stringify({ results: [{ version: "0.35.1" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "no", seen: ["0.35.1"] });
  });

  it("treats an add-on with no versions as a genuine no", () => {
    expect(findVersion(JSON.stringify({ results: [] }), "0.36.0")).toMatchObject({ status: "no" });
  });

  // The three below are the whole reason this function exists rather than a `.find()` inline.
  // Every one of them would read as "not submitted yet" to a naive check, and the caller turns
  // that into "submit" — which on a re-run means submitting a version AMO already holds.

  it("treats an auth error as unknown, never as absent", () => {
    const result = findVersion(JSON.stringify({ detail: "Invalid token." }), "0.36.0");
    expect(result.status).toBe("unknown");
    expect(result.reason).toBe("Invalid token.");
  });

  it("treats a non-JSON body as unknown", () => {
    expect(findVersion("<html>502 Bad Gateway</html>", "0.36.0")).toMatchObject({ status: "unknown" });
  });

  it("treats a results field that is not an array as unknown", () => {
    expect(findVersion(JSON.stringify({ results: null }), "0.36.0").status).toBe("unknown");
    expect(findVersion("null", "0.36.0").status).toBe("unknown");
  });

  it("does not crash on malformed version entries", () => {
    const body = JSON.stringify({ results: [null, { version: 42 }, { version: "0.36.0" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "yes" });
  });

  it("matches the version exactly, not by prefix", () => {
    // "0.3" must not match "0.36.0", and "0.36.0" must not be satisfied by "0.36.0-beta".
    const body = JSON.stringify({ results: [{ version: "0.36.0-beta" }] });
    expect(findVersion(body, "0.36.0")).toMatchObject({ status: "no" });
    expect(findVersion(JSON.stringify({ results: [{ version: "0.36.0" }] }), "0.3").status).toBe("no");
  });
});

describe("versionsUrl", () => {
  it("asks for unlisted and in-review versions too", () => {
    // A freshly uploaded version is not public until a reviewer approves it. Without this filter
    // the check would report "not submitted" for something submitted minutes ago.
    expect(versionsUrl("a@b")).toContain("filter=all_with_unlisted");
  });

  it("encodes the add-on id, which contains an @", () => {
    expect(versionsUrl("dfir-companion@hasamba.github.io")).toContain("dfir-companion%40hasamba.github.io");
  });
});
