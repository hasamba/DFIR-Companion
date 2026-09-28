import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { EMPTY_ATTACK_MATRIX, resetAttackMatrixCacheForTests } from "../../src/analysis/attackMatrixData.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";

// GET /attack/matrix (#1764): the bundled ATT&CK catalogue the dashboard's Matrix view draws on.
// It must always answer 200 — a missing data file is "catalogue not available", never an error the
// panel has to survive — and the browser may cache it for a day.

async function app(): Promise<ReturnType<typeof createApp>> {
  const root = await mkdtemp(join(tmpdir(), "dfir-attack-matrix-"));
  return createApp(new CaseStore(root));
}

afterEach(() => resetAttackMatrixCacheForTests());

describe("GET /attack/matrix", () => {
  it("serves the bundled catalogue with a one-day public cache header", async () => {
    resetAttackMatrixCacheForTests();
    const res = await request(await app()).get("/attack/matrix");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.headers["cache-control"]).toBe("public, max-age=86400");
    expect(res.body.attackVersion).toMatch(/^\d+\.\d+$/);
    expect(res.body.tactics.length).toBeGreaterThanOrEqual(14);
    expect(res.body.techniques.length).toBeGreaterThan(500);
    const t1059 = res.body.techniques.find((t: { id: string }) => t.id === "T1059.001");
    expect(t1059).toMatchObject({ name: "PowerShell", parent: "T1059" });
    expect(Array.isArray(t1059.tactics)).toBe(true);
    expect(Array.isArray(t1059.platforms)).toBe(true);
  });

  it("gzips the ~90 KB body for a client that accepts it", async () => {
    resetAttackMatrixCacheForTests();
    const res = await request(await app())
      .get("/attack/matrix")
      .set("Accept-Encoding", "gzip");
    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBe("gzip");
    expect(res.body.techniques.length).toBeGreaterThan(500);
  });

  it("still answers 200 with an empty catalogue when the data file is missing", async () => {
    resetAttackMatrixCacheForTests(EMPTY_ATTACK_MATRIX);
    const res = await request(await app()).get("/attack/matrix");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ...EMPTY_ATTACK_MATRIX });
    expect(res.body.techniques).toEqual([]);
  });

  // Public reference data. Unlisted, a top-level path falls to the global-admin default and the
  // matrix would be empty for every reader and investigator in team mode.
  it("is readable by any authenticated user, and only by GET", () => {
    expect(resolveRequestPolicy("GET", "/attack/matrix")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/attack/matrix")).toEqual({ kind: "global", permission: "admin" });
  });
});
