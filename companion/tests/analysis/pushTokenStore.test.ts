import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PushTokenStore, generatePushToken } from "../../src/analysis/pushTokenStore.js";

describe("PushTokenStore", () => {
  let store: PushTokenStore;
  let cases: CaseStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-pushtok-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new PushTokenStore(cases);
  });

  it("returns null when no token has been generated", async () => {
    expect(await store.get("c1")).toBeNull();
  });

  it("sets and reads a token round-trip", async () => {
    const rec = await store.set("c1", "tok-abc", "2026-06-13T00:00:00.000Z");
    expect(rec.token).toBe("tok-abc");
    const read = await store.get("c1");
    expect(read?.token).toBe("tok-abc");
    expect(read?.createdAt).toBe("2026-06-13T00:00:00.000Z");
  });

  it("rotates the token in place", async () => {
    await store.set("c1", "old", "2026-06-13T00:00:00.000Z");
    await store.set("c1", "new", "2026-06-13T01:00:00.000Z");
    expect((await store.get("c1"))?.token).toBe("new");
  });

  it("clear() removes the token (get → null)", async () => {
    await store.set("c1", "tok", "2026-06-13T00:00:00.000Z");
    await store.clear("c1");
    expect(await store.get("c1")).toBeNull();
  });

  it("generatePushToken returns a 32-hex-char secret, unique per call", () => {
    const a = generatePushToken();
    const b = generatePushToken();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});
