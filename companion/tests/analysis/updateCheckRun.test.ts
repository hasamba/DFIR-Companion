import { describe, it, expect } from "vitest";
import { performUpdateCheck } from "../../src/analysis/updateCheckRun.js";
import type { UpdateCheckStore } from "../../src/analysis/updateCheckStore.js";
import type { UpdateResult } from "../../src/analysis/updateCheck.js";
import type { UpdateCheckRecord } from "../../src/analysis/updateCheckStore.js";

function fakeStore(initial: UpdateCheckRecord = {}, opts: { failSet?: boolean } = {}) {
  let rec = initial;
  return {
    async load() { return rec; },
    async setEnabled(enabled: boolean) { rec = { ...rec, enabled }; },
    async setResult(result: UpdateResult) { if (opts.failSet) throw new Error("disk full"); rec = { ...rec, result }; },
  } as unknown as UpdateCheckStore;
}

const okFetch = (tag: string) =>
  (async () => ({
    ok: true,
    status: 200,
    json: async () => ({ tag_name: tag, html_url: "https://gh/rel" }),
  })) as unknown as typeof fetch;

const badFetch = () =>
  (async () => { throw new Error("offline"); }) as unknown as typeof fetch;

describe("performUpdateCheck", () => {
  it("returns the parsed latest on success", async () => {
    const r = await performUpdateCheck({ store: fakeStore(), repo: "a/b", fetchFn: okFetch("v2.0.0"), now: 5 });
    expect(r.latestVersion).toBe("2.0.0");
    expect(r.checkedAt).toBe(5);
    expect(r.error).toBeUndefined();
  });

  it("preserves the last-good version and stamps an error on fetch failure", async () => {
    const prev: UpdateResult = { latestVersion: "1.0.0", latestTag: "v1.0.0", htmlUrl: "https://x", checkedAt: 1 };
    const r = await performUpdateCheck({ store: fakeStore({ result: prev }), repo: "a/b", fetchFn: badFetch(), now: 9 });
    expect(r.latestVersion).toBe("1.0.0");
    expect(r.error).toMatch(/offline/);
  });

  it("never throws even when the store fails to persist", async () => {
    await expect(
      performUpdateCheck({ store: fakeStore({}, { failSet: true }), repo: "a/b", fetchFn: okFetch("v2.0.0"), now: 1 })
    ).resolves.toBeDefined();
  });
});
