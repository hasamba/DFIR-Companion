// #2258 — feedback, provenance and retry for one-click artifact pushes.
import { describe, expect, it, vi } from "vitest";
import {
  artifactPushSuccessText,
  importSourceUrl,
  isRetryablePushStatus,
  postWithOneRetry,
  PUSH_RETRY_DELAY_MS,
} from "../src/artifactPush.js";

describe("artifactPushSuccessText", () => {
  it("says the push was saved but NOT analyzed when the case's AI is off", () => {
    const text = artifactPushSuccessText({ ok: true, caseId: "c1", rows: 3, analyzed: false, reason: "ai-off" });
    expect(text).toMatch(/saved as evidence/i);
    expect(text).toMatch(/not analyzed/i);
    expect(text).toMatch(/AI is off/);
    expect(text).not.toMatch(/Pushed/);
  });

  it("keeps the normal Pushed wording otherwise", () => {
    expect(artifactPushSuccessText({ ok: true, caseId: "c1", rows: 3 })).toBe('Pushed 3 rows to "c1"');
    expect(artifactPushSuccessText({ ok: true, caseId: "c1" })).toBe('Pushed to "c1"');
  });
});

describe("importSourceUrl", () => {
  it("passes an http(s) page URL through", () => {
    expect(importSourceUrl("https://velo.example/app/index.html#/hunts")).toBe("https://velo.example/app/index.html#/hunts");
  });

  it("drops anything the companion would refuse", () => {
    expect(importSourceUrl("")).toBeUndefined();
    expect(importSourceUrl(undefined)).toBeUndefined();
    expect(importSourceUrl("file:///C:/report.html")).toBeUndefined();
    expect(importSourceUrl("chrome-extension://abc/popup.html")).toBeUndefined();
    expect(importSourceUrl("not a url")).toBeUndefined();
    expect(importSourceUrl(`https://e.example/${"a".repeat(2048)}`)).toBeUndefined();
  });
});

describe("isRetryablePushStatus", () => {
  it("retries unreachable, rate-limited and server errors only", () => {
    for (const s of [0, 429, 500, 502, 503]) expect(isRetryablePushStatus(s)).toBe(true);
    for (const s of [202, 400, 401, 404, 409, 423]) expect(isRetryablePushStatus(s)).toBe(false);
  });
});

describe("postWithOneRetry", () => {
  it("retries exactly once, after the delay, on a 503", async () => {
    const send = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 503 })
      .mockResolvedValueOnce({ ok: true, status: 202 });
    const sleep = vi.fn(async () => undefined);
    expect(await postWithOneRetry(send, sleep)).toEqual({ ok: true, status: 202 });
    expect(send).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(PUSH_RETRY_DELAY_MS);
  });

  it("gives up after the single retry", async () => {
    const send = vi.fn().mockResolvedValue({ ok: false, status: 0 });
    const sleep = vi.fn(async () => undefined);
    expect(await postWithOneRetry(send, sleep)).toEqual({ ok: false, status: 0 });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("does not retry a success or a considered rejection", async () => {
    for (const first of [{ ok: true, status: 202 }, { ok: false, status: 404 }]) {
      const send = vi.fn().mockResolvedValue(first);
      const sleep = vi.fn(async () => undefined);
      expect(await postWithOneRetry(send, sleep)).toEqual(first);
      expect(send).toHaveBeenCalledTimes(1);
      expect(sleep).not.toHaveBeenCalled();
    }
  });
});
