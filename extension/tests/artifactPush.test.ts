// #2258 — feedback, provenance and retry for one-click artifact pushes.
import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  artifactPushErrorText,
  artifactPushSuccessText,
  importSourceUrl,
  isAmbiguousPushStatus,
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
  it("retries only a 429 — refused before the companion persisted anything", () => {
    expect(isRetryablePushStatus(429)).toBe(true);
    for (const s of [0, 202, 400, 401, 404, 409, 423, 500, 502, 503]) expect(isRetryablePushStatus(s)).toBe(false);
  });
});

describe("isAmbiguousPushStatus", () => {
  it("flags a lost response and server errors as possibly already saved", () => {
    for (const s of [0, 500, 502, 503]) expect(isAmbiguousPushStatus(s)).toBe(true);
    for (const s of [202, 400, 404, 423, 429]) expect(isAmbiguousPushStatus(s)).toBe(false);
  });
});

describe("artifactPushErrorText", () => {
  it("tells the analyst to check the case before re-pushing on 0 / 5xx", () => {
    for (const s of [0, 500, 503]) {
      expect(artifactPushErrorText(s, "Import rejected")).toMatch(
        /may already be saved — check the case before pushing again/,
      );
    }
  });

  it("leaves a considered rejection's message alone", () => {
    for (const s of [400, 404, 429]) expect(artifactPushErrorText(s, "nope")).toBe("nope");
  });
});

describe("postWithOneRetry", () => {
  it("retries exactly once, after the delay, on a 429", async () => {
    const send = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 429 })
      .mockResolvedValueOnce({ ok: true, status: 202 });
    const sleep = vi.fn(async () => undefined);
    expect(await postWithOneRetry(send, sleep)).toEqual({ ok: true, status: 202 });
    expect(send).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(PUSH_RETRY_DELAY_MS);
  });

  it("gives up after the single retry", async () => {
    const send = vi.fn().mockResolvedValue({ ok: false, status: 429 });
    const sleep = vi.fn(async () => undefined);
    expect(await postWithOneRetry(send, sleep)).toEqual({ ok: false, status: 429 });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("never repeats a push that may already be saved (0 / 5xx)", async () => {
    for (const first of [{ ok: false, status: 0 }, { ok: false, status: 500 }, { ok: false, status: 503 }]) {
      const send = vi.fn().mockResolvedValue(first);
      const sleep = vi.fn(async () => undefined);
      expect(await postWithOneRetry(send, sleep)).toEqual(first);
      expect(send).toHaveBeenCalledTimes(1);
      expect(sleep).not.toHaveBeenCalled();
    }
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

// serviceWorker.ts registers listeners at import time, so its wiring is asserted against source.
describe("service-worker artifact push wiring", () => {
  const sw = readFileSync(resolve(__dirname, "../src/serviceWorker.ts"), "utf-8");
  const body = /async function pushArtifact\([\s\S]*?\n\}/.exec(sw)?.[0] ?? "";

  it("sends through the 429-only retry and warns on an ambiguous failure", () => {
    expect(body).toContain("postWithOneRetry(");
    expect(body).toMatch(/artifactPushErrorText\(\s*result\.status,/);
  });
});
