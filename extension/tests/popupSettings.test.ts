import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS, MIN_INTERVAL_SECONDS } from "../src/types.js";
import {
  caseListFailure,
  clampIntervalSeconds,
  settingsFromForm,
  type PopupForm,
} from "../src/popupSettings.js";

function form(overrides: Partial<PopupForm> = {}): PopupForm {
  return {
    caseId: "CASE-1",
    companionUrl: "http://127.0.0.1:4773",
    serviceToken: "tok-abc",
    intervalSeconds: "60",
    ...overrides,
  };
}

describe("settingsFromForm", () => {
  // The bug this guards: the popup persisted the STORED token rather than the typed one, so a
  // token entered in the popup vanished on the next read and every import went out unauthenticated.
  it("keeps the token the analyst typed", () => {
    expect(
      settingsFromForm(form({ serviceToken: "fresh-token" }), false)
        .serviceToken,
    ).toBe("fresh-token");
  });

  it("trims a pasted token", () => {
    expect(
      settingsFromForm(form({ serviceToken: "  tok-abc\n" }), false)
        .serviceToken,
    ).toBe("tok-abc");
  });

  it("keeps a deliberately cleared token cleared", () => {
    expect(
      settingsFromForm(form({ serviceToken: "   " }), false).serviceToken,
    ).toBe("");
  });

  it("carries the running flag the caller owns", () => {
    expect(settingsFromForm(form(), true).running).toBe(true);
    expect(settingsFromForm(form(), false).running).toBe(false);
  });

  it("normalizes the companion URL", () => {
    expect(
      settingsFromForm(
        form({ companionUrl: " http://127.0.0.1:4773/// " }),
        false,
      ).companionUrl,
    ).toBe("http://127.0.0.1:4773");
  });

  it("falls back to the default URL when the field is empty", () => {
    expect(
      settingsFromForm(form({ companionUrl: "" }), false).companionUrl,
    ).toBe(DEFAULT_SETTINGS.companionUrl);
  });

  it("trims the case id", () => {
    expect(settingsFromForm(form({ caseId: " CASE-1 " }), false).caseId).toBe(
      "CASE-1",
    );
  });

  // Chrome alarms in packed extensions fire at most every 30 s (#2257): a shorter interval was
  // accepted, then silently not honoured.
  it("clamps the interval to the 30-second browser floor", () => {
    expect(MIN_INTERVAL_SECONDS).toBe(30);
    expect(
      settingsFromForm(form({ intervalSeconds: "5" }), false).intervalSeconds,
    ).toBe(30);
  });

  it("keeps an interval above the floor", () => {
    expect(
      settingsFromForm(form({ intervalSeconds: "45" }), false).intervalSeconds,
    ).toBe(45);
  });

  it("defaults the interval to 30 seconds", () => {
    expect(DEFAULT_SETTINGS.intervalSeconds).toBe(30);
  });

  it("falls back to the default interval when the field is not a number", () => {
    expect(
      settingsFromForm(form({ intervalSeconds: "abc" }), false).intervalSeconds,
    ).toBe(30);
  });

  it("no longer stores a dedup threshold (dedup is companion-side, #2257)", () => {
    expect(settingsFromForm(form(), false)).not.toHaveProperty("dedupThreshold");
    expect(DEFAULT_SETTINGS).not.toHaveProperty("dedupThreshold");
  });
});

describe("clampIntervalSeconds", () => {
  it("raises an old stored value under 30 s to the floor", () => {
    expect(clampIntervalSeconds(10)).toBe(30);
    expect(clampIntervalSeconds(5)).toBe(30);
  });

  it("keeps a valid value", () => {
    expect(clampIntervalSeconds(120)).toBe(120);
  });

  it("falls back to the default for missing or invalid values", () => {
    expect(clampIntervalSeconds(undefined)).toBe(30);
    expect(clampIntervalSeconds("abc")).toBe(30);
    expect(clampIntervalSeconds(0)).toBe(30);
    expect(clampIntervalSeconds(Number.NaN)).toBe(30);
  });

  it("accepts a numeric string from the form", () => {
    expect(clampIntervalSeconds("90")).toBe(90);
  });
});

describe("caseListFailure", () => {
  // A 401 is the companion answering, not the companion being down. Reporting it as "offline"
  // sent analysts to restart a server that was already running.
  it("names the token on 401 rather than blaming the connection", () => {
    const message = caseListFailure(401);
    expect(message).toMatch(/token/i);
    expect(message).not.toMatch(/offline/i);
  });

  it("names the token's permissions on 403", () => {
    const message = caseListFailure(403);
    expect(message).toMatch(/token/i);
    expect(message).not.toMatch(/offline/i);
  });

  it("reports offline when the fetch itself failed", () => {
    expect(caseListFailure(0)).toMatch(/offline/i);
  });

  it("reports the status for any other rejection", () => {
    expect(caseListFailure(500)).toContain("500");
  });
});
