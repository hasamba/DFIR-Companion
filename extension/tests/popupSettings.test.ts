import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS } from "../src/types.js";
import {
  caseListFailure,
  settingsFromForm,
  type PopupForm,
} from "../src/popupSettings.js";

function form(overrides: Partial<PopupForm> = {}): PopupForm {
  return {
    caseId: "CASE-1",
    companionUrl: "http://127.0.0.1:4773",
    serviceToken: "tok-abc",
    intervalSeconds: "10",
    dedupThreshold: "5",
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

  it("clamps the interval to the 5-second floor", () => {
    expect(
      settingsFromForm(form({ intervalSeconds: "1" }), false).intervalSeconds,
    ).toBe(5);
  });

  it("falls back to the default interval when the field is not a number", () => {
    expect(
      settingsFromForm(form({ intervalSeconds: "abc" }), false).intervalSeconds,
    ).toBe(10);
  });

  it("clamps a negative dedup threshold to zero", () => {
    expect(
      settingsFromForm(form({ dedupThreshold: "-3" }), false).dedupThreshold,
    ).toBe(0);
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
