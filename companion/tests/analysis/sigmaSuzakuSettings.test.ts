import { describe, expect, it } from "vitest";
import {
  DEFAULT_SUZAKU_STATUSES,
  sigmaSuzakuEnabled,
  sigmaSuzakuStatusesFromEnv,
} from "../../src/analysis/sigmaSettings.js";

// #2499: the Suzaku rules have their own switch and status filter, separate from the SigmaHQ one.

describe("DFIR_SIGMA_SUZAKU_RULES", () => {
  it("is on unless it says off", () => {
    expect(sigmaSuzakuEnabled({})).toBe(true);
    expect(sigmaSuzakuEnabled({ DFIR_SIGMA_SUZAKU_RULES: "on" })).toBe(true);
    for (const v of ["off", "0", "false", "no", " OFF "])
      expect(sigmaSuzakuEnabled({ DFIR_SIGMA_SUZAKU_RULES: v })).toBe(false);
  });
});

describe("DFIR_SIGMA_SUZAKU_STATUSES", () => {
  it("defaults to stable, test and experimental", () => {
    expect(DEFAULT_SUZAKU_STATUSES).toEqual(["stable", "test", "experimental"]);
    expect(sigmaSuzakuStatusesFromEnv({})).toEqual({
      statuses: ["stable", "test", "experimental"],
      ignored: [],
      defaulted: true,
    });
  });

  it("reads its own variable, not the SigmaHQ one", () => {
    const env = { DFIR_SIGMA_RULE_STATUSES: "experimental", DFIR_SIGMA_SUZAKU_STATUSES: "stable,test" };
    expect(sigmaSuzakuStatusesFromEnv(env).statuses).toEqual(["stable", "test"]);
  });

  it("names what it ignored", () => {
    const r = sigmaSuzakuStatusesFromEnv({ DFIR_SIGMA_SUZAKU_STATUSES: "test,deprecated,typo" });
    expect(r).toEqual({ statuses: ["test"], ignored: ["deprecated", "typo"], defaulted: false });
  });
});
