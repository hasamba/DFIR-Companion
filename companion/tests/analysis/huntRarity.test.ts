import { describe, it, expect } from "vitest";
import {
  DEFAULT_RARITY,
  isRare,
  rarityBlocked,
  raritySettingsFromEnv,
} from "../../src/analysis/huntRarity.js";
import type { HuntCoverage } from "../../src/analysis/huntFraming.js";

const cov = (answered: number, partialArtifacts = 0): HuntCoverage => ({
  known: true,
  answered,
  targeted: answered,
  notAnswered: 0,
  huntsWithCoverage: 1,
  huntsWithoutCoverage: 0,
  partialArtifacts,
  answeredHosts: [],
});

describe("host rarity (#2670, D2)", () => {
  it("grades nothing rare below the minimum number of answering hosts", () => {
    expect(isRare(1, 19, DEFAULT_RARITY)).toBe(false);
    expect(rarityBlocked(cov(19), DEFAULT_RARITY)).toMatch(/only 19 host\(s\) answered/);
    expect(isRare(1, 20, DEFAULT_RARITY)).toBe(true);
    expect(rarityBlocked(cov(20), DEFAULT_RARITY)).toBeNull();
  });

  it("applies at most 5% of the answering hosts, by integer maths", () => {
    expect(isRare(1, 20, DEFAULT_RARITY)).toBe(true); // 5% exactly
    expect(isRare(2, 20, DEFAULT_RARITY)).toBe(false); // 10%
    expect(isRare(5, 100, DEFAULT_RARITY)).toBe(true);
    expect(isRare(6, 100, DEFAULT_RARITY)).toBe(false);
  });

  it("and never more than 10 hosts", () => {
    expect(isRare(10, 300, DEFAULT_RARITY)).toBe(true);
    expect(isRare(11, 300, DEFAULT_RARITY)).toBe(false); // 3.7%, but over the host cap
  });

  it("never grades on unknown or partial coverage", () => {
    expect(rarityBlocked({ known: false, reason: "coverage unknown" }, DEFAULT_RARITY)).toBe(
      "coverage unknown",
    );
    expect(rarityBlocked(cov(300, 1), DEFAULT_RARITY)).toMatch(/partial/);
  });

  it("reads the three settings, and ignores junk", () => {
    expect(
      raritySettingsFromEnv({
        DFIR_HUNT_RARE_MIN_HOSTS: "50",
        DFIR_HUNT_RARE_MAX_PCT: "2",
        DFIR_HUNT_RARE_MAX_HOSTS: "3",
      }),
    ).toEqual({ minHosts: 50, maxPct: 2, maxHosts: 3 });
    expect(raritySettingsFromEnv({ DFIR_HUNT_RARE_MAX_PCT: "200", DFIR_HUNT_RARE_MIN_HOSTS: "x" })).toEqual(
      DEFAULT_RARITY,
    );
  });
});
