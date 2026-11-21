import { describe, it, expect } from "vitest";
import {
  artifactFamilies,
  DEFAULT_RARITY,
  isRare,
  itemArtifactPartial,
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
  partialArtifactNames: [],
  collectedArtifactNames: [],
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

  it("never grades on unknown coverage; a partial artifact no longer blocks the whole case (#2732)", () => {
    expect(rarityBlocked({ known: false, reason: "coverage unknown" }, DEFAULT_RARITY)).toBe(
      "coverage unknown",
    );
    expect(rarityBlocked(cov(300, 1), DEFAULT_RARITY)).toBeNull();
  });

  it("blocks an item reported by a partial artifact, matched on the artifact's base name (#2732)", () => {
    const c = {
      partialArtifactNames: ["Windows.System.TaskScheduler"],
      collectedArtifactNames: [
        "Windows.System.TaskScheduler",
        "Windows.Sys.StartupItems",
        "Windows.Forensics.Prefetch",
      ],
    };
    expect(itemArtifactPartial({ family: "program", artifacts: ["Windows.Forensics.Prefetch"] }, c)).toBe(
      false,
    );
    expect(
      itemArtifactPartial({ family: "autorun", artifacts: ["windows.system.taskscheduler/Analysis"] }, c),
    ).toBe(true);
    expect(
      itemArtifactPartial(
        { family: "program", artifacts: ["Windows.Forensics.Prefetch"], artifactsIncomplete: true },
        c,
      ),
    ).toBe(true);
    expect(itemArtifactPartial({ family: "program" }, c), "artifacts unknown").toBe(true);
    expect(itemArtifactPartial({ family: "program", artifacts: [] }, c), "no artifact recorded").toBe(true);
  });

  it("blocks an item of a kind the partial artifact reports, even one only a complete artifact reported (#2732)", () => {
    const amcacheCut = {
      partialArtifactNames: ["Windows.Forensics.Amcache"],
      collectedArtifactNames: [
        "Windows.Forensics.Amcache",
        "Windows.Forensics.Prefetch",
        "Windows.Sys.StartupItems",
      ],
    };
    // Prefetch and Amcache share one program item: Amcache's lost rows may hold more hosts for it.
    expect(
      itemArtifactPartial({ family: "program", artifacts: ["Windows.Forensics.Prefetch"] }, amcacheCut),
    ).toBe(true);
    expect(
      itemArtifactPartial({ family: "installed", artifacts: ["Windows.Forensics.Prefetch"] }, amcacheCut),
    ).toBe(true);
    expect(
      itemArtifactPartial({ family: "autorun", artifacts: ["Windows.Sys.StartupItems"] }, amcacheCut),
      "an unrelated kind keeps its grading",
    ).toBe(false);
    const unknownCut = {
      partialArtifactNames: ["Custom.Org.Collector"],
      collectedArtifactNames: ["Custom.Org.Collector", "Windows.Sys.StartupItems"],
    };
    expect(
      itemArtifactPartial({ family: "autorun", artifacts: ["Windows.Sys.StartupItems"] }, unknownCut),
      "an unrecognised partial artifact could report any kind",
    ).toBe(true);
  });

  it("maps hunt artifacts to the kinds of item they report", () => {
    expect(artifactFamilies("Windows.Forensics.Prefetch")).toEqual(["program"]);
    expect(artifactFamilies("Windows.Registry.UserAssist")).toEqual(["program"]);
    expect(artifactFamilies("Windows.Registry.AppCompatCache")).toEqual(["program"]);
    expect(artifactFamilies("Windows.Forensics.Amcache/InventoryApplication")).toEqual([
      "program",
      "installed",
    ]);
    expect(artifactFamilies("Windows.System.TaskScheduler")).toEqual(["autorun"]);
    expect(artifactFamilies("Windows.Analysis.EvidenceOfDownload")).toEqual(["download"]);
    expect(artifactFamilies("Custom.Org.Collector")).toEqual(["program", "installed", "autorun", "download"]);
  });

  it("fails closed on an artifact name the hunts did not collect (a row's own Source column)", () => {
    const c = {
      partialArtifactNames: ["Windows.System.TaskScheduler"],
      collectedArtifactNames: ["Windows.System.TaskScheduler"],
    };
    expect(itemArtifactPartial({ family: "program", artifacts: ["Microsoft-Windows-Something"] }, c)).toBe(
      true,
    );
    expect(
      itemArtifactPartial({ family: "program" }, { partialArtifactNames: [], collectedArtifactNames: [] }),
      "nothing partial: grade as before",
    ).toBe(false);
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
