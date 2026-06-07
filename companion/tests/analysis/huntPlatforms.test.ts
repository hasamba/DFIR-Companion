import { describe, it, expect } from "vitest";
import { resolveHuntPlatforms, HUNT_PLATFORMS } from "../../src/analysis/huntPlatforms.js";

describe("resolveHuntPlatforms — DFIR_HUNT_PLATFORMS allowlist", () => {
  it("defaults to ALL platforms when unset / empty / whitespace", () => {
    expect(resolveHuntPlatforms(undefined)).toEqual([...HUNT_PLATFORMS]);
    expect(resolveHuntPlatforms(null)).toEqual([...HUNT_PLATFORMS]);
    expect(resolveHuntPlatforms("")).toEqual([...HUNT_PLATFORMS]);
    expect(resolveHuntPlatforms("   ")).toEqual([...HUNT_PLATFORMS]);
  });

  it("returns only the named platform (the 'leave only Velociraptor' case)", () => {
    expect(resolveHuntPlatforms("velociraptor")).toEqual(["velociraptor"]);
  });

  it("returns the named subset in canonical display order, not input order", () => {
    expect(resolveHuntPlatforms("suricata,velociraptor")).toEqual(["velociraptor", "suricata"]);
  });

  it("splits on comma, space, and semicolon and is case-insensitive", () => {
    expect(resolveHuntPlatforms("velociraptor, SIGMA ; Yara")).toEqual(["velociraptor", "sigma", "yara"]);
  });

  it("maps friendly aliases to canonical keys", () => {
    expect(resolveHuntPlatforms("vql")).toEqual(["velociraptor"]);
    expect(resolveHuntPlatforms("kql")).toEqual(["defender"]);
    expect(resolveHuntPlatforms("esql,kibana,elk")).toEqual(["elastic"]); // all alias to one
    expect(resolveHuntPlatforms("spl")).toEqual(["splunk"]);
    expect(resolveHuntPlatforms("snort")).toEqual(["suricata"]);
  });

  it("ignores unknown tokens but keeps the recognized ones", () => {
    expect(resolveHuntPlatforms("velociraptor, nessus, splunk")).toEqual(["velociraptor", "splunk"]);
  });

  it("falls back to ALL when every token is unrecognized (typo never empties the modal)", () => {
    expect(resolveHuntPlatforms("nope,garbage")).toEqual([...HUNT_PLATFORMS]);
  });

  it("dedupes repeated / aliased duplicates", () => {
    expect(resolveHuntPlatforms("yara yara YARA")).toEqual(["yara"]);
    expect(resolveHuntPlatforms("defender,kql,sentinel")).toEqual(["defender"]);
  });
});
