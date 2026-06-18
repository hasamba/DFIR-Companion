import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  CorrelationProfileStore,
  DEFAULT_PROFILE,
  PROFILE_WINDOWS,
} from "../../src/analysis/correlationProfile.js";

describe("CorrelationProfileStore", () => {
  let root: string;
  let cases: CaseStore;
  let store: CorrelationProfileStore;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-corrprofile-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new CorrelationProfileStore(cases);
  });

  it("returns the default profile when none exists", async () => {
    expect(await store.load("c1")).toEqual(DEFAULT_PROFILE);
  });

  it("round-trips a named profile", async () => {
    await store.save("c1", { profileName: "strict", windowSeconds: PROFILE_WINDOWS.strict });
    const p = await store.load("c1");
    expect(p.profileName).toBe("strict");
    expect(p.windowSeconds).toBe(0);
  });

  it("round-trips a custom profile", async () => {
    await store.save("c1", { profileName: "custom", windowSeconds: 120 });
    const p = await store.load("c1");
    expect(p.profileName).toBe("custom");
    expect(p.windowSeconds).toBe(120);
  });

  it("falls back to default for an invalid profileName on disk", async () => {
    const profilePath = join(cases.stateDir("c1"), "correlation-profile.json");
    await writeFile(profilePath, JSON.stringify({ profileName: "invalid", windowSeconds: -1 }));
    const p = await store.load("c1");
    expect(p.profileName).toBe(DEFAULT_PROFILE.profileName);
    expect(p.windowSeconds).toBe(DEFAULT_PROFILE.windowSeconds);
  });

  it("PROFILE_WINDOWS has the expected preset values", () => {
    expect(PROFILE_WINDOWS.strict).toBe(0);
    expect(PROFILE_WINDOWS.moderate).toBe(2);
    expect(PROFILE_WINDOWS.aggressive).toBe(300);
  });
});
