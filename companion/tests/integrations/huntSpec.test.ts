import { describe, it, expect } from "vitest";
import {
  buildHuntSpec,
  HuntSpecError,
  type HuntSpecCheck,
} from "../../src/integrations/velociraptor/huntSpec.js";

// #1606: every name the analyst typed into a bundle's params either reaches the hunt or stops it. A
// dropped override runs the artifact with its defaults — for RuleLevel that BROADENS a fleet-wide hunt.
const HAYA = "Windows.Hayabusa.Rules";
const noCheck = (): HuntSpecCheck => ({ unknownArtifacts: [], unavailableArtifacts: [], definitions: [] });

describe("buildHuntSpec — refuses what it used to drop (#1606)", () => {
  it("refuses a malformed parameter name, naming the key and the artifact", () => {
    const build = () => buildHuntSpec([HAYA], { [HAYA]: { "Rule Level": "Critical" } });
    expect(build).toThrow(HuntSpecError);
    expect(build).toThrow(/"Rule Level".*Windows\.Hayabusa\.Rules/);
  });

  it("refuses the whole spec even when the other names are fine", () => {
    expect(() =>
      buildHuntSpec([HAYA], { [HAYA]: { RuleStatus: "stable", "Rule-Level": "Critical" } }),
    ).toThrow(/"Rule-Level"/);
  });

  it("refuses a well-formed name the artifact does not declare on this server", () => {
    const check: HuntSpecCheck = {
      ...noCheck(),
      definitions: [{ name: HAYA, parameters: [{ name: "RuleLevel" }, { name: "RuleStatus" }] }],
    };
    const build = () => buildHuntSpec([HAYA], { [HAYA]: { RuleLevl: "Critical" } }, check);
    expect(build).toThrow(HuntSpecError);
    expect(build).toThrow(/RuleLevl.*RuleLevel, RuleStatus/);
  });

  // Velociraptor matches parameter names case-sensitively: `rulelevel` would not bind to RuleLevel.
  it("sends a case-only mismatch in the artifact's own spelling", () => {
    const check: HuntSpecCheck = {
      ...noCheck(),
      definitions: [{ name: HAYA, parameters: [{ name: "RuleLevel" }] }],
    };
    expect(buildHuntSpec([HAYA], { [HAYA]: { rulelevel: "All" } }, check)).toBe(
      `spec=dict(\`${HAYA}\`=dict(RuleLevel='All'))`,
    );
  });

  it("refuses two keys that name the same declared parameter", () => {
    const check: HuntSpecCheck = {
      ...noCheck(),
      definitions: [{ name: HAYA, parameters: [{ name: "RuleLevel" }] }],
    };
    expect(() => buildHuntSpec([HAYA], { [HAYA]: { RuleLevel: "All", rulelevel: "High" } }, check)).toThrow(
      /RuleLevel is set twice/,
    );
  });

  // Autoruns declares names like `Boot execute`. VQL takes them as backtick-quoted keys.
  it("sends a declared name with spaces backtick-quoted", () => {
    const AR = "Windows.Sysinternals.Autoruns";
    const check: HuntSpecCheck = {
      ...noCheck(),
      definitions: [{ name: AR, parameters: [{ name: "Boot execute" }, { name: "All" }] }],
    };
    expect(buildHuntSpec([AR], { [AR]: { "Boot execute": "Y" } }, check)).toBe(
      `spec=dict(\`${AR}\`=dict(\`Boot execute\`='Y'))`,
    );
  });

  it("with metadata, a malformed name that is not declared is still named as malformed", () => {
    const check: HuntSpecCheck = {
      ...noCheck(),
      definitions: [{ name: HAYA, parameters: [{ name: "RuleLevel" }] }],
    };
    expect(() => buildHuntSpec([HAYA], { [HAYA]: { "Rule Level": "All" } }, check)).toThrow(
      /invalid parameter name "Rule Level"/,
    );
  });

  it("does not check names when the server reports no parameters for the artifact", () => {
    const check: HuntSpecCheck = { ...noCheck(), definitions: [{ name: HAYA, parameters: [] }] };
    expect(buildHuntSpec([HAYA], { [HAYA]: { Anything: "x" } }, check)).toContain("Anything='x'");
  });

  it("refuses params keyed to an invalid artifact name, even outside the hunt", () => {
    expect(() => buildHuntSpec([HAYA], { "Windows Hayabusa": { RuleLevel: "All" } })).toThrow(
      /invalid artifact name "Windows Hayabusa"/,
    );
  });

  it("refuses params for an artifact that is not in the bundle (a typo'd artifact key)", () => {
    const build = () => buildHuntSpec([HAYA], { "Windows.Hayabusa.Rule": { RuleLevel: "All" } }, noCheck());
    expect(build).toThrow(HuntSpecError);
    expect(build).toThrow(/"Windows\.Hayabusa\.Rule".*not in this bundle/);
  });

  it("skips params for artifacts the pre-flight left out — the launch already reports them", () => {
    const check: HuntSpecCheck = {
      unknownArtifacts: ["Custom.Missing"],
      unavailableArtifacts: [{ artifact: "Generic.Scanner.ThorZIP" }],
      definitions: [],
    };
    const spec = buildHuntSpec(
      [HAYA],
      {
        [HAYA]: { RuleLevel: "All" },
        "Custom.Missing": { X: "y" },
        "Generic.Scanner.ThorZIP": { Y: "z" },
      },
      check,
    );
    expect(spec).toBe(`spec=dict(\`${HAYA}\`=dict(RuleLevel='All'))`);
  });

  it("without a pre-flight check, still skips params for artifacts outside the hunt", () => {
    expect(buildHuntSpec([HAYA], { "Not.In.Hunt": { X: "y" } })).toBeUndefined();
  });

  it("refuses a parameter map that is not an object of name: value", () => {
    expect(() =>
      buildHuntSpec([HAYA], { [HAYA]: ["RuleLevel"] as unknown as Record<string, string> }),
    ).toThrow(HuntSpecError);
    expect(() =>
      buildHuntSpec([HAYA], { [HAYA]: "RuleLevel=All" as unknown as Record<string, string> }),
    ).toThrow(/must be an object/);
    expect(() => buildHuntSpec([HAYA], [] as unknown as Record<string, Record<string, string>>)).toThrow(
      HuntSpecError,
    );
  });

  it("refuses a nested object value instead of sending [object Object]", () => {
    expect(() => buildHuntSpec([HAYA], { [HAYA]: { RuleLevel: { a: 1 } as unknown as string } })).toThrow(
      /RuleLevel.*text value/,
    );
  });

  it("the too-long refusal is a HuntSpecError too", () => {
    expect(() => buildHuntSpec([HAYA], { [HAYA]: { RuleExclusions: "a".repeat(70_000) } })).toThrow(
      HuntSpecError,
    );
  });

  it("caps a huge key in the message", () => {
    try {
      buildHuntSpec([HAYA], { [HAYA]: { ["x y".repeat(5000)]: "v" } });
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message.length).toBeLessThan(500);
    }
  });

  it("still builds the spec for well-formed params", () => {
    expect(buildHuntSpec([HAYA], { [HAYA]: { RuleLevel: "Critical, High, and Medium" } })).toBe(
      `spec=dict(\`${HAYA}\`=dict(RuleLevel='Critical, High, and Medium'))`,
    );
    expect(buildHuntSpec([HAYA], undefined)).toBeUndefined();
    expect(buildHuntSpec([HAYA], { [HAYA]: {} })).toBeUndefined();
  });
});
