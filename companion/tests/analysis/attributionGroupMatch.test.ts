import { describe, it, expect } from "vitest";
import { matchAdversaryGroupId } from "../../src/analysis/attributionGroupMatch.js";
import type { AdversaryGroup } from "../../src/analysis/adversaryTechniques.js";

function group(over: Partial<AdversaryGroup> = {}): AdversaryGroup {
  return {
    id: "G0016",
    name: "APT29",
    aliases: ["Cozy Bear", "The Dukes"],
    description: "",
    techniques: [],
    ...over,
  };
}

describe("matchAdversaryGroupId", () => {
  it("matches case-insensitively on the group's own name", () => {
    expect(matchAdversaryGroupId("apt29", [group()])).toBe("G0016");
  });

  it("matches case-insensitively on an alias", () => {
    expect(matchAdversaryGroupId("cozy bear", [group()])).toBe("G0016");
  });

  it("returns null when nothing matches", () => {
    expect(matchAdversaryGroupId("UNC1234", [group()])).toBeNull();
  });

  it("returns null for an empty label", () => {
    expect(matchAdversaryGroupId("", [group()])).toBeNull();
  });

  it("never uses a substring match — a label that merely contains a group name does not match", () => {
    expect(matchAdversaryGroupId("APT29-adjacent cluster", [group()])).toBeNull();
  });
});
