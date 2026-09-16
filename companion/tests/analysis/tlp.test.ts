import { describe, it, expect } from "vitest";
import {
  normalizeLegacyTlp,
  mostRestrictive,
  hasUnmarkedOrUnrecognized,
  requiresAnalystConfirmation,
  blocksSharing,
  combineMarkings,
} from "../../src/analysis/tlp.js";
import type { TlpMarking } from "../../src/analysis/stateTypes.js";

function real(label: "RED" | "AMBER_STRICT" | "AMBER" | "GREEN" | "CLEAR"): TlpMarking {
  return { label };
}

describe("normalizeLegacyTlp", () => {
  it("maps TheHive's real legacy numeric scheme correctly, including the WHITE->CLEAR rename", () => {
    expect(normalizeLegacyTlp(0)).toEqual({ label: "CLEAR" });
    expect(normalizeLegacyTlp(1)).toEqual({ label: "GREEN" });
    expect(normalizeLegacyTlp(2)).toEqual({ label: "AMBER" });
    expect(normalizeLegacyTlp(3)).toEqual({ label: "RED" });
  });

  it("maps legacy and current TLP string forms", () => {
    expect(normalizeLegacyTlp("TLP:WHITE")).toEqual({ label: "CLEAR" });
    expect(normalizeLegacyTlp("TLP:GREEN")).toEqual({ label: "GREEN" });
    expect(normalizeLegacyTlp("TLP:AMBER")).toEqual({ label: "AMBER" });
    expect(normalizeLegacyTlp("TLP:RED")).toEqual({ label: "RED" });
    expect(normalizeLegacyTlp("TLP:CLEAR")).toEqual({ label: "CLEAR" });
    expect(normalizeLegacyTlp("TLP:AMBER+STRICT")).toEqual({ label: "AMBER_STRICT" });
  });

  it("is case-insensitive and tolerates surrounding whitespace", () => {
    expect(normalizeLegacyTlp(" tlp:red ")).toEqual({ label: "RED" });
  });

  it("returns undefined when no marking value was given at all", () => {
    expect(normalizeLegacyTlp(undefined)).toBeUndefined();
    expect(normalizeLegacyTlp(null)).toBeUndefined();
  });

  it("returns an unrecognized marking, preserving the raw value, for anything else", () => {
    expect(normalizeLegacyTlp(99)).toEqual({ label: "unrecognized", raw: 99 });
    expect(normalizeLegacyTlp("bogus")).toEqual({ label: "unrecognized", raw: "bogus" });
  });

  it("never confuses an unrecognized marking with a missing one", () => {
    expect(normalizeLegacyTlp("bogus")).not.toBeUndefined();
  });

  it("treats a value of the wrong JS type (untrusted import data) as unrecognized, never a throw", () => {
    expect(normalizeLegacyTlp({ nested: true })).toEqual({ label: "unrecognized", raw: "[object Object]" });
    expect(normalizeLegacyTlp(true)).toEqual({ label: "unrecognized", raw: "true" });
  });

  it("returns undefined for an empty or whitespace-only string", () => {
    expect(normalizeLegacyTlp("")).toBeUndefined();
    expect(normalizeLegacyTlp("   ")).toBeUndefined();
  });
});

describe("mostRestrictive", () => {
  it("orders labels RED > AMBER_STRICT > AMBER > GREEN > CLEAR", () => {
    expect(mostRestrictive([real("GREEN"), real("RED"), real("AMBER")])).toBe("RED");
    expect(mostRestrictive([real("CLEAR"), real("AMBER_STRICT")])).toBe("AMBER_STRICT");
    expect(mostRestrictive([real("GREEN"), real("AMBER")])).toBe("AMBER");
    expect(mostRestrictive([real("CLEAR"), real("GREEN")])).toBe("GREEN");
  });

  it("returns undefined for empty input", () => {
    expect(mostRestrictive([])).toBeUndefined();
  });

  it("ignores unmarked and unrecognized entries — only real labels rank", () => {
    expect(mostRestrictive([undefined, real("GREEN"), { label: "unrecognized", raw: "x" }])).toBe("GREEN");
  });

  it("returns undefined when nothing rankable is present at all", () => {
    expect(mostRestrictive([undefined, { label: "unrecognized", raw: "x" }])).toBeUndefined();
  });
});

describe("hasUnmarkedOrUnrecognized", () => {
  it("is true when any entry is undefined", () => {
    expect(hasUnmarkedOrUnrecognized([real("GREEN"), undefined])).toBe(true);
  });

  it("is true when any entry is unrecognized", () => {
    expect(hasUnmarkedOrUnrecognized([real("GREEN"), { label: "unrecognized", raw: "x" }])).toBe(true);
  });

  it("is false when every entry is a real label", () => {
    expect(hasUnmarkedOrUnrecognized([real("GREEN"), real("RED")])).toBe(false);
  });

  it("is false for empty input — nothing to be unmarked", () => {
    expect(hasUnmarkedOrUnrecognized([])).toBe(false);
  });
});

describe("requiresAnalystConfirmation", () => {
  it("is true for RED, AMBER_STRICT and AMBER", () => {
    expect(requiresAnalystConfirmation(real("RED"))).toBe(true);
    expect(requiresAnalystConfirmation(real("AMBER_STRICT"))).toBe(true);
    expect(requiresAnalystConfirmation(real("AMBER"))).toBe(true);
  });

  it("is false for GREEN and CLEAR", () => {
    expect(requiresAnalystConfirmation(real("GREEN"))).toBe(false);
    expect(requiresAnalystConfirmation(real("CLEAR"))).toBe(false);
  });

  it("is true for an unrecognized marking", () => {
    expect(requiresAnalystConfirmation({ label: "unrecognized", raw: "x" })).toBe(true);
  });

  it("is unconditionally true for undefined (missing) — never a case-native exception", () => {
    expect(requiresAnalystConfirmation(undefined)).toBe(true);
  });
});

describe("blocksSharing", () => {
  it("is true only for a real RED label", () => {
    expect(blocksSharing(real("RED"))).toBe(true);
  });

  it("is false for AMBER_STRICT, AMBER, GREEN and CLEAR", () => {
    expect(blocksSharing(real("AMBER_STRICT"))).toBe(false);
    expect(blocksSharing(real("AMBER"))).toBe(false);
    expect(blocksSharing(real("GREEN"))).toBe(false);
    expect(blocksSharing(real("CLEAR"))).toBe(false);
  });

  it("is false for an unrecognized marking — it requires confirmation, not a block", () => {
    expect(blocksSharing({ label: "unrecognized", raw: "x" })).toBe(false);
  });

  it("is false for undefined (missing) — missing requires confirmation, not a block", () => {
    expect(blocksSharing(undefined)).toBe(false);
  });
});

describe("combineMarkings", () => {
  it("a real marking always survives a merge with an unmarked one — never last-write-wins", () => {
    expect(combineMarkings(real("RED"), undefined)).toEqual({ label: "RED" });
    expect(combineMarkings(undefined, real("RED"))).toEqual({ label: "RED" });
  });

  it("the tighter of two real markings wins", () => {
    expect(combineMarkings(real("GREEN"), real("RED"))).toEqual({ label: "RED" });
  });

  it("a real marking survives a merge with an unrecognized one", () => {
    expect(combineMarkings(real("GREEN"), { label: "unrecognized", raw: "x" })).toEqual({ label: "GREEN" });
  });

  it("preserves an unrecognized marking when the other side has no marking at all", () => {
    expect(combineMarkings({ label: "unrecognized", raw: "x" }, undefined)).toEqual({
      label: "unrecognized",
      raw: "x",
    });
  });

  it("returns undefined only when neither side ever had a marking", () => {
    expect(combineMarkings(undefined, undefined)).toBeUndefined();
  });
});
