import { describe, it, expect } from "vitest";
import { iocProvenanceSuffix } from "../../src/analysis/iocProvenanceLabel.js";
import { MENTIONED_NOTE } from "../../src/analysis/iocMentioned.js";
import { MENTIONED_HASH_NOTE } from "../../src/analysis/iocMentionedHash.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

// #1471 finding 6. Three provenance suffixes exist — client-reported (#1266), mentioned network
// (#1461) and mentioned hash (#1459) — and every export that re-derived them by hand carried only
// the first. One type-aware helper composes all three from the existing constants so a consumer
// cannot pick up one and miss the other two.

function ioc(over: Partial<IOC>): Pick<IOC, "type" | "provenance"> {
  return { type: "ip", ...over };
}

describe("iocProvenanceSuffix (#1471)", () => {
  it("client-reported: the #1266 suffix, whatever the type", () => {
    expect(iocProvenanceSuffix(ioc({ provenance: "client-reported" }))).toBe(" (client-reported)");
    expect(iocProvenanceSuffix(ioc({ type: "hash", provenance: "client-reported" }))).toBe(
      " (client-reported)",
    );
  });

  it("mentioned network IOC: the #1461 note, composed from MENTIONED_NOTE", () => {
    for (const type of ["ip", "domain", "url"] as const) {
      expect(iocProvenanceSuffix(ioc({ type, provenance: "mentioned" }))).toBe(` (${MENTIONED_NOTE})`);
    }
    expect(iocProvenanceSuffix(ioc({ provenance: "mentioned" }))).toBe(
      " (referenced in free text; no network record)",
    );
  });

  it("mentioned hash: the #1459 note, composed from MENTIONED_HASH_NOTE", () => {
    expect(iocProvenanceSuffix(ioc({ type: "hash", provenance: "mentioned" }))).toBe(
      ` (mentioned in free text; ${MENTIONED_HASH_NOTE})`,
    );
    expect(iocProvenanceSuffix(ioc({ type: "hash", provenance: "mentioned" }))).toBe(
      " (mentioned in free text; no file with this hash was observed)",
    );
  });

  it("plain IOC, a non-network non-hash mention, or a near-miss literal: empty", () => {
    expect(iocProvenanceSuffix(ioc({}))).toBe("");
    expect(iocProvenanceSuffix(ioc({ type: "file", provenance: "mentioned" }))).toBe("");
    expect(iocProvenanceSuffix(ioc({ provenance: "mentioned-ish" as IOC["provenance"] }))).toBe("");
  });
});
