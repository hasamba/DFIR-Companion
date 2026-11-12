import { describe, expect, it } from "vitest";
import { renderMainSourceBlock } from "../../src/analysis/mainSourcePromptBlock.js";
import { HUNT_PLATFORMS } from "../../src/analysis/huntPlatforms.js";

// #2594 part two: the synthesis note that names the case's main evidence source.

const ALL = [...HUNT_PLATFORMS];

describe("renderMainSourceBlock (#2594)", () => {
  it("names the tool and its language for a copy-language source", () => {
    const b = renderMainSourceBlock("splunk", ALL);
    expect(b).toContain("MAIN EVIDENCE SOURCE: Splunk");
    expect(b).toContain("Splunk SPL");
    expect(b).toContain("not a Velociraptor artifact");
    expect(b).toContain("unless the step needs collection from an endpoint");
    expect(renderMainSourceBlock("crowdstrike", ALL)).toContain("CrowdStrike Falcon CQL");
    expect(renderMainSourceBlock("m365", ALL)).toContain("KQL");
  });

  it("is empty when the answer is Velociraptor anyway", () => {
    expect(renderMainSourceBlock("velociraptor", ALL)).toBe("");
    expect(renderMainSourceBlock("host-other", ALL)).toBe("");
    expect(renderMainSourceBlock(null, ALL)).toBe("");
  });

  it("is empty when the source's platform is disabled (hunts fall back to VQL)", () => {
    expect(
      renderMainSourceBlock(
        "splunk",
        ALL.filter((p) => p !== "splunk"),
      ),
    ).toBe("");
  });

  it("covers Mixed and other cloud logs without promising a query language", () => {
    expect(renderMainSourceBlock("mixed", ALL)).toMatch(/^MIXED EVIDENCE:/);
    const cloud = renderMainSourceBlock("cloud-other", ALL);
    expect(cloud).toContain("CloudTrail");
    expect(cloud).not.toMatch(/written in/);
  });
});
