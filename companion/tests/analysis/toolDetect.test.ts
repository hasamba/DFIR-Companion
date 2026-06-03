import { describe, it, expect } from "vitest";
import { detectTool } from "../../src/analysis/toolDetect.js";

describe("detectTool", () => {
  it("detects tools from import filenames", () => {
    expect(detectTool("0001_velociraptor_processes.csv")).toBe("Velociraptor");
    expect(detectTool("WIN11_thor_2026-06-03_0939.json")).toBe("THOR");
    expect(detectTool("Sysmon-EventLogs.csv")).toBe("Sysmon");
    expect(detectTool("splunk_export.log")).toBe("Splunk");
  });

  it("detects tools from captured browser tab titles", () => {
    expect(detectTool("Endpoint detections | CrowdStrike Falcon")).toBe("CrowdStrike Falcon");
    expect(detectTool("Velociraptor - Hunt Manager")).toBe("Velociraptor");
    expect(detectTool("Discover - Elastic")).toBe("Elastic");
    expect(detectTool("Search | Splunk")).toBe("Splunk");
  });

  it("disambiguates SentinelOne, Microsoft Sentinel, and Defender", () => {
    expect(detectTool("SentinelOne Console")).toBe("SentinelOne");
    expect(detectTool("Sentinel one - threats")).toBe("SentinelOne");
    expect(detectTool("Microsoft Sentinel incidents")).toBe("Microsoft Sentinel");
    expect(detectTool("Microsoft Defender for Endpoint")).toBe("Microsoft Defender");
    expect(detectTool("Windows-Defender-Operational.csv")).toBe("Microsoft Defender");
  });

  it("returns undefined when no known tool is present", () => {
    expect(detectTool("random_export.csv")).toBeUndefined();
    expect(detectTool("")).toBeUndefined();
    expect(detectTool(undefined)).toBeUndefined();
  });
});
