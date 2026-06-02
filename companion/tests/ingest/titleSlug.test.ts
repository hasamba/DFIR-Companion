import { describe, it, expect } from "vitest";
import { slugifyTitle } from "../../src/ingest/titleSlug.js";

describe("slugifyTitle", () => {
  it("returns empty string for empty input", () => {
    expect(slugifyTitle("")).toBe("");
  });

  it("preserves safe characters and hyphenates spaces", () => {
    expect(slugifyTitle("Velociraptor Hunts")).toBe("Velociraptor-Hunts");
  });

  it("collapses punctuation/Unicode/em-dashes to a single hyphen", () => {
    expect(slugifyTitle("Velociraptor — Hunts")).toBe("Velociraptor-Hunts");
    expect(slugifyTitle("VirusTotal: hash a1b2c3")).toBe("VirusTotal-hash-a1b2c3");
  });

  it("strips OS-reserved characters (<>:\"/\\|?*) and control chars", () => {
    expect(slugifyTitle('C:\\Windows\\System32')).toBe("C-Windows-System32");
    expect(slugifyTitle('file<name>:"weird"|?*')).toBe("file-name-weird");
  });

  it("trims leading/trailing punctuation", () => {
    expect(slugifyTitle("   ---hello---   ")).toBe("hello");
  });

  it("drops non-ASCII (emoji, accented letters) cleanly", () => {
    expect(slugifyTitle("💀 attacker.exe")).toBe("attacker.exe");
  });

  it("truncates long titles without trailing punctuation", () => {
    const long = "A".repeat(80) + " trailing";
    const slug = slugifyTitle(long, 20);
    expect(slug.length).toBeLessThanOrEqual(20);
    expect(slug).not.toMatch(/[-._]$/);
  });

  it("returns empty string when input has no safe characters", () => {
    expect(slugifyTitle("💀💀💀")).toBe("");
    expect(slugifyTitle("   ")).toBe("");
  });
});
