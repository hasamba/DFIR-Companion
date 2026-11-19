import { describe, expect, it } from "vitest";
import { buildStartupBanner } from "../../src/logging/startupBanner.js";

describe("buildStartupBanner", () => {
  const url = "http://127.0.0.1:4773/dashboard";

  it("says the server is ready and names the dashboard URL", () => {
    const text = buildStartupBanner(url).join("\n");
    expect(text).toContain("fully loaded");
    expect(text).toContain(url);
  });

  it("uses plain ASCII only, so log files and old Windows consoles render it", () => {
    for (const line of buildStartupBanner(url)) {
      expect(line).toMatch(/^[\x20-\x7e]*$/);
    }
  });

  it("keeps the box edges aligned for short and long URLs", () => {
    for (const u of [url, "https://dfir.example.internal:44773/dashboard"]) {
      const lines = buildStartupBanner(u);
      const first = lines.findIndex((l) => l.trimStart().startsWith("+-"));
      const last = lines.lastIndexOf(lines[first] ?? "");
      const boxLines = lines.slice(first, last + 1);
      const widths = new Set(boxLines.map((l) => l.trimEnd().length));
      expect(boxLines.length).toBeGreaterThanOrEqual(4);
      expect(widths.size).toBe(1);
    }
  });

  it("returns a new array each call", () => {
    expect(buildStartupBanner(url)).not.toBe(buildStartupBanner(url));
  });
});
