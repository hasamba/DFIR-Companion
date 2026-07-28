import { describe, it, expect } from "vitest";
import { homedir } from "node:os";
import { join } from "node:path";
import { expandHome } from "../../src/storage/expandHome.js";

describe("expandHome", () => {
  it("expands a bare tilde to homedir", () => {
    expect(expandHome("~")).toBe(homedir());
  });

  it("expands ~/subdir to homedir/subdir", () => {
    expect(expandHome("~/Documents/cases")).toBe(join(homedir(), "Documents/cases"));
  });

  it("expands ~\\backslash style (Windows)", () => {
    expect(expandHome("~\\Documents\\cases")).toBe(join(homedir(), "Documents\\cases"));
  });

  it("leaves absolute paths untouched", () => {
    expect(expandHome("/var/lib/dfir/cases")).toBe("/var/lib/dfir/cases");
    expect(expandHome("C:\\Evidence\\cases")).toBe("C:\\Evidence\\cases");
  });

  it("leaves relative paths untouched (anchored elsewhere)", () => {
    expect(expandHome("cases")).toBe("cases");
    expect(expandHome("./cases")).toBe("./cases");
  });

  it("does NOT expand ~otheruser (no portable API)", () => {
    expect(expandHome("~alice/cases")).toBe("~alice/cases");
  });

  it("handles empty string", () => {
    expect(expandHome("")).toBe("");
  });
});
