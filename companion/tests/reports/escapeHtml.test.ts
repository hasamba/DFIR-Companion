import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { escapeHtml } from "../../src/reports/escapeHtml.js";

/**
 * The drift guard for #521.
 *
 * `html.ts` and `interactiveHtml.ts` each carried a byte-identical private copy of this function,
 * and both omitted the single quote. Nothing connected them, so hardening one would silently leave
 * the other vulnerable. These tests pin the escape set and assert that neither exporter has grown a
 * private copy again.
 */
describe("escapeHtml", () => {
  it("escapes every character that can break out of markup or an attribute", () => {
    expect(escapeHtml(`& < > " '`)).toBe("&amp; &lt; &gt; &quot; &#39;");
  });

  it("escapes the ampersand first, so an escape is never double-escaped", () => {
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });

  it("leaves ordinary evidence text untouched", () => {
    expect(escapeHtml("C:\\Users\\analyst\\mimikatz.exe")).toBe("C:\\Users\\analyst\\mimikatz.exe");
  });

  // A value carrying an apostrophe — an analyst note, a quoted command line — must not be able to
  // close a single-quoted attribute in either exporter.
  it("neutralises an apostrophe that would otherwise close a single-quoted attribute", () => {
    expect(escapeHtml("' onload='alert(1)")).not.toContain("'");
  });

  // Every module that escapes evidence into the report document, including the two SVG renderers
  // embedded in it — they had the same four-character copy under the name `esc`.
  it("is defined once: no report module carries its own copy", () => {
    for (const module of ["html.ts", "interactiveHtml.ts", "assetGraphSvg.ts", "swimlaneSvg.ts"]) {
      const source = readFileSync(
        fileURLToPath(new URL(`../../src/reports/${module}`, import.meta.url)),
        "utf8",
      );
      expect(source, `${module} defines its own escaper`).not.toMatch(/replace\(\/&\/g/);
      expect(source, `${module} does not import the shared escaper`).toMatch(/from\s+"\.\/escapeHtml\.js"/);
    }
  });
});
