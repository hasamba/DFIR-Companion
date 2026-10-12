import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// THE STARTUP REFUSAL MUST POINT AT DOCUMENTATION THAT EXISTS (#2166).
//
// Single-user mode bound to a non-loopback address refuses to start and tells the operator to set
// DFIR_ALLOW_UNAUTHENTICATED_REMOTE "to the documented container-loopback-proxy or public-demo
// value". The manual documented only the first, so an operator deploying a public demo copied the
// loopback value — which asserts a topology a public deployment does not have.
//
// The accepted values are derived from the code, so a new value fails here until the manual names
// it, keeping the error message's word "documented" true.
const root = new URL("../../../", import.meta.url);
const read = (p: string): string => readFileSync(new URL(p, root), "utf8");

const authConfig = read("companion/src/auth/authConfig.ts");
const advanced = read("mkdocs-docs/reference/advanced.md");
const settings = read("mkdocs-docs/reference/settings.md");

const acceptedValues = [...authConfig.matchAll(/DFIR_ALLOW_UNAUTHENTICATED_REMOTE\s*===\s*"([^"]+)"/g)].map(
  (m) => m[1],
);

describe("remote-exposure opt-out documentation (#2166)", () => {
  it("finds the accepted opt-out values in the code", () => {
    expect(acceptedValues.length).toBeGreaterThan(0);
  });

  it.each(acceptedValues)("documents the %s value in the advanced reference", (value) => {
    expect(advanced).toContain(`\`${value}\``);
  });

  it("names the variable in the settings reference", () => {
    expect(settings).toContain("DFIR_ALLOW_UNAUTHENTICATED_REMOTE");
  });

  it("discloses that demo mode leaves the demo seeder open", () => {
    expect(advanced).toContain("/cases/seed-demo");
    expect(advanced).not.toContain("All mutating routes are blocked");
  });
});
