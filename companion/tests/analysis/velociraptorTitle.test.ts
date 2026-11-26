// capWithHostSuffix (#2881) — a description capped AFTER withHostSuffix lost the "@ HOST" suffix
// midway ("… @ WS-LA") whenever the core landed within a suffix-length of the cap. The helper
// reserves room for the suffix under the cap, so the host is either whole or (only when it cannot
// fit at all) absent — never a fragment. Host names here are invented.
import { describe, expect, it } from "vitest";
import {
  capWithHostSuffix,
  injectKeepingHost,
  ransomTailWithHost,
  withHostSuffix,
} from "../../src/analysis/velociraptorTitle.js";

const HOST = "WS-LAB-01";

describe("capWithHostSuffix", () => {
  it("leaves a short description exactly as withHostSuffix builds it", () => {
    expect(capWithHostSuffix("Title - detail", HOST, 600)).toBe(withHostSuffix("Title - detail", HOST));
    expect(capWithHostSuffix("Title only", HOST, 600)).toBe("Title only - @ WS-LAB-01");
  });

  it("keeps the whole host suffix for every core length around and above the cap", () => {
    const cap = 120;
    for (let n = 1; n <= cap + 40; n++) {
      const core = `T - ${"x".repeat(n)}`;
      const out = capWithHostSuffix(core, HOST, cap);
      expect(out.length).toBeLessThanOrEqual(cap);
      expect(out.endsWith(` @ ${HOST}`)).toBe(true);
    }
  });

  it("uses the longer ' - @ HOST' suffix when the trimmed core has no title boundary", () => {
    const out = capWithHostSuffix("y".repeat(200), HOST, 100);
    expect(out).toHaveLength(100);
    expect(out.endsWith(` - @ ${HOST}`)).toBe(true);
  });

  it("re-adds the suffix when the cap cuts off a host mention that was in the core", () => {
    const out = capWithHostSuffix(`T - ${"z".repeat(200)} on ${HOST}`, HOST, 100);
    expect(out.length).toBeLessThanOrEqual(100);
    expect(out.endsWith(` @ ${HOST}`)).toBe(true);
  });

  it("adds nothing when the host still appears inside the capped text", () => {
    const core = `T on ${HOST} - ${"z".repeat(200)}`;
    expect(capWithHostSuffix(core, HOST, 100)).toBe(core.slice(0, 100));
  });

  it("falls back to a plain slice with no host, or a host too long to fit", () => {
    const core = `T - ${"q".repeat(200)}`;
    expect(capWithHostSuffix(core, "", 50)).toBe(core.slice(0, 50));
    expect(capWithHostSuffix(core, "H".repeat(60), 50)).toBe(core.slice(0, 50));
  });
});

// #2885 — the Velociraptor importer's two re-cap points: the ransomware note after the host, and the
// import loop's artifact-name injection.
describe("ransomTailWithHost", () => {
  it("is capWithHostSuffix when there is no ransomware note", () => {
    expect(ransomTailWithHost("x".repeat(700), HOST, undefined, 600)).toBe(
      capWithHostSuffix("x".repeat(700), HOST, 600),
    );
  });

  it("bounds an oversized note so the host still fits within the cap", () => {
    const out = ransomTailWithHost("T - " + "x".repeat(700), HOST, "n".repeat(2000), 600);
    expect(out.length).toBeLessThanOrEqual(600);
    expect(out).toContain(` @ ${HOST} — n`);
    expect(out.endsWith(" (T1486)")).toBe(true);
  });
});

describe("injectKeepingHost", () => {
  const prefix = (d: string): string => `[Art] ${d}`;

  it("re-applies a withHostSuffix suffix after the transform, under the cap", () => {
    const desc = withHostSuffix("T - " + "x".repeat(200), HOST);
    const out = injectKeepingHost(desc, HOST, 120, prefix);
    expect(out.length).toBeLessThanOrEqual(120);
    expect(out.startsWith("[Art] T - ")).toBe(true);
    expect(out.endsWith(` @ ${HOST}`)).toBe(true);
  });

  it("is unchanged from transform-then-slice when the result fits", () => {
    const desc = withHostSuffix("Title only", HOST);
    expect(injectKeepingHost(desc, HOST, 1200, prefix)).toBe(prefix(desc));
  });

  it("falls back to transform-then-slice when the host is not a trailing suffix", () => {
    const desc = `T on ${HOST} - ${"z".repeat(200)} [logged under former hostname OLD-01]`;
    expect(injectKeepingHost(desc, HOST, 100, prefix)).toBe(prefix(desc).slice(0, 100));
    const inText = `T on ${HOST} @ ${HOST}`;
    expect(injectKeepingHost(inText, HOST, 100, prefix)).toBe(prefix(inText));
  });
});
