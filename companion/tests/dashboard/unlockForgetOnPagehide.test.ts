import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect } from "vitest";

// #2416: the tab-close "forget this unlock" must reach the server in team mode, where every
// state-changing request needs the X-DFIR-CSRF header. sendBeacon cannot carry headers (the server
// answered 403 and the cookie survived the browser session); a keepalive fetch goes through the
// dashboard's fetch wrapper, which adds the header.

const source = readFileSync(join(__dirname, "../../../public/js/dashboard-case-connect.js"), "utf8");

describe("tab-close unlock forget (#2416)", () => {
  it("uses a keepalive fetch, not sendBeacon, for POST /cases/:id/lock on pagehide", () => {
    const start = source.indexOf('addEventListener("pagehide"');
    expect(start).toBeGreaterThan(-1);
    const handler = source.slice(start, source.indexOf("});", start) + 3);
    expect(handler).toMatch(/fetch\(`\/cases\/\$\{activeUnlockedCaseId\}\/lock`/);
    expect(handler).toMatch(/keepalive:\s*true/);
    expect(source).not.toMatch(/sendBeacon\(/);
  });

  it("the dashboard's fetch wrapper adds the CSRF header to same-origin POSTs", () => {
    const html = readFileSync(join(__dirname, "../../../public/dashboard.html"), "utf8");
    expect(html).toMatch(/window\.fetch = async function/);
    expect(html).toMatch(/headers\.set\('X-DFIR-CSRF'/);
  });
});
