import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// SECURITY.md MUST DESCRIBE THE AUTH MODES THE SERVER ACTUALLY HAS (#2165).
//
// The Posture paragraph said "there is no built-in authentication" as a blanket statement, and told
// the reader to bind 0.0.0.0 behind their own proxy. Both had drifted: team mode
// (DFIR_AUTH_MODE=team) adds accounts, OIDC, per-case roles and CSRF-protected sessions, and
// assertRemoteBindingSafe (companion/src/auth/authConfig.ts) refuses to start single-user mode on a
// non-loopback address unless DFIR_ALLOW_UNAUTHENTICATED_REMOTE names a documented opt-out.
const root = new URL("../../../", import.meta.url);
const security = readFileSync(new URL("SECURITY.md", root), "utf8");

/** The Posture section only — other sections are owned by other issues. */
function postureSection(md: string): string {
  const start = md.indexOf("## Posture");
  const next = md.indexOf("\n## ", start + 1);
  return md.slice(start, next === -1 ? undefined : next);
}

describe("SECURITY.md posture matches the auth modes (#2165)", () => {
  const posture = postureSection(security);

  it("has a Posture section", () => {
    expect(posture.length).toBeGreaterThan(0);
  });

  it("names team mode", () => {
    expect(posture).toContain("DFIR_AUTH_MODE=team");
  });

  it("never says 'no built-in authentication' without scoping it to single-user mode", () => {
    for (const sentence of posture.replace(/\s+/g, " ").split(/(?<=\.)\s/)) {
      if (/no built-in\s+authentication/i.test(sentence)) {
        expect(sentence).toMatch(/single-user/i);
      }
    }
  });

  it("matches assertRemoteBindingSafe: single-user refuses a non-loopback bind", () => {
    expect(posture).toMatch(/refuses to start/i);
    expect(posture).toContain("DFIR_ALLOW_UNAUTHENTICATED_REMOTE");
    expect(posture).toContain("container-loopback-proxy");
    expect(posture).toContain("public-demo");
  });

  it("no longer advises binding 0.0.0.0 behind your own proxy", () => {
    expect(posture).not.toMatch(/put it behind your\s+own auth/i);
  });
});
