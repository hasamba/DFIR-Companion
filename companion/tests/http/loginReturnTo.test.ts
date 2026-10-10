import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const ORIGIN = "http://127.0.0.1:4773";

async function loadHelper(): Promise<{ html: string; fn: (v: string | null) => string }> {
  const html = await readFile(new URL("../../../public/login.html", import.meta.url), "utf8");
  const match = /function safeReturnTo\(v\) \{[\s\S]*?\n {6}\}\n/.exec(html);
  expect(match, "login.html must define safeReturnTo").not.toBeNull();
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const fn = new Function("location", `${match![0]}\nreturn safeReturnTo;`)({ origin: ORIGIN }) as (
    v: string | null,
  ) => string;
  return { html, fn };
}

describe("login page returnTo sanitiser (#2107)", () => {
  const hostile = [
    "/\\attacker.com/x",
    "/\t/evil.com",
    "/\n/evil.com",
    "/\r/evil.com",
    "/..//evil.com",
    "/\\\\evil.com",
    "//evil.com",
    "https://evil.com",
    "javascript:alert(1)",
    "",
  ];
  for (const value of hostile) {
    it(`rejects ${JSON.stringify(value)}`, async () => {
      const { fn } = await loadHelper();
      expect(fn(value)).toBe("/dashboard");
    });
  }

  it("keeps legitimate local paths", async () => {
    const { fn } = await loadHelper();
    expect(fn("/dashboard")).toBe("/dashboard");
    expect(fn("/dashboard?case=a%20b#x")).toBe("/dashboard?case=a%20b#x");
    expect(fn("/admin")).toBe("/admin");
    expect(fn(null)).toBe("/dashboard");
  });

  it("no longer uses the old startsWith('//') check", async () => {
    const { html } = await loadHelper();
    expect(html).not.toContain("!requested.startsWith('//')");
    expect(html).toContain("safeReturnTo(params.get('returnTo'))");
  });
});
