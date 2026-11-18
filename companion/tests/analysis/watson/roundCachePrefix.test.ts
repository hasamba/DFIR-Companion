import { describe, expect, it } from "vitest";
import { Scripted, final, toolHarness } from "./roundToolsFixtures.js";

// #2658: through a real Watson round, the request carries the masked timeline as its cache prefix when
// anonymization is on, the prompt starts with it, and a second round with unchanged events sends the very
// same prefix. With anonymization off (#2675) the clear timeline is the prefix: the prompt is clear anyway.

describe("Watson round cache prefix (#2658)", () => {
  it("anonymization on: the same masked prefix on two rounds", async () => {
    const p = new Scripted([final(), final()]);
    const h = await toolHarness(p, { anonymize: true });
    await h.run("first question");
    await h.run("second question");
    const [a, b] = p.sent;
    expect(a.cachePrefix).toBeTruthy();
    expect(a.userPrompt.startsWith(a.cachePrefix!)).toBe(true);
    expect(a.cachePrefix).toContain("<<<TIMELINE>>>");
    expect(b.cachePrefix).toBe(a.cachePrefix);
  });

  it("anonymization off: the same clear prefix on two rounds (#2675)", async () => {
    const p = new Scripted([final(), final()]);
    const h = await toolHarness(p);
    await h.run("first question");
    await h.run("second question");
    const [a, b] = p.sent;
    expect(a.cachePrefix).toBeTruthy();
    expect(a.userPrompt.startsWith(a.cachePrefix!)).toBe(true);
    expect(a.cachePrefix).toContain("<<<TIMELINE>>>");
    expect(b.cachePrefix).toBe(a.cachePrefix);
  });
});
