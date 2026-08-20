import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("new notification-channel defaults", () => {
  it("enables milestone alerts in the dashboard, matching the server default", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const milestone = /<input\b[^>]*\bid="ntfEvtMilestone"[^>]*>/i.exec(html)?.[0] ?? "";

    expect(milestone).not.toBe("");
    expect(milestone).toMatch(/\bchecked\b/i);
  });
});
