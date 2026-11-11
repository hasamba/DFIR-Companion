// #2560: the "Account weaknesses (AWS)" block under the Cloud Coverage table. Read from
// GET /cases/:id/cloud-weaknesses; nothing shows before any CloudTrail import recorded the list, the
// empty list says so, and every evidence value (a bucket is named by whoever made it) is escaped.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  loadCloudCoverage(caseId: string): void;
}

const HOSTILE = '"><img src=x onerror=alert(1)><script>alert(1)</script>';

async function render(weaknesses: unknown): Promise<string> {
  const el = { innerHTML: "" };
  const api = loadDashboardModule<Api>("dashboard-derived-panels.js", ["dashboard-escape.js"], {
    document: { getElementById: (id: string) => (id === "cloudCoverage" ? el : { value: "c1" }) },
    fetch: (url: string) =>
      Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve(url.includes("cloud-weaknesses") ? weaknesses : { items: [], caveats: [] }),
      }),
  });
  api.loadCloudCoverage("c1");
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  return el.innerHTML;
}

const item = (bucket: string) => ({
  kind: "object-lock-missing",
  account: "111122223333",
  bucket,
  title: "Bucket has no Object Lock configuration",
  detail: "GetBucketObjectLockConfiguration answered ObjectLockConfigurationNotFoundError.",
  cites: [{ role: "check", eventId: HOSTILE, time: "2026-03-01T10:00:00Z" }],
});

describe("Cloud Coverage — account weaknesses block (#2560)", () => {
  it("shows nothing before any CloudTrail import recorded the list", async () => {
    expect(await render({ read: false, items: [], limits: ["x"] })).not.toContain("Account weaknesses");
  });

  it("says none matched for an empty list, and shows the limits and the CSV link", async () => {
    const html = await render({
      read: true,
      items: [],
      limits: ["Records already in the case are not read again."],
    });
    expect(html).toContain("Account weaknesses (AWS)");
    expect(html).toContain("None of the checks matched the CloudTrail records read so far.");
    expect(html).toContain("Records already in the case are not read again.");
    expect(html).toContain('href="/cases/c1/cloud-weaknesses.csv"');
  });

  it("escapes an attacker-chosen bucket name and eventID, and links the record's second", async () => {
    const html = await render({ read: true, items: [item(HOSTILE)], limits: [] });
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain('data-act="superTimelineAt" data-time="2026-03-01T10:00:00Z"');
  });
});
