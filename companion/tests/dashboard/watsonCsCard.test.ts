import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2666 — Watson's CrowdStrike Next-Gen SIEM search card.

interface Api {
  watsonCsCardHtml: (p: Record<string, unknown>) => string;
}

const api = () => loadDashboardModule<Api>("dashboard-watson-cs.js", ["dashboard-escape.js"], {});

const card = (over: Record<string, unknown> = {}) => ({
  id: "wp-cs",
  kind: "cs_search",
  status: "pending",
  title: "Encoded PowerShell",
  query: "#event_simpleName=ProcessRollup2 | table([CommandLine])",
  start: "2026-11-14T00:00:00.000Z",
  end: "2026-11-16T00:00:00.000Z",
  repository: "search-all",
  ...over,
});

describe("Watson's CrowdStrike search card (#2666)", () => {
  it("a pending card shows the exact query, the range and Run search / Reject", () => {
    const html = api().watsonCsCardHtml(card());
    expect(html).toContain("CrowdStrike NG-SIEM search · pending");
    expect(html).toContain("#event_simpleName=ProcessRollup2 | table([CommandLine])");
    expect(html).toContain("Repository search-all");
    expect(html).toContain('data-w-verb="apply"');
    expect(html).toContain("Run search");
    expect(html).toContain('data-w-verb="reject"');
  });

  it("an applied card shows the outcome and has no buttons but Copy", () => {
    const html = api().watsonCsCardHtml(
      card({
        status: "applied",
        launched: { jobId: "j", at: "2026-11-17T10:00:00.000Z", by: "Dana" },
        watch: { state: "finished", text: "CrowdStrike NG-SIEM search Encoded PowerShell found nothing" },
      }),
    );
    expect(html).toContain("found nothing");
    expect(html).not.toContain('data-w-verb="apply"');
  });

  it("escapes model text", () => {
    const html = api().watsonCsCardHtml(
      card({ title: "<img src=x onerror=alert(1)>", query: "</pre><script>x</script>" }),
    );
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>");
  });
});
