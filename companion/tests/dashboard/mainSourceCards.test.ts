import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2559 — the Hunts panel's main-source line and the copy-ready cards in that source's language.

interface Api {
  loadMainSource: () => Promise<void>;
  setPlaybookLanguageHunts: (h: unknown[]) => void;
  playbookLanguageHuntsHtml: (taskId: string) => string;
}

function load(elements: Record<string, Record<string, unknown>>, fetchBody?: unknown) {
  const document = { getElementById: (id: string) => elements[id] ?? null };
  const fetch = async () => ({ ok: true, json: async () => fetchBody });
  return loadDashboardModule<Api>("dashboard-main-source.js", ["dashboard-escape.js"], { document, fetch });
}

const hunt = (over: Record<string, unknown> = {}) => ({
  taskId: "t1",
  language: "cql",
  platform: "crowdstrike",
  title: "Find the loader",
  rationale: "why",
  query: "#event_simpleName=ProcessRollup2",
  severity: "High",
  mitreTechniques: ["T1204.002"],
  ...over,
});

describe("playbook language cards (#2559)", () => {
  it("renders a task's card with its language label, Copy and Regenerate, and no deploy button", () => {
    const api = load({});
    api.setPlaybookLanguageHunts([hunt(), hunt({ taskId: "t2", title: "Other" })]);
    const html = api.playbookLanguageHuntsHtml("t1");
    expect(html).toContain("CrowdStrike Falcon CQL");
    expect(html).toContain("copy-ready");
    expect(html).toContain("msh-copy");
    expect(html).toContain("msh-regen");
    expect(html).not.toContain("vhs-deploy");
    expect(html).not.toContain("Deploy hunt");
    expect(html).not.toContain("Other");
    expect(api.playbookLanguageHuntsHtml("t9")).toBe("");
  });

  it("escapes adversary text in the title, rationale and the AI query", () => {
    const api = load({});
    api.setPlaybookLanguageHunts([
      hunt({ title: "<img src=x onerror=alert(1)>", query: "</textarea><script>alert(1)</script>" }),
    ]);
    const html = api.playbookLanguageHuntsHtml("t1");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;/textarea&gt;");
  });
});

describe("main-source line (#2559)", () => {
  const families = [
    { family: "velociraptor", label: "Velociraptor" },
    { family: "crowdstrike", label: "CrowdStrike Falcon" },
  ];

  it("names the source, its file count and the hunt language, with an override dropdown", async () => {
    const line: Record<string, unknown> = { innerHTML: "" };
    const api = load(
      { caseId: { value: "c1" }, mainSourceLine: line },
      {
        auto: "crowdstrike",
        override: null,
        effective: "crowdstrike",
        counts: [{ family: "crowdstrike", files: 14 }],
        totalFiles: 15,
        language: { language: "cql", label: "CrowdStrike Falcon CQL", note: "" },
        families,
      },
    );
    await api.loadMainSource();
    const html = String(line.innerHTML);
    expect(html).toContain("Main evidence source: CrowdStrike Falcon (14 of 15 evidence files");
    expect(html).toContain("hunts are written in CrowdStrike Falcon CQL");
    expect(html).toContain('<option value="" selected>Automatic</option>');
    expect(html).toContain('<option value="mixed">');
  });

  it("explains a mixed case and marks the analyst's override", async () => {
    const line: Record<string, unknown> = { innerHTML: "" };
    const api = load(
      { caseId: { value: "c1" }, mainSourceLine: line },
      {
        auto: "crowdstrike",
        override: "mixed",
        effective: "mixed",
        counts: [],
        totalFiles: 2,
        language: null,
        families,
      },
    );
    await api.loadMainSource();
    expect(String(line.innerHTML)).toContain("Mixed evidence (set by you)");
    expect(String(line.innerHTML)).toContain('<option value="mixed" selected>');
  });
});

describe("playbook language cards are styled like the Hunts panel's", () => {
  it("every hunt-card rule also applies inside the playbook section", async () => {
    const { readFileSync } = await import("node:fs");
    const css = readFileSync(new URL("../../../public/css/dashboard-sections.css", import.meta.url), "utf8");
    for (const cls of ["vhs-card", "vhs-head", "vhs-title", "vhs-rationale", "vhs-techs", "vhs-actions"])
      expect(css).toContain(`#sec-playbook .${cls}`);
    expect(css).toContain("#sec-playbook textarea.vhs-vql");
  });
});
