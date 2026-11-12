import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { FAMILY_LABELS, SOURCE_FAMILIES } from "../../src/analysis/caseMainSource.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2594 part one: the playbook button names the main source's language, and the New case dialog
// offers the same sources the server accepts.

interface Btn {
  text: string;
  title: string;
}
interface Api {
  playbookHuntButton: (ms: unknown) => Btn;
  loadMainSource: () => Promise<void>;
}

function load(elements: Record<string, Record<string, unknown>> = {}, fetchBody?: unknown, ok = true) {
  const document = { getElementById: (id: string) => elements[id] ?? null };
  const fetch = async () => ({ ok, json: async () => fetchBody });
  return loadDashboardModule<Api>("dashboard-main-source.js", ["dashboard-escape.js"], { document, fetch });
}

const ms = (effective: string | null, language: string | null, label = "") => ({
  effective,
  override: null,
  totalFiles: 1,
  counts: [],
  families: [],
  language: effective && effective !== "mixed" ? { language, label, note: "" } : null,
});

const VQL_TEXT = "✨ Suggest Velociraptor hunts";

describe("playbookHuntButton (#2594)", () => {
  it("names each copy-ready language", () => {
    const api = load();
    expect(api.playbookHuntButton(ms("crowdstrike", "cql", "CrowdStrike Falcon CQL")).text).toBe(
      "✨ Suggest Falcon queries",
    );
    expect(api.playbookHuntButton(ms("defender", "kql-device")).text).toBe("✨ Suggest KQL queries");
    expect(api.playbookHuntButton(ms("m365", "kql-cloud")).text).toBe("✨ Suggest KQL queries");
    expect(api.playbookHuntButton(ms("elastic", "esql")).text).toBe("✨ Suggest ES|QL queries");
    const spl = api.playbookHuntButton(ms("splunk", "spl", "Splunk SPL"));
    expect(spl.text).toBe("✨ Suggest SPL queries");
    expect(spl.title).toContain("Splunk SPL");
    expect(spl.title).not.toMatch(/VQL|endpoint/);
  });

  it("keeps today's Velociraptor label for VQL sources, a disabled platform and no evidence", () => {
    const api = load();
    for (const s of [
      ms("velociraptor", "vql"),
      ms("host-other", null),
      ms("splunk", null),
      ms(null, null),
      null,
    ])
      expect(api.playbookHuntButton(s).text).toBe(VQL_TEXT);
  });

  it("does not promise VQL for other cloud logs or Mixed", () => {
    const api = load();
    const cloud = api.playbookHuntButton(ms("cloud-other", null));
    expect(cloud.text).toBe("✨ Suggest hunts");
    expect(cloud.title).toContain("Query Translator");
    const mixed = api.playbookHuntButton(ms("mixed", null));
    expect(mixed.text).toBe("✨ Suggest hunts");
    expect(mixed.title).toMatch(/falls back to Velociraptor VQL/);
  });

  it("updates the button when the main source loads, and resets it when the load fails", async () => {
    const btn = { textContent: VQL_TEXT, title: "" };
    const line = { innerHTML: "" };
    await load(
      { pbHuntBtn: btn, mainSourceLine: line, caseId: { value: "c1" } },
      ms("splunk", "spl", "Splunk SPL"),
    ).loadMainSource();
    expect(btn.textContent).toBe("✨ Suggest SPL queries");
    await load(
      { pbHuntBtn: btn, mainSourceLine: line, caseId: { value: "c1" } },
      null,
      false,
    ).loadMainSource();
    expect(btn.textContent).toBe(VQL_TEXT);
  });
});

describe("New case dialog main-source picker (#2594)", () => {
  const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const select = /<select id="ncMainSource"[^>]*>([\s\S]*?)<\/select>/.exec(html)?.[1] ?? "";
  const options = [...select.matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)].map((m) => [m[1], m[2]]);

  it("offers Automatic, every source the server accepts with its label, then Mixed", () => {
    expect(options[0][0]).toBe("");
    expect(options.slice(1, -1)).toEqual(SOURCE_FAMILIES.map((f) => [f, FAMILY_LABELS[f]]));
    expect(options[options.length - 1][0]).toBe("mixed");
  });

  it("sits under the Servers picker", () => {
    expect(html.indexOf('id="ncMainSource"')).toBeGreaterThan(html.indexOf('id="ncServerSet"'));
    expect(html.indexOf('id="ncMainSource"')).toBeLessThan(html.indexOf('id="ncTemplate"'));
  });
});
