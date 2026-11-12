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

describe("the Settings main-source row and the Hunts line edit one value (#2594 part two)", () => {
  type El = Record<string, unknown> & { innerHTML?: string; textContent?: string; hidden?: boolean };
  function setup(responses: Array<{ ok: boolean; body: unknown }>) {
    const els: Record<string, El> = {
      caseId: { value: "c1" },
      mainSourceLine: {
        innerHTML: "",
        insertAdjacentHTML(_: string, h: string) {
          this.innerHTML += h;
        },
      },
      caseMainSourceRow: { hidden: true },
      caseMainSourceCurrent: { textContent: "" },
      caseMainSourceSelect: { innerHTML: "", disabled: false },
      caseMainSourceMsg: { textContent: "" },
      mainSourceSelect: { disabled: false },
    };
    const calls: Array<{ url: string; method: string }> = [];
    const document = { getElementById: (id: string) => els[id] ?? null };
    const fetch = async (url: string, init?: { method?: string }) => {
      calls.push({ url, method: init?.method ?? "GET" });
      const r = responses.shift() ?? { ok: true, body: null };
      return { ok: r.ok, json: async () => r.body };
    };
    const api = loadDashboardModule<Api & { setMainSource?: unknown }>(
      "dashboard-main-source.js",
      ["dashboard-escape.js"],
      { document, fetch, resetVeloHuntSuggest: () => undefined, loadPlaybook: () => undefined },
    );
    return { api, els, calls };
  }
  const state = (override: string | null, effective: string | null) => ({
    ...ms(effective, effective === "splunk" ? "spl" : null, "Splunk SPL"),
    override,
    families: [{ family: "splunk", label: "Splunk" }],
  });
  const tick = () => new Promise((r) => setTimeout(r, 0));

  it("shows the source in Settings with the same choices as the Hunts line", async () => {
    const { api, els } = setup([{ ok: true, body: state("splunk", "splunk") }]);
    await api.loadMainSource();
    expect(els.caseMainSourceRow.hidden).toBe(false);
    expect(els.caseMainSourceCurrent.textContent).toBe(
      "Main evidence source: Splunk (set by you) — Splunk SPL",
    );
    expect(els.caseMainSourceSelect.innerHTML).toContain('value="splunk" selected');
    expect(els.caseMainSourceSelect.innerHTML).toContain("Mixed (per finding)");
  });

  it("a change in Settings writes once, then both places show the confirmed value", async () => {
    const { api, els, calls } = setup([
      { ok: true, body: state(null, null) },
      { ok: true, body: state("splunk", "splunk") },
    ]);
    await api.loadMainSource();
    (els.caseMainSourceSelect.onchange as () => void)();
    (els.caseMainSourceSelect.onchange as () => void)(); // a second change while the first is in flight
    await tick();
    await tick();
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
    expect(els.caseMainSourceCurrent.textContent).toContain("Splunk (set by you)");
    expect(els.mainSourceLine.innerHTML).toContain("Splunk");
  });

  it("a refused change (frozen case) restores the saved value and shows why in Settings", async () => {
    const { api, els } = setup([
      { ok: true, body: state(null, null) },
      { ok: false, body: { error: "case is closed" } },
    ]);
    await api.loadMainSource();
    (els.caseMainSourceSelect.onchange as () => void)();
    await tick();
    await tick();
    expect(els.caseMainSourceMsg.textContent).toBe("case is closed");
    expect(els.caseMainSourceSelect.innerHTML).toContain('value="" selected');
    expect(els.caseMainSourceSelect.disabled).toBe(false);
  });

  it("a refresh during a save does not bring back the old value", async () => {
    const { api, els, calls } = setup([
      { ok: true, body: state(null, null) },
      { ok: true, body: state("splunk", "splunk") },
      { ok: true, body: state(null, null) }, // a stale answer, if a refresh were sent
    ]);
    await api.loadMainSource();
    (els.caseMainSourceSelect.onchange as () => void)(); // the save starts
    await api.loadMainSource(); // a state update arrives mid-save
    await tick();
    await tick();
    expect(calls.filter((c) => c.method === "GET")).toHaveLength(1);
    expect(els.caseMainSourceCurrent.textContent).toContain("Splunk (set by you)");
    expect(els.caseMainSourceSelect.disabled).toBe(false);
  });

  it("an answer for the previous case is dropped after a case switch", async () => {
    const { api, els } = setup([{ ok: true, body: state("splunk", "splunk") }]);
    const pending = api.loadMainSource();
    (els.caseId as { value: string }).value = "c2";
    await pending;
    expect(els.caseMainSourceCurrent.textContent).toBe("");
  });
});
