// #2543: the IOC panel's analyst label — a chip beside the value and a selector in the row's
// actions, read from GET /cases/:id/ioc-attribution and saved with PUT. Labels from another case
// never show, and every value that reaches markup is escaped.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  activeCaseId: string;
  loadIocAttribution(caseId: string): Promise<void>;
  setIocAttribution(value: string, label: string): Promise<void>;
  iocAttributionChip(ioc: { value: string; aliasValues?: string[] }): string;
  iocAttributionSelect(ioc: { value: string }): string;
}

function load(labels: Record<string, unknown>) {
  const calls: Array<{ url: string; init?: { method?: string; body?: string } }> = [];
  const api = loadDashboardModule<Api>("dashboard-ioc-attribution.js", ["dashboard-escape.js"], {
    activeCaseId: "c1",
    investigatorName: () => "Alice",
    fetch: (url: string, init?: { method?: string; body?: string }) => {
      calls.push({ url, init });
      return Promise.resolve({ ok: true, json: () => Promise.resolve(labels) });
    },
  });
  return { api, calls };
}
const entry = (value: string, label: string) => ({ value, label, setAt: "t", setBy: "a" });

describe("IOC attribution chip (#2543)", () => {
  it("shows the label beside the value once loaded, matching case-insensitively and via an alias", async () => {
    const { api } = load({
      "203.0.113.10": entry("203.0.113.10", "ours"),
      "evil.example": entry("evil.example", "attacker"),
    });
    expect(api.iocAttributionChip({ value: "203.0.113.10" })).toBe("");
    await api.loadIocAttribution("c1");
    expect(api.iocAttributionChip({ value: "203.0.113.10" })).toContain(">ours<");
    expect(api.iocAttributionChip({ value: "www.evil.example", aliasValues: ["EVIL.example"] })).toContain(
      "ioc-attr-attacker",
    );
    expect(api.iocAttributionChip({ value: "192.0.2.1" })).toBe("");
  });

  it("never shows another case's labels", async () => {
    const { api } = load({ "203.0.113.10": entry("203.0.113.10", "ours") });
    await api.loadIocAttribution("c1");
    api.activeCaseId = "c2";
    expect(api.iocAttributionChip({ value: "203.0.113.10" })).toBe("");
  });

  it("the selector escapes an attacker-chosen value and marks the current label", async () => {
    const hostile = '"><script>alert(1)</script>';
    const { api } = load({ [hostile.toLowerCase()]: entry(hostile, "attacker") });
    await api.loadIocAttribution("c1");
    const html = api.iocAttributionSelect({ value: hostile });
    expect(html).not.toContain("<script>");
    expect(html).toContain('data-act="iocSetAttribution"');
    expect(html).toContain('<option value="attacker" selected>');
  });

  it("PUTs the label (or null to clear) for the active case, with the analyst's name", async () => {
    const { api, calls } = load({});
    await api.setIocAttribution("203.0.113.10", "responder");
    await api.setIocAttribution("203.0.113.10", "");
    const puts = calls.filter((c) => c.init?.method === "PUT");
    expect(puts.map((c) => c.url)).toEqual(["/cases/c1/ioc-attribution", "/cases/c1/ioc-attribution"]);
    expect(puts.map((c) => JSON.parse(c.init!.body!))).toEqual([
      { value: "203.0.113.10", label: "responder", actor: "Alice" },
      { value: "203.0.113.10", label: null, actor: "Alice" },
    ]);
  });

  it("is wired: the IOC row renders the chip and the selector, and data-act dispatches the change", () => {
    const root = new URL("../../../public/", import.meta.url);
    const html = readFileSync(new URL("dashboard.html", root), "utf8");
    expect(html).toContain('<script src="/js/dashboard-ioc-attribution.js"></script>');
    expect(html).toContain("iocAttributionChip(i)");
    expect(html).toContain("iocAttributionSelect(i)");
    const act = readFileSync(new URL("js/dashboard-data-act.js", root), "utf8");
    expect(act).toContain("iocSetAttribution: (el) => setIocAttribution(el.dataset.value, el.value)");
    const connect = readFileSync(new URL("js/dashboard-case-connect.js", root), "utf8");
    expect(connect).toContain('["iocAttribution", () => loadIocAttribution(caseId)]');
  });
});
