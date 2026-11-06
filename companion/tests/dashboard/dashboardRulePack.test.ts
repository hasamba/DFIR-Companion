import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-rule-pack.js — Content tagger → Rule pack (#2349): status, check → review,
// measure, install, roll back; demo disables the buttons. Every call goes to a /tagger/pack route.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

class FakeEl {
  children: FakeEl[] = [];
  hidden = false;
  disabled = false;
  className = "";
  title = "";
  id = "";
  style = { color: "", cssText: "" };
  onclick: (() => unknown) | null = null;
  private text = "";
  constructor(readonly tag: string) {}
  get textContent(): string {
    return this.text + this.children.map((c) => c.textContent).join("");
  }
  set textContent(v: string) {
    this.text = v;
    this.children = [];
  }
  appendChild(c: FakeEl): FakeEl {
    this.children.push(c);
    return c;
  }
  all(): FakeEl[] {
    return [this, ...this.children.flatMap((c) => c.all())];
  }
}

interface Api {
  loadRulePack: () => Promise<void>;
  checkRulePack: () => Promise<void>;
  measureRulePack: () => Promise<void>;
  installRulePack: () => Promise<void>;
  rollbackRulePack: (to: string) => Promise<void>;
}

const PACK = {
  version: "rules-2026.11.05",
  origin: "downloaded",
  verifiedByGitHub: true,
  rulesSha256: "a".repeat(64),
  ruleCount: 2,
  sources: [{ name: "Example", commit: "b".repeat(40), date: "2026-10-26" }],
};
const STATUS = {
  appVersion: "0.45.0",
  installed: null,
  previous: null,
  superseded: false,
  inUse: "bundled",
  activeRules: "bundled with the app (0.45.0)",
  updateCheck: false,
  demoMode: false,
};
const REVIEW = {
  token: "tok-1",
  pack: PACK,
  comparedWith: "bundled with the app (0.45.0)",
  activeSource: "default",
  counts: { added: 1, changed: 0, removed: 1 },
  added: [{ key: "new_rule", upstream: { description: "New", severity: "High" } }],
  changed: [],
  removed: [{ key: "old_rule", rule: { description: "Old" } }],
};

function harness(status: Record<string, unknown> = STATUS) {
  const els: Record<string, FakeEl> = {
    rulePackPanel: new FakeEl("div"),
    rulePackStatus: new FakeEl("div"),
    rulePackMsg: new FakeEl("div"),
    rulePackReview: new FakeEl("div"),
  };
  els.rulePackPanel.hidden = true;
  const calls: Array<{ url: string; body?: Record<string, unknown> }> = [];
  let ran = 0;
  const api = loadDashboardModule<Api>("dashboard-rule-pack.js", [], {
    document: {
      getElementById: (id: string) =>
        els[id] ??
        Object.values(els)
          .flatMap((e) => e.all())
          .find((e) => e.id === id) ??
        null,
      createElement: (tag: string) => new FakeEl(tag),
    },
    superCaseId: () => "c1",
    runTagger: () => {
      ran += 1;
    },
    confirm: () => true,
    fetch: async (url: string, init?: { body?: string }) => {
      calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
      const json = (d: unknown) => ({ ok: true, status: 200, json: async () => d });
      if (url === "/tagger/pack") return json(status);
      if (url === "/tagger/pack/check")
        return json({
          check: { status: "update", message: "Rule pack rules-2026.11.05 is available" },
          review: REVIEW,
        });
      if (url === "/tagger/pack/measure")
        return json({
          scanned: 3,
          raised: 1,
          intoForensic: 1,
          noLongerRaised: 0,
          wouldStayOut: 0,
          tagsChanged: 2,
          comparedWith: "bundled",
          note: "Nothing was changed. The tagger only raises grades.",
        });
      if (url === "/tagger/pack/install") return json({ ok: true, installed: PACK });
      if (url === "/tagger/pack/rollback") return json({ ok: true, installed: null });
      return { ok: false, status: 404, json: async () => ({}) };
    },
  });
  const button = (label: string) =>
    Object.values(els)
      .flatMap((e) => e.all())
      .find((e) => e.tag === "button" && e.textContent === label);
  return { api, els, calls, button, ran: () => ran };
}

describe("the Rule pack panel", () => {
  it("is mounted in the Content tagger area and served", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-rule-pack.js"></script>');
    expect(html).toMatch(/id="rulePackPanel"/);
    expect(html).toMatch(/id="env-DFIR_RULE_PACK_UPDATE_CHECK"/);
    expect(STATIC_ASSETS).toHaveProperty("/js/dashboard-rule-pack.js");
  });

  it("shows the rules in use and the actions", async () => {
    const h = harness();
    await h.api.loadRulePack();
    expect(h.els.rulePackPanel.hidden).toBe(false);
    expect(h.els.rulePackStatus.textContent).toContain("in use — bundled with the app (0.45.0)");
    expect(h.button("Check for updates")).toBeTruthy();
    expect(h.button("Install from file")).toBeTruthy();
    expect(h.button("Roll back to bundled rules")).toBeUndefined();
  });

  it("check shows the review; measure and install call their routes with the review token", async () => {
    const h = harness();
    await h.api.loadRulePack();
    await h.api.checkRulePack();
    const review = h.els.rulePackReview.textContent;
    expect(review).toContain("Rule pack rules-2026.11.05");
    expect(review).toContain("1 added, 0 changed, 1 removed");
    expect(review).toContain("new_rule · High — New");
    expect(review).toContain("Upstream sources: Example");
    await h.api.measureRulePack();
    expect(h.calls.find((c) => c.url === "/tagger/pack/measure")?.body).toEqual({
      token: "tok-1",
      caseId: "c1",
    });
    expect(h.els.rulePackReview.textContent).toContain("1 would be raised");
    expect(h.els.rulePackReview.textContent).toContain("only raises grades");
    await h.api.installRulePack();
    expect(h.calls.find((c) => c.url === "/tagger/pack/install")?.body).toEqual({ token: "tok-1" });
    expect(h.els.rulePackMsg.textContent).toContain(
      "Open cases keep their current grades until you press Run tagger",
    );
    h.button("Run tagger")?.onclick?.();
    expect(h.ran()).toBe(1);
  });

  it("offers roll back when a pack is installed, and names a file pack as not checked against GitHub", async () => {
    const h = harness({
      ...STATUS,
      installed: { ...PACK, origin: "file", verifiedByGitHub: false },
      previous: PACK,
      inUse: "pack",
    });
    await h.api.loadRulePack();
    expect(h.els.rulePackStatus.textContent).toContain("not checked against GitHub");
    expect(h.button("Roll back to rules-2026.11.05")).toBeTruthy();
    await h.api.rollbackRulePack("bundled");
    expect(h.calls.find((c) => c.url === "/tagger/pack/rollback")?.body).toEqual({ to: "bundled" });
  });

  it("disables downloads and installs in the demo", async () => {
    const h = harness({ ...STATUS, demoMode: true });
    await h.api.loadRulePack();
    expect(h.button("Check for updates")?.disabled).toBe(true);
    expect(h.button("Install from file")?.disabled).toBe(true);
    expect(h.els.rulePackStatus.textContent).toContain("disabled in the public demo");
  });
});
