import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-detection-rules.js — Content tagger → Detection rules (#2389): one collapsible
// box, a line each for the tagger rules and Sigma, an update button only when one is due.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

type Line = { label: string; text: string; action: string | null; button?: string; warn?: boolean } | null;
interface Api {
  drTaggerLine: (st: unknown) => Line;
  drSigmaLine: (s: unknown) => Line;
  drSetTagger: (st: unknown) => void;
  drSetSigma: (s: unknown) => void;
  drRunAction: (a: string) => void;
}

class FakeEl {
  children: FakeEl[] = [];
  hidden = false;
  open = false;
  className = "";
  type = "";
  onclick: ((ev: { preventDefault(): void; stopPropagation(): void }) => unknown) | null = null;
  private text = "";
  constructor(readonly tag: string) {}
  get textContent(): string {
    return this.text + this.children.map((c) => c.textContent).join(" ");
  }
  set textContent(v: string) {
    this.text = v;
    this.children = [];
  }
  appendChild(c: FakeEl): FakeEl {
    this.children.push(c);
    return c;
  }
  append(...c: FakeEl[]): void {
    this.children.push(...c);
  }
  all(): FakeEl[] {
    return [this, ...this.children.flatMap((c) => c.all())];
  }
}

function harness() {
  const els: Record<string, FakeEl> = {
    detectionRulesBox: new FakeEl("details"),
    detectionRulesLines: new FakeEl("div"),
  };
  els.detectionRulesBox.hidden = true;
  const did: string[] = [];
  const api = loadDashboardModule<Api>("dashboard-detection-rules.js", [], {
    document: {
      getElementById: (id: string) => els[id] ?? null,
      createElement: (tag: string) => new FakeEl(tag),
    },
    DfirRulePack: { checkRulePack: () => did.push("tagger-check") },
    openSettingsTab: (t: string) => did.push(`settings:${t}`),
    sigmaCheck: () => did.push("sigma-check"),
  });
  const buttons = () => els.detectionRulesLines.all().filter((e) => e.tag === "button");
  return { api, els, did, buttons };
}

const PACK_STATUS = { inUse: "pack", installed: { version: "rules-2026.11.06.2" } };
const SIGMA = { enabled: true, active: { release: "r2026-07-01" } };

describe("the Detection rules box (#2389)", () => {
  it("is mounted around the rule pack panel, collapsed, and served before the rule pack script", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toMatch(/<details id="detectionRulesBox"[^>]*>\s*<summary>/);
    expect(html.indexOf("detectionRulesBox")).toBeLessThan(html.indexOf('id="rulePackPanel"'));
    expect(html.indexOf("/js/dashboard-detection-rules.js")).toBeLessThan(
      html.indexOf("/js/dashboard-rule-pack.js"),
    );
    expect(STATIC_ASSETS).toHaveProperty("/js/dashboard-detection-rules.js");
  });

  it("says current with no button, and offers Review update… only when a newer release was found", () => {
    const { api } = harness();
    expect(api.drTaggerLine({ ...PACK_STATUS, lastCheck: { status: "current" } })).toMatchObject({
      text: "rule pack rules-2026.11.06.2 — current",
      action: null,
    });
    expect(
      api.drTaggerLine({ ...PACK_STATUS, lastCheck: { status: "update", latest: "rules-2026.11.09" } }),
    ).toMatchObject({
      text: "rule pack rules-2026.11.06.2 — rules-2026.11.09 available",
      button: "Review update…",
    });
    expect(
      api.drSigmaLine({ ...SIGMA, lastCheck: { latest: "r2026-10-01", updateAvailable: true } }),
    ).toMatchObject({
      text: "SigmaHQ r2026-07-01 — r2026-10-01 available",
      action: "sigma",
      button: "Review update…",
    });
    expect(
      api.drSigmaLine({ ...SIGMA, lastCheck: { latest: "r2026-07-01", updateAvailable: false } })?.action,
    ).toBeNull();
  });

  it("offers a check when nothing was checked yet, and says so when the last check failed", () => {
    const { api } = harness();
    expect(
      api.drTaggerLine({ inUse: "bundled", activeRules: "bundled with the app (0.45.0)" }),
    ).toMatchObject({
      text: "bundled with the app (0.45.0) — not checked",
      button: "Check for updates",
    });
    expect(
      api.drSigmaLine({ ...SIGMA, lastCheck: { error: "offline", updateAvailable: false } }),
    ).toMatchObject({
      text: "SigmaHQ r2026-07-01 — the last check failed",
      button: "Check again",
    });
    expect(api.drSigmaLine({ ...SIGMA, enabled: false })?.text).toBe(
      "SigmaHQ r2026-07-01 — grading switched off",
    );
  });

  it("shows the box once a line is known, and hides it when neither is", () => {
    const { api, els } = harness();
    api.drSetTagger({ ...PACK_STATUS, lastCheck: { status: "current" } });
    expect(els.detectionRulesBox.hidden).toBe(false);
    expect(els.detectionRulesLines.textContent).toContain("Tagger rules");
    api.drSetTagger(null);
    expect(els.detectionRulesBox.hidden).toBe(true);
  });

  it("a button runs the existing review and does not fold the box", () => {
    const { api, els, did, buttons } = harness();
    api.drSetTagger({ ...PACK_STATUS, lastCheck: { status: "update", latest: "rules-2026.11.09" } });
    api.drSetSigma({ ...SIGMA, lastCheck: { latest: "r2026-10-01", updateAvailable: true } });
    const stops: string[] = [];
    const ev = { preventDefault: () => stops.push("p"), stopPropagation: () => stops.push("s") };
    const [tagger, sigma] = buttons();
    tagger.onclick!(ev);
    expect(els.detectionRulesBox.open).toBe(true);
    sigma.onclick!(ev);
    expect(did).toEqual(["tagger-check", "settings:sigma", "sigma-check"]);
    expect(stops).toEqual(["p", "s", "p", "s"]);
  });
});
