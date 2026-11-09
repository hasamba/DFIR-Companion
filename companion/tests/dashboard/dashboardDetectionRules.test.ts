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
  drSuzakuLine: (s: unknown) => Line;
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
    suzakuCheck: () => did.push("suzaku-check"),
  });
  const buttons = () => els.detectionRulesLines.all().filter((e) => e.tag === "button");
  return { api, els, did, buttons };
}

const PACK_STATUS = { inUse: "pack", installed: { version: "rules-2026.11.06.2" } };
const SIGMA = { enabled: true, active: { release: "r2026-07-01" } };

describe("the Sigma line with unreleased SigmaHQ changes (#2518)", () => {
  it("says the newest release is installed but the main branch has unreleased changes", () => {
    const { api } = harness();
    expect(
      api.drSigmaLine({
        ...SIGMA,
        lastCheck: {
          latest: "r2026-07-01",
          updateAvailable: false,
          main: { gradedChanges: 10, date: "2026-11-07" },
        },
      }),
    ).toMatchObject({
      text: "SigmaHQ r2026-07-01 — newest release; 10 unreleased change(s) on SigmaHQ's main branch",
      action: "sigma",
      button: "Review…",
    });
    expect(
      api.drSigmaLine({
        ...SIGMA,
        lastCheck: { latest: "r2026-07-01", updateAvailable: false, main: { gradedChanges: 0 } },
      })?.text,
    ).toBe("SigmaHQ r2026-07-01 — current");
    expect(
      api.drSigmaLine({
        ...SIGMA,
        lastCheck: { latest: "r2026-07-01", updateAvailable: false, main: { stale: true } },
      }),
    ).toMatchObject({
      text: "SigmaHQ r2026-07-01 — the rules changed since the last check",
      button: "Check again",
    });
  });
});

describe("the Suzaku line (#2508)", () => {
  const sz = (suzaku: Record<string, unknown>) => ({ ...SIGMA, settings: { suzaku } });
  const active = { release: "suzaku-2026-11-01", source: "bundled" };

  it("offers a check, then a review when a newer commit exists, and nothing when current", () => {
    const { api } = harness();
    expect(api.drSuzakuLine(sz({ enabled: true, active }))).toMatchObject({
      label: "Suzaku rules",
      text: "suzaku-2026-11-01 — not checked",
      action: "suzaku",
      button: "Check for updates",
    });
    expect(
      api.drSuzakuLine(
        sz({
          enabled: true,
          active,
          lastCheck: { updateAvailable: true, latest: "suzaku-2026-11-20-aaaaaaa" },
        }),
      ),
    ).toMatchObject({
      text: "suzaku-2026-11-01 — suzaku-2026-11-20-aaaaaaa available",
      button: "Review update…",
    });
    expect(
      api.drSuzakuLine(sz({ enabled: true, active, lastCheck: { updateAvailable: false } }))?.action,
    ).toBeNull();
    expect(api.drSuzakuLine(sz({ enabled: true, active, lastCheck: { error: "x" } }))?.button).toBe(
      "Check again",
    );
  });

  it("is absent while Suzaku is switched off or the server has no Suzaku store", () => {
    const { api } = harness();
    expect(api.drSuzakuLine(sz({ enabled: false, active }))).toBeNull();
    expect(api.drSuzakuLine(sz({ enabled: true }))).toBeNull();
    expect(api.drSuzakuLine(SIGMA)).toBeNull();
  });

  it("renders beside the Sigma line and its button opens the Suzaku check in Settings", () => {
    const { api, els, did, buttons } = harness();
    api.drSetSigma(sz({ enabled: true, active }));
    expect(els.detectionRulesLines.textContent).toContain("Suzaku rules");
    const btn = buttons().find((b) => b.textContent === "Check for updates" && did.length === 0);
    api.drRunAction("suzaku");
    expect(did).toEqual(["settings:sigma", "suzaku-check"]);
    expect(btn).toBeDefined();
  });
});

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

  it("names the bundled Suzaku rules beside the SigmaHQ release (#2499)", () => {
    const { api } = harness();
    const origins = [{ name: "Suzaku", release: "suzaku-2026-11-01" }];
    expect(
      api.drSigmaLine({ ...SIGMA, origins, lastCheck: { latest: "r2026-07-01", updateAvailable: false } }),
    ).toMatchObject({ text: "SigmaHQ r2026-07-01 + Suzaku suzaku-2026-11-01 — current" });
  });

  it("never calls a pack that needs a newer app current", () => {
    const { api } = harness();
    const line = api.drTaggerLine({
      ...PACK_STATUS,
      lastCheck: {
        status: "needs-newer-app",
        message: "rule pack rules-2026.12.01 needs DFIR Companion 0.46.0 or newer.",
      },
    });
    expect(line?.text).not.toContain("current");
    expect(line).toMatchObject({ warn: true, action: null });
    expect(line?.text).toContain("needs DFIR Companion 0.46.0 or newer");
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
