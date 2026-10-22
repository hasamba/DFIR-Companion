import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { declaredFunctions } from "../helpers/dashboardModule.js";

// public/js/dashboard-sigma-rules.js — Settings → Sigma rules (#2204). Rule titles and reasons come
// from release files the analyst may have uploaded, so the module must never write HTML from them.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
const MODULE = new URL("../../../public/js/dashboard-sigma-rules.js", import.meta.url);

describe("the Sigma rules settings tab", () => {
  it("never renders server strings as HTML", async () => {
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/\.innerHTML\s*=|insertAdjacentHTML|outerHTML\s*=/);
  });

  it("declares the functions the page calls", () => {
    const fns = declaredFunctions("dashboard-sigma-rules.js");
    for (const name of [
      "initSigmaRules",
      "loadSigmaRules",
      "sigmaCheck",
      "sigmaInstallFile",
      "sigmaInstall",
      "sigmaRollback",
      "sigmaToggleRule",
    ])
      expect(fns).toContain(name);
  });

  it("is loaded, served, wires itself once and loads when its tab opens", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const src = await readFile(MODULE, "utf8");
    expect(html).toContain('<script src="/js/dashboard-sigma-rules.js"></script>');
    expect(STATIC_ASSETS["/js/dashboard-sigma-rules.js"]).toMatch(/javascript/);
    expect(
      src.match(/addEventListener\("DOMContentLoaded", initSigmaRules, \{ once: true \}\)/g),
    ).toHaveLength(1);
    expect(src).toContain('if (b.dataset.stab === "sigma") b.addEventListener("click", loadSigmaRules);');
    expect(html).toContain('data-stab="sigma"');
    expect(html).toContain('id="stab-sigma"');
  });

  it("renders every Sigma setting as a generic env field", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    for (const key of [
      "DFIR_SIGMA_RULES",
      "DFIR_SIGMA_MIN_LEVEL",
      "DFIR_SIGMA_RULE_STATUSES",
      "DFIR_SIGMA_UPDATE_CHECK",
    ])
      expect(html).toContain(`id="env-${key}"`);
  });
});
