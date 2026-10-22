import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { SIGMA_RELEASE_MAX_ZIP_BYTES } from "../../src/analysis/sigmaReleaseArchive.js";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { declaredFunctions, loadDashboardModule } from "../helpers/dashboardModule.js";

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
      "sigmaExcludeRule",
      "sigmaRemoveExclusion",
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

  // #2213: a file over the server's cap must be refused before it is read, or a large zip freezes
  // the tab while it is base64-encoded. The cap is the server constant, so the limits cannot drift.
  describe("install from file size guard", () => {
    function loadWithFile(size: number) {
      const box = { textContent: "", style: { color: "" } };
      const file = { name: "dump.zip", size, arrayBuffer: vi.fn(async () => new ArrayBuffer(4)) };
      const fetch = vi.fn(async () => {
        throw new Error("offline");
      });
      const document = {
        readyState: "loading",
        addEventListener: () => undefined,
        getElementById: (id: string) =>
          id === "sigmaFile" ? { files: [file] } : id === "sigmaMessage" ? box : null,
      };
      const mod = loadDashboardModule<{ sigmaInstallFile: () => Promise<void> }>(
        "dashboard-sigma-rules.js",
        [],
        { document, fetch },
      );
      return { mod, box, file, fetch };
    }

    it("refuses a zip over the server cap without reading it", async () => {
      const { mod, box, file, fetch } = loadWithFile(SIGMA_RELEASE_MAX_ZIP_BYTES + 1);
      await mod.sigmaInstallFile();
      expect(file.arrayBuffer).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
      expect(box.textContent).toContain("too large");
      expect(box.textContent).toContain("32 MB");
    });

    it("reads a zip exactly at the server cap", async () => {
      const { mod, file } = loadWithFile(SIGMA_RELEASE_MAX_ZIP_BYTES);
      await mod.sigmaInstallFile();
      expect(file.arrayBuffer).toHaveBeenCalledTimes(1);
    });
  });
  // #2216: in the public demo every change is refused by the server. The rule Enable/Disable and
  // Install buttons must be disabled like Check, File and Roll back, not answer with a 403.
  describe("demo mode", () => {
    type Node = Record<string, unknown> & { children: Node[]; listeners: string[] };
    function makeNode(tag: string): Node {
      const node: Node = {
        tag,
        children: [],
        listeners: [],
        textContent: "",
        className: "",
        dataset: {},
        hidden: false,
        appendChild(child: Node) {
          node.children.push(child);
          return child;
        },
        addEventListener(type: string) {
          node.listeners.push(type);
        },
      };
      return node;
    }
    function buttons(root: Node): Node[] {
      const own = root.tag === "button" ? [root] : [];
      return [...own, ...root.children.flatMap(buttons)];
    }
    function load(demo: boolean) {
      const nodes: Record<string, Node> = {
        sigmaRulesBody: makeNode("tbody"),
        sigmaRulesCount: makeNode("span"),
        sigmaPreview: makeNode("div"),
        sigmaDemo: makeNode("div"),
      };
      nodes.sigmaDemo.hidden = !demo;
      const prompt = vi.fn(() => "noisy");
      const fetch = vi.fn(async () => ({ ok: true, json: async () => ({}) }));
      const document = {
        readyState: "loading",
        addEventListener: () => undefined,
        getElementById: (id: string) => nodes[id] ?? null,
        createElement: (tag: string) => makeNode(tag),
      };
      const mod = loadDashboardModule<{
        sigmaRenderRules: (list: unknown[]) => void;
        sigmaRenderPreview: (p: unknown) => void;
        sigmaToggleRule: (id: string, disable: boolean) => Promise<void>;
        sigmaExcludeRule: (id: string) => Promise<void>;
        sigmaRemoveExclusion: (id: string, field: string, value: string) => Promise<void>;
      }>("dashboard-sigma-rules.js", [], { document, fetch, prompt });
      return { mod, nodes, prompt, fetch };
    }
    const RULES = [
      {
        id: "r1",
        title: "Rule one",
        source: "cloudtrail",
        outcome: "loaded",
        exclusions: [{ field: "userIdentity.arn", value: "<img src=x onerror=alert(1)>", reason: "backup" }],
      },
      { id: "r2", title: "Rule two", source: "cloudtrail", outcome: "disabled" },
    ];
    const PREVIEW = {
      token: "t",
      usable: true,
      release: { release: "r2026-01-01", source: "github", sha256: "abc" },
      diff: { added: [], changed: [], removed: [], otherSources: 0 },
      loads: {},
    };

    it("disables the rule Exclude, Enable/Disable and Remove buttons when the demo notice shows", () => {
      const { mod, nodes } = load(true);
      mod.sigmaRenderRules(RULES);
      const btns = buttons(nodes.sigmaRulesBody);
      // r1: one Remove (under its exclusion), Exclude… and Disable; r2: Enable.
      expect(btns.map((b) => b.textContent)).toEqual(["Remove", "Exclude…", "Disable", "Enable"]);
      for (const b of btns) {
        expect(b.disabled).toBe(true);
        expect(b.title).toBe("Not available in the public demo");
      }
    });

    it("leaves the rule buttons enabled outside the demo", () => {
      const { mod, nodes } = load(false);
      mod.sigmaRenderRules(RULES);
      const btns = buttons(nodes.sigmaRulesBody);
      expect(btns).toHaveLength(4);
      for (const b of btns) expect(b.disabled).toBeFalsy();
    });

    it("disables Install this release in the demo", () => {
      const { mod, nodes } = load(true);
      mod.sigmaRenderPreview(PREVIEW);
      const [install] = buttons(nodes.sigmaPreview);
      expect(install.disabled).toBe(true);
    });

    it("leaves Install enabled outside the demo for a usable release", () => {
      const { mod, nodes } = load(false);
      mod.sigmaRenderPreview(PREVIEW);
      const [install] = buttons(nodes.sigmaPreview);
      expect(install.disabled).toBe(false);
    });

    function texts(root: Node): string[] {
      return [String(root.textContent ?? ""), ...root.children.flatMap(texts)].filter(Boolean);
    }

    it("lists each exclusion as text, never as HTML (#2218)", () => {
      const { mod, nodes } = load(false);
      mod.sigmaRenderRules(RULES);
      expect(texts(nodes.sigmaRulesBody)).toContain(
        "userIdentity.arn = <img src=x onerror=alert(1)> — backup",
      );
    });

    it("asks nothing and sends nothing when Exclude or Remove is used in the demo", async () => {
      const { mod, prompt, fetch } = load(true);
      await mod.sigmaExcludeRule("r1");
      await mod.sigmaRemoveExclusion("r1", "f", "v");
      expect(prompt).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    });

    it("sends the field, value and reason for Exclude, and remove: true for Remove", async () => {
      const { mod, prompt, fetch } = load(false);
      prompt
        .mockReturnValueOnce("userIdentity.arn")
        .mockReturnValueOnce("*:role/Backup")
        .mockReturnValueOnce("job");
      await mod.sigmaExcludeRule("r1");
      expect(prompt).toHaveBeenCalledTimes(3);
      const calls = fetch.mock.calls as unknown as [string, { method: string; body: string }][];
      expect(calls[0][0]).toBe("/sigma/exclusions");
      expect(calls[0][1].method).toBe("PUT");
      expect(JSON.parse(calls[0][1].body)).toEqual({
        id: "r1",
        field: "userIdentity.arn",
        value: "*:role/Backup",
        reason: "job",
      });
      fetch.mockClear();
      await mod.sigmaRemoveExclusion("r1", "userIdentity.arn", "*:role/Backup");
      const removeCall = fetch.mock.calls[0] as unknown as [string, { body: string }];
      expect(JSON.parse(removeCall[1].body)).toEqual({
        id: "r1",
        field: "userIdentity.arn",
        value: "*:role/Backup",
        remove: true,
      });
    });

    it("sends nothing when the analyst cancels a prompt", async () => {
      const { mod, prompt, fetch } = load(false);
      prompt.mockReturnValueOnce(null as unknown as string);
      await mod.sigmaExcludeRule("r1");
      expect(fetch).not.toHaveBeenCalled();
    });

    it("asks nothing and sends nothing when a rule is toggled in the demo", async () => {
      const { mod, prompt, fetch } = load(true);
      await mod.sigmaToggleRule("r1", true);
      expect(prompt).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    });
  });
});
