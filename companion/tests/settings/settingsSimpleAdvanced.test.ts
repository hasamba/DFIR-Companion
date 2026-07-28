import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

import { validateEnvUpdates } from "../../src/settings/envManager.js";

/**
 * The Settings modal renders 16 tabs and 257 `env-*` fields, almost all of them tuning knobs that
 * already work at their defaults. Simple mode shows only the controls a feature is DEAD without —
 * API keys, service URLs, tool binaries — by opting each one in with a `data-simple` attribute.
 * Everything unmarked is hidden by CSS, so a newly added knob is Advanced by default: the safe way
 * round, and the reason these tests pin the Simple set exhaustively rather than as a floor.
 *
 * Editing SIMPLE_ENV_KEYS is the review moment that stops Simple drifting back toward 257 fields.
 */

/** The env keys each Settings tab shows in Simple mode. One entry per tab that has any. */
const SIMPLE_ENV_KEYS: Record<string, string[]> = {
  general: [],   // the Simple General view is the setup-wizard button + investigator name, no env fields
  // The three models you can point somewhere. Timeouts, token caps, prompt-file overrides and the
  // VQL hunt model stay Advanced — each has a working default or falls back to the synthesis model.
  ai: [
    "DFIR_VISION_PROVIDER", "DFIR_VISION_MODEL", "DFIR_VISION_KEY", "DFIR_VISION_BASE_URL",
    "DFIR_AI_SYNTH_PROVIDER", "DFIR_AI_SYNTH_MODEL", "DFIR_AI_SYNTH_KEY", "DFIR_AI_SYNTH_BASE_URL",
    "DFIR_AI_SECOND_OPINION_PROVIDER", "DFIR_AI_SECOND_OPINION_MODEL",
    "DFIR_AI_SECOND_OPINION_KEY", "DFIR_AI_SECOND_OPINION_BASE_URL",
  ],
};

const ALL_SIMPLE = Object.values(SIMPLE_ENV_KEYS).flat().sort();

async function dashboard(): Promise<string> {
  return readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
}

const hasClass = (attrs: string, c: string) => new RegExp(`class="[^"]*\\b${c}\\b`).test(attrs);
/** A bare `data-simple`. Deliberately excludes `data-simple="all"`, which is a pane-level opt-in. */
const isMarked = (attrs: string) => /\bdata-simple\b(?!=)/.test(attrs);

/**
 * Every `<div>` whose attributes satisfy `pred`, returned as its complete outer HTML. Depth is
 * counted on `<div>`/`</div>` only, which is exact for Settings markup: the blocks nest divs, and
 * the deepest non-div content is a `<label>`/`<input>`/`<select>` that never contains one.
 */
function divBlocks(html: string, pred: (attrs: string) => boolean): string[] {
  const out: string[] = [];
  const open = /<div\b([^>]*)>/g;
  let m: RegExpExecArray | null;
  while ((m = open.exec(html))) {
    if (!pred(m[1])) continue;
    const tok = /<div\b[^>]*>|<\/div>/g;
    tok.lastIndex = open.lastIndex;
    let depth = 1, end = open.lastIndex, t: RegExpExecArray | null;
    while (depth > 0 && (t = tok.exec(html))) {
      depth += t[0] === "</div>" ? -1 : 1;
      end = tok.lastIndex;
    }
    out.push(html.slice(m.index, end));
  }
  return out;
}

/** The env keys visible in Simple mode: those inside a `.sfield` that carries `data-simple`. */
function simpleEnvKeys(html: string): string[] {
  const keys = new Set<string>();
  for (const block of divBlocks(html, a => hasClass(a, "sfield") && isMarked(a)))
    for (const m of block.matchAll(/id="env-([A-Za-z0-9_]+)"/g)) keys.add(m[1]);
  return [...keys].sort();
}

function paneInfo(html: string): { id: string; all: boolean; hasSimple: boolean }[] {
  return divBlocks(html, a => hasClass(a, "stab-pane")).map(block => {
    const openTag = block.slice(0, block.indexOf(">") + 1);
    const id = /id="stab-([a-z-]+)"/.exec(openTag)![1];
    const all = /data-simple="all"/.test(openTag);
    return { id, all, hasSimple: all || /data-simple\b/.test(block.slice(openTag.length)) };
  });
}

describe("Settings Simple mode — the pinned field set", () => {
  it("marks exactly the pinned Simple env fields — no more, no less", async () => {
    expect(simpleEnvKeys(await dashboard())).toEqual(ALL_SIMPLE);
  });

  it("never shows a Simple field the server would refuse to save", async () => {
    const keys = simpleEnvKeys(await dashboard());
    expect(validateEnvUpdates(Object.fromEntries(keys.map(k => [k, "x"])))).toEqual([]);
  });

  it("never marks a read-only field Simple", async () => {
    const html = await dashboard();
    const readOnly = [...html.matchAll(/id="env-([A-Za-z0-9_]+)"[^>]*\b(?:readonly|disabled)\b/g)].map(m => m[1]);
    expect(simpleEnvKeys(html).filter(k => readOnly.includes(k))).toEqual([]);
  });
});

describe("Settings Simple mode — structural invariants the CSS depends on", () => {
  it("marks the row around every Simple field, so the CSS can't swallow it", async () => {
    const html = await dashboard();
    const swallowed: string[] = [];
    for (const row of divBlocks(html, a => ["sfield-row", "sfield-row3", "sgrid"].some(c => hasClass(a, c)))) {
      const openTag = row.slice(0, row.indexOf(">") + 1);
      if (isMarked(openTag)) continue;
      for (const sf of divBlocks(row.slice(openTag.length), a => hasClass(a, "sfield") && isMarked(a)))
        for (const m of sf.matchAll(/id="env-([A-Za-z0-9_]+)"/g)) swallowed.push(m[1]);
    }
    expect(swallowed).toEqual([]);
  });

  it("shows a tab in Simple exactly when its pane has Simple content", async () => {
    const html = await dashboard();
    const tabs = new Map([...html.matchAll(/<button class="stab[^"]*" data-stab="([a-z-]+)"([^>]*)>/g)]
      .map(m => [m[1], /\bdata-simple\b/.test(m[2])] as const));
    for (const { id, hasSimple } of paneInfo(html)) {
      expect({ tab: id, shown: tabs.get(id) }).toEqual({ tab: id, shown: hasSimple });
    }
  });

  it("uses the whole-pane escape hatch only for Notifications", async () => {
    const all = paneInfo(await dashboard()).filter(p => p.all).map(p => p.id);
    expect(all.length).toBeLessThanOrEqual(1);
    expect(all.filter(id => id !== "notifications")).toEqual([]);
  });
});

describe("Settings Simple mode — wiring", () => {
  it("hides everything unmarked, beating the inline display JS sets on panels", async () => {
    const html = await dashboard();
    for (const rule of [
      '.settings-modal[data-mode="simple"] .stab:not([data-simple])',
      '.settings-modal[data-mode="simple"] .stab-pane:not([data-simple="all"]) > *:not([data-simple])',
      '.settings-modal[data-mode="simple"] :is(.sfield-row, .sfield-row3, .sgrid) > .sfield:not([data-simple])',
    ]) {
      const at = html.indexOf(rule);
      expect(at, `missing CSS rule: ${rule}`).toBeGreaterThan(-1);
      expect(html.slice(at, at + rule.length + 40)).toContain("display: none !important");
    }
  });

  it("opens in Simple unless the analyst chose Advanced", async () => {
    const html = await dashboard();
    const fn = html.slice(html.indexOf("function settingsMode()"), html.indexOf("function stabHidden("));
    expect(fn).toContain('localStorage.getItem(SETTINGS_MODE_KEY) === "advanced" ? "advanced" : "simple"');
    expect(html.slice(html.indexOf("function openSettingsModal()"))).toMatch(/applySettingsMode\(settingsMode\(\)\)/);
  });

  it("routes Settings deep links through the helper that unhides the target tab", async () => {
    const html = await dashboard();
    for (const t of ["velociraptor", "tools", "dashboard-views"]) expect(html).toContain(`openSettingsTab("${t}")`);
    // The old hand-rolled form (open the modal, then click a tab) lands on a hidden tab in Simple.
    expect(html).not.toMatch(/querySelector\('\.stab\[data-stab="[a-z-]+"\]'\)/);
  });
});
