import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { dashboardClientSource } from "../helpers/dashboardModule.js";
// The Essential-mode rules are CSS, and #415 moved the CSS into its own file.
import { dashboardStylesheet } from "../helpers/dashboardModule.js";

import { validateEnvUpdates } from "../../src/settings/envManager.js";

/**
 * The Settings modal renders 16 tabs and 257 `env-*` fields, almost all of them tuning knobs that
 * already work at their defaults. Essential mode shows only the controls a feature is DEAD without —
 * API keys, service URLs, tool binaries — by opting each one in with a `data-essential` attribute.
 * Everything unmarked is hidden by CSS, so a newly added knob is outside Essential by default: the safe way
 * round, and the reason these tests pin the Essential set exhaustively rather than as a floor.
 *
 * Editing ESSENTIAL_ENV_KEYS is the review moment that stops Essential drifting back toward 257 fields.
 */

/** The env keys each Settings tab shows in Essential mode. One entry per tab that has any. */
const ESSENTIAL_ENV_KEYS: Record<string, string[]> = {
  general: [], // the Essential General view is the setup-wizard button + investigator name, no env fields
  // The three models you can point somewhere. Timeouts, token caps, prompt-file overrides and the
  // VQL hunt model are All-only — each has a working default or falls back to the synthesis model.
  ai: [
    "DFIR_VISION_PROVIDER",
    "DFIR_VISION_MODEL",
    "DFIR_VISION_KEY",
    "DFIR_VISION_BASE_URL",
    "DFIR_AI_SYNTH_PROVIDER",
    "DFIR_AI_SYNTH_MODEL",
    "DFIR_AI_SYNTH_KEY",
    "DFIR_AI_SYNTH_BASE_URL",
    "DFIR_AI_SECOND_OPINION_PROVIDER",
    "DFIR_AI_SECOND_OPINION_MODEL",
    "DFIR_AI_SECOND_OPINION_KEY",
    "DFIR_AI_SECOND_OPINION_BASE_URL",
  ],
  // Credentials, plus each self-hostable source's "Skip TLS verify" flag. `_CA` (finding a bundle
  // path is a deliberate trip), the keyless hashlookup/RDAP/GeoIP endpoint URLs, the GeoIP map
  // limits, and every throttle delay stay All-only.
  enrichment: [
    "DFIR_VT_KEY",
    "DFIR_ABUSEIPDB_KEY",
    "DFIR_HUNTINGCH_KEY",
    "DFIR_ROCKYRACCOON_KEY",
    "DFIR_CROWDSTRIKE_CLIENT_ID",
    "DFIR_CROWDSTRIKE_CLIENT_SECRET",
    "DFIR_MISP_URL",
    "DFIR_MISP_KEY",
    "DFIR_MISP_INSECURE",
    "DFIR_YETI_URL",
    "DFIR_YETI_KEY",
    "DFIR_YETI_INSECURE",
    "DFIR_OPENCTI_URL",
    "DFIR_OPENCTI_KEY",
    "DFIR_OPENCTI_INSECURE",
    "DFIR_GEOIP_KEY",
  ],
  // Keys only. Domain limits, the HIBP user-agent, the DeHashed base URL and the delay all default.
  exposure: ["DFIR_LEAKCHECK_KEY", "DFIR_HIBP_KEY", "DFIR_DEHASHED_KEY", "DFIR_SHODAN_KEY"],
  // What each integration needs to connect at all. Optional IRIS ids, `_CA`, the 15
  // Velociraptor tuning/VQL knobs, and DFIR_PUBLIC_URL (link rendering only) are All-only.
  //
  // EVERY "Skip TLS verify" flag the dashboard can write is Essential, alongside the global
  // DFIR_TLS_ALLOW_INSECURE_EXTERNAL opt-in a non-loopback host additionally needs. A self-hosted
  // instance behind a self-signed cert is dead without them, and the error the analyst actually
  // meets ("self-signed certificate ... DEPTH_ZERO_SELF_SIGNED_CERT") names no setting at all — so
  // burying the flag in All left the connect flow failing with no visible knob to reach for. Jira
  // and ServiceNow have the same flag and are deliberately NOT here: theirs are read-only by
  // design (a security boundary the dashboard must not move), and Essential never shows read-only.
  integrations: [
    "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
    "DFIR_IRIS_URL",
    "DFIR_IRIS_KEY",
    "DFIR_IRIS_INSECURE",
    "DFIR_TIMESKETCH_URL",
    "DFIR_TIMESKETCH_USER",
    "DFIR_TIMESKETCH_PASSWORD",
    "DFIR_TIMESKETCH_INSECURE",
    "DFIR_NOTION_TOKEN",
    "DFIR_NOTION_DATABASE_ID",
    "DFIR_NOTION_PARENT_PAGE_ID",
    "DFIR_NOTION_INSECURE",
    "DFIR_CLICKUP_TOKEN",
    "DFIR_CLICKUP_LIST_ID",
    "DFIR_CLICKUP_INSECURE",
    "DFIR_NOTIFY_INSECURE",
    "DFIR_VELOCIRAPTOR_API_CONFIG",
    "DFIR_VELOCIRAPTOR_BINARY",
    "DFIR_VELOCIRAPTOR_GUI_URL",
    "DFIR_PUSH_TOKEN",
  ],
  // Tools is All-only in full — no entry here, and its tab is hidden in Essential. Every external
  // binary is blank-means-off: nothing is broken by leaving Hayabusa, Suricata, Snort, YARA and the
  // Velociraptor CLI unconfigured, so wiring them up is a deliberate trip to All.
  //
  // The Notifications TAB contributes no env keys — its config lives behind the /notifications
  // API, which is why that pane opts in whole with data-essential="pane" rather than field by
  // field. The "Notifications (global)" block whose DFIR_NOTIFY_INSECURE is listed above sits on
  // the INTEGRATIONS tab, not that one, and is the webhook half of the same self-signed-cert story
  // (a self-hosted Mattermost). DFIR_NOTIFY_CA and DFIR_PUBLIC_URL beside it stay All-only.
};

const ALL_ESSENTIAL = Object.values(ESSENTIAL_ENV_KEYS).flat().sort();

// The markup is still in dashboard.html; the Essential/All WIRING moved to
// js/dashboard-settings-modal.js (#415 tier 3). Both are read here so the assertions about markup
// and the assertions about behaviour keep working from one source, as they did when the two lived
// in the same file. Reading only the page would have made every wiring assertion compare against
// "" — which is a pass for `not.toContain` and a confusing failure for the rest.
async function dashboard(): Promise<string> {
  const [page, modal] = await Promise.all([
    readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8"),
    readFile(new URL("../../../public/js/dashboard-settings-modal.js", import.meta.url), "utf8"),
  ]);
  return `${page}\n${modal}`;
}

/** Whole-token class match. A `\b`-based regex would read `class="sfield-row"` as having `sfield`
 *  (the hyphen is a word boundary), which made every marked ROW look like a marked FIELD and swept
 *  its unmarked All-only siblings into the Essential set. */
const hasClass = (attrs: string, c: string) => {
  const m = /class="([^"]*)"/.exec(attrs);
  return !!m && m[1].split(/\s+/).includes(c);
};
/** A bare `data-essential`. Deliberately excludes `data-essential="pane"`, which is a pane-level opt-in. */
const isMarked = (attrs: string) => /\bdata-essential\b(?!=)/.test(attrs);

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
    let depth = 1,
      end = open.lastIndex,
      t: RegExpExecArray | null;
    while (depth > 0 && (t = tok.exec(html))) {
      depth += t[0] === "</div>" ? -1 : 1;
      end = tok.lastIndex;
    }
    out.push(html.slice(m.index, end));
  }
  return out;
}

/** The env keys visible in Essential mode: those inside a `.sfield` that carries `data-essential`. */
function essentialEnvKeys(html: string): string[] {
  const keys = new Set<string>();
  for (const block of divBlocks(html, (a) => hasClass(a, "sfield") && isMarked(a)))
    for (const m of block.matchAll(/id="env-([A-Za-z0-9_]+)"/g)) keys.add(m[1]);
  return [...keys].sort();
}

function paneInfo(html: string): { id: string; all: boolean; hasEssential: boolean }[] {
  return divBlocks(html, (a) => hasClass(a, "stab-pane")).map((block) => {
    const openTag = block.slice(0, block.indexOf(">") + 1);
    const id = /id="stab-([a-z-]+)"/.exec(openTag)![1];
    const all = /data-essential="pane"/.test(openTag);
    return { id, all, hasEssential: all || /data-essential\b/.test(block.slice(openTag.length)) };
  });
}

describe("Settings Essential mode — the pinned field set", () => {
  it("marks exactly the pinned Essential env fields — no more, no less", async () => {
    expect(essentialEnvKeys(await dashboard())).toEqual(ALL_ESSENTIAL);
  });

  it("never shows an Essential field the server would refuse to save", async () => {
    const keys = essentialEnvKeys(await dashboard());
    expect(validateEnvUpdates(Object.fromEntries(keys.map((k) => [k, "x"])))).toEqual([]);
  });

  it("never marks a read-only field Essential", async () => {
    const html = await dashboard();
    const readOnly = [...html.matchAll(/id="env-([A-Za-z0-9_]+)"[^>]*\b(?:readonly|disabled)\b/g)].map(
      (m) => m[1],
    );
    expect(essentialEnvKeys(html).filter((k) => readOnly.includes(k))).toEqual([]);
  });
});

describe("Settings Essential mode — structural invariants the CSS depends on", () => {
  it("marks the row around every Essential field, so the CSS can't swallow it", async () => {
    const html = await dashboard();
    const swallowed: string[] = [];
    for (const row of divBlocks(html, (a) =>
      ["sfield-row", "sfield-row3", "sgrid"].some((c) => hasClass(a, c)),
    )) {
      const openTag = row.slice(0, row.indexOf(">") + 1);
      if (isMarked(openTag)) continue;
      for (const sf of divBlocks(row.slice(openTag.length), (a) => hasClass(a, "sfield") && isMarked(a)))
        for (const m of sf.matchAll(/id="env-([A-Za-z0-9_]+)"/g)) swallowed.push(m[1]);
    }
    expect(swallowed).toEqual([]);
  });

  it("shows a tab in Essential exactly when its pane has Essential content", async () => {
    const html = await dashboard();
    // Attribute-order agnostic on purpose: where `data-essential` sits in the tag is a style choice,
    // and a contributor who writes it in a different order deserves a real failure, not this one.
    const tabs = new Map(
      [...html.matchAll(/<button\b([^>]*\bdata-stab="([a-z-]+)"[^>]*)>/g)].map(
        (m) => [m[2], /\bdata-essential\b/.test(m[1])] as const,
      ),
    );
    for (const { id, hasEssential } of paneInfo(html)) {
      expect({ tab: id, shown: tabs.get(id) }).toEqual({ tab: id, shown: hasEssential });
    }
  });

  it("uses the whole-pane escape hatch only for Notifications", async () => {
    const all = paneInfo(await dashboard())
      .filter((p) => p.all)
      .map((p) => p.id);
    expect(all.length).toBeLessThanOrEqual(1);
    expect(all.filter((id) => id !== "notifications")).toEqual([]);
  });
});

describe("Settings Essential mode — wiring", () => {
  it("hides everything unmarked, beating the inline display JS sets on panels", () => {
    const html = dashboardStylesheet();
    // The `:not([data-searching])` on each is what suspends Essential while the search box has a
    // query, so a search can reach the tabs and fields this mode hides. Keeping it here means
    // dropping it is a failure in BOTH suites; tests/settings/settingsSearch.test.ts additionally
    // pins it onto every Essential rule, including ones added after this list.
    for (const rule of [
      '.settings-modal[data-mode="essential"]:not([data-searching]) .stab:not([data-essential])',
      '.settings-modal[data-mode="essential"]:not([data-searching]) .stab-pane:not([data-essential="pane"]) > *:not([data-essential])',
      '.settings-modal[data-mode="essential"]:not([data-searching]) :is(.sfield-row, .sfield-row3, .sgrid) > .sfield:not([data-essential])',
    ]) {
      const at = html.indexOf(rule);
      expect(at, `missing CSS rule: ${rule}`).toBeGreaterThan(-1);
      expect(html.slice(at, at + rule.length + 40)).toContain("display: none !important");
    }
  });

  // A row that contributes ONE field to Essential used to draw it at its column share — 49% in a
  // `.sfield-row`, 33% in a `.sfield-row3` — with the rest of the line blank, because `display: none`
  // on its row-mates removes them from a FIXED grid without collapsing their tracks. 22 rows sit in
  // that position (every enrichment and exposure API key among them), so the two widths landed a few
  // rows apart — Timesketch's "Skip TLS verify" above Notion's — and read as a bug rather than a
  // layout. Pinned because the fix is invisible in the markup: nothing about a stranded field says it
  // is stranded, so a later rewrite of the hiding rules can drop the span with nothing else failing.
  it("lets a row's only Essential field span the whole row", () => {
    const css = dashboardStylesheet();
    const rule =
      '.settings-modal[data-mode="essential"]:not([data-searching]) :is(.sfield-row, .sfield-row3, .sgrid):not(:has(> .sfield[data-essential] ~ .sfield[data-essential])) > .sfield[data-essential]';
    const at = css.indexOf(rule);
    expect(at, "missing the lone-field span rule").toBeGreaterThan(-1);
    expect(css.slice(at, at + rule.length + 40)).toContain("grid-column: 1 / -1");
  });

  it("opens in Essential unless the analyst chose All", async () => {
    const html = await dashboard();
    const fn = html.slice(html.indexOf("function settingsMode()"), html.indexOf("function stabHidden("));
    // Whitespace-tolerant: this was one line in the inline block and is four after prettier
    // formatted the extracted module. What matters is that "all" is the only stored value that
    // selects All, so anything else — including a missing key — opens Essential.
    expect(fn.replace(/\s+/g, " ")).toContain(
      'localStorage.getItem(SETTINGS_MODE_KEY) === "all" ? "all" : "essential"',
    );
    expect(html.slice(html.indexOf("function openSettingsModal()"))).toMatch(
      /applySettingsMode\(settingsMode\(\)\)/,
    );
  });

  it("routes Settings deep links through the helper that unhides the target tab", async () => {
    // Whole-client source, not the page plus one module: the three deep links now sit in three
    // DIFFERENT modules (velo-monitors, settings-tools, views-editor) after #415 tier 3. The
    // invariant is "no deep link anywhere hand-rolls the tab click", so the haystack has to be
    // everything the page loads.
    const html = dashboardClientSource();
    for (const t of ["velociraptor", "tools", "dashboard-views"])
      expect(html).toContain(`openSettingsTab("${t}")`);
    // The old hand-rolled form (open the modal, then click a tab) lands on a hidden tab in Essential.
    expect(html).not.toMatch(/querySelector\('\.stab\[data-stab="[a-z-]+"\]'\)/);
  });
});
