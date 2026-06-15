// Content-script (isolated world) orchestration for automated artifact fetching (issue #102).
//
// Flow on a recognized DFIR console:
//   1. adapterForUrl() decides if this tab is a known tool — if not, we do nothing (plain screenshot
//      capture still works via content.ts).
//   2. We ask the service worker to inject pageHook.js into the MAIN world (executeScript bypasses
//      page CSP) and hand the hook the adapter's API URL patterns via postMessage.
//   3. The hook forwards matching API response bodies back; we extract clean rows via the adapter and
//      remember the latest set.
//   4. We inject a floating "Push N rows to DFIR-Companion" button. It only sends to the localhost
//      companion when the analyst clicks it (explicit intent — never automatic).
//   5. If nothing was intercepted, the button falls back to scraping the visible results <table>.
//
// All browser-only glue; the pure logic it calls (adapter matching/extraction, matrixToRows) is
// unit-tested separately.

import { adapterForUrl } from "./adapters/registry.js";
import type { Adapter, CapturedArtifact } from "./adapters/types.js";
import { matrixToRows } from "./adapters/domTable.js";
import { DFIR_CAPTURE_MSG, DFIR_CONFIG_MSG, DFIR_READY_MSG } from "./adapters/bridge.js";
import type { EnsureHookMessage, PushArtifactMessage, PushArtifactResult } from "./types.js";

const BTN_ID = "dfir-companion-push-btn";

let activeAdapter: Adapter | null = null;
let latest: CapturedArtifact | null = null;
let busy = false;

export async function initArtifactCapture(): Promise<void> {
  activeAdapter = adapterForUrl(location.href);
  if (!activeAdapter) return;

  // Attach the listener BEFORE requesting injection so we never miss the hook's "ready" handshake.
  window.addEventListener("message", onPageMessage);
  requestHookInjection();
  sendConfig();

  // Only show the push button when a case is selected — so the button stays hidden when the
  // analyst is not actively investigating and hasn't connected the extension to a case.
  const stored = await chrome.storage.local.get("settings");
  const initialCaseId = (stored.settings as { caseId?: string } | undefined)?.caseId ?? "";
  if (initialCaseId) ensureButton();

  // Dynamically show/hide when the analyst connects or disconnects from a case via the popup.
  chrome.storage.onChanged.addListener((changes) => {
    if (!changes.settings) return;
    const newCaseId = (changes.settings.newValue as { caseId?: string } | undefined)?.caseId ?? "";
    if (newCaseId) {
      ensureButton();
    } else {
      document.getElementById(BTN_ID)?.remove();
    }
  });
}

// ── MAIN-world hook injection + handshake ──────────────────────────────────────────────────────

// Ask the service worker to inject the MAIN-world fetch/XHR hook. We go via the SW + executeScript
// (rather than a <script src> tag) because executeScript bypasses the page's CSP, and DFIR consoles
// tend to ship strict CSPs. Once the hook installs it posts a "ready" message and we (re)send the URL
// patterns; sendConfig() below also fires proactively in case the hook was already installed on a
// prior navigation in this tab (it's idempotent).
function requestHookInjection(): void {
  const msg: EnsureHookMessage = { kind: "ensure_hook" };
  try { void chrome.runtime.sendMessage(msg); } catch { /* SW asleep / page CSP — scrape still works */ }
}

function sendConfig(): void {
  if (!activeAdapter) return;
  window.postMessage({ source: DFIR_CONFIG_MSG, patterns: [...activeAdapter.apiPatterns] }, "*");
}

function onPageMessage(ev: MessageEvent): void {
  if (ev.source !== window || !activeAdapter) return;
  const d = ev.data as { source?: string; url?: string; body?: string } | null;
  if (!d || typeof d.source !== "string") return;

  if (d.source === DFIR_READY_MSG) { sendConfig(); return; }

  if (d.source === DFIR_CAPTURE_MSG && typeof d.body === "string") {
    let parsed: unknown;
    try { parsed = JSON.parse(d.body); } catch { return; } // non-JSON body — ignore
    let rows: unknown[] | null = null;
    try { rows = activeAdapter.extractRows(String(d.url ?? ""), parsed); } catch { rows = null; }
    if (rows && rows.length) {
      const label = labelRows(rows, String(d.url ?? ""));
      latest = { adapterId: activeAdapter.id, rows, sourceUrl: location.href, via: "intercept", label };
      renderButton();
    }
  }
}

// Stamp the artifact/notebook the rows came from onto each row (as `_Source`, which the companion's
// importer already reads) so every timeline event records its source and the analyst can navigate
// back. Returns the derived label (also used for the pushed evidence filename). #102
function labelRows(rows: unknown[], apiUrl: string): string {
  if (!activeAdapter?.sourceLabel) return "";
  let label = "";
  try {
    // The Velociraptor results-tab artifact selector is a <select>; collect those first (the chosen
    // option is the artifact being viewed), then <input> values, so the selector wins.
    const selects = Array.from(document.querySelectorAll("select")).map((s) => s.value || "");
    const inputs = Array.from(document.querySelectorAll("input")).map((i) => i.value || "");
    const domInputs = [...selects, ...inputs].filter(Boolean);
    // Notebook cells title their artifact in a heading (<h1>DetectRaptor.Windows.Detection.Evtx</h1>).
    const domHeadings = Array.from(document.querySelectorAll("h1,h2,h3")).map((h) => h.textContent || "").filter(Boolean);
    label = activeAdapter.sourceLabel({ apiUrl, pageUrl: location.href, domInputs, domHeadings, rows });
  } catch { label = ""; }
  if (label) {
    for (const r of rows) {
      if (r && typeof r === "object" && !(r as Record<string, unknown>)._Source) {
        (r as Record<string, unknown>)._Source = label;
      }
    }
  }
  return label;
}

// ── DOM-scrape fallback ────────────────────────────────────────────────────────────────────────

function scrapeVisibleTable(): CapturedArtifact | null {
  if (!activeAdapter) return null;
  const selector = activeAdapter.tableSelector || "table";
  let best: HTMLTableElement | null = null;
  let bestRows = 0;
  document.querySelectorAll<HTMLTableElement>(selector).forEach((t) => {
    const n = t.querySelectorAll("tr").length;
    if (n > bestRows) { best = t; bestRows = n; }
  });
  if (!best || bestRows < 2) return null;

  const { headers, rows } = readTableMatrix(best);
  const objs = matrixToRows(headers, rows);
  if (!objs.length) return null;
  const label = labelRows(objs, "");
  return { adapterId: activeAdapter.id, rows: objs, sourceUrl: location.href, via: "scrape", label };
}

function readTableMatrix(table: HTMLTableElement): { headers: string[]; rows: string[][] } {
  const cellText = (c: Element) => (c.textContent ?? "").replace(/\s+/g, " ").trim();
  const trs = Array.from(table.querySelectorAll("tr"));
  let headers: string[] = [];
  let bodyStart = 0;

  const headTr = table.querySelector("thead tr") ?? trs[0];
  if (headTr) {
    const ths = Array.from(headTr.querySelectorAll("th"));
    if (ths.length) {
      headers = ths.map(cellText);
      if (headTr === trs[0]) bodyStart = 1; // first row was the header
    } else if (headTr === trs[0]) {
      headers = Array.from(headTr.querySelectorAll("td")).map(cellText);
      bodyStart = 1;
    }
  }

  const bodyTrs = table.querySelector("tbody")
    ? Array.from(table.querySelectorAll("tbody tr"))
    : trs.slice(bodyStart);
  const rows = bodyTrs
    .map((tr) => Array.from(tr.querySelectorAll("td,th")).map(cellText))
    .filter((cells) => cells.some((c) => c !== ""));
  return { headers, rows };
}

// ── Floating push button ─────────────────────────────────────────────────────────────────────

function ensureButton(): void {
  if (document.getElementById(BTN_ID)) return;
  const btn = document.createElement("button");
  btn.id = BTN_ID;
  btn.type = "button";
  Object.assign(btn.style, {
    position: "fixed", right: "16px", bottom: "16px", zIndex: "2147483647",
    padding: "8px 12px", borderRadius: "8px", border: "none", cursor: "pointer",
    font: "600 13px system-ui, sans-serif", color: "#fff", background: "#555",
    boxShadow: "0 2px 8px rgba(0,0,0,.3)", maxWidth: "320px",
  } as Partial<CSSStyleDeclaration>);
  btn.addEventListener("click", onClick);
  // The page may not have a <body> yet at document_idle on some SPAs — guard.
  (document.body || document.documentElement).appendChild(btn);
  renderButton();
}

function renderButton(state?: { text: string; color: string }): void {
  const btn = document.getElementById(BTN_ID) as HTMLButtonElement | null;
  if (!btn || !activeAdapter) return;
  if (state) { btn.textContent = state.text; btn.style.background = state.color; return; }
  if (latest) {
    btn.textContent = `📤 Push ${latest.rows.length} ${activeAdapter.label} rows → DFIR-Companion`;
    btn.style.background = "#1a7f37"; // green — data ready to push
  } else {
    btn.textContent = `📤 Push ${activeAdapter.label} table → DFIR-Companion`;
    btn.style.background = "#555"; // grey — will scrape the visible table on click
  }
}

async function onClick(): Promise<void> {
  if (busy || !activeAdapter) return;
  const artifact = latest ?? scrapeVisibleTable();
  if (!artifact || !artifact.rows.length) {
    flash("No results found on this page", "#b35900");
    return;
  }
  busy = true;
  renderButton({ text: `Pushing ${artifact.rows.length} rows…`, color: "#0b5cad" });
  try {
    const msg: PushArtifactMessage = {
      kind: "push_artifact",
      adapterId: artifact.adapterId,
      rows: artifact.rows,
      sourceUrl: artifact.sourceUrl,
      sourceLabel: artifact.label,
    };
    const res = (await chrome.runtime.sendMessage(msg)) as PushArtifactResult | undefined;
    if (res?.ok) {
      flash(`✓ Pushed ${res.rows ?? artifact.rows.length} rows to "${res.caseId}"`, "#1a7f37");
    } else {
      flash(`✗ ${res?.error ?? "Push failed"}`, "#b42318");
    }
  } catch (err) {
    flash(`✗ ${(err as Error).message}`, "#b42318");
  } finally {
    busy = false;
  }
}

// Show a transient status on the button, then restore the normal label.
function flash(text: string, color: string): void {
  renderButton({ text, color });
  window.setTimeout(() => { if (!busy) renderButton(); }, 4000);
}
