// Content-script (isolated world) orchestration for automated artifact fetching (issue #102).
//
// Flow on a recognized DFIR console:
//   1. adapterForUrl() decides if this tab is a known tool. Unless the popup forces an override
//      (see applyAdapter() / onExtensionMessage() below), an unrecognized page does nothing here
//      — plain screenshot capture still works via content.ts.
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

import { adapterForUrl, adapterById } from "./adapters/registry.js";
import type { Adapter, CapturedArtifact } from "./adapters/types.js";
import { resolveActiveAdapter } from "./adapters/override.js";
import { matrixToRows } from "./adapters/domTable.js";
import { decodeCapturedBodies } from "./adapters/extractUtils.js";
import { DFIR_CAPTURE_MSG, DFIR_CONFIG_MSG, DFIR_READY_MSG } from "./adapters/bridge.js";
import { clampButtonPosition, isDrag, parseButtonPos, type ButtonPos } from "./buttonPosition.js";
import type { EnsureHookMessage, PushArtifactMessage, PushArtifactResult, CaptureStatusResult } from "./types.js";

const BTN_ID = "dfir-companion-push-btn";
// chrome.storage.local key holding the analyst's dragged button position (null = default corner).
const POS_KEY = "pushButtonPos";

let activeAdapter: Adapter | null = null;
let detectedAdapterId: string | null = null;
let overrideAdapterId = ""; // "" | OVERRIDE_NONE | an adapter id — see adapters/override.ts
let latest: CapturedArtifact | null = null;
let busy = false;
// Cached case id — kept in sync so the MutationObserver below can re-inject the button
// synchronously without an async storage read.
let currentCaseId = "";
// Cached dragged position, applied on every (re-)injection. null → keep the default bottom-right.
let buttonPos: ButtonPos | null = null;
// Set briefly after a drag so the trailing click does not fire a push.
let suppressClick = false;

export async function initArtifactCapture(): Promise<void> {
  detectedAdapterId = adapterForUrl(location.href)?.id ?? null;

  // Attach listeners BEFORE activating so we never miss the hook's "ready" handshake or a popup
  // override sent immediately after injection.
  window.addEventListener("message", onPageMessage);
  chrome.runtime.onMessage.addListener(onExtensionMessage);
  applyAdapter();

  // Only show the push button when a case is selected — so the button stays hidden when the
  // analyst is not actively investigating and hasn't connected the extension to a case.
  const stored = await chrome.storage.local.get(["settings", POS_KEY]);
  currentCaseId = (stored.settings as { caseId?: string } | undefined)?.caseId ?? "";
  buttonPos = parseButtonPos(stored[POS_KEY]);
  if (currentCaseId && activeAdapter) ensureButton();

  // Kibana (and other DFIR consoles) are React SPAs — their initial render can replace the
  // document body's children, removing the injected button. Watch for direct-child removal and
  // re-inject whenever the button disappears while a case is selected.
  const bodyTarget = document.body ?? document.documentElement;
  const bodyObserver = new MutationObserver(() => {
    if (currentCaseId && activeAdapter && !document.getElementById(BTN_ID)) ensureButton();
  });
  bodyObserver.observe(bodyTarget, { childList: true });

  // Dynamically show/hide when the analyst connects or disconnects from a case via the popup.
  chrome.storage.onChanged.addListener((changes) => {
    // Sync the dragged position across already-open tabs.
    if (changes[POS_KEY]) {
      buttonPos = parseButtonPos(changes[POS_KEY].newValue);
      const b = document.getElementById(BTN_ID) as HTMLButtonElement | null;
      if (b) applyButtonPosition(b);
    }
    if (!changes.settings) return;
    currentCaseId = (changes.settings.newValue as { caseId?: string } | undefined)?.caseId ?? "";
    if (currentCaseId && activeAdapter) {
      ensureButton();
    } else {
      document.getElementById(BTN_ID)?.remove();
    }
  });
}

// (Re)compute which adapter is active from detection + override, reset captured state, and — when
// an adapter is now active — (re)request the MAIN-world hook with its API patterns. Called once at
// init, and again whenever the popup changes the override for this tab. Unlike before manual
// override existed, this now runs (and the listeners above are registered) even on pages
// adapterForUrl doesn't recognize — cheaply, since applyAdapter() itself no-ops until an adapter
// is actually active — so a later popup override can still activate capture on that page.
function applyAdapter(): void {
  const id = resolveActiveAdapter(detectedAdapterId, overrideAdapterId);
  if (id !== (activeAdapter?.id ?? null)) {
    activeAdapter = id ? adapterById(id) : null;
    latest = null;
  }
  if (activeAdapter) {
    requestHookInjection();
    sendConfig();
  }
  if (currentCaseId && activeAdapter) {
    ensureButton();
    renderButton();
  } else {
    document.getElementById(BTN_ID)?.remove();
  }
}

// ── Manual override (popup ⇄ this content script) ────────────────────────────────────────────
// The popup can't reach adapterForUrl's result directly — it lives here, in the tab. These two
// message kinds (sent via chrome.tabs.sendMessage, which — unlike chrome.runtime.sendMessage from
// a content script — targets THIS listener, not the service worker's onMessage in
// serviceWorker.ts) let the popup read and override it. See adapters/override.ts for the
// resolution rule and popup.ts for the UI.
function onExtensionMessage(
  msg: unknown,
  _sender: chrome.runtime.MessageSender,
  sendResponse: (response: CaptureStatusResult) => void,
): boolean | undefined {
  const m = msg as { kind?: string; overrideAdapterId?: string } | null;
  if (!m || typeof m.kind !== "string") return undefined;
  if (m.kind === "get_capture_status") {
    sendResponse(captureStatus());
    return true;
  }
  if (m.kind === "set_adapter_override") {
    overrideAdapterId = typeof m.overrideAdapterId === "string" ? m.overrideAdapterId : "";
    applyAdapter();
    sendResponse(captureStatus());
    return true;
  }
  return undefined;
}

function captureStatus(): CaptureStatusResult {
  return {
    detectedAdapterId,
    overrideAdapterId,
    activeLabel: activeAdapter?.label ?? null,
    rowCount: latest?.rows.length ?? 0,
  };
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
    // Decoding may be async (compressed bfetch) — kick it off and don't block the message handler.
    void ingestCapturedBody(String(d.url ?? ""), d.body);
  }
}

// Decode a captured API body (single JSON, streamed NDJSON, or compressed bfetch — see
// decodeCapturedBodies) and accumulate the clean rows across every object the stream carried. On a
// non-empty result we remember it as `latest` and turn the push button green.
async function ingestCapturedBody(url: string, body: string): Promise<void> {
  if (!activeAdapter) return;
  let bodies: unknown[];
  try { bodies = await decodeCapturedBodies(body); } catch { return; }
  if (!bodies.length) return;
  const rows: unknown[] = [];
  for (const parsed of bodies) {
    let part: unknown[] | null = null;
    try { part = activeAdapter.extractRows(url, parsed); } catch { part = null; }
    if (part && part.length) rows.push(...part);
  }
  if (rows.length) {
    const label = labelRows(rows, url);
    latest = { adapterId: activeAdapter.id, rows, sourceUrl: location.href, via: "intercept", label };
    renderButton();
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
  const rawObjs = matrixToRows(headers, rows);
  if (!rawObjs.length) return null;
  const objs = activeAdapter.processScrapedRows ? activeAdapter.processScrapedRows(rawObjs) : rawObjs;
  const label = labelRows(objs, "");
  return { adapterId: activeAdapter.id, rows: objs, sourceUrl: location.href, via: "scrape", label };
}

export function readTableMatrix(table: HTMLTableElement): { headers: string[]; rows: string[][] } {
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
    padding: "8px 12px", borderRadius: "8px", border: "none", cursor: "grab",
    font: "600 13px system-ui, sans-serif", color: "#fff", background: "#555",
    boxShadow: "0 2px 8px rgba(0,0,0,.3)", maxWidth: "320px", touchAction: "none",
  } as Partial<CSSStyleDeclaration>);
  btn.addEventListener("click", onClick);
  // The page may not have a <body> yet at document_idle on some SPAs — guard.
  (document.body || document.documentElement).appendChild(btn);
  renderButton();
  attachDrag(btn);
  applyButtonPosition(btn); // re-apply the saved drag position on every (re-)injection
}

// Apply the saved drag position, clamped to the current viewport (so a spot saved in a larger
// window can't hide the button). No saved position → keep the default bottom-right corner.
function applyButtonPosition(btn: HTMLButtonElement): void {
  if (!buttonPos) return;
  const rect = btn.getBoundingClientRect();
  const pos = clampButtonPosition(
    buttonPos,
    { width: rect.width, height: rect.height },
    { width: window.innerWidth, height: window.innerHeight },
  );
  btn.style.left = `${pos.left}px`;
  btn.style.top = `${pos.top}px`;
  btn.style.right = "auto";
  btn.style.bottom = "auto";
}

// Make the button draggable. Past the drag threshold the button follows the pointer; on release the
// position is clamped, persisted, and the trailing click is suppressed so a drag never pushes.
function attachDrag(btn: HTMLButtonElement): void {
  let startX = 0, startY = 0, originLeft = 0, originTop = 0, dragging = false;

  btn.addEventListener("pointerdown", (e: PointerEvent) => {
    if (e.button !== 0) return; // primary button only
    const rect = btn.getBoundingClientRect();
    startX = e.clientX; startY = e.clientY;
    originLeft = rect.left; originTop = rect.top;
    dragging = false;
    try { btn.setPointerCapture(e.pointerId); } catch { /* capture unsupported — drag still best-effort */ }
  });

  btn.addEventListener("pointermove", (e: PointerEvent) => {
    if (!btn.hasPointerCapture(e.pointerId)) return;
    const dx = e.clientX - startX, dy = e.clientY - startY;
    if (!dragging && !isDrag(dx, dy)) return;
    dragging = true;
    e.preventDefault();
    btn.style.cursor = "grabbing";
    const rect = btn.getBoundingClientRect();
    const pos = clampButtonPosition(
      { left: originLeft + dx, top: originTop + dy },
      { width: rect.width, height: rect.height },
      { width: window.innerWidth, height: window.innerHeight },
    );
    btn.style.left = `${pos.left}px`;
    btn.style.top = `${pos.top}px`;
    btn.style.right = "auto";
    btn.style.bottom = "auto";
  });

  const end = (e: PointerEvent): void => {
    if (btn.hasPointerCapture(e.pointerId)) btn.releasePointerCapture(e.pointerId);
    btn.style.cursor = "grab";
    if (!dragging) return;
    dragging = false;
    suppressClick = true; // swallow the click that follows this pointerup
    window.setTimeout(() => { suppressClick = false; }, 0);
    const rect = btn.getBoundingClientRect();
    buttonPos = { left: rect.left, top: rect.top };
    try { void chrome.storage.local.set({ [POS_KEY]: buttonPos }); } catch { /* storage unavailable */ }
  };
  btn.addEventListener("pointerup", end);
  btn.addEventListener("pointercancel", end);
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
  if (suppressClick) return; // this click is the tail of a drag — don't push
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
