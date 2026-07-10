import { DEFAULT_SETTINGS, normalizeCompanionUrl, type Settings } from "./types.js";
import { ADAPTERS } from "./adapters/registry.js";
import { OVERRIDE_NONE } from "./adapters/override.js";
import type { CaptureStatusResult, GetCaptureStatusMessage, SetAdapterOverrideMessage } from "./types.js";

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const caseSelect = () => document.getElementById("caseId") as HTMLSelectElement;
const statusEl = () => document.getElementById("status") as HTMLDivElement;

const toolSelect = () => document.getElementById("toolOverride") as HTMLSelectElement;
const toolHint = () => document.getElementById("toolHint") as HTMLDivElement;

async function activeTabId(): Promise<number | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id ?? null;
}

function populateToolOptions(sel: HTMLSelectElement): void {
  sel.innerHTML = "";
  sel.appendChild(new Option("Auto-detect", ""));
  for (const a of ADAPTERS) sel.appendChild(new Option(a.label, a.id));
  sel.appendChild(new Option("None — plain screenshot", OVERRIDE_NONE));
}

function describeStatus(status: CaptureStatusResult): string {
  const detected = status.detectedAdapterId
    ? ADAPTERS.find((a) => a.id === status.detectedAdapterId)?.label ?? status.detectedAdapterId
    : "not recognized";
  if (!status.activeLabel) return `detected: ${detected}`;
  const rows = status.rowCount > 0 ? ` (${status.rowCount} rows captured)` : "";
  return `detected: ${detected} — capturing as ${status.activeLabel}${rows}`;
}

// Populate the "Detected tool" row from the active tab's content script, and wire the override
// <select> to push changes back to it. Hides the row entirely when the active tab has no content
// script to talk to (a chrome:// page, or a page loaded before the extension was installed) —
// same catch-and-degrade pattern loadCases() below uses for an offline companion.
async function initToolOverride(): Promise<void> {
  const row = document.getElementById("toolRow");
  const sel = toolSelect();
  if (!row || !sel) return;
  const tabId = await activeTabId();
  if (!tabId) { row.style.display = "none"; return; }
  try {
    const msg: GetCaptureStatusMessage = { kind: "get_capture_status" };
    const status = (await chrome.tabs.sendMessage(tabId, msg)) as CaptureStatusResult;
    populateToolOptions(sel);
    sel.value = status.overrideAdapterId;
    toolHint().textContent = describeStatus(status);
  } catch {
    row.style.display = "none";
    return;
  }
  sel.onchange = async () => {
    try {
      const msg: SetAdapterOverrideMessage = { kind: "set_adapter_override", overrideAdapterId: sel.value };
      const status = (await chrome.tabs.sendMessage(tabId, msg)) as CaptureStatusResult;
      toolHint().textContent = describeStatus(status);
    } catch {
      toolHint().textContent = "override failed — reload the page and try again";
    }
  };
}

async function load(): Promise<Settings> {
  const stored = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
}

async function save(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ settings });
  await chrome.runtime.sendMessage({ kind: "settings_changed" }).catch(() => {});
}

function readForm(running: boolean): Settings {
  return {
    caseId: caseSelect().value.trim(),
    companionUrl: normalizeCompanionUrl($("companionUrl").value),
    intervalSeconds: Math.max(5, Number($("intervalSeconds").value) || 10),
    dedupThreshold: Math.max(0, Number($("dedupThreshold").value) || 5),
    running,
  };
}

async function refreshStatus(s: Settings): Promise<void> {
  const el = statusEl();
  const prefix = s.running ? "capturing" : "stopped";
  try {
    const res = await fetch(`${s.companionUrl}/health`, { method: "GET" });
    if (res.ok) {
      el.textContent = `${prefix} — companion online`;
      el.className = "on";
    } else {
      el.textContent = `${prefix} — companion offline (health HTTP ${res.status} @ ${s.companionUrl})`;
      el.className = "off";
    }
  } catch (err) {
    el.textContent = `${prefix} — companion offline: ${(err as Error).message} (${s.companionUrl}/health)`;
    el.className = "off";
  }
}

// Populate the case dropdown from the companion (GET /cases). The extension only ATTACHES
// to existing cases — they're created in the dashboard — so this is the only way to pick
// one. On failure (companion offline, or an older server without GET /cases) fall back to
// the last-used case id so Start can still resume an existing case.
async function loadCases(companionUrl: string, selectedId: string): Promise<boolean> {
  const sel = caseSelect();
  try {
    const res = await fetch(`${companionUrl}/cases`, { method: "GET" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const cases = (await res.json()) as Array<{ caseId: string; name: string }>;
    sel.innerHTML = "";
    if (cases.length === 0) {
      sel.appendChild(new Option("(no cases — create one in the dashboard)", ""));
      return true;
    }
    sel.appendChild(new Option("— no case (push button hidden) —", ""));
    for (const c of cases) {
      const label = c.name && c.name !== c.caseId ? `${c.caseId} — ${c.name}` : c.caseId;
      sel.appendChild(new Option(label, c.caseId));
    }
    sel.value = cases.some((c) => c.caseId === selectedId) ? selectedId : "";
    return true;
  } catch {
    // Offline or endpoint missing — keep the last-used case selectable so Start works.
    sel.innerHTML = "";
    if (selectedId) sel.appendChild(new Option(`${selectedId} (offline — last used)`, selectedId));
    else sel.appendChild(new Option("(companion offline — start it, then Refresh)", ""));
    return false;
  }
}

async function showLastCapture(): Promise<void> {
  const el = document.getElementById("lastCapture");
  if (!el) return;
  const { lastCapture } = await chrome.storage.local.get("lastCapture");
  if (lastCapture) {
    const c = lastCapture as { at: string; trigger: string; bytes: number; diag: string };
    el.textContent = `last capture (${c.trigger}, ${c.bytes}B) @ ${c.at}: ${c.diag}`;
  } else {
    el.textContent = "no capture attempted yet";
  }
}

// Show the actual keyboard shortcut bound to toggle-capture (it may be unset if it
// conflicted at install), and wire the "rebind" link to Chrome's shortcuts page.
async function showHotkey(): Promise<void> {
  const keysEl = document.getElementById("hotkeyKeys");
  try {
    const cmds = await chrome.commands.getAll();
    const toggle = cmds.find((c) => c.name === "toggle-capture");
    if (keysEl) keysEl.textContent = toggle?.shortcut || "(not set)";
  } catch {
    /* commands API unavailable — leave the default hint */
  }
  const rebind = document.getElementById("rebind");
  if (rebind) {
    rebind.onclick = (e) => {
      e.preventDefault();
      void chrome.tabs.create({ url: "chrome://extensions/shortcuts" });
    };
  }
}

async function init() {
  const s = await load();
  $("companionUrl").value = s.companionUrl;
  $("intervalSeconds").value = String(s.intervalSeconds);
  $("dedupThreshold").value = String(s.dedupThreshold);
  await loadCases(s.companionUrl, s.caseId);
  await refreshStatus(s);
  await showLastCapture();
  await showHotkey();
  await initToolOverride();

  // Auto-save the case selection immediately on change so the analyst can switch cases
  // (or clear them) without pressing Start — screenshots stay in their current state.
  caseSelect().addEventListener("change", async () => {
    const current = await load();
    await save({ ...current, caseId: caseSelect().value });
  });

  // Re-fetch the case list — e.g. after creating a case in the dashboard, or after
  // pointing Companion URL at a different instance.
  document.getElementById("refreshCases")!.onclick = async () => {
    const url = normalizeCompanionUrl($("companionUrl").value);
    const ok = await loadCases(url, caseSelect().value);
    statusEl().textContent = ok ? "case list refreshed" : `companion offline — check URL (${url})`;
  };
  // Cases are created in the dashboard — open it in a new tab.
  document.getElementById("openDashboard")!.onclick = (e) => {
    e.preventDefault();
    const url = normalizeCompanionUrl($("companionUrl").value);
    void chrome.tabs.create({ url: `${url}/dashboard` });
  };
  document.getElementById("start")!.onclick = async () => {
    const f = readForm(true);
    if (!f.caseId) {
      statusEl().textContent = "select a case — create one in the dashboard, then Refresh cases";
      return;
    }
    await save(f);
    await refreshStatus(f);
  };
  document.getElementById("stop")!.onclick = async () => {
    const f = readForm(false);
    await save(f);
    await refreshStatus(f);
  };
}

void init();
