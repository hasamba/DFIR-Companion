import { DEFAULT_SETTINGS, normalizeCompanionUrl, type Settings } from "./types.js";
import { caseListFailure, settingsFromForm } from "./popupSettings.js";
import { ADAPTERS } from "./adapters/registry.js";
import { OVERRIDE_NONE } from "./adapters/override.js";
import {
  appendAuditEntry,
  hasSiteAccess,
  isCapturableTab,
  originPatternFromUrl,
  requestSiteAccess,
  revokeSiteAccess,
  SITE_ACCESS_AUDIT_KEY,
} from "./siteAccess.js";
import type {
  ActivateSiteMessage,
  CaptureOnceMessage,
  CaptureStatusResult,
  GetCaptureStatusMessage,
  SetAdapterOverrideMessage,
} from "./types.js";
import { browserApi, isFirefox } from "./browser.js";

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const caseSelect = () => document.getElementById("caseId") as HTMLSelectElement;
const statusEl = () => document.getElementById("status") as HTMLDivElement;

const toolSelect = () => document.getElementById("toolOverride") as HTMLSelectElement;
const toolHint = () => document.getElementById("toolHint") as HTMLDivElement;
interface PopupTab {
  id?: number;
  url?: string;
  incognito?: boolean;
}

let currentTab: PopupTab | null = null;

async function activeTab(): Promise<PopupTab | null> {
  const [tab] = await browserApi.tabs.query({ active: true, currentWindow: true });
  return tab ?? null;
}

async function activeTabId(): Promise<number | null> {
  return currentTab?.id ?? (await activeTab())?.id ?? null;
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
    const status = (await browserApi.tabs.sendMessage(tabId, msg)) as CaptureStatusResult;
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
      const status = (await browserApi.tabs.sendMessage(tabId, msg)) as CaptureStatusResult;
      toolHint().textContent = describeStatus(status);
    } catch {
      toolHint().textContent = "override failed — reload the page and try again";
    }
  };
}

async function recordDeniedAccess(origin: string): Promise<void> {
  const stored = await browserApi.storage.local.get(SITE_ACCESS_AUDIT_KEY);
  const entry = { at: new Date().toISOString(), origin, action: "denied" as const };
  await browserApi.storage.local.set({
    [SITE_ACCESS_AUDIT_KEY]: appendAuditEntry(stored[SITE_ACCESS_AUDIT_KEY], entry),
  });
}

function setSiteAccessText(state: string, hint: string, className: "on" | "off"): void {
  const stateEl = document.getElementById("siteAccessState")!;
  stateEl.textContent = state;
  stateEl.className = className;
  document.getElementById("siteAccessHint")!.textContent = hint;
}

async function refreshSiteAccess(): Promise<void> {
  const button = document.getElementById("siteAccessAction") as HTMLButtonElement;
  const originEl = document.getElementById("siteOrigin")!;
  if (!currentTab || !isCapturableTab(currentTab) || !currentTab.url) {
    originEl.textContent = "restricted or private browser page";
    setSiteAccessText("unavailable", "DFIR Companion cannot read or capture this page.", "off");
    button.hidden = true;
    return;
  }
  const origin = originPatternFromUrl(currentTab.url)!;
  const allowed = await hasSiteAccess(currentTab.url, browserApi.permissions);
  originEl.textContent = origin.replace(/\/\*$/, "");
  button.hidden = false;
  button.textContent = allowed ? "Revoke this site" : "Allow this site";
  button.dataset.allowed = String(allowed);
  setSiteAccessText(
    allowed ? "connected" : "not connected",
    allowed
      ? "This origin can show the console Push button and use ongoing capture."
      : "No page data is readable until you approve this exact origin.",
    allowed ? "on" : "off",
  );
  if (allowed && typeof currentTab.id === "number") {
    const message: ActivateSiteMessage = { kind: "activate_site", tabId: currentTab.id };
    await browserApi.runtime.sendMessage(message).catch(() => false);
  }
}

async function grantCurrentSite(): Promise<boolean> {
  if (!currentTab?.url || !isCapturableTab(currentTab)) return false;
  try {
    const result = await requestSiteAccess(currentTab.url, browserApi.permissions);
    if (result.status === "denied") await recordDeniedAccess(result.origin);
    await refreshSiteAccess();
    if (result.status !== "granted") {
      statusEl().textContent = "site access denied — capture remains off";
      return false;
    }
    await initToolOverride();
    return true;
  } catch (error) {
    statusEl().textContent = `site access unavailable: ${(error as Error).message}`;
    return false;
  }
}

async function revokeCurrentSite(): Promise<void> {
  if (!currentTab?.url) return;
  const removed = await revokeSiteAccess(currentTab.url, browserApi.permissions);
  await refreshSiteAccess();
  statusEl().textContent = removed ? "site access revoked" : "site access could not be revoked";
}

function wireSiteAccessControls(): void {
  document.getElementById("siteAccessAction")!.onclick = async () => {
    const allowed = (document.getElementById("siteAccessAction") as HTMLButtonElement).dataset.allowed === "true";
    if (allowed) await revokeCurrentSite();
    else await grantCurrentSite();
  };
  document.getElementById("manageSiteAccess")!.onclick = (event) => {
    event.preventDefault();
    void browserApi.runtime.openOptionsPage();
  };
}

async function load(): Promise<Settings> {
  const stored = await browserApi.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
}

async function save(settings: Settings): Promise<void> {
  await browserApi.storage.local.set({ settings });
  await browserApi.runtime.sendMessage({ kind: "settings_changed" }).catch(() => {});
}

function readForm(running: boolean): Settings {
  return settingsFromForm(
    {
      caseId: caseSelect().value,
      companionUrl: $("companionUrl").value,
      serviceToken: $("serviceToken").value,
      intervalSeconds: $("intervalSeconds").value,
      dedupThreshold: $("dedupThreshold").value,
    },
    running,
  );
}

/**
 * Persist the whole form, keeping the capture state the service worker owns.
 *
 * Every field edit routes through here. The popup is a transient window — it closes on the next
 * click into the page — so a value that is only in the DOM is lost the moment the analyst looks
 * away. That is how a typed Team service token used to disappear on a page reload.
 */
async function persistForm(): Promise<Settings> {
  const stored = await load();
  const next = readForm(stored.running);
  await save(next);
  return next;
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
async function loadCases(
  companionUrl: string,
  selectedId: string,
  serviceToken: string,
): Promise<{ ok: boolean; failure?: string }> {
  const sel = caseSelect();
  // 0 means the fetch never got a response at all; any other value is the companion answering,
  // which is a very different thing to tell the analyst (see caseListFailure).
  let status = 0;
  try {
    const res = await fetch(`${companionUrl}/cases`, {
      method: "GET",
      headers: serviceToken ? { Authorization: `Bearer ${serviceToken}` } : {},
    });
    status = res.status;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const cases = (await res.json()) as Array<{ caseId: string; name: string }>;
    sel.innerHTML = "";
    if (cases.length === 0) {
      sel.appendChild(new Option("(no cases — create one in the dashboard)", ""));
      return { ok: true };
    }
    sel.appendChild(new Option("— no case (push button hidden) —", ""));
    for (const c of cases) {
      const label = c.name && c.name !== c.caseId ? `${c.caseId} — ${c.name}` : c.caseId;
      sel.appendChild(new Option(label, c.caseId));
    }
    sel.value = cases.some((c) => c.caseId === selectedId) ? selectedId : "";
    return { ok: true };
  } catch {
    // Unreachable, unauthorized, or an endpoint the server does not have — keep the last-used case
    // selectable either way so Start still works once the cause is fixed.
    const failure = caseListFailure(status);
    sel.innerHTML = "";
    if (selectedId) sel.appendChild(new Option(`${selectedId} (last used — ${failure})`, selectedId));
    else sel.appendChild(new Option(`(${failure})`, ""));
    return { ok: false, failure };
  }
}

async function showLastCapture(): Promise<void> {
  const el = document.getElementById("lastCapture");
  if (!el) return;
  const { lastCapture } = await browserApi.storage.local.get("lastCapture");
  if (lastCapture) {
    const c = lastCapture as { at: string; trigger: string; bytes: number; diag: string };
    el.textContent = `last capture (${c.trigger}, ${c.bytes}B) @ ${c.at}: ${c.diag}`;
  } else {
    el.textContent = "no capture attempted yet";
  }
}

// Show the actual keyboard shortcut bound to toggle-capture (it may be unset if it
// conflicted at install), and wire the "rebind" link to the browser's shortcuts page.
async function showHotkey(): Promise<void> {
  const keysEl = document.getElementById("hotkeyKeys");
  try {
    const cmds = await browserApi.commands.getAll();
    const toggle = cmds.find((c) => c.name === "toggle-capture");
    if (keysEl) keysEl.textContent = toggle?.shortcut || "(not set)";
  } catch {
    /* commands API unavailable — leave the default hint */
  }
  const rebind = document.getElementById("rebind");
  if (rebind) {
    rebind.onclick = (e) => {
      e.preventDefault();
      // Firefox refuses tabs.create() for privileged about: URLs, so its shortcuts page can't be
      // opened for the analyst — spell out the path instead. Chrome navigates straight there.
      if (isFirefox()) {
        rebind.textContent = "Add-ons (Ctrl+Shift+A) → gear → Manage Extension Shortcuts";
        return;
      }
      void browserApi.tabs.create({ url: "chrome://extensions/shortcuts" });
    };
  }
}

async function init() {
  currentTab = await activeTab();
  const s = await load();
  $("companionUrl").value = s.companionUrl;
  $("serviceToken").value = s.serviceToken;
  $("intervalSeconds").value = String(s.intervalSeconds);
  $("dedupThreshold").value = String(s.dedupThreshold);
  await loadCases(s.companionUrl, s.caseId, s.serviceToken);
  await refreshStatus(s);
  await showLastCapture();
  await showHotkey();
  wireSiteAccessControls();
  await refreshSiteAccess();
  await initToolOverride();

  // Auto-save every field as soon as the analyst leaves it, so nothing depends on remembering to
  // press Start. The popup closes on the next click into the page, and an unsaved value dies with
  // it: that is what used to strand the Team service token and make imports 401.
  //
  // "change" rather than "input": it fires on blur for a text box and immediately for the case
  // dropdown, which keeps the write count low without ever losing a value.
  for (const id of ["caseId", "companionUrl", "serviceToken", "intervalSeconds", "dedupThreshold"]) {
    document.getElementById(id)!.addEventListener("change", () => void persistForm());
  }

  // Re-fetch the case list — e.g. after creating a case in the dashboard, or after
  // pointing Companion URL at a different instance.
  document.getElementById("refreshCases")!.onclick = async () => {
    // Persist first: the analyst has usually just pasted a token or a URL, and Refresh is the
    // natural place to press before Start.
    const saved = await persistForm();
    const result = await loadCases(saved.companionUrl, saved.caseId, saved.serviceToken);
    // Re-persist: a refresh can drop the stored case from the list (it was closed or archived, or
    // the token is scoped elsewhere), which blanks the dropdown. Without this the service worker
    // would keep capturing into a case the analyst can no longer see.
    const settled = await persistForm();
    statusEl().textContent = result.ok
      ? "case list refreshed"
      : `${result.failure} (${settled.companionUrl})`;
  };
  // Cases are created in the dashboard — open it in a new tab.
  document.getElementById("openDashboard")!.onclick = (e) => {
    e.preventDefault();
    const url = normalizeCompanionUrl($("companionUrl").value);
    void browserApi.tabs.create({ url: `${url}/dashboard` });
  };
  document.getElementById("start")!.onclick = async () => {
    const f = readForm(true);
    if (!f.caseId) {
      statusEl().textContent = "select a case — create one in the dashboard, then Refresh cases";
      return;
    }
    if (!(await grantCurrentSite())) return;
    await save(f);
    await refreshStatus(f);
  };
  document.getElementById("stop")!.onclick = async () => {
    const f = readForm(false);
    await save(f);
    await refreshStatus(f);
  };
  document.getElementById("captureOnce")!.onclick = async () => {
    const current = await load();
    const f = readForm(current.running);
    if (!f.caseId) {
      statusEl().textContent = "select a case before capturing";
      return;
    }
    if (!currentTab || !isCapturableTab(currentTab)) {
      statusEl().textContent = "this browser or private page cannot be captured";
      return;
    }
    await save(f);
    const message: CaptureOnceMessage = { kind: "capture_once" };
    const result = await browserApi.runtime.sendMessage(message) as { ok: boolean; error?: string };
    statusEl().textContent = result.ok ? "one-off capture saved" : `capture blocked — ${result.error ?? "unknown error"}`;
    await showLastCapture();
  };
}

void init();
