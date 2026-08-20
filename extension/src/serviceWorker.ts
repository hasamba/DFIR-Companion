import { CompanionClient } from "./companionClient.js";
import { CaptureQueue } from "./captureQueue.js";
import { CaptureController } from "./captureController.js";
import { setActionIcon } from "./actionIcon.js";
import { buildArtifactFilename } from "./adapters/artifactName.js";
import { browserApi } from "./browser.js";
import {
  appendAuditEntry,
  hasSiteAccess,
  isCapturableTab,
  originPatternFromUrl,
  originPatternMatchesUrl,
  SITE_ACCESS_AUDIT_KEY,
  type SiteAccessAuditAction,
} from "./siteAccess.js";
import {
  DEFAULT_SETTINGS,
  type ContextPushResultMessage, type ContextTableResult,
  type GetContextTableMessage, type PushArtifactMessage, type PushArtifactResult,
  type Settings, type SiteAccessChangedMessage, type TriggerType,
} from "./types.js";

const ALARM = "dfir-capture-timer";
const queue = new CaptureQueue();

interface CaptureAttemptResult {
  ok: boolean;
  error?: string;
}

async function getSettings(): Promise<Settings> {
  const stored = await browserApi.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
}

function controllerFor(settings: Settings): CaptureController {
  return new CaptureController(
    new CompanionClient(settings.companionUrl, undefined, settings.serviceToken),
    queue,
  );
}

async function tabHasPersistentAccess(tab: chrome.tabs.Tab): Promise<boolean> {
  if (!isCapturableTab(tab) || !tab.url) return false;
  return hasSiteAccess(tab.url, browserApi.permissions);
}

async function recordBlockedCapture(trigger: TriggerType, error: string): Promise<CaptureAttemptResult> {
  await browserApi.storage.local.set({
    lastCapture: { at: new Date().toISOString(), trigger, url: "", bytes: 0, diag: `blocked — ${error}` },
  });
  await browserApi.action.setBadgeText({ text: "NO" });
  await browserApi.action.setBadgeBackgroundColor({ color: "#777777" });
  return { ok: false, error };
}

async function captureActiveTab(trigger: TriggerType, oneOff = false): Promise<CaptureAttemptResult> {
  const settings = await getSettings();
  if ((!settings.running && !oneOff) || !settings.caseId) {
    return { ok: false, error: "select a case before capturing" };
  }

  const [tab] = await browserApi.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab || tab.id === undefined || !tab.url || !isCapturableTab(tab)) {
    return recordBlockedCapture(trigger, "this browser or private page cannot be captured");
  }
  if (!oneOff && !(await tabHasPersistentAccess(tab))) {
    return recordBlockedCapture(trigger, "site access is not granted; open the extension on this site");
  }

  let dataUrl: string;
  try {
    dataUrl = await browserApi.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  } catch {
    return recordBlockedCapture(trigger, "the browser denied screenshot access; click the extension and try again");
  }
  const imageBase64 = dataUrl.replace(/^data:image\/\w+;base64,/, "");

  const status = await controllerFor(settings).capture(settings.caseId, trigger, {
    url: tab.url,
    tabTitle: tab.title ?? "",
    imageBase64,
  });

  // Captures that had been waiting in the offline queue but which the companion has now refused
  // for good (their case was deleted/closed while they waited). They are removed so they cannot
  // block the queue — which means their loss has to be SAID, not swallowed (#215).
  const droppedNote = status.dropped?.length
    ? ` · ${status.dropped.length} queued capture(s) discarded — case gone/closed (HTTP ${[...new Set(status.dropped.map((d) => d.status))].join(", ")})`
    : "";

  // Record the last capture outcome so the popup can surface it.
  const diag = (status.rejected
    ? status.rejectedMessage
      ? `rejected (HTTP ${status.rejected}) — ${status.rejectedMessage}`
      : `rejected (HTTP ${status.rejected}) — case missing? create/select it in the dashboard`
    : status.online
      ? `ok (online=true, queued=${status.queued})`
      : `offline — capture queued for retry (queued=${status.queued})`) + droppedNote;
  await browserApi.storage.local.set({
    lastCapture: { at: new Date().toISOString(), trigger, url: tab.url, bytes: imageBase64.length, diag },
  });

  if (status.rejected || status.dropped?.length) {
    await browserApi.action.setBadgeText({ text: "!" });
    // Amber — this capture was rejected, and/or queued captures had to be discarded (#215).
    await browserApi.action.setBadgeBackgroundColor({ color: "#d18616" });
  } else {
    await browserApi.action.setBadgeText({ text: status.online ? (status.queued ? String(status.queued) : "") : "off" });
    await browserApi.action.setBadgeBackgroundColor({ color: status.online ? "#2d6cdf" : "#cc3333" });
  }
  return status.rejected
    ? { ok: false, error: diag }
    : { ok: true };
}

// Inject the MAIN-world fetch/XHR hook (pageHook.js) into a tab the content script recognized as a
// known DFIR console (#102). executeScript into world "MAIN" bypasses the page's CSP (a <script src>
// tag would be blocked by the strict CSPs these consoles ship). Idempotent — the hook guards against
// double install. Best-effort: a restricted/blocked page just falls back to DOM-scrape.
//
// MAIN is requested unconditionally: Chrome has always supported it and Firefox has since 128,
// which scripts/manifest-firefox.mjs pins as the floor. It must not silently degrade to the
// isolated world — there
// the hook would wrap the content script's own `fetch`, which no page script ever calls, so it
// would install, report ready, and then capture nothing at all.
async function recordSiteAccess(action: SiteAccessAuditAction, origin: string): Promise<void> {
  const stored = await browserApi.storage.local.get(SITE_ACCESS_AUDIT_KEY);
  const entry = { at: new Date().toISOString(), origin, action };
  await browserApi.storage.local.set({
    [SITE_ACCESS_AUDIT_KEY]: appendAuditEntry(stored[SITE_ACCESS_AUDIT_KEY], entry),
  });
}

async function ensureContentScript(tabId: number, origin: string): Promise<void> {
  const accessMessage: SiteAccessChangedMessage = {
    kind: "site_access_changed",
    origins: [origin],
    allowed: true,
  };
  try {
    await browserApi.tabs.sendMessage(tabId, { kind: "get_capture_status" });
    await browserApi.tabs.sendMessage(tabId, accessMessage);
    return;
  } catch {
    // No content script in this document yet.
  }
  await browserApi.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
}

async function activateSite(tabId: number): Promise<boolean> {
  let tab: chrome.tabs.Tab;
  try {
    tab = await browserApi.tabs.get(tabId);
  } catch {
    return false;
  }
  if (!(await tabHasPersistentAccess(tab))) return false;
  const origin = originPatternFromUrl(tab.url ?? "");
  if (!origin) return false;
  try {
    await ensureContentScript(tabId, origin);
    return true;
  } catch {
    return false;
  }
}

async function injectHook(tab: chrome.tabs.Tab | undefined): Promise<void> {
  if (typeof tab?.id !== "number" || !(await tabHasPersistentAccess(tab))) return;
  try {
    await browserApi.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      files: ["pageHook.js"],
    });
  } catch { /* page not injectable — the content script's DOM-scrape fallback still works */ }
}

// Push a tool artifact (intercepted JSON or scraped table) the content script captured to the
// companion's unified import route (#102). Uses the active case from settings — the artifact path
// reuses the same case the analyst already selected for screenshot capture.
async function pushArtifact(
  msg: PushArtifactMessage,
  sourceTab?: chrome.tabs.Tab,
): Promise<PushArtifactResult> {
  if (sourceTab && !(await tabHasPersistentAccess(sourceTab))) {
    return { ok: false, error: "Site access was revoked — open the extension to reconnect this console." };
  }
  const settings = await getSettings();
  if (!settings.caseId) {
    return { ok: false, error: "No case selected — open the extension popup and pick a case." };
  }
  const rows = Array.isArray(msg.rows) ? msg.rows : undefined;
  const text = typeof msg.text === "string" ? msg.text : undefined;
  if (!rows?.length && !text?.trim()) return { ok: false, error: "Nothing to push." };

  // Name the evidence file after the source artifact/notebook when known (nicer audit trail + a
  // Velociraptor-looking name keeps detectImportKind routing it to the Velociraptor importer).
  const filename = buildArtifactFilename(msg.sourceLabel?.trim() || msg.adapterId, new Date());
  const client = new CompanionClient(settings.companionUrl, undefined, settings.serviceToken);
  // Exactly one of rows/text is set (context-menu selection/link pushes text; table pushes rows —
  // see PushArtifactMessage). The companion's importDetect classifies either shape identically to
  // an uploaded file, so no format hint beyond the filename is needed.
  const result = rows?.length
    ? await client.postImport(settings.caseId, { json: JSON.stringify(rows), filename })
    : await client.postImport(settings.caseId, { text: text as string, filename });

  const rowCount = rows?.length ?? 0;
  await browserApi.storage.local.set({
    lastArtifactPush: {
      at: new Date().toISOString(), adapterId: msg.adapterId, rows: rowCount,
      caseId: settings.caseId, ok: result.ok, status: result.status,
    },
  });

  if (result.ok) return { ok: true, status: result.status, rows: rowCount, caseId: settings.caseId };
  const error = result.status === 0 ? `Companion offline at ${settings.companionUrl}`
    : result.status === 404 ? `Case "${settings.caseId}" not found — re-select it in the popup`
    : result.status === 400 ? "Companion couldn't detect the artifact format"
    : result.status === 501 ? "Companion has no AI provider configured for this artifact type"
    : `Import rejected (HTTP ${result.status})`;
  return { ok: false, status: result.status, error };
}

// ── Context-menu send (#new) ──────────────────────────────────────────────────────────────────
const MENU_PARENT = "dfir-companion-menu";
const MENU_SELECTION = "dfir-send-selection";
const MENU_TABLE = "dfir-send-table";
const MENU_LINK = "dfir-send-link";

// Menu items persist across service-worker restarts once created, so this only needs to run on
// install/update — removeAll() first makes it idempotent (Chrome throws "duplicate id" otherwise).
// Awaited rather than passed a callback: the promise form is the one both namespaces agree on.
async function registerContextMenus(): Promise<void> {
  await browserApi.contextMenus.removeAll();
  browserApi.contextMenus.create({ id: MENU_PARENT, title: "DFIR-Companion", contexts: ["page", "selection", "link"] });
  browserApi.contextMenus.create({ id: MENU_SELECTION, parentId: MENU_PARENT, title: "Send selection to DFIR-Companion", contexts: ["selection"] });
  browserApi.contextMenus.create({ id: MENU_TABLE, parentId: MENU_PARENT, title: "Send table to DFIR-Companion", contexts: ["page"] });
  browserApi.contextMenus.create({ id: MENU_LINK, parentId: MENU_PARENT, title: "Send link to DFIR-Companion", contexts: ["link"] });
}

// Best-effort toast delivery — a tab that can't receive messages (chrome://, a PDF viewer, or one
// that navigated away before the push resolved) just doesn't show a toast; the push itself already
// completed (or failed) server-side regardless.
async function sendContextToast(tabId: number, ok: boolean, message: string): Promise<void> {
  const payload: ContextPushResultMessage = { kind: "context_push_result", ok, message };
  try { await browserApi.tabs.sendMessage(tabId, payload); } catch { /* tab unreachable */ }
}

async function handleContextMenuClick(
  info: chrome.contextMenus.OnClickData,
  tab: chrome.tabs.Tab | undefined,
): Promise<void> {
  if (typeof tab?.id !== "number" || tab.incognito) return;
  const tabId = tab.id;

  let text: string | undefined;
  let rows: unknown[] | undefined;
  let sourceLabel: string;

  if (info.menuItemId === MENU_SELECTION) {
    text = info.selectionText ?? "";
    sourceLabel = "context-menu:selection";
  } else if (info.menuItemId === MENU_LINK) {
    text = info.linkUrl ?? "";
    sourceLabel = "context-menu:link";
  } else if (info.menuItemId === MENU_TABLE) {
    sourceLabel = "context-menu:table";
    let result: ContextTableResult | undefined;
    try {
      const req: GetContextTableMessage = { kind: "get_context_table" };
      result = await browserApi.tabs.sendMessage(tabId, req);
    } catch {
      result = undefined; // content script unreachable on this tab
    }
    if (!result?.rows?.length) {
      void sendContextToast(tabId, false, "No table found at that location.");
      return;
    }
    rows = result.rows;
  } else {
    return; // not one of our menu items
  }

  if (!rows?.length && !text?.trim()) {
    void sendContextToast(tabId, false, "Nothing to send.");
    return;
  }

  const msg: PushArtifactMessage = {
    kind: "push_artifact",
    adapterId: "context-menu",
    sourceUrl: tab.url ?? "",
    sourceLabel,
    ...(rows ? { rows } : { text }),
  };
  const res = await pushArtifact(msg);
  void sendContextToast(tabId, res.ok, res.ok ? `Pushed to "${res.caseId}"` : (res.error ?? "Push failed"));
}

function changedOrigins(change: chrome.permissions.Permissions): string[] {
  return (change.origins ?? []).filter((origin) => typeof origin === "string");
}

async function notifyContentScripts(origins: string[], allowed: boolean): Promise<void> {
  if (!origins.length) return;
  const message: SiteAccessChangedMessage = { kind: "site_access_changed", origins, allowed };
  const tabs = await browserApi.tabs.query({});
  await Promise.all(tabs.map(async (tab) => {
    if (typeof tab.id !== "number") return;
    try { await browserApi.tabs.sendMessage(tab.id, message); } catch { /* no content script */ }
  }));
}

async function activateMatchingTabs(origins: string[]): Promise<void> {
  const tabs = await browserApi.tabs.query({});
  const matchingIds = tabs.flatMap((tab) => {
    if (typeof tab.id !== "number" || !isCapturableTab(tab)) return [];
    const matches = origins.some((origin) => originPatternMatchesUrl(origin, tab.url ?? ""));
    return matches ? [tab.id] : [];
  });
  await Promise.all(matchingIds.map((tabId) => activateSite(tabId)));
}

async function handlePermissionChange(
  action: SiteAccessAuditAction,
  change: chrome.permissions.Permissions,
): Promise<void> {
  const origins = changedOrigins(change);
  for (const origin of origins) await recordSiteAccess(action, origin);
  if (action === "granted") await activateMatchingTabs(origins);
  else await notifyContentScripts(origins, false);
}

async function rescheduleAlarm(): Promise<void> {
  const settings = await getSettings();
  await browserApi.alarms.clear(ALARM);
  if (settings.running) {
    await browserApi.alarms.create(ALARM, { periodInMinutes: Math.max(settings.intervalSeconds, 5) / 60 });
  }
  // Keep the toolbar icon in sync with capture state (recording dot vs idle ring).
  await setActionIcon(settings.running).catch(() => {});
}

// Flip capture on/off (used by the keyboard shortcut). Persists the same settings shape
// the popup writes, reschedules the alarm + icon, and flashes the toolbar badge so the
// hotkey has a visible effect. When turning ON, take one capture immediately so the
// shortcut feels responsive instead of waiting for the next timer tick.
async function toggleCapture(): Promise<void> {
  const settings = await getSettings();
  if (!settings.running) {
    const [tab] = await browserApi.tabs.query({ active: true, lastFocusedWindow: true });
    if (!tab || !(await tabHasPersistentAccess(tab))) {
      await recordBlockedCapture("manual", "site access is required; open the extension on this site");
      return;
    }
  }
  const next: Settings = { ...settings, running: !settings.running };
  await browserApi.storage.local.set({ settings: next });
  await rescheduleAlarm();
  await browserApi.action.setBadgeText({ text: next.running ? "REC" : "off" });
  await browserApi.action.setBadgeBackgroundColor({ color: next.running ? "#cc3333" : "#777777" });
  if (next.running) void captureActiveTab("manual");
}

browserApi.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) void captureActiveTab("timer");
});
browserApi.tabs.onActivated.addListener(() => void captureActiveTab("tab_switch"));
browserApi.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0) void captureActiveTab("navigation");
});
browserApi.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId === 0) void activateSite(details.tabId);
});
browserApi.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.kind === "user_event") { void captureActiveTab("click"); return; }
  if (msg?.kind === "settings_changed") { void rescheduleAlarm(); return; }
  if (msg?.kind === "ensure_hook") { void injectHook(sender.tab); return; }
  if (msg?.kind === "activate_site") {
    const tabId = (msg as { tabId?: unknown }).tabId;
    if (sender.tab || typeof tabId !== "number" || !Number.isInteger(tabId)) {
      sendResponse(false);
      return;
    }
    // The rejection arm still answers the kept-open channel — an unanswered sendResponse leaves
    // the popup rejecting with "message port closed" instead of a real result.
    void activateSite(tabId).then(sendResponse, () => sendResponse(false));
    return true;
  }
  if (msg?.kind === "capture_once") {
    if (sender.tab) {
      sendResponse({ ok: false, error: "one-off capture requires an extension action" });
      return;
    }
    void captureActiveTab("manual", true).then(sendResponse, (e: unknown) =>
      sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }),
    );
    return true;
  }
  if (msg?.kind === "push_artifact") {
    // Async — return true to keep the message channel open until pushArtifact resolves.
    void pushArtifact(msg as PushArtifactMessage, sender.tab).then(sendResponse, (e: unknown) =>
      sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }),
    );
    return true;
  }
});
browserApi.runtime.onInstalled.addListener(() => { void rescheduleAlarm(); void registerContextMenus(); });
browserApi.runtime.onStartup.addListener(() => void rescheduleAlarm());
browserApi.contextMenus.onClicked.addListener((info, tab) => void handleContextMenuClick(info, tab));
browserApi.permissions.onAdded.addListener((change) => void handlePermissionChange("granted", change));
browserApi.permissions.onRemoved.addListener((change) => void handlePermissionChange("revoked", change));
// Keyboard shortcut (default Ctrl+Shift+S / Cmd+Shift+S) to toggle capture on/off.
browserApi.commands?.onCommand.addListener((command) => {
  if (command === "toggle-capture") void toggleCapture();
});
