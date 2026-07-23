import { CompanionClient } from "./companionClient.js";
import { CaptureQueue } from "./captureQueue.js";
import { CaptureController } from "./captureController.js";
import { setActionIcon } from "./actionIcon.js";
import { buildArtifactFilename } from "./adapters/artifactName.js";
import {
  DEFAULT_SETTINGS, type ContextPushResultMessage, type ContextTableResult,
  type GetContextTableMessage, type PushArtifactMessage, type PushArtifactResult,
  type Settings, type TriggerType,
} from "./types.js";

const ALARM = "dfir-capture-timer";
const queue = new CaptureQueue();

async function getSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
}

function controllerFor(settings: Settings): CaptureController {
  return new CaptureController(new CompanionClient(settings.companionUrl), queue);
}

async function captureActiveTab(trigger: TriggerType): Promise<void> {
  const settings = await getSettings();
  if (!settings.running || !settings.caseId) return;

  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab || tab.id === undefined || !tab.url || tab.url.startsWith("chrome")) return;

  let dataUrl: string;
  try {
    dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  } catch {
    return; // e.g. capturing not allowed on this page
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
  await chrome.storage.local.set({
    lastCapture: { at: new Date().toISOString(), trigger, url: tab.url, bytes: imageBase64.length, diag },
  });

  if (status.rejected || status.dropped?.length) {
    await chrome.action.setBadgeText({ text: "!" });
    // Amber — this capture was rejected, and/or queued captures had to be discarded (#215).
    await chrome.action.setBadgeBackgroundColor({ color: "#d18616" });
  } else {
    await chrome.action.setBadgeText({ text: status.online ? (status.queued ? String(status.queued) : "") : "off" });
    await chrome.action.setBadgeBackgroundColor({ color: status.online ? "#2d6cdf" : "#cc3333" });
  }
}

// Inject the MAIN-world fetch/XHR hook (pageHook.js) into a tab the content script recognized as a
// known DFIR console (#102). executeScript into world "MAIN" bypasses the page's CSP (a <script src>
// tag would be blocked by the strict CSPs these consoles ship). Idempotent — the hook guards against
// double install. Best-effort: a restricted/blocked page just falls back to DOM-scrape.
async function injectHook(tabId: number | undefined): Promise<void> {
  if (typeof tabId !== "number") return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      files: ["pageHook.js"],
    });
  } catch { /* page not injectable — the content script's DOM-scrape fallback still works */ }
}

// Push a tool artifact (intercepted JSON or scraped table) the content script captured to the
// companion's unified import route (#102). Uses the active case from settings — the artifact path
// reuses the same case the analyst already selected for screenshot capture.
async function pushArtifact(msg: PushArtifactMessage): Promise<PushArtifactResult> {
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
  const client = new CompanionClient(settings.companionUrl);
  // Exactly one of rows/text is set (context-menu selection/link pushes text; table pushes rows —
  // see PushArtifactMessage). The companion's importDetect classifies either shape identically to
  // an uploaded file, so no format hint beyond the filename is needed.
  const result = rows?.length
    ? await client.postImport(settings.caseId, { json: JSON.stringify(rows), filename })
    : await client.postImport(settings.caseId, { text: text as string, filename });

  const rowCount = rows?.length ?? 0;
  await chrome.storage.local.set({
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
function registerContextMenus(): void {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: MENU_PARENT, title: "DFIR-Companion", contexts: ["page", "selection", "link"] });
    chrome.contextMenus.create({ id: MENU_SELECTION, parentId: MENU_PARENT, title: "Send selection to DFIR-Companion", contexts: ["selection"] });
    chrome.contextMenus.create({ id: MENU_TABLE, parentId: MENU_PARENT, title: "Send table to DFIR-Companion", contexts: ["page"] });
    chrome.contextMenus.create({ id: MENU_LINK, parentId: MENU_PARENT, title: "Send link to DFIR-Companion", contexts: ["link"] });
  });
}

// Best-effort toast delivery — a tab that can't receive messages (chrome://, a PDF viewer, or one
// that navigated away before the push resolved) just doesn't show a toast; the push itself already
// completed (or failed) server-side regardless.
async function sendContextToast(tabId: number, ok: boolean, message: string): Promise<void> {
  const payload: ContextPushResultMessage = { kind: "context_push_result", ok, message };
  try { await chrome.tabs.sendMessage(tabId, payload); } catch { /* tab unreachable */ }
}

async function handleContextMenuClick(
  info: chrome.contextMenus.OnClickData,
  tab: chrome.tabs.Tab | undefined,
): Promise<void> {
  if (!tab?.id) return;
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
      result = await chrome.tabs.sendMessage(tabId, req);
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

async function rescheduleAlarm(): Promise<void> {
  const settings = await getSettings();
  await chrome.alarms.clear(ALARM);
  if (settings.running) {
    await chrome.alarms.create(ALARM, { periodInMinutes: Math.max(settings.intervalSeconds, 5) / 60 });
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
  const next: Settings = { ...settings, running: !settings.running };
  await chrome.storage.local.set({ settings: next });
  await rescheduleAlarm();
  await chrome.action.setBadgeText({ text: next.running ? "REC" : "off" });
  await chrome.action.setBadgeBackgroundColor({ color: next.running ? "#cc3333" : "#777777" });
  if (next.running) void captureActiveTab("timer");
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) void captureActiveTab("timer");
});
chrome.tabs.onActivated.addListener(() => void captureActiveTab("tab_switch"));
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0) void captureActiveTab("navigation");
});
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.kind === "user_event") { void captureActiveTab("click"); return; }
  if (msg?.kind === "settings_changed") { void rescheduleAlarm(); return; }
  if (msg?.kind === "ensure_hook") { void injectHook(sender.tab?.id); return; }
  if (msg?.kind === "push_artifact") {
    // Async — return true to keep the message channel open until pushArtifact resolves.
    void pushArtifact(msg as PushArtifactMessage).then(sendResponse);
    return true;
  }
});
chrome.runtime.onInstalled.addListener(() => { void rescheduleAlarm(); registerContextMenus(); });
chrome.runtime.onStartup.addListener(() => void rescheduleAlarm());
chrome.contextMenus.onClicked.addListener((info, tab) => void handleContextMenuClick(info, tab));
// Keyboard shortcut (default Ctrl+Shift+S / Cmd+Shift+S) to toggle capture on/off.
chrome.commands?.onCommand.addListener((command) => {
  if (command === "toggle-capture") void toggleCapture();
});
