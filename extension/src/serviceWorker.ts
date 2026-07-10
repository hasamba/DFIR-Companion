import { CompanionClient } from "./companionClient.js";
import { CaptureQueue } from "./captureQueue.js";
import { CaptureController } from "./captureController.js";
import { setActionIcon } from "./actionIcon.js";
import { buildArtifactFilename } from "./adapters/artifactName.js";
import { DEFAULT_SETTINGS, type PushArtifactMessage, type PushArtifactResult, type Settings, type TriggerType } from "./types.js";

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

  // Record the last capture outcome so the popup can surface it.
  const diag = status.rejected
    ? status.rejectedMessage
      ? `rejected (HTTP ${status.rejected}) — ${status.rejectedMessage}`
      : `rejected (HTTP ${status.rejected}) — case missing? create/select it in the dashboard`
    : status.online
      ? `ok (online=true, queued=${status.queued})`
      : `offline — capture queued for retry (queued=${status.queued})`;
  await chrome.storage.local.set({
    lastCapture: { at: new Date().toISOString(), trigger, url: tab.url, bytes: imageBase64.length, diag },
  });

  if (status.rejected) {
    await chrome.action.setBadgeText({ text: "!" });
    await chrome.action.setBadgeBackgroundColor({ color: "#d18616" }); // amber — case rejected, not queued
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
chrome.runtime.onInstalled.addListener(() => void rescheduleAlarm());
chrome.runtime.onStartup.addListener(() => void rescheduleAlarm());
// Keyboard shortcut (default Ctrl+Shift+S / Cmd+Shift+S) to toggle capture on/off.
chrome.commands?.onCommand.addListener((command) => {
  if (command === "toggle-capture") void toggleCapture();
});
