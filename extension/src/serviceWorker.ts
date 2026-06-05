import { CompanionClient } from "./companionClient.js";
import { CaptureQueue } from "./captureQueue.js";
import { CaptureController } from "./captureController.js";
import { setActionIcon } from "./actionIcon.js";
import { DEFAULT_SETTINGS, type Settings, type TriggerType } from "./types.js";

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
    ? `rejected (HTTP ${status.rejected}) — case missing? create/select it in the dashboard`
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
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.kind === "user_event") void captureActiveTab("click");
  if (msg?.kind === "settings_changed") void rescheduleAlarm();
});
chrome.runtime.onInstalled.addListener(() => void rescheduleAlarm());
chrome.runtime.onStartup.addListener(() => void rescheduleAlarm());
// Keyboard shortcut (default Ctrl+Shift+S / Cmd+Shift+S) to toggle capture on/off.
chrome.commands?.onCommand.addListener((command) => {
  if (command === "toggle-capture") void toggleCapture();
});
