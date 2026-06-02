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
  const diag = status.online
    ? `ok (online=true, queued=${status.queued})`
    : `offline — capture queued for retry (queued=${status.queued})`;
  await chrome.storage.local.set({
    lastCapture: { at: new Date().toISOString(), trigger, url: tab.url, bytes: imageBase64.length, diag },
  });

  await chrome.action.setBadgeText({ text: status.online ? (status.queued ? String(status.queued) : "") : "off" });
  await chrome.action.setBadgeBackgroundColor({ color: status.online ? "#2d6cdf" : "#cc3333" });
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
