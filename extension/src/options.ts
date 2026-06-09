import { DEFAULT_SETTINGS, normalizeCompanionUrl, type Settings } from "./types.js";

async function init() {
  const stored = await chrome.storage.local.get("settings");
  const settings: Settings = { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
  const input = document.getElementById("companionUrl") as HTMLInputElement;
  const msg = document.getElementById("msg")!;
  input.value = settings.companionUrl;

  document.getElementById("save")!.onclick = async () => {
    const updated = { ...settings, companionUrl: normalizeCompanionUrl(input.value) };
    await chrome.storage.local.set({ settings: updated });
    await chrome.runtime.sendMessage({ kind: "settings_changed" }).catch(() => {});
    msg.textContent = "Saved.";
    setTimeout(() => { msg.textContent = ""; }, 2000);
  };
}

void init();
