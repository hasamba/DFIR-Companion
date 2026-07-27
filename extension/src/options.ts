import { DEFAULT_SETTINGS, normalizeCompanionUrl, type Settings } from "./types.js";
import { browserApi } from "./browser.js";

async function init() {
  const stored = await browserApi.storage.local.get("settings");
  const settings: Settings = { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
  const input = document.getElementById("companionUrl") as HTMLInputElement;
  const msg = document.getElementById("msg")!;
  input.value = settings.companionUrl;

  document.getElementById("save")!.onclick = async () => {
    const updated = { ...settings, companionUrl: normalizeCompanionUrl(input.value) };
    await browserApi.storage.local.set({ settings: updated });
    await browserApi.runtime.sendMessage({ kind: "settings_changed" }).catch(() => {});
    msg.textContent = "Saved.";
    setTimeout(() => { msg.textContent = ""; }, 2000);
  };
}

void init();
