import { CompanionClient } from "./companionClient.js";
import { DEFAULT_SETTINGS, type Settings } from "./types.js";

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const statusEl = () => document.getElementById("status") as HTMLDivElement;

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
    caseId: $("caseId").value.trim(),
    companionUrl: $("companionUrl").value.trim() || DEFAULT_SETTINGS.companionUrl,
    intervalSeconds: Math.max(5, Number($("intervalSeconds").value) || 10),
    dedupThreshold: Math.max(0, Number($("dedupThreshold").value) || 5),
    running,
  };
}

async function refreshStatus(s: Settings): Promise<void> {
  const online = await new CompanionClient(s.companionUrl).ping();
  const el = statusEl();
  el.textContent = `${s.running ? "capturing" : "stopped"} — companion ${online ? "online" : "offline"}`;
  el.className = online ? "on" : "off";
}

async function init() {
  const s = await load();
  $("caseId").value = s.caseId;
  $("companionUrl").value = s.companionUrl;
  $("intervalSeconds").value = String(s.intervalSeconds);
  $("dedupThreshold").value = String(s.dedupThreshold);
  await refreshStatus(s);

  document.getElementById("createCase")!.onclick = async () => {
    const f = readForm(s.running);
    if (!f.caseId) {
      statusEl().textContent = "enter a Case ID first";
      return;
    }
    try {
      const res = await fetch(`${f.companionUrl}/cases`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ caseId: f.caseId, name: f.caseId, investigator: "investigator", aiProvider: null }),
      });
      statusEl().textContent =
        res.status === 201 ? `case ${f.caseId} created` : `create failed: HTTP ${res.status}`;
    } catch (err) {
      statusEl().textContent = `create failed: ${(err as Error).message} — is the companion running at ${f.companionUrl}?`;
    }
  };
  document.getElementById("start")!.onclick = async () => {
    const f = readForm(true);
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
