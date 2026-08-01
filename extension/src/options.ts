import { DEFAULT_SETTINGS, normalizeCompanionUrl, type Settings } from "./types.js";
import { browserApi } from "./browser.js";
import { readAuditEntries, SITE_ACCESS_AUDIT_KEY } from "./siteAccess.js";

function appendEmptyState(list: HTMLUListElement, text: string): void {
  const item = document.createElement("li");
  item.textContent = text;
  item.className = "hint";
  list.appendChild(item);
}

async function renderSiteAccess(): Promise<void> {
  const originsList = document.getElementById("approvedOrigins") as HTMLUListElement;
  const auditList = document.getElementById("accessAudit") as HTMLUListElement;
  const [permissions, stored] = await Promise.all([
    browserApi.permissions.getAll(),
    browserApi.storage.local.get(SITE_ACCESS_AUDIT_KEY),
  ]);
  const origins = (permissions.origins ?? []).filter((origin) => /^https?:\/\//.test(origin)).sort();
  originsList.replaceChildren();
  if (!origins.length) appendEmptyState(originsList, "No console origins approved.");
  for (const origin of origins) originsList.appendChild(originRow(origin));

  const entries = readAuditEntries(stored[SITE_ACCESS_AUDIT_KEY]).slice(-25).reverse();
  auditList.replaceChildren();
  if (!entries.length) appendEmptyState(auditList, "No permission changes recorded yet.");
  for (const entry of entries) {
    const item = document.createElement("li");
    item.textContent = `${entry.at}  ${entry.action.toUpperCase()}  ${entry.origin}`;
    auditList.appendChild(item);
  }
}

function originRow(origin: string): HTMLLIElement {
  const item = document.createElement("li");
  const label = document.createElement("code");
  label.textContent = origin;
  const revoke = document.createElement("button");
  revoke.type = "button";
  revoke.textContent = "Revoke";
  revoke.onclick = async () => {
    await browserApi.permissions.remove({ origins: [origin] });
    await renderSiteAccess();
  };
  item.append(label, revoke);
  return item;
}

async function init() {
  const stored = await browserApi.storage.local.get("settings");
  const settings: Settings = { ...DEFAULT_SETTINGS, ...(stored.settings as Partial<Settings> | undefined) };
  const input = document.getElementById("companionUrl") as HTMLInputElement;
  const tokenInput = document.getElementById("serviceToken") as HTMLInputElement;
  const msg = document.getElementById("msg")!;
  input.value = settings.companionUrl;
  tokenInput.value = settings.serviceToken;
  await renderSiteAccess();

  browserApi.permissions.onAdded.addListener(() => void renderSiteAccess());
  browserApi.permissions.onRemoved.addListener(() => void renderSiteAccess());

  document.getElementById("save")!.onclick = async () => {
    const updated = {
      ...settings,
      companionUrl: normalizeCompanionUrl(input.value),
      serviceToken: tokenInput.value.trim(),
    };
    await browserApi.storage.local.set({ settings: updated });
    await browserApi.runtime.sendMessage({ kind: "settings_changed" }).catch(() => {});
    msg.textContent = "Saved.";
    setTimeout(() => { msg.textContent = ""; }, 2000);
  };
}

void init();
