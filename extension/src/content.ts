import { initArtifactCapture, setArtifactCaptureEnabled } from "./artifactCapture.js";
import { initContextMenuCapture } from "./contextMenuCapture.js";
import { browserApi } from "./browser.js";
import { isExtensionContextInvalidated, runBestEffortExtensionCall } from "./extensionContext.js";
import { originPatternMatchesUrl } from "./siteAccess.js";
import type { SiteAccessChangedMessage } from "./types.js";

let lastKeyNotify = 0;
let siteAccessEnabled = true;

function disableInvalidatedContext(): void {
  siteAccessEnabled = false;
  setArtifactCaptureEnabled(false);
}

function notify(reason: "click" | "keydown") {
  if (!siteAccessEnabled) return;
  runBestEffortExtensionCall(
    () => browserApi.runtime.sendMessage({ kind: "user_event", reason }),
    disableInvalidatedContext,
  );
}

document.addEventListener("click", () => notify("click"), { capture: true, passive: true });

document.addEventListener("keydown", () => {
  const now = Date.now();
  if (now - lastKeyNotify > 3000) { // debounce typing bursts
    lastKeyNotify = now;
    notify("keydown");
  }
}, { capture: true, passive: true });

// Automated artifact fetching (#102): on recognized DFIR consoles (Splunk / Velociraptor /
// Security Onion / SO-CRATES / Elastic / CrowdStrike / VolWeb) inject a "Push to DFIR-Companion"
// button + the API-interception hook. Every other site gets no button/hook by default, but the
// popup's manual override (see popup.ts) can still force one on. This bundle itself is injected
// only after the analyst approves the current origin.

browserApi.runtime.onMessage.addListener((message) => {
  const change = message as Partial<SiteAccessChangedMessage>;
  if (change.kind !== "site_access_changed" || !Array.isArray(change.origins)) return;
  if (!change.origins.some((origin) => originPatternMatchesUrl(origin, location.href))) return;
  siteAccessEnabled = change.allowed === true;
  setArtifactCaptureEnabled(siteAccessEnabled);
});

// Context-menu send (#new): right-click-target tracking + toast rendering on analyst-approved pages.
initContextMenuCapture(() => siteAccessEnabled);
void initArtifactCapture().catch((error: unknown) => {
  if (isExtensionContextInvalidated(error)) disableInvalidatedContext();
});
