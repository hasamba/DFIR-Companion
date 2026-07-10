import { initArtifactCapture } from "./artifactCapture.js";

let lastKeyNotify = 0;

function notify(reason: "click" | "keydown") {
  chrome.runtime.sendMessage({ kind: "user_event", reason }).catch(() => {});
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
// popup's manual override (see popup.ts) can still force one on — so a lightweight listener is
// always registered, even where nothing is currently detected.
void initArtifactCapture();
