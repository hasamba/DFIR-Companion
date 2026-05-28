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
