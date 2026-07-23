// Context-menu send (right-click → "Send … to DFIR-Companion"). Runs on every page (content.js
// already matches <all_urls>) so it works even where no adapter is registered — unlike the
// adapter-driven floating push button in artifactCapture.ts.
//
// Chrome's contextMenus API gives no reference to the element under the cursor, so table
// targeting uses the standard workaround: remember the element from the native "contextmenu"
// event, then walk up to its nearest <table> ancestor when the service worker asks for it.

import { readTableMatrix } from "./artifactCapture.js";
import { matrixToRows } from "./adapters/domTable.js";
import type { ContextPushResultMessage, ContextTableResult } from "./types.js";

const TOAST_ID = "dfir-companion-toast";
// Explicitly `number`, not ReturnType<typeof window.setTimeout>: `window` is typed
// `Window & typeof globalThis`, so once @types/node is in the program that lookup resolves to
// Node's setTimeout (NodeJS.Timeout) rather than the DOM's. This is content-script code — the
// browser timer id is a number.
let toastTimer: number | undefined;
let lastRightClickTarget: Element | null = null;

export function initContextMenuCapture(): void {
  // Capture phase so this fires even if a page's own contextmenu handler stops propagation.
  document.addEventListener("contextmenu", (e) => {
    lastRightClickTarget = e.target instanceof Element ? e.target : null;
  }, true);

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    const kind = (msg as { kind?: string })?.kind;
    if (kind === "get_context_table") {
      sendResponse(findContextTable() satisfies ContextTableResult);
      return; // synchronous response — no need to keep the channel open
    }
    if (kind === "context_push_result") {
      const { ok, message } = msg as ContextPushResultMessage;
      showToast(message, ok ? "#1a7f37" : "#b42318");
      return;
    }
  });
}

function findContextTable(): ContextTableResult {
  const table = lastRightClickTarget?.closest("table") ?? null;
  if (!table) return { rows: null };
  const { headers, rows } = readTableMatrix(table);
  const objs = matrixToRows(headers, rows);
  return { rows: objs.length ? objs : null };
}

// Small floating banner, independent of the adapter push button's #dfir-companion-push-btn — a
// context-menu send can happen on any page, including ones with no adapter/button. Reuses the same
// success/error colors as artifactCapture.ts's flash() for visual consistency.
function showToast(message: string, color: string): void {
  let el = document.getElementById(TOAST_ID);
  if (!el) {
    el = document.createElement("div");
    el.id = TOAST_ID;
    Object.assign(el.style, {
      position: "fixed", top: "16px", right: "16px", zIndex: "2147483647",
      padding: "10px 14px", borderRadius: "8px", font: "600 13px system-ui, sans-serif",
      color: "#fff", boxShadow: "0 2px 8px rgba(0,0,0,.3)", maxWidth: "320px",
      pointerEvents: "none",
    } as Partial<CSSStyleDeclaration>);
    (document.body || document.documentElement).appendChild(el);
  }
  el.textContent = message;
  el.style.background = color;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => el?.remove(), 4000);
}
