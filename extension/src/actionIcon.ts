// Toolbar icon that reflects capture state: a solid red "recording" dot when ON,
// a dim hollow ring when OFF. Rendered at runtime with OffscreenCanvas (available
// in MV3 service workers) so the extension ships no binary icon assets.

const RECORDING_RED = "#e5484d";
const IDLE_GREY = "#8b94a3";

// Draw the action icon at a given pixel size. Exported for clarity/reuse; the
// service worker renders 16px + 32px for crisp toolbars at any display scale.
export function drawActionIcon(size: number, recording: boolean): ImageData {
  const canvas = new OffscreenCanvas(size, size);
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("OffscreenCanvas 2D context unavailable");

  ctx.clearRect(0, 0, size, size);
  const center = size / 2;
  const radius = size * 0.34;

  ctx.beginPath();
  ctx.arc(center, center, radius, 0, Math.PI * 2);
  if (recording) {
    ctx.fillStyle = RECORDING_RED;
    ctx.fill();
  } else {
    // Hollow ring reads as "idle / not recording".
    ctx.lineWidth = Math.max(1, size * 0.12);
    ctx.strokeStyle = IDLE_GREY;
    ctx.stroke();
  }
  return ctx.getImageData(0, 0, size, size);
}

// Update the toolbar icon + tooltip to match the current capture state.
export async function setActionIcon(recording: boolean): Promise<void> {
  await chrome.action.setIcon({
    imageData: { 16: drawActionIcon(16, recording), 32: drawActionIcon(32, recording) },
  });
  await chrome.action.setTitle({
    title: recording ? "DFIR Companion — recording" : "DFIR Companion — stopped",
  });
}
