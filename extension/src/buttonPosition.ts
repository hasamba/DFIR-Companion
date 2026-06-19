// Pure geometry for the draggable "Push to DFIR-Companion" button. Browser-free so it can be
// unit-tested. The injected button is fixed-positioned; we persist an absolute top-left pixel
// position and clamp it into the viewport on apply, so a saved spot from a larger window — or a
// later resize — can never push the button off-screen. The browser glue (pointer drag, storage)
// lives in artifactCapture.ts and consumes these helpers.

export interface ButtonPos {
  left: number;
  top: number;
}
export interface Size {
  width: number;
  height: number;
}
export interface Viewport {
  width: number;
  height: number;
}

/** Pointer travel (px) past which a press becomes a drag rather than a click. */
export const DRAG_THRESHOLD_PX = 4;

/**
 * Keep the button fully within the viewport, leaving a `margin` gap on every edge. When the button
 * is larger than the viewport (a very small window), it is pinned to the top-left margin rather than
 * producing a negative inset.
 */
export function clampButtonPosition(pos: ButtonPos, size: Size, viewport: Viewport, margin = 8): ButtonPos {
  const maxLeft = Math.max(margin, viewport.width - size.width - margin);
  const maxTop = Math.max(margin, viewport.height - size.height - margin);
  return {
    left: Math.min(Math.max(margin, pos.left), maxLeft),
    top: Math.min(Math.max(margin, pos.top), maxTop),
  };
}

/** Did the pointer move far enough from the press point to count as a drag (vs a click)? */
export function isDrag(dx: number, dy: number, threshold = DRAG_THRESHOLD_PX): boolean {
  return Math.hypot(dx, dy) >= threshold;
}

/** Validate a value loaded from storage into a ButtonPos, or null if it isn't one. */
export function parseButtonPos(v: unknown): ButtonPos | null {
  if (!v || typeof v !== "object") return null;
  const { left, top } = v as Record<string, unknown>;
  if (typeof left !== "number" || typeof top !== "number") return null;
  if (!Number.isFinite(left) || !Number.isFinite(top)) return null;
  return { left, top };
}
