// A named, analyst-defined time window believed to bound attacker activity on a host — a saved
// timeframe used to scope the super-timeline query (see analysis/superTimeline.ts). Durable,
// investigation-owned data: kept in DwellWindowStore and included in case snapshot export/import.

export interface DwellWindow {
  id: string; // uuid
  label: string; // analyst-entered, e.g. "Attacker session 1"
  start: string; // ISO-8601
  end: string; // ISO-8601
  createdAt: string; // ISO-8601
}

export interface DwellWindowInput {
  label: string;
  start: string;
  end: string;
}

// Trim/validate raw create/update input. Throws a descriptive Error on the first problem found —
// callers (the store, the route) surface err.message directly.
export function sanitizeDwellWindowInput(raw: { label?: unknown; start?: unknown; end?: unknown }): DwellWindowInput {
  const label = String(raw.label ?? "").trim();
  if (!label) throw new Error("label is required");

  const startMs = Date.parse(String(raw.start ?? ""));
  if (Number.isNaN(startMs)) throw new Error("start must be a valid date");
  const endMs = Date.parse(String(raw.end ?? ""));
  if (Number.isNaN(endMs)) throw new Error("end must be a valid date");
  if (endMs < startMs) throw new Error("end must be after start");

  return {
    label: label.slice(0, 200),
    start: new Date(startMs).toISOString(),
    end: new Date(endMs).toISOString(),
  };
}
