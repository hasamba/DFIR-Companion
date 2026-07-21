// Translates ONE analyst-chosen collection window into the per-artifact date parameters each
// Velociraptor artifact happens to expose, so a triage bundle collects less AT THE SOURCE rather than
// being filtered after import. Pure: no I/O, no Velociraptor client, no Express. The output feeds the
// existing per-artifact `params` → `spec=dict(...)` hunt path (see velociraptorApi.buildHuntSpec).

// A resolved collection window. `end` is OPTIONAL and absent for relative presets: a hunt keeps
// scheduling on clients that check in after launch, so pinning an upper bound at launch time would
// silently drop activity that happened in between.
export interface TimeScope {
  start: string;        // ISO-8601 UTC
  end?: string;         // ISO-8601 UTC
}

// Raw run-form input: either a relative preset or an absolute custom range.
// Note: `preset` takes precedence over `start`/`end` — if both are supplied, dates are ignored.
export interface TimeScopeInput {
  preset?: unknown;     // "24h" | "7d" | "30d" | "90d" | "all" | "custom"; deliberately untyped (untrusted boundary)
  start?: unknown;      // ISO-8601 date string; deliberately untyped (untrusted boundary)
  end?: unknown;        // ISO-8601 date string; deliberately untyped (untrusted boundary)
}

const PRESET_MS: Record<string, number> = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
  "90d": 90 * 24 * 60 * 60 * 1000,
};

// Resolve run-form input into an absolute window, or undefined for "collect all time" (the default).
// Throws a descriptive Error on bad input — routes surface err.message directly, as sanitizeDwellWindowInput does.
export function resolveTimeScope(raw: TimeScopeInput | undefined, now: Date = new Date()): TimeScope | undefined {
  if (!raw) return undefined;
  const preset = String(raw.preset ?? "").trim();
  if (preset && preset !== "all" && preset !== "custom") {
    const ms = PRESET_MS[preset];
    if (!ms) throw new Error(`unknown time-scope preset "${preset}"`);
    return { start: new Date(now.getTime() - ms).toISOString() };
  }
  const rawStart = String(raw.start ?? "").trim();
  const rawEnd = String(raw.end ?? "").trim();
  if (!rawStart && !rawEnd) {
    // If "custom" was explicitly selected, require a start; otherwise allow "all time"
    if (preset === "custom") throw new Error("start is required for a custom time scope");
    return undefined;   // "all time" / nothing chosen
  }
  if (!rawStart) throw new Error("start is required for a custom time scope");
  const startMs = Date.parse(rawStart);
  if (Number.isNaN(startMs)) throw new Error("start must be a valid date");
  if (!rawEnd) return { start: new Date(startMs).toISOString() };
  const endMs = Date.parse(rawEnd);
  if (Number.isNaN(endMs)) throw new Error("end must be a valid date");
  if (endMs < startMs) throw new Error("end must be at or after start");
  return { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString() };
}
