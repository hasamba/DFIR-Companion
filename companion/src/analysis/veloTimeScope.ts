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

// A date-parameter pair for one artifact: which parameter takes the lower bound, which the upper.
export interface TimeScopeParamPair {
  start?: string;
  end?: string;
}

// How one artifact ended up mapped (or not) — surfaced in the run-form preview so nothing is guessed
// silently, and so "collects in full" is visibly different from "scoped".
export interface ArtifactTimeScopeMapping {
  artifact: string;
  startParam?: string;
  endParam?: string;
  source: "correction" | "builtin" | "detected" | "none";
  manual?: boolean;   // the bundle already sets one of these parameters by hand; that value wins
}

export interface TimeScopePlan {
  scoped: ArtifactTimeScopeMapping[];
  unscoped: ArtifactTimeScopeMapping[];   // no date parameter found — these collect in full
  params: Record<string, Record<string, string>>;   // bundle params + the window, ready for buildHuntSpec
  degraded: boolean;   // the server reported no parameter metadata for ANY bundle artifact
}

// Just enough of VeloArtifactInfo to map parameters — kept structural so the pure module doesn't
// import the Velociraptor client.
export interface TimeScopeArtifactDef {
  name: string;
  parameters?: { name: string; type?: string }[];
}

export interface TimeScopePlanInput {
  artifacts: string[];
  definitions: TimeScopeArtifactDef[];
  scope: TimeScope;
  corrections?: Record<string, TimeScopeParamPair>;        // saved on the bundle by the analyst
  builtInCorrections?: Record<string, TimeScopeParamPair>; // shipped table (defaults to BUILT_IN_TIME_SCOPE_PARAMS)
  bundleParams?: Record<string, Record<string, string>>;   // the bundle's existing per-artifact params
}

// Artifacts whose date parameters auto-detection gets wrong or can't see. Empty today: every artifact
// in the shipped bundles that HAS date parameters names them detectably. It exists as the escape hatch
// the design calls for — add an entry here (rather than special-casing the classifier) when a real
// server turns up an artifact that needs one.
export const BUILT_IN_TIME_SCOPE_PARAMS: Record<string, TimeScopeParamPair> = {};

const LOWER_HINTS = ["after", "start", "begin", "from", "since", "earliest"];
const UPPER_HINTS = ["before", "end", "until", "latest"];
const TEMPORAL_HINTS = ["date", "time", "stamp"];

const hasAny = (haystack: string, needles: string[]): boolean => needles.some((n) => haystack.includes(n));

// Classify one parameter as a lower/upper time bound, or neither.
//
// A name must carry BOTH a direction hint AND a temporal hint ("DateAfter", "StartDate", "dateBefore").
// Requiring both is what keeps "PathFrom" and "CopyTo" out — a false positive here silently
// under-collects, which looks like absence of evidence, so the classifier is deliberately conservative.
// A parameter the server DECLARES as a timestamp only needs a direction hint.
function classifyParam(param: { name: string; type?: string }): "start" | "end" | null {
  const lower = param.name.toLowerCase();
  const isTimestampTyped = (param.type ?? "").includes("timestamp");
  const temporal = isTimestampTyped || hasAny(lower, TEMPORAL_HINTS);
  if (!temporal) return null;
  if (hasAny(lower, LOWER_HINTS)) return "start";
  if (hasAny(lower, UPPER_HINTS)) return "end";
  return null;
}

// Auto-detect an artifact's bound parameters. Timestamp-typed parameters win over name-only matches;
// within each group the first match in declaration order wins.
function detectPair(params: { name: string; type?: string }[]): TimeScopeParamPair {
  const pair: TimeScopeParamPair = {};
  const typedFirst = [...params].sort((a, b) => Number((b.type ?? "").includes("timestamp")) - Number((a.type ?? "").includes("timestamp")));
  for (const p of typedFirst) {
    const kind = classifyParam(p);
    if (kind === "start" && !pair.start) pair.start = p.name;
    if (kind === "end" && !pair.end) pair.end = p.name;
  }
  return pair;
}

// Fan ONE window out across a bundle's artifacts. Precedence, highest first: the analyst's saved
// correction → the shipped table → auto-detection from the server. A parameter the bundle already sets
// by hand is never overwritten (the artifact still counts as scoped, and is flagged `manual`).
export function buildTimeScopePlan(input: TimeScopePlanInput): TimeScopePlan {
  const { artifacts, definitions, scope } = input;
  const corrections = input.corrections ?? {};
  const builtIns = input.builtInCorrections ?? BUILT_IN_TIME_SCOPE_PARAMS;
  const byName = new Map(definitions.map((d) => [d.name, d]));

  // Start from the bundle's own params so unrelated tuning (e.g. Hayabusa RuleLevel) survives.
  const params: Record<string, Record<string, string>> = {};
  for (const [artifact, kv] of Object.entries(input.bundleParams ?? {})) params[artifact] = { ...kv };

  const scoped: ArtifactTimeScopeMapping[] = [];
  const unscoped: ArtifactTimeScopeMapping[] = [];
  let sawAnyMetadata = false;

  for (const artifact of artifacts) {
    const def = byName.get(artifact);
    const declared = def?.parameters ?? [];
    if (declared.length) sawAnyMetadata = true;

    let pair: TimeScopeParamPair | undefined;
    let source: ArtifactTimeScopeMapping["source"] = "none";
    if (corrections[artifact]?.start || corrections[artifact]?.end) { pair = corrections[artifact]; source = "correction"; }
    else if (builtIns[artifact]?.start || builtIns[artifact]?.end) { pair = builtIns[artifact]; source = "builtin"; }
    else {
      const detected = detectPair(declared);
      if (detected.start || detected.end) { pair = detected; source = "detected"; }
    }

    if (!pair) { unscoped.push({ artifact, source: "none" }); continue; }

    const existing = params[artifact] ?? {};
    let manual = false;
    const set = (paramName: string | undefined, value: string | undefined): void => {
      if (!paramName || !value) return;
      if (Object.prototype.hasOwnProperty.call(existing, paramName)) { manual = true; return; }   // analyst's value wins
      existing[paramName] = value;
    };
    set(pair.start, scope.start);
    set(pair.end, scope.end);
    if (Object.keys(existing).length) params[artifact] = existing;
    scoped.push({ artifact, startParam: pair.start, endParam: pair.end, source, ...(manual ? { manual: true } : {}) });
  }

  return { scoped, unscoped, params, degraded: !sawAnyMetadata };
}
