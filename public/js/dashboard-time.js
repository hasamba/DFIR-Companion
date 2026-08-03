// Every "how long ago was that" formatter the dashboard had, in one file (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED. See js/dashboard-escape.js for the whole argument; the
// short form is that dashboard.html's inline script calls these by bare name at 427 sites, one of
// them while the page is still parsing, so the declarations have to be real globals that exist
// before <script nonce> at line 6538 runs.
//
// SIX OF THESE DO THE SAME JOB AND DISAGREE. lgAgo, veloClientsAge, veloMonAge, relTime,
// activityTimeAgo and cockpitAge all turn a timestamp into a relative string, and all six differ:
// on an unparseable input they return "just now" / "never refreshed" / "never" / "unknown" / "—"
// / "" respectively; three floor and three round; one falls back to a locale string past 48h.
// They were 700 to 12,000 lines apart, so nothing made that visible.
//
// THEY ARE MOVED VERBATIM ANYWAY. Unifying them would change what six panels render, which is a
// product decision and not this issue's. Putting them side by side is the prerequisite for making
// it once, deliberately -- and the tests below pin what each one does today so that change cannot
// happen by accident.

// The case timeline is UTC, so the <input type="datetime-local"> pickers (scope, manual event)
// are treated as UTC wall-clock, NOT the browser's local zone: show the UTC components, and parse
// the picked value back as UTC.
function isoToUtcInput(iso) {
  if (!iso) return "";
  const d = new Date(iso); if (isNaN(d)) return "";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}

function utcInputToIso(v) {
  if (!v) return null;
  const d = new Date((v.length === 16 ? v + ":00" : v) + "Z"); // the picked wall-clock IS UTC
  return isNaN(d) ? null : d.toISOString();
}

// Age formatter for the "generated X ago" header.
function lgAgo(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "just now";   // unparseable timestamp — never "NaN h ago"
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return "a few seconds ago";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

// Client inventory (#70): the persisted host ↔ client_id map a single-endpoint collection resolves
// against. Refreshed at startup + lazily on a collect miss; this shows its size + a manual refresh.
function veloClientsAge(updatedAt) {
  if (!updatedAt) return "never refreshed";
  const ms = Date.now() - new Date(updatedAt).getTime();
  if (!isFinite(ms) || ms < 0) return "just now";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "just now"; if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60); if (h < 24) return h + "h ago";
  return Math.floor(h / 24) + "d ago";
}

function veloMonAge(iso) {
  if (!iso) return "never";
  const ms = Date.now() - new Date(iso).getTime();
  if (!isFinite(ms) || ms < 0) return "just now";
  const s = Math.floor(ms / 1000); if (s < 60) return s + "s ago";
  const m = Math.floor(s / 60); if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60); if (h < 24) return h + "h ago";
  return Math.floor(h / 24) + "d ago";
}

// --- Synthesis freshness + what-changed diff ----------------------------------
// Shows when synthesis last actually ran and how the findings changed since the prior run, so
// the analyst can see the effect of a re-synthesis instead of findings silently shuffling.
function relTime(iso) {
  if (!iso) return "never";
  const t = Date.parse(iso); if (isNaN(t)) return "unknown";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + "s ago";
  const m = Math.round(s / 60); if (m < 60) return m + "m ago";
  const h = Math.round(m / 60); if (h < 24) return h + "h ago";
  return Math.round(h / 24) + "d ago";
}

function fmtTime(iso) {
  try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
}

function mcpJobDuration(ms) {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return minutes < 60 ? `${minutes}m ${seconds % 60}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function activityTimeAgo(iso) {
  // The Number.isNaN below does NOT cover a missing timestamp, which is why this looks redundant
  // and is not (#458): `new Date(null)` is the epoch rather than Invalid Date, so a null
  // collectedAt used to arrive here as a valid instant and render "20513d ago" — 57 years.
  // `new Date(undefined)` IS Invalid Date, so only null ever reached that path.
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return "—";
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function cockpitAge(value) {
  if (!value) return "";
  const t = Date.parse(value);
  if (!Number.isFinite(t)) return "";
  const mins = Math.max(0, Math.floor((Date.now() - t) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return new Date(t).toLocaleString();
}

// Host Clock Skew panel (#228) — per-host offsets, the alignment toggle and manual overrides.
// Offsets are stored in milliseconds; the UI talks in seconds because that is how an analyst
// thinks about NTP drift and timezone slips.
function skewOffsetLabel(ms) {
  const abs = Math.abs(ms);
  if (abs < 1000) return ms === 0 ? "0s" : ms + "ms";
  if (abs < 90_000) return (ms / 1000).toFixed(ms % 1000 === 0 ? 0 : 1) + "s";
  if (abs < 5_400_000) return (ms / 60_000).toFixed(1) + "m";
  return (ms / 3_600_000).toFixed(2) + "h";
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirTime = {
  isoToUtcInput,
  utcInputToIso,
  lgAgo,
  veloClientsAge,
  veloMonAge,
  relTime,
  fmtTime,
  mcpJobDuration,
  activityTimeAgo,
  cockpitAge,
  skewOffsetLabel,
};
