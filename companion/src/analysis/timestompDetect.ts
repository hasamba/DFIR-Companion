// Deterministic NTFS $STANDARD_INFORMATION ($SI) vs $FILE_NAME ($FN) timestamp comparison to flag
// timestomping (ATT&CK T1070.006). Ported in spirit from Timesketch's `ntfs_timestomp` analyzer, but
// adapted to our data model: our MFT importers — Windows.NTFS.MFT (Velociraptor) and MFTECmd (KAPE) —
// carry BOTH the $SI and $FN timestamps on the SAME row (Created0x10 = $SI, Created0x30 = $FN), so we
// compare them inline per file instead of grouping separate plaso events by file_reference the way
// Timesketch has to.
//
// Two independent, deterministic fingerprints — either one fires the flag:
//   1. Backdating — $SI Created is EARLIER than $FN Created by more than a threshold (default 10 min,
//      matching Timesketch's `10 * 60_000_000` µs). Attackers backdate the user-facing $SI to make a
//      dropped file look like an old system file; $FN (set when the MFT record is created and not
//      writable through the usual Win32 time APIs) keeps the true time. Directional on purpose (only
//      $SI earlier than $FN, never the reverse) to cut false positives.
//   2. Sub-second truncation — $SI Created lands on a whole second (no / all-zero sub-second field)
//      while $FN Created carries a non-zero sub-second. Genuine NTFS creation times have 100 ns
//      precision; naive timestomp tools (Metasploit `timestomp`, PowerShell `.CreationTime = <round
//      DateTime>`) write a zeroed sub-second. A file COPIED from an older source, by contrast,
//      preserves the source's full-precision $SI — so this is a low-false-positive tell.
//
// Graded Medium, never High: both signals have benign causes (a file copied from an older source
// keeps the old $SI while $FN is the copy time; some files are legitimately created on a whole
// second), so this feeds the false-positive-marking workflow rather than manufacturing a High —
// consistent with the project's signal-to-noise discipline. Pure, AI-free, unit-tested.

export const DEFAULT_TIMESTOMP_THRESHOLD_MS = 10 * 60 * 1000; // 10 minutes, matching Timesketch

// Threshold in ms, overridable via DFIR_TIMESTOMP_THRESHOLD_MINUTES (positive number). Read at call
// time (not module load) so a test / deployment can set it without re-importing.
export function timestompThresholdMs(): number {
  const min = Number(process.env.DFIR_TIMESTOMP_THRESHOLD_MINUTES);
  return Number.isFinite(min) && min > 0 ? min * 60 * 1000 : DEFAULT_TIMESTOMP_THRESHOLD_MS;
}

export type TimestompSignal = "backdated" | "subsecond-zeroed";

export interface TimestompVerdict {
  mitre: string[];             // always ["T1070.006"]
  severity: "Medium";
  signals: TimestompSignal[];  // which fingerprint(s) fired, worst-first (backdated before subsecond)
  note: string;                // human-readable, appended to the event description
  deltaMs: number;             // fnCreated - siCreated (signed, positive ⇒ $SI is earlier)
}

// Sentinel date prefixes that mean "unset" in MFT output (FILETIME 0 / .NET min date) — never a real
// timestomp signal, so a row carrying one is skipped rather than flagged.
const UNSET_PREFIXES = ["0001-01-01", "1601-01-01"];
const MIN_VALID_MS = Date.parse("1970-01-02T00:00:00Z"); // reject epoch-0 / pre-epoch sentinels

// Parse an MFT timestamp string to epoch ms, tolerating both RFC3339 ("...T..Z", Velociraptor) and
// EZ-tools' naive "yyyy-MM-dd HH:mm:ss.fffffff" (space, 7-digit fraction, no zone → treated as UTC).
// Returns NaN for unset sentinels / unparseable / pre-1970 values.
function parseMs(raw: string): number {
  const t = raw.trim();
  if (!t || UNSET_PREFIXES.some((p) => t.startsWith(p))) return NaN;
  let s = t.replace(" ", "T");            // naive "date time" → ISO "dateTtime"
  s = s.replace(/(\.\d{3})\d+/, "$1");    // truncate >3-digit fraction so Date.parse accepts it
  if (!/[zZ]|[+-]\d{2}:?\d{2}$/.test(s)) s += "Z"; // no zone ⇒ UTC (EZ tools emit UTC)
  const ms = Date.parse(s);
  return Number.isFinite(ms) && ms >= MIN_VALID_MS ? ms : NaN;
}

// The sub-second fraction digits of a timestamp string (from the RAW value, before any ms
// truncation), or "" when absent. Read from raw so the truncation signal survives.
function subSecondDigits(raw: string): string {
  const m = raw.match(/:\d{2}:\d{2}\.(\d+)/);
  return m ? m[1] : "";
}
function hasNonZeroSubSecond(raw: string): boolean {
  return /[1-9]/.test(subSecondDigits(raw));
}

function humanizeDelta(ms: number): string {
  const abs = Math.abs(ms);
  const day = 86_400_000, hour = 3_600_000, min = 60_000;
  if (abs >= day) {
    const d = Math.floor(abs / day);
    return d >= 365 ? `${Math.floor(d / 365)}y ${Math.floor((d % 365) / 30)}mo` : `${d}d`;
  }
  if (abs >= hour) return `${Math.floor(abs / hour)}h`;
  return `${Math.max(1, Math.floor(abs / min))}m`;
}

// Compare a file's raw $SI-created and $FN-created timestamp strings (straight off the MFT row — pass
// the RAW values, not the normalized event time, so the sub-second signal is preserved). Returns a
// verdict when a timestomp fingerprint is present, else null (missing pair, unparseable, or clean).
export function detectTimestomp(
  siCreated: string | null | undefined,
  fnCreated: string | null | undefined,
  thresholdMs: number = timestompThresholdMs(),
): TimestompVerdict | null {
  const si = (siCreated ?? "").toString();
  const fn = (fnCreated ?? "").toString();
  const siMs = parseMs(si);
  const fnMs = parseMs(fn);
  if (!Number.isFinite(siMs) || !Number.isFinite(fnMs)) return null;

  const deltaMs = fnMs - siMs; // positive ⇒ $SI predates $FN (backdating direction)
  const signals: TimestompSignal[] = [];

  if (deltaMs > thresholdMs) signals.push("backdated");
  // Sub-second zeroing only counts in the backdating direction ($SI at or before $FN), so a normal
  // file that merely happens to be created on a whole second isn't flagged on its own.
  if (deltaMs >= 0 && !hasNonZeroSubSecond(si) && hasNonZeroSubSecond(fn)) signals.push("subsecond-zeroed");

  if (signals.length === 0) return null;

  const parts: string[] = [];
  if (signals.includes("backdated")) {
    parts.push(`$SI creation predates $FN creation by ${humanizeDelta(deltaMs)}`);
  }
  if (signals.includes("subsecond-zeroed")) {
    parts.push("$SI sub-second precision zeroed while $FN has it");
  }
  const note = `Possible timestomping (T1070.006): ${parts.join("; ")}`;

  return { mitre: ["T1070.006"], severity: "Medium", signals, note, deltaMs };
}
