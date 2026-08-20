import { describe, it, expect } from "vitest";
import { thorFields } from "../../src/analysis/thorRowMap.js";

// Field-for-field copies of three real findings from a THOR scan collected through
// `Generic.Scanner.ThorZIP/ThorResultsJson` (case INC-2026-010). Trimmed to the keys the mapper reads.
const ENVELOPE = { scanid: "S-Q6xzjtl84jQ", log_version: "v1.0.0" };

const processHit = {
  ...ENVELOPE,
  time: "2026-08-18T15:45:21.000Z",
  hostname: "DESKTOP-OPE297N",
  level: "Alert",
  module: "ProcessCheck",
  message: "Malicious process found",
  pid: 5800,
  command: '"C:\\Program Files\\Velociraptor\\Velociraptor.exe" --config client.config.yaml service run',
  parent: "C:\\Windows\\System32\\services.exe",
  process_name: "Velociraptor.exe",
  owner: "NT AUTHORITY\\SYSTEM",
  image_file: "C:\\Program Files\\Velociraptor\\Velociraptor.exe",
  image_sha256: "c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e",
  reason_1: "YARA rule PSAttack_EXE / PSAttack - Powershell attack tool - file PSAttack.exe",
  rulename_1: "PSAttack_EXE",
  tags_1: "EXE, HKTL, SCRIPT, T1059_001",
  score: 100,
};
const fileHit = {
  ...ENVELOPE,
  level: "Warning",
  module: "Filescan",
  message: "Possibly Dangerous file found",
  file: "C:\\Users\\vagrant\\AppData\\Local\\DFIR-Lab\\CredentialAccess\\mimikatz.exe",
  sha256: "9695cf4566ddf878a69c3d419e0da4eea87b0f24261ad8e79a3a9c4a9885429c",
  owner: "BUILTIN\\Administrators",
  reason_1: "Filename IOC \\mimikatz.exe",
  ref_1: "Cred Dumping",
  score: 60,
};
const logHit = {
  ...ENVELOPE,
  level: "Warning",
  module: "LogScan",
  message: "Suspicious Log Entry found",
  entry: "2026-08-18T16:14:39.033 Engine:command line reported as threat: mimikatz.exe",
  file: "C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-20251205-033941.log",
  reason_1: "Keyword IOC match",
  matched_1: "sekurlsa::logonpasswords",
  score: 79,
};

describe("thorFields — a THOR finding collected through Velociraptor", () => {
  it("names the FILE a file finding is about, in the title", () => {
    expect(thorFields(fileHit)!.description).toBe(
      "THOR Warning [Filescan]: Possibly Dangerous file found — mimikatz.exe",
    );
  });

  it("names the ENTRY a log finding is about, not just the log file", () => {
    const f = thorFields(logHit)!;
    expect(f.detail).toContain("entry: 2026-08-18T16:14:39.033 Engine:command line reported as threat");
    expect(f.detail).toContain("MPLog-20251205-033941.log"); // the log it came from, too
  });

  it("does not basename a log entry — it is prose, not a path", () => {
    // The entry is full of backslashes (it quotes a Windows command line), so splitting on them left
    // a title starting mid-word: "…— c echo SIMULATION ONLY".
    const title = thorFields(logHit)!.description;
    expect(title).toContain("— 2026-08-18T16:14:39.033 Engine:command line reported as threat");
    expect(title).not.toMatch(/— [a-z]/); // never starts the subject mid-word
  });

  it("names the PROCESS a process finding is about, and keeps the chain fields", () => {
    const f = thorFields(processHit)!;
    expect(f.description).toBe("THOR Alert [ProcessCheck]: Malicious process found — Velociraptor.exe");
    expect(f.processName).toBe("Velociraptor.exe");
    expect(f.parentName).toBe("services.exe"); // basename, for parent→child chain validation
  });

  it("drops the Velociraptor artifact/source label the analyst never needed", () => {
    expect(thorFields(fileHit)!.description).not.toContain("ThorResultsJson");
    expect(thorFields(fileHit)!.description).not.toContain("Velociraptor");
  });

  it("fills the [details] panel with why THOR flagged it", () => {
    const detail = thorFields(fileHit)!.detail;
    expect(detail).toContain("file: C:\\Users\\vagrant");
    expect(detail).toContain("sha256: 9695cf45");
    expect(detail).toContain("reason 1: Filename IOC \\mimikatz.exe");
    expect(detail).toContain("Cred Dumping");
    expect(detail).toContain("score: 60");
  });

  it("keeps the title free of the ' - ' the dashboard splits on, so nothing is cut off it", () => {
    for (const row of [processHit, fileHit, logHit])
      expect(thorFields(row)!.description).not.toContain(" - ");
  });

  it("carries path, hash and MITRE through for correlation", () => {
    expect(thorFields(fileHit)!.path).toBe(fileHit.file);
    expect(thorFields(fileHit)!.sha256).toBe(fileHit.sha256);
    expect(thorFields(processHit)!.mitre).toEqual(["T1059.001"]);
  });

  it("separates findings that share a message but not a subject (39 log hits are 39 findings)", () => {
    const a = thorFields({ ...logHit, entry: "entry A" })!.aggKey;
    const b = thorFields({ ...logHit, entry: "entry B" })!.aggKey;
    expect(a).not.toBe(b);
  });

  it("grades by THOR's level, lifecycle modules included", () => {
    expect(thorFields(processHit)!.severity).toBe("Critical");
    expect(thorFields(fileHit)!.severity).toBe("High");
    expect(
      thorFields({ ...ENVELOPE, level: "Notice", module: "Startup", message: "THOR Lite license" })!.severity,
      // A Notice is a Notice whatever module raised it. Grading the Init/Startup ones Info kept licence
      // banners out of the forensic timeline, and it cost the accounting an analyst actually does:
      // THOR's summary reports 2 Notices and the case showed 0 Medium. Matching the scanner's own
      // report beats tidying it — a wrong total is what breaks trust in the import.
    ).toBe("Medium");
  });

  it("returns undefined for a row that is not a THOR record", () => {
    expect(thorFields({ OSPath: "C:\\evil.exe", Level: "high" })).toBeUndefined();
  });
});

// Codex review, P2: `module` + `message` + `level` is what importDetect uses to claim a whole FILE for
// the THOR importer, and for a file that is safe — the analyst chose it. A Velociraptor hunt is a mixed
// row stream, so the same three column names on ANY custom artifact that logs `level: "Warning"` would
// silently be relabelled THOR, regraded on THOR's scale and stripped of its artifact title. THOR stamps
// every line of its JSON log with its own scan envelope (all 1081 rows of the reference scan carry both
// `scanid` and `log_version`); that, or an artifact that names THOR, is the real signature.
describe("thorFields — only genuine THOR rows", () => {
  const lookalike = { module: "Sync", message: "Backup finished", level: "Warning" };

  it("ignores a non-THOR artifact that happens to log module/message/level", () => {
    expect(thorFields(lookalike)).toBeUndefined();
    expect(thorFields(lookalike, { artifact: "Custom.App.SyncLog" })).toBeUndefined();
  });

  it("claims a row carrying THOR's scan envelope", () => {
    expect(thorFields({ ...lookalike, scanid: "S-abc" })).toBeDefined();
    expect(thorFields({ ...lookalike, log_version: "v1.0.0" })).toBeDefined();
  });

  it("claims a row from an artifact that names THOR, even without the envelope", () => {
    expect(thorFields(lookalike, { artifact: "Generic.Scanner.ThorZIP/ThorResultsJson" })).toBeDefined();
  });
});

// Codex review, P1: the generic Velociraptor key includes the host; the THOR key did not. On a FLEET
// hunt the same finding from two endpoints produced one identical key, and aggregateEvents keeps only
// the FIRST event's asset — so a second machine's compromise collapsed into an "×2" row attributed
// entirely to the first host, and disappeared from that machine's timeline.
describe("thorFields — one finding per endpoint", () => {
  it("keys the same finding on two hosts separately", () => {
    const a = thorFields(fileHit, { host: "DESKTOP-OPE297N" })!.aggKey;
    const b = thorFields(fileHit, { host: "WIN-UK1GV882OK6" })!.aggKey;
    expect(a).not.toBe(b);
  });

  it("still collapses a genuine repeat on the SAME host", () => {
    const a = thorFields(fileHit, { host: "DESKTOP-OPE297N" })!.aggKey;
    const b = thorFields({ ...fileHit }, { host: "DESKTOP-OPE297N" })!.aggKey;
    expect(a).toBe(b);
  });
});

// Codex found the aggregation key; the analyst found this one. A THOR LogScan row reports a suspicious
// LINE in a log, and it carries two fields that belong to OTHER things:  is the log the line was
// read from (shared by every hit in that log) and  is a file merely NAMED in the line. Handing
// either to the event as its own identity makes correlate merge on them — step 1 unions equal hashes,
// step 2 unions equal paths — so 18 distinct Defender detections plus the mimikatz file finding
// collapsed into ONE row. The forensic timeline showed 2 THOR events where the parser had produced 20.
describe("thorFields — identity fields describe the SUBJECT, not its context", () => {
  const logRow = {
    ...ENVELOPE,
    level: "Warning",
    module: "LogScan",
    message: "Suspicious Log Entry found",
    entry: "2026-08-18T16:14:39.033 Engine:command line reported as threat: mimikatz.exe",
    file: "C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-20251205-033941.log",
    sha256_1: "9695cf4566ddf878a69c3d419e0da4eea87b0f24261ad8e79a3a9c4a9885429c",
    md5_1: "c8b5d63042bc4bbb7f5c0f9e15b61f16",
  };

  it("gives a log-entry finding no hash and no path of its own", () => {
    const f = thorFields(logRow)!;
    expect(f.sha256).toBeUndefined(); // the hash of a file the line MENTIONS is not this event's identity
    expect(f.md5).toBeUndefined();
    expect(f.path).toBeUndefined(); // the log it was read from is shared by every other hit in it
  });

  it("still shows the analyst both, in the details panel", () => {
    const detail = thorFields(logRow)!.detail;
    expect(detail).toContain("MPLog-20251205-033941.log");
    expect(detail).toContain("entry: 2026-08-18T16:14:39.033");
  });

  it("keeps the identity of a FILE finding, whose hash and path are its own", () => {
    expect(thorFields(fileHit)!.sha256).toBe(fileHit.sha256);
    expect(thorFields(fileHit)!.path).toBe(fileHit.file);
  });

  it("keeps the identity of a PROCESS finding — the image it ran from", () => {
    expect(thorFields(processHit)!.sha256).toBe(processHit.image_sha256);
    expect(thorFields(processHit)!.path).toBe(processHit.image_file);
  });

  // A reason-context file () is never the subject, whatever the module.
  it("never takes identity from a reason-context file", () => {
    const f = thorFields({ ...fileHit, sha256: undefined, sha256_1: "a".repeat(64) })!;
    expect(f.sha256).toBeUndefined();
  });
});

// Codex review, P2. Two Defender log lines can share a long identical prefix — the same base64 blob,
// the same command line — and differ only near the end. Clipping the subject into the title, and
// clipping the aggregation key to a fixed width, both threw that difference away: the rows became one
// counted row at parse time, and (because correlate's exact-duplicate step keys on the DESCRIPTION)
// one row again afterwards. The distinguishing tail must survive into both.
describe("thorFields — two entries that differ only late stay two findings", () => {
  const long = "A".repeat(400);
  const entryRow = (tail: string) => ({
    ...ENVELOPE,
    level: "Warning",
    module: "LogScan",
    message: "Suspicious Log Entry found",
    entry: `Resource Path:i n ${long} ${tail}`,
  });

  it("gives them different aggregation keys", () => {
    expect(thorFields(entryRow("threat A"))!.aggKey).not.toBe(thorFields(entryRow("threat B"))!.aggKey);
  });

  it("gives them different descriptions, which is what correlate dedupes on", () => {
    expect(thorFields(entryRow("threat A"))!.description).not.toBe(
      thorFields(entryRow("threat B"))!.description,
    );
  });

  it("still bounds both, so one runaway log line cannot bloat the case", () => {
    const f = thorFields(entryRow("threat A"))!;
    expect(f.aggKey.length).toBeLessThanOrEqual(440);
    expect(f.description.length).toBeLessThanOrEqual(600);
  });
});
