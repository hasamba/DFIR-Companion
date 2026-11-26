// #2885: velociraptorImport.ts appended the "@ HOST" suffix and THEN cut the whole description to its
// cap. When the core sat within a suffix-length of the cap the host was cut to a fragment ("@ WS-LA",
// which reads as another host on the timeline row); past the cap the host was dropped. Each mapper
// now trims the core to leave room (capWithHostSuffix, #2881). Every value here is invented; only the
// column layouts follow the artifacts.
import { describe, expect, it } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

const HOST = "WS-LAB-01";
const SUFFIX = ` @ ${HOST}`;

type Row = Record<string, unknown>;

const descriptions = (rows: Row[]): string[] =>
  parseVelociraptorJson(JSON.stringify(rows)).events.map((e) => e.description);

// Sweep one free-text field's length across the cap window. Each length must produce at least one
// event, and every event must end with the WHOLE host and stay within `max`.
function sweep(from: number, to: number, build: (n: number) => Row, max: number, ends = SUFFIX): void {
  for (let n = from; n <= to; n++) {
    const out = descriptions([build(n)]);
    expect(out.length, `length ${n}`).toBeGreaterThan(0);
    for (const d of out) {
      expect(d.length, `length ${n}`).toBeLessThanOrEqual(max);
      expect(d.endsWith(ends), `length ${n}: …${d.slice(-40)}`).toBe(true);
    }
  }
}

// The main loop inserts "[<artifact>] " into a description that does not already name the artifact.
const withPrefix = (cap: number, artifact: string): number => cap + artifact.length + 3;

describe("Velociraptor importer keeps the '@ HOST' suffix whole under the cap (#2885)", () => {
  it("YARA hit with a long file path", () => {
    const art = "Windows.Detection.Yara.Glob";
    sweep(
      480,
      640,
      (n) => ({
        _Source: art,
        Rule: "Example_Rule",
        Namespace: "default",
        OSPath: `C:\\Data\\${"y".repeat(n)}.bin`,
        Fqdn: HOST,
      }),
      withPrefix(600, art),
    );
  });

  it("DetectRaptor detection with a long file name (4000 cap)", () => {
    sweep(
      3880,
      4040,
      (n) => ({
        _Source: "DetectRaptor.Windows.Detection.MFT",
        EventTime: "2026-01-01T00:00:00Z",
        Detection: "Example Tool",
        OSPath: `C:\\Data\\${"d".repeat(n)}.exe`,
        Fqdn: HOST,
      }),
      4000,
    );
  });

  it("non-DetectRaptor detection is not cut again by the artifact-name injection (1200)", () => {
    sweep(
      1080,
      1240,
      (n) => ({
        _Source: "Custom.Windows.Detection.Example",
        EventTime: "2026-01-01T00:00:00Z",
        Detection: "Example Tool",
        OSPath: `C:\\Data\\${"d".repeat(n)}.exe`,
        Fqdn: HOST,
      }),
      1200,
    );
  });

  it("generic row with a long Message", () => {
    sweep(520, 640, (n) => ({ _Source: "Custom.Example.Artifact", Message: "m".repeat(n), Fqdn: HOST }), 600);
  });

  const usn = (path: string): Row => ({
    _Source: "Windows.Forensics.Usn",
    Timestamp: "2026-01-01T00:00:00Z",
    OSPath: path,
    Reason: ["FILE_CREATE"],
    Usn: 1,
    MFTId: 2,
    Fqdn: HOST,
  });

  it("USN row with a long path", () => {
    sweep(520, 640, (n) => usn(`C:\\Data\\${"u".repeat(n)}.txt`), 600);
  });

  const RANSOM_TAIL = `${SUFFIX} — file encrypted with the .lockbit3 ransomware extension (T1486)`;

  it("USN ransomware row keeps the whole host right before the ransomware note", () => {
    sweep(440, 640, (n) => usn(`C:\\Data\\${"u".repeat(n)}.docx.lockbit3`), 600, RANSOM_TAIL);
  });

  const mft = (path: string): Row => ({
    _Source: "Windows.NTFS.MFT",
    EntryNumber: 1,
    OSPath: path,
    Created0x10: "2026-01-01T00:00:00Z",
    Fqdn: HOST,
  });

  it("MFT row with a long path", () => {
    sweep(520, 640, (n) => mft(`C:\\Data\\${"f".repeat(n)}.txt`), 600);
  });

  it("MFT ransomware row keeps the whole host right before the ransomware note", () => {
    sweep(440, 640, (n) => mft(`C:\\Data\\${"f".repeat(n)}.docx.lockbit3`), 600, RANSOM_TAIL);
  });

  it("action row (shellbag) with a long folder path", () => {
    sweep(
      520,
      640,
      (n) => ({
        _Source: "Windows.Forensics.Shellbags",
        _RawData: "00",
        FullPath: `C:\\${"s".repeat(n)}`,
        Fqdn: HOST,
      }),
      600,
    );
  });

  it("process row with a long call chain", () => {
    const art = "Windows.System.Pslist";
    sweep(
      520,
      640,
      (n) => ({
        _Source: art,
        Pid: 4321,
        Ppid: 1000,
        Name: "example.exe",
        CallChain: "c".repeat(n),
        Fqdn: HOST,
      }),
      withPrefix(600, art),
    );
  });

  it("download row with a long source URL", () => {
    sweep(
      520,
      640,
      (n) => ({
        _Source: "Windows.Analysis.EvidenceOfDownload",
        DownloadedFilePath: "C:\\Users\\example\\Downloads\\example.zip",
        HostUrl: `https://example.test/${"p".repeat(n)}`,
        ZoneId: "3",
        Fqdn: HOST,
      }),
      withPrefix(600, "Windows.Analysis.EvidenceOfDownload"),
    );
  });

  it("Sigma row without a parsed event, with a long rule title", () => {
    sweep(
      480,
      640,
      (n) => ({
        _Source: "Windows.Sigma.Base",
        Rule: { Title: "t".repeat(n), Level: "high" },
        Message: "example message",
        Fqdn: HOST,
      }),
      withPrefix(600, "Windows.Sigma.Base"),
    );
  });

  // A parsed Windows event: mapWindows ends its description with " @ HOST"; the Sigma / detection
  // overlay then put the rule name in front and cut the whole string to 600 again, so a long rule
  // name pushed the host off the end.
  const sysmonProcess: Row = {
    System: {
      EventID: 1,
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: HOST,
      TimeCreated: "2026-01-01T00:00:00Z",
    },
    EventData: { Image: "C:\\Tools\\example.exe", CommandLine: `example.exe ${"a".repeat(400)}` },
    Fqdn: HOST,
  };

  it("Sigma overlay on a parsed event with a long rule title", () => {
    const art = "Windows.Hayabusa.Sigma";
    sweep(
      0,
      160,
      (n) => ({ _Source: art, Rule: { Title: `Rule ${"t".repeat(n)}`, Level: "high" }, ...sysmonProcess }),
      withPrefix(600, art),
    );
  });

  it("detection overlay on a parsed event with a long rule name", () => {
    sweep(
      0,
      160,
      (n) => ({
        _Source: "DetectRaptor.Windows.Detection.Evtx",
        Detection: `Rule ${"t".repeat(n)}`,
        ...sysmonProcess,
      }),
      600,
    );
  });

  it("netstat row with a long process name", () => {
    const art = "Windows.Network.Netstat";
    sweep(
      520,
      640,
      (n) => ({
        _Source: art,
        Name: `${"n".repeat(n)}.exe`,
        Pid: 4321,
        Laddr: "10.0.0.5",
        Lport: 50000,
        Raddr: "198.51.100.7",
        Rport: 443,
        Status: "ESTABLISHED",
        Type: "TCP",
        Fqdn: HOST,
      }),
      withPrefix(600, art),
    );
  });

  it("a short row is unchanged: the host suffix follows the full description", () => {
    const [d] = descriptions([usn("C:\\Data\\short.txt")]);
    expect(d).toBe(`Velociraptor [Windows.Forensics.Usn]: FILE_CREATE — C:\\Data\\short.txt - @ ${HOST}`);
    const [r] = descriptions([usn("C:\\Data\\short.docx.lockbit3")]);
    expect(r).toBe(
      `Velociraptor [Windows.Forensics.Usn]: FILE_CREATE — C:\\Data\\short.docx.lockbit3 - @ ${HOST} — file encrypted with the .lockbit3 ransomware extension (T1486)`,
    );
  });
});
