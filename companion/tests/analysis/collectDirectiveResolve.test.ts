import { describe, it, expect } from "vitest";
import { resolveCollectVql } from "../../src/analysis/collectDirectiveResolve.js";

describe("resolveCollectVql", () => {
  it("uses an explicit Velociraptor artifact name verbatim", () => {
    expect(resolveCollectVql({ artifact: "Windows.EventLogs.Evtx" }))
      .toEqual({ vql: "SELECT * FROM Artifact.Windows.EventLogs.Evtx()", artifact: "Windows.EventLogs.Evtx" });
  });

  it("strips an 'Artifact.' prefix from an explicit name", () => {
    expect(resolveCollectVql({ artifact: "Artifact.Windows.Forensics.Prefetch" })?.artifact).toBe("Windows.Forensics.Prefetch");
  });

  it("maps event-log log sources (evtx / event ids) to Windows.EventLogs.Evtx", () => {
    expect(resolveCollectVql({ logSource: "Security.evtx 4624/4672" })?.artifact).toBe("Windows.EventLogs.Evtx");
    expect(resolveCollectVql({ logSource: "pull the Windows event logs" })?.artifact).toBe("Windows.EventLogs.Evtx");
  });

  it("maps $MFT to the shadow-catalog MFT artifact", () => {
    expect(resolveCollectVql({ logSource: "$MFT" })?.artifact).toBe("Windows.NTFS.MFT");
  });

  it("maps forensic keywords onto the shadow catalog", () => {
    expect(resolveCollectVql({ logSource: "prefetch" })?.artifact).toBe("Windows.Forensics.Prefetch");
    expect(resolveCollectVql({ logSource: "amcache hive" })?.artifact).toBe("Windows.Forensics.Amcache");
    expect(resolveCollectVql({ logSource: "SRUM database" })?.artifact).toBe("Windows.Forensics.SRUM");
    expect(resolveCollectVql({ logSource: "USN journal" })?.artifact).toBe("Windows.Forensics.Usn");
  });

  it("maps netstat / scheduled tasks to their built-ins", () => {
    expect(resolveCollectVql({ logSource: "netstat / active connections" })?.artifact).toBe("Windows.Network.Netstat");
    expect(resolveCollectVql({ logSource: "scheduled tasks" })?.artifact).toBe("Windows.System.TaskScheduler");
  });

  it("prefers an explicit artifact over a keyword in logSource", () => {
    expect(resolveCollectVql({ artifact: "Windows.NTFS.MFT", logSource: "prefetch" })?.artifact).toBe("Windows.NTFS.MFT");
  });

  it("returns null when nothing maps (UI falls back to a manual checklist)", () => {
    expect(resolveCollectVql({ logSource: "ask the SOC team about the firewall" })).toBeNull();
    expect(resolveCollectVql({})).toBeNull();
    expect(resolveCollectVql(undefined)).toBeNull();
  });

  it("produces a runnable single-statement VQL", () => {
    const r = resolveCollectVql({ artifact: "Windows.Forensics.Bam" });
    expect(r!.vql).toMatch(/^SELECT \* FROM Artifact\.[A-Za-z0-9.]+\(\)$/);
  });
});
