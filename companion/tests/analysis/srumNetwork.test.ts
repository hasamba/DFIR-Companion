import { describe, it, expect } from "vitest";
import {
  readSrumRow,
  totalSrum,
  srumSignal,
  humanBytes,
  NOTABLE_SENT_BYTES,
  type SrumRow,
} from "../../src/analysis/srumNetwork.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import { linkArchiveToExfil } from "../../src/analysis/exfilCorrelate.js";

const row = (over: Partial<SrumRow> = {}): SrumRow => ({
  id: "1",
  app: "rclone.exe",
  user: "CORP\\jdoe",
  sid: "S-1-5-21-1-2-3-1001",
  interfaceId: "1689399632855555",
  timestamp: "2026-01-01T10:00:00Z",
  bytesSent: 50 * 1024 * 1024,
  bytesReceived: 1024,
  ...over,
});

// SrumECmd's CSV header is BytesReceived; BytesRecvd is the raw ESE column the tool maps before
// writing. Both are accepted, because other SRUM readers export the raw name.
describe("readSrumRow — the column names SrumECmd actually writes", () => {
  const cells: Record<string, unknown> = {
    Id: "42",
    Timestamp: "2026-01-01 10:00:00",
    AppId: "104",
    ExeInfo: "C:\\Users\\jdoe\\rclone.exe",
    UserName: "CORP\\jdoe",
    Sid: "S-1-5-21-1-2-3-1001",
    InterfaceLuid: "1689399632855555",
    BytesSent: "52428800",
    BytesReceived: "1024",
  };

  it("reads the attribution the artifact carries", () => {
    const r = readSrumRow((k) => cells[k])!;
    expect(r.id).toBe("42");
    expect(r.app).toBe("C:\\Users\\jdoe\\rclone.exe");
    expect(r.user).toBe("CORP\\jdoe");
    expect(r.sid).toBe("S-1-5-21-1-2-3-1001");
    expect(r.interfaceId).toBe("1689399632855555");
    expect(r.bytesSent).toBe(52428800);
    expect(r.bytesReceived).toBe(1024);
  });

  it("still accepts the raw ESE spelling other readers export", () => {
    const alt: Record<string, unknown> = { ...cells, BytesReceived: undefined, BytesRecvd: "2048" };
    expect(readSrumRow((k) => alt[k])!.bytesReceived).toBe(2048);
  });

  it("returns null when there is no application to attribute traffic to", () => {
    expect(readSrumRow(() => "")).toBeNull();
  });

  it("treats an unreadable counter as zero rather than NaN", () => {
    const bad: Record<string, unknown> = { ...cells, BytesSent: "-", BytesReceived: "n/a" };
    const r = readSrumRow((k) => bad[k])!;
    expect(r.bytesSent).toBe(0);
    expect(r.bytesReceived).toBe(0);
  });
});

describe("totalSrum — attribution is per application AND user AND interface", () => {
  it("keeps two users of one application apart", () => {
    const totals = totalSrum([
      row({ id: "1", sid: "S-1-1", user: "alice" }),
      row({ id: "2", sid: "S-1-2", user: "bob" }),
    ]);
    expect(totals).toHaveLength(2);
  });

  it("keeps two interfaces apart, because a VPN is not the LAN", () => {
    const totals = totalSrum([row({ id: "1", interfaceId: "A" }), row({ id: "2", interfaceId: "B" })]);
    expect(totals).toHaveLength(2);
  });

  it("sums rows that share the full attribution", () => {
    const t = totalSrum([row({ id: "1" }), row({ id: "2" })])[0];
    expect(t.bytesSent).toBe(100 * 1024 * 1024);
    expect(t.rows).toBe(2);
  });

  // Re-importing the same export must not double the case's totals.
  it("counts a repeated record once", () => {
    const rows = [row({ id: "1" }), row({ id: "2" })];
    const t = totalSrum([...rows, ...rows])[0];
    expect(t.rows).toBe(2);
    expect(t.bytesSent).toBe(100 * 1024 * 1024);
  });

  // AutoIncId restarts per export, so two databases merged into one file both contain Id=1.
  // Keying on the id alone dropped the second row and UNDER-counted.
  it("keeps two distinct rows that share a record id from different exports", () => {
    const t = totalSrum([
      row({ id: "1", timestamp: "2026-01-01T10:00:00Z", bytesSent: 100 }),
      row({ id: "1", timestamp: "2026-01-01T11:00:00Z", bytesSent: 200 }),
    ])[0];
    expect(t.rows).toBe(2);
    expect(t.bytesSent).toBe(300);
  });

  // SRUM rows are snapshots, and consecutive ones can describe the same interval.
  it("counts an overlapping snapshot once when the export carries no record id", () => {
    const a = row({ id: "" });
    const t = totalSrum([a, { ...a }])[0];
    expect(t.rows).toBe(1);
  });

  it("records the interval the total covers and the rows that made it", () => {
    const t = totalSrum([
      row({ id: "1", timestamp: "2026-01-01T10:00:00Z" }),
      row({ id: "2", timestamp: "2026-01-01T12:00:00Z" }),
    ])[0];
    expect(t.first).toBe("2026-01-01T10:00:00Z");
    expect(t.last).toBe("2026-01-01T12:00:00Z");
    expect(t.rowIds).toEqual(["1", "2"]);
  });

  it("orders the biggest sender first", () => {
    const totals = totalSrum([
      row({ id: "1", app: "small.exe", bytesSent: 10 }),
      row({ id: "2", app: "big.exe", bytesSent: 999 }),
    ]);
    expect(totals[0].app).toBe("big.exe");
  });
});

describe("srumSignal — volume is a lead, never a verdict", () => {
  const big = totalSrum([row({ id: "1", bytesSent: 4 * 1024 * 1024 * 1024 })])[0];

  it("says nothing about an ordinary amount of traffic", () => {
    expect(srumSignal(totalSrum([row({ id: "1", bytesSent: 1024 })])[0])).toBeNull();
  });

  it("reports a large volume as evidence, not a finding, on its own", () => {
    const s = srumSignal(big)!;
    expect(s.severity).toBe("Info");
    expect(s.mitre).toEqual([]);
    expect(s.note).toContain("Backup clients, cloud sync and OS updates");
  });

  it("raises only when the case also holds staging evidence in the window", () => {
    const s = srumSignal(big, true)!;
    expect(s.severity).toBe("Low");
    expect(s.mitre).toContain("T1041");
    expect(s.note).toContain("SEQUENCE is the lead");
  });

  // This has to travel with every number the module produces.
  it("always states what SRUM cannot show", () => {
    for (const s of [srumSignal(big), srumSignal(big, true)]) {
      expect(s!.note).toContain("no remote address");
      expect(s!.note).toContain("does not establish exfiltration");
    }
  });

  it("names the user the traffic is attributed to, with the SID", () => {
    const n = srumSignal(big)!.note;
    expect(n).toContain("CORP\\jdoe");
    expect(n).toContain("S-1-5-21-1-2-3-1001");
  });

  // A rounded figure with nothing behind it cannot be checked by whoever reads the report.
  it("carries the exact counters, the interval, the interface and the rows behind the total", () => {
    const n = srumSignal(big)!.note;
    expect(n).toContain("4294967296 bytes sent");
    expect(n).toContain("on interface 1689399632855555");
    expect(n).toContain("between 2026-01-01T10:00:00Z");
    expect(n).toContain("from SRUM rows 1");
  });

  it("says so plainly when no user was recorded", () => {
    const anon = totalSrum([row({ id: "1", user: "", sid: "", bytesSent: NOTABLE_SENT_BYTES * 2 })])[0];
    expect(srumSignal(anon)!.note).toContain("an unrecorded user");
  });
});

describe("humanBytes", () => {
  it("renders a readable magnitude", () => {
    expect(humanBytes(512)).toBe("512 B");
    expect(humanBytes(1536)).toBe("1.5 KB");
    expect(humanBytes(4 * 1024 * 1024 * 1024)).toBe("4.0 GB");
  });
});

describe("wired into the KAPE importer", () => {
  const csv = [
    "Id,Timestamp,AppId,ExeInfo,UserName,Sid,InterfaceLuid,BytesSent,BytesReceived",
    "1,2026-01-01 10:00:00,104,C:\\Users\\jdoe\\rclone.exe,CORP\\jdoe,S-1-5-21-1-2-3-1001,168939,4294967296,1024",
    "2,2026-01-01 11:00:00,104,C:\\Users\\jdoe\\rclone.exe,CORP\\jdoe,S-1-5-21-1-2-3-1001,168939,1048576,512",
  ].join("\n");

  it("recognises a real SrumECmd export", () => {
    expect(parseKapeCsv(csv).artifact).toBe("SRUM");
  });

  it("emits one attributed total rather than a sentence per row", () => {
    const r = parseKapeCsv(csv);
    const total = r.events.find((e) => /sent by/.test(e.description));
    expect(total).toBeDefined();
    expect(total!.description).toContain("CORP\\jdoe");
    expect(total!.description).toContain("no remote address");
  });
});

// The staging pairing is the point of the item, and it cannot happen at import time — the importer
// has no case to compare against. It happens where every host's evidence is already in one timeline.
describe("SRUM totals pair with archive staging in the correlator", () => {
  const staging = {
    id: "s1",
    timestamp: "2026-01-01T09:00:00Z",
    description: "Compress-Archive -Path C:\\data -DestinationPath C:\\Temp\\out.zip",
    severity: "Medium" as const,
    mitreTechniques: ["T1560.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS-01",
  };
  const total = {
    id: "t1",
    timestamp: "2026-01-01T10:00:00Z",
    description: "SRUM total: 4.0 GB sent by rclone.exe as CORP\\jdoe over 2 recorded interval(s).",
    severity: "Info" as const,
    mitreTechniques: [] as string[],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS-01",
  };

  it("raises a SRUM total that follows archive staging on the same host", () => {
    const out = linkArchiveToExfil([staging, total] as never);
    const t = out.find((e) => /SRUM total/.test(e.description))!;
    expect(t.severity).toBe("High");
    expect(t.mitreTechniques).toContain("T1041");
    expect(t.description).toContain("preceded by archive staging");
    // The limitation travels with the escalation.
    expect(t.description).toContain("does not show what left");
  });

  it("leaves a SRUM total alone when the host has no staging evidence", () => {
    const out = linkArchiveToExfil([{ ...total, asset: "WS-02" }, staging] as never);
    const t = out.find((e) => /SRUM total/.test(e.description))!;
    expect(t.severity).toBe("Info");
  });

  it("does not pair a total that precedes the staging", () => {
    const early = { ...total, timestamp: "2026-01-01T08:00:00Z" };
    const out = linkArchiveToExfil([staging, early] as never);
    expect(out.find((e) => /SRUM total/.test(e.description))!.severity).toBe("Info");
  });
});
