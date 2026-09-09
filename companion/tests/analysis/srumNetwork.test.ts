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

// SrumECmd emits BytesRecvd. The previous profile matched on BytesReceived, which SrumECmd does not
// emit — so it never recognised a real export.
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
    BytesRecvd: "1024",
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

  it("still accepts the BytesReceived spelling other exports use", () => {
    const alt: Record<string, unknown> = { ...cells, BytesRecvd: undefined, BytesReceived: "2048" };
    expect(readSrumRow((k) => alt[k])!.bytesReceived).toBe(2048);
  });

  it("returns null when there is no application to attribute traffic to", () => {
    expect(readSrumRow(() => "")).toBeNull();
  });

  it("treats an unreadable counter as zero rather than NaN", () => {
    const bad: Record<string, unknown> = { ...cells, BytesSent: "-", BytesRecvd: "n/a" };
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

  it("names the user the traffic is attributed to", () => {
    expect(srumSignal(big)!.note).toContain("CORP\\jdoe");
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
    "Id,Timestamp,AppId,ExeInfo,UserName,Sid,InterfaceLuid,BytesSent,BytesRecvd",
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
