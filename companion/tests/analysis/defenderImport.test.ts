import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";

// #930 item 1, part A — the Defender decode through the Windows-event mapper. Elastic _source shape,
// the spelling the EVTX renderer uses for event_data (spaces kept).

const DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational";
const record = (event_id: number, extra: Record<string, string> = {}, ts = "2026-06-01T10:00:00.000Z") => ({
  "@timestamp": ts,
  log_name: DEFENDER_CHANNEL,
  computer_name: "WS-042.corp.example.invalid",
  event_id,
  message: "Microsoft Defender Antivirus has detected malware or other potentially unwanted software.",
  event_data: {
    "Detection ID": "{5B6A6C58-1F33-4B4E-9A9F-0C0A1D2E3F40}",
    "Threat Name": "Trojan:Win32/Wacatac.B!ml",
    "Severity Name": "Severe",
    Path: "file:_C:\\Users\\a.mehta\\Downloads\\invoice.exe",
    "Detection User": "CORP\\a.mehta",
    ...extra,
  },
});

describe("Defender Operational events through the Windows mapper", () => {
  it("grades a detection Medium with the control slot first and the flagged file as the path", () => {
    const r = parseSiemExport(JSON.stringify([record(1116)]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(
      e.description.startsWith(
        "[control: unknown] detected Trojan:Win32/Wacatac.B!ml [Severe] — C:\\Users\\a.mehta\\Downloads\\invoice.exe",
      ),
    ).toBe(true);
    expect(e.description).toContain("(EID 1116, Microsoft Defender)");
    expect(e.path).toBe("C:\\Users\\a.mehta\\Downloads\\invoice.exe");
    expect(e.canonical?.event).toMatchObject({
      category: "file",
      type: "detection",
      action: "detected",
      outcome: "unknown",
    });
    expect(e.canonical?.object).toEqual({
      kind: "file",
      id: "{5B6A6C58-1F33-4B4E-9A9F-0C0A1D2E3F40}",
      name: "Trojan:Win32/Wacatac.B!ml",
    });
    expect(e.canonical?.target).toEqual({ kind: "host", name: "WS-042.corp.example.invalid" }); // the host keeps its slot
    expect(e.canonical?.file?.path).toBe("C:\\Users\\a.mehta\\Downloads\\invoice.exe");
  });

  it("keeps two actions on one file as two rows, in both input orders", () => {
    const ok = record(
      1117,
      { "Action Name": "Quarantine", "Error Code": "0x00000000" },
      "2026-06-01T10:00:05.000Z",
    );
    const failed = record(
      1117,
      { "Action Name": "Quarantine", "Error Code": "0x80508023" },
      "2026-06-01T10:00:06.000Z",
    );
    for (const rows of [
      [ok, failed],
      [failed, ok],
    ]) {
      const r = parseSiemExport(JSON.stringify(rows));
      expect(r.events).toHaveLength(2);
      const controls = r.events.map((e) => /^\[control: ([a-z-]+)\]/.exec(e.description)?.[1]).sort();
      expect(controls).toEqual(["remediated", "remediation-failed"]);
    }
    // a byte-identical re-import is one row
    expect(parseSiemExport(JSON.stringify([ok, ok])).events).toHaveLength(1);
  });

  it("leaves a non-Defender Windows event byte-for-byte as before", () => {
    const logon = {
      "@timestamp": "2017-03-20T07:00:00.000Z",
      log_name: "Security",
      computer_name: "WINDMILLDC",
      event_id: 4624,
      event_data: {
        TargetUserName: "svc",
        TargetDomainName: "WINDMILL",
        LogonType: "3",
        IpAddress: "10.10.200.11",
      },
    };
    const e = parseSiemExport(JSON.stringify([logon])).events[0];
    expect(e.description).toBe(
      "Windows Security Successful logon (EID 4624) - WINDMILL\\svc - LogonType=3 - IpAddress=10.10.200.11 @ WINDMILLDC [Network from 10.10.200.11]",
    );
    expect(e.description).not.toContain("[control:");
  });

  it("keeps the EID, tool and host tail even when the label is at its bound", () => {
    const many = Array.from(
      { length: 8 },
      (_, i) => `file:_C:\\Users\\a.mehta\\Downloads\\${"n".repeat(40)}${i}.exe`,
    ).join("; ");
    const e = parseSiemExport(JSON.stringify([record(1116, { Path: many, "Threat Name": "T".repeat(120) })]))
      .events[0];
    expect(e.description.length).toBeLessThanOrEqual(600);
    expect(e.description).toContain("(EID 1116, Microsoft Defender)");
    expect(e.description).toContain("@ WS-042.corp.example.invalid");
  });

  it("does not overwrite an Image the record already carries", () => {
    const e = parseSiemExport(JSON.stringify([record(1116, { Image: "C:\\Windows\\explorer.exe" })]))
      .events[0];
    expect(e.path).toBe("C:\\Windows\\explorer.exe"); // the record's own evidence stays
    expect(e.description).toContain("— C:\\Users\\a.mehta\\Downloads\\invoice.exe"); // the flagged file is still named
  });

  it("does not claim a Defender event id on another channel", () => {
    const sec = { ...record(1116), log_name: "Security" };
    const e = parseSiemExport(JSON.stringify([sec])).events[0];
    expect(e.description).not.toContain("[control:");
  });
});
