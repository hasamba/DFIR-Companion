import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";

// Winlogbeat 7 (ECS) records collected through Windows Event Forwarding: `host.name` is the beat's
// own host — the Event Collector — while `winlog.computer_name` is the machine that logged the
// event. Shape trimmed from the public OTRF APT3 Evals (CALDERA scenario) dataset.
const forwarded = (computer: string, recordId: number) => ({
  "@timestamp": "2019-10-20T20:11:06.937Z",
  "@metadata": { beat: "winlogbeat", type: "_doc", version: "7.4.0" },
  event: { created: "2019-10-20T20:11:09.988Z", kind: "event", code: 4688, action: "Process Creation" },
  log: { level: "information" },
  message: "A new process has been created.",
  winlog: {
    channel: "Security",
    computer_name: computer,
    event_id: 4688,
    provider_name: "Microsoft-Windows-Security-Auditing",
    record_id: recordId,
    event_data: {
      NewProcessName: "C:\\Windows\\System32\\whoami.exe",
      CommandLine: "whoami /all",
      SubjectUserName: "analyst",
      SubjectDomainName: "LAB",
    },
  },
  host: { name: "WEC01" },
  agent: { type: "winlogbeat", hostname: "WEC01", version: "7.4.0" },
});

const lines = (...recs: object[]) => recs.map((r) => JSON.stringify(r)).join("\n");

describe("parseSiemExport — forwarded Winlogbeat 7 records", () => {
  it("attributes each event to winlog.computer_name, not the collector in host.name", () => {
    const r = parseSiemExport(lines(forwarded("WS01.lab.local", 1), forwarded("WS02.lab.local", 2)));
    const assets = r.events.map((e) => e.asset).sort();
    expect(assets).toEqual(["WS01.lab.local", "WS02.lab.local"]);
  });

  it("still uses host.name when the record carries no winlog.computer_name", () => {
    const rec = forwarded("ignored", 3);
    const { computer_name: _drop, ...winlog } = rec.winlog;
    const r = parseSiemExport(lines({ ...rec, winlog }));
    expect(r.events[0]?.asset).toBe("WEC01");
  });
});
