import { describe, it, expect } from "vitest";
import {
  decodeXmlEntities,
  looksLikeWinEventXml,
  parseWinEventXml,
  parseWinEventXmlProgress,
  parseEvtxXml,
  parseEvtxXmlProgress,
} from "../../src/analysis/evtxXmlImport.js";

// A Security-channel logon (4624) + a Sysmon process-create (EID 1) in the standard wevtutil/
// Event-Viewer XML envelope. CommandLine carries escaped XML entities.
const SAMPLE = `<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2024-05-14T12:00:00.0123583Z"/>
    <EventRecordID>15385677</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC-BO-01.northstar-branch.local</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">NORTHSTAR-BRANCH</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">::ffff:10.44.10.21</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>1</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-05-14T12:01:00.0000000Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>DC-BO-01.northstar-branch.local</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="UtcTime">2024-05-14 12:01:00.000</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c echo a &amp; echo b &lt;nul&gt;</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="Hashes">SHA256=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899,MD5=00112233445566778899aabbccddeeff</Data>
  </EventData>
</Event>
</Events>`;

const FIRST_EVENT = /<Event\b[\s\S]*?<\/Event>/i.exec(SAMPLE)?.[0] ?? "";
function repeatedEvents(count: number): string {
  return `<Events>${FIRST_EVENT.repeat(count)}</Events>`;
}

describe("decodeXmlEntities", () => {
  it("decodes predefined + numeric entities", () => {
    expect(decodeXmlEntities("a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos; &#65;&#x42;")).toBe(
      "a & b <c> \"d\" 'e' AB",
    );
  });
  it("leaves a non-entity ampersand intact", () => {
    expect(decodeXmlEntities("rock & roll")).toBe("rock & roll");
  });
});

describe("looksLikeWinEventXml", () => {
  it("matches the events schema namespace", () => {
    expect(looksLikeWinEventXml(SAMPLE)).toBe(true);
  });
  it("matches a namespace-stripped <Event><System><EventID>", () => {
    expect(
      looksLikeWinEventXml("<Events><Event><System><EventID>1</EventID></System></Event></Events>"),
    ).toBe(true);
  });
  it("rejects JSON / CSV / plain text", () => {
    expect(looksLikeWinEventXml('{"EventID":1}')).toBe(false);
    expect(looksLikeWinEventXml("EventID,Channel\n1,Security")).toBe(false);
    expect(looksLikeWinEventXml("<html><body>hi</body></html>")).toBe(false);
  });
});

describe("parseWinEventXml", () => {
  it("parses System fields + EventData Name→value pairs", () => {
    const recs = parseWinEventXml(SAMPLE);
    expect(recs).toHaveLength(2);
    expect(recs[0].EventID).toBe("4624");
    expect(recs[0].Channel).toBe("Security");
    expect(recs[0].Computer).toBe("DC-BO-01.northstar-branch.local");
    expect(recs[0]["@timestamp"]).toBe("2024-05-14T12:00:00.0123583Z");
    const ed0 = recs[0].EventData as Record<string, unknown>;
    expect(ed0.TargetUserName).toBe("jdoe");
    expect(ed0.IpAddress).toBe("::ffff:10.44.10.21");
  });
  it("decodes escaped entities inside a Data value", () => {
    const ed1 = parseWinEventXml(SAMPLE)[1].EventData as Record<string, unknown>;
    expect(ed1.CommandLine).toBe("cmd.exe /c echo a & echo b <nul>");
  });
  it("falls back to the provider name when Channel is absent", () => {
    const xml = `<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID>
      <Computer>h1</Computer></System><EventData><Data Name="X">y</Data></EventData></Event></Events>`;
    expect(parseWinEventXml(xml)[0].Channel).toBe("Microsoft-Windows-Sysmon");
  });
  it("skips a block with no EventID", () => {
    const xml = `<Events><Event><System><Channel>Security</Channel></System></Event></Events>`;
    expect(parseWinEventXml(xml)).toHaveLength(0);
  });
  it("reports monotonic event progress without changing parsed records", async () => {
    const progress: Array<[number, number]> = [];
    const records = await parseWinEventXmlProgress(SAMPLE, (done, total) => {
      progress.push([done, total]);
    });
    expect(records).toEqual(parseWinEventXml(SAMPLE));
    expect(progress.at(-1)).toEqual([2, 2]);
    expect(progress.every(([done, total]) => done <= total)).toBe(true);
  });

  it("stops parsing promptly when the analyst cancels", async () => {
    const controller = new AbortController();
    setImmediate(() => controller.abort());
    const work = parseWinEventXmlProgress(repeatedEvents(600), undefined, controller.signal);

    await expect(work).rejects.toMatchObject({ name: "AbortError" });
  });

  it("coalesces live progress while still yielding frequently", async () => {
    const progress: number[] = [];
    await parseWinEventXmlProgress(repeatedEvents(12_000), (done) => {
      progress.push(done);
    });

    expect(progress).toEqual([5000, 10_000, 12_000]);
  });
});

describe("parseEvtxXml — reuses the SIEM Windows mapping", () => {
  it("maps Security + Sysmon events with derived severity, MITRE, IOCs and host", () => {
    const r = parseEvtxXml(SAMPLE);
    expect(r.format).toBe("winevent-xml");
    expect(r.total).toBe(2);
    expect(r.kept).toBe(2);
    expect(r.hostname).toBe("DC-BO-01.northstar-branch.local");

    const logon = r.events.find((e) => /Successful logon/i.test(e.description));
    expect(logon).toBeTruthy();
    expect(logon?.asset).toBe("DC-BO-01.northstar-branch.local");

    const proc = r.events.find((e) => /Process create/i.test(e.description));
    expect(proc?.processName).toBe("cmd.exe");
    expect(proc?.parentName).toBe("explorer.exe");

    // IP (IPv4-mapped IPv6 cleaned) + hash extracted as IOCs.
    expect(r.iocs.some((c) => c.type === "ip" && c.value === "10.44.10.21")).toBe(true);
    expect(r.iocs.some((c) => c.type === "hash" && c.value.length === 64)).toBe(true);
  });

  it("honors the severity floor", () => {
    const r = parseEvtxXml(SAMPLE, { minSeverity: "Medium" });
    // 4624 (Low) drops; the Sysmon process-create survives because cmd.exe is a LOLBin and the
    // shared mapWindows bumps it to Medium.
    expect(r.events.every((e) => !/Successful logon/i.test(e.description))).toBe(true);
    expect(r.events.some((e) => /Process create/i.test(e.description))).toBe(true);
  });

  it("yields and honors cancellation during the expensive record-mapping phase", async () => {
    const controller = new AbortController();
    const processProgress: number[] = [];
    const work = parseEvtxXmlProgress(
      repeatedEvents(6000),
      {},
      undefined,
      (done) => {
        processProgress.push(done);
        if (done >= 5000) controller.abort();
      },
      controller.signal,
    );

    await expect(work).rejects.toMatchObject({ name: "AbortError" });
    expect(processProgress).toEqual([5000]);
  });

  it("keeps aggregated canonical provenance bounded for very repetitive logs", async () => {
    const result = await parseEvtxXmlProgress(repeatedEvents(600));

    expect(result.events).toHaveLength(1);
    expect(result.events[0].count).toBe(600);
    expect(result.events[0].canonical?.evidence.rawRecords).toHaveLength(1);
  });
});
