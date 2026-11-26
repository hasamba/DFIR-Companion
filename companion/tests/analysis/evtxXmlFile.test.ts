// #2823: a Windows Event XML export streamed from disk builds exactly what the whole-text importer
// (parseEvtxXmlProgress) builds — blocks split across reads, unclosed and EventID-less blocks, the
// OS-behaviour rules, the debug summary and the source-artifact hash. Synthetic data only.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseEvtxXmlProgress } from "../../src/analysis/evtxXmlImport.js";
import { parseEvtxXmlFile } from "../../src/analysis/evtxXmlFile.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { decodeImportedText } from "../../src/ingest/decodeText.js";
import type { SiemImportOptions } from "../../src/analysis/siemImport.js";
import { access, CMD, create, G, HOST, PWSH, T0, toEventXml } from "./fixtures/osBehaviourRows.js";

let dir: string;
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "evtx-xml-"));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

let n = 0;
async function fileOf(content: string | Buffer): Promise<string> {
  const path = join(dir, `f${n++}.xml`);
  await writeFile(path, content);
  return path;
}

const esc = (v: string) => v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
function event(i: number, eid: number, channel: string, data: Record<string, string>, tag = "Event"): string {
  const at = new Date(Date.UTC(2026, 2, 1, 10, 0, i % 60)).toISOString();
  const fields = Object.entries(data)
    .map(([k, v]) => `<Data Name="${k}">${esc(v)}</Data>`)
    .join("\n      ");
  return (
    `<${tag} xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n  <System>\n` +
    `    <Provider Name="${channel}"/>\n    <EventID>${eid}</EventID>\n` +
    `    <TimeCreated SystemTime="${at}"/>\n    <EventRecordID>${i}</EventRecordID>\n` +
    `    <Channel>${channel}</Channel>\n    <Computer>WS-${i % 3}</Computer>\n  </System>\n` +
    `  <EventData>\n      ${fields}\n  </EventData>\n</${tag}>`
  );
}

function mixedEvents(count: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    if (i % 5 === 0)
      out.push(
        event(i, 1, "Microsoft-Windows-Sysmon/Operational", {
          Image: `C:\\Users\\Public\\t${i % 4}.exe`,
          CommandLine: `t.exe -enc QQ http://198.51.100.${i % 9}/x`,
          ProcessId: String(i % 11),
        }),
      );
    else if (i % 5 === 1)
      out.push(
        event(i, 3, "Microsoft-Windows-Sysmon/Operational", {
          Image: "C:\\Windows\\System32\\svchost.exe",
          Protocol: "tcp",
          Initiated: "true",
          DestinationIp: `203.0.113.${i % 20}`,
          DestinationPort: "443",
        }),
      );
    else if (i % 5 === 2)
      out.push(
        event(i, 22, "Microsoft-Windows-Sysmon/Operational", {
          Image: "C:\\Windows\\System32\\svchost.exe",
          ProcessId: "8",
          QueryName: `h${i % 3}.example.test`,
          QueryResults: `::ffff:203.0.113.${i % 40};`,
        }),
      );
    else if (i % 5 === 3)
      out.push(
        event(i, 4624, "Security", {
          TargetUserName: `u${i % 4}`,
          TargetDomainName: "LAB",
          LogonType: "10",
          IpAddress: `192.0.2.${i % 7}`,
        }),
      );
    else
      out.push(
        event(i, 7045, "System", { ServiceName: `S${i % 2}`, ServiceFileName: "C:\\Windows\\Temp\\s.exe" }),
      );
  }
  return out;
}

async function both(xml: string | Buffer, opts: SiemImportOptions = {}, chunkBytes = 97) {
  const path = await fileOf(xml);
  const text = decodeImportedText(Buffer.isBuffer(xml) ? xml : Buffer.from(xml));
  const wholeDebug = createImportDebugRecorder();
  const streamDebug = createImportDebugRecorder();
  const wholeParse: [number, number][] = [];
  const streamParse: [number, number][] = [];
  const whole = await parseEvtxXmlProgress(
    text,
    { ...opts, debug: wholeDebug },
    (d, t) => void wholeParse.push([d, t]),
  );
  const streamed = await parseEvtxXmlFile(
    path,
    { ...opts, debug: streamDebug },
    (d, t) => void streamParse.push([d, t]),
    undefined,
    undefined,
    chunkBytes,
  );
  return {
    whole,
    streamed,
    wholeDebug: wholeDebug.summary(),
    streamDebug: streamDebug.summary(),
    wholeParse,
    streamParse,
  };
}

describe("parseEvtxXmlFile matches parseEvtxXmlProgress", () => {
  it.each([
    ["default options", {}],
    ["a small cap", { maxEvents: 20 }],
    ["aggregation off and an Info floor", { aggregate: false, minSeverity: "Info" as const }],
  ])("on a mixed export with %s, read in tiny parts", async (_label, opts) => {
    const xml = `\uFEFF<?xml version="1.0"?>\n<Events>\n${mixedEvents(400).join("\n")}\n</Events>\n`;
    const r = await both(xml, opts);
    expect(r.streamed).toEqual(r.whole);
    expect(r.streamDebug).toEqual(r.wholeDebug);
    expect(r.streamParse.at(-1)).toEqual(r.wholeParse.at(-1));
  });

  it("keeps the OS-behaviour rules the XML path runs (#1621)", async () => {
    const child = create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`);
    const own = access(T0 + 50, PWSH, G.pwsh, CMD, G.cmd);
    const r = await both(toEventXml([child, own]), { aggregate: false, minSeverity: "Info" }, 64);
    expect(r.streamed).toEqual(r.whole);
  });

  it("on upper-case tags, an EventID-less block, a stray close tag and an unclosed tail", async () => {
    const events = mixedEvents(30);
    const xml =
      "</Event> noise <Events>" +
      events.slice(0, 10).join("") +
      event(99, 1, "X", { a: "b" }, "EVENT") +
      "<Event><System><Channel>none</Channel></System></Event>" +
      events.slice(10).join("\r\n") +
      "<Event xmlns='x'><System><EventID>4</EventID>"; // never closed
    const r = await both(xml);
    expect(r.streamed).toEqual(r.whole);
    expect(r.streamDebug).toEqual(r.wholeDebug);
  });

  it("an open tag left unclosed swallows the next block, as the whole-text regex does", async () => {
    const xml = "<Event broken>" + mixedEvents(6).join("");
    const r = await both(xml, {}, 13);
    expect(r.streamed).toEqual(r.whole);
  });

  it("on a file with no events at all", async () => {
    const r = await both("<Events></Events>");
    expect(r.streamed).toEqual(r.whole);
    expect(r.streamDebug).toEqual(r.wholeDebug);
    expect(r.streamParse).toEqual(r.wholeParse);
  });
});
