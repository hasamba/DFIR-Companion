import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// A script file created under a web root is how a webshell lands. The ruleset graded the web server
// SPAWNING a shell (web_server_shell_child) but nothing graded the write itself, so a webshell that
// was dropped and not yet used — or used through a channel that left no process row — stayed at
// Low/Info and never reached the AI. Two grades:
//   • High — the web server process itself wrote the script into a web root: the upload shape.
//   • Medium — any other create of a script under a web root (a USN FileCreate names no writer): a
//     lead, because a deployment writes the same files.
// These tests run the REAL importers and the SHIPPED ruleset.

const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const WRITE_BY_SERVER = "web_server_script_write";
const CREATED = "web_root_script_created";

type Graded = { severity: string; mitre: string[]; ruleIds: string[] };

function tag(mapped: Partial<ForensicEvent>): Graded {
  const event = {
    ...mapped,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: mapped.mitreTechniques ?? [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return { severity: after.severity, mitre: after.mitreTechniques ?? [], ruleIds: proposal?.ruleIds ?? [] };
}

function sysmonWrite(image: string, target: string): Graded {
  const rec = {
    "@timestamp": "2026-09-22T14:37:51Z",
    channel: "Microsoft-Windows-Sysmon/Operational",
    computer_name: "WEB-01",
    event_id: 11,
    message: "File created",
    event_data: { Image: image, TargetFilename: target },
  };
  return tag(parseSiemExport(JSON.stringify([rec])).events[0]);
}

function usn(name: string, parent: string, reason: string): Graded {
  const ext = name.slice(name.lastIndexOf("."));
  const csv = [
    "Name,Extension,EntryNumber,ParentPath,UpdateReasons,UpdateTimestamp",
    `${name},${ext},5,${parent},${reason},2026-09-22 14:37:51`,
  ].join("\n");
  return tag(parseKapeCsv(csv).events[0]);
}

const W3WP = "C:\\Windows\\System32\\inetsrv\\w3wp.exe";
const TOMCAT = "C:\\Program Files\\Apache Software Foundation\\Tomcat 9.0\\bin\\tomcat9.exe";
const EXPLORER = "C:\\Windows\\explorer.exe";

describe("bundled data/tags.yaml — webshell writes", () => {
  it("loads both rules with T1505.003", () => {
    expect(RULES.rules.find((r) => r.id === WRITE_BY_SERVER)?.severity).toBe("High");
    expect(RULES.rules.find((r) => r.id === CREATED)?.severity).toBe("Medium");
    for (const id of [WRITE_BY_SERVER, CREATED]) {
      expect(RULES.rules.find((r) => r.id === id)?.mitre).toEqual(["T1505.003"]);
    }
  });

  for (const [image, target] of [
    [W3WP, "C:\\inetpub\\wwwroot\\aspnet_client\\system_web\\cmd.aspx"],
    [W3WP, "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\x.aspx"],
    [W3WP, "D:\\sites\\shop\\wwwroot\\upload\\img.ashx"],
  ]) {
    it(`grades the web server writing ${target.split("\\").pop()} High`, () => {
      const r = sysmonWrite(image, target);
      expect(r.ruleIds).toContain(WRITE_BY_SERVER);
      expect(r.severity).toBe("High");
      expect(r.mitre).toContain("T1505.003");
    });
  }

  // Tomcat explodes a .war into hundreds of .jsp files and a PHP CMS updates itself through
  // php-cgi/httpd — the server writing its own pages is routine there, so only Medium.
  for (const [image, target] of [
    [TOMCAT, "C:\\Program Files\\Apache Software Foundation\\Tomcat 9.0\\webapps\\ROOT\\shell.jsp"],
    ["C:\\php\\php-cgi.exe", "C:\\inetpub\\wwwroot\\blog\\wp-includes\\version.php"],
    ["C:\\xampp\\apache\\bin\\httpd.exe", "C:\\xampp\\htdocs\\cms\\index.php"],
    [W3WP, "C:\\inetpub\\wwwroot\\blog\\wp-content\\plugins\\a\\a.php"],
  ]) {
    it(`grades ${target.split("\\").pop()} written by ${image.split("\\").pop()} Medium, not High`, () => {
      const r = sysmonWrite(image, target);
      expect(r.ruleIds).toContain(CREATED);
      expect(r.ruleIds).not.toContain(WRITE_BY_SERVER);
      expect(r.severity).toBe("Medium");
    });
  }

  it("leaves IIS's own temp folder alone", () => {
    expect(usn("a.asp", ".\\inetpub\\temp\\appPools\\DefaultAppPool", "FileCreate").ruleIds).toEqual([]);
  });

  it("grades a script another process wrote under a web root Medium", () => {
    const r = sysmonWrite(EXPLORER, "C:\\inetpub\\wwwroot\\help.aspx");
    expect(r.ruleIds).toContain(CREATED);
    expect(r.ruleIds).not.toContain(WRITE_BY_SERVER);
    expect(r.severity).toBe("Medium");
  });

  it("grades a USN FileCreate of a script under a web root Medium", () => {
    const r = usn("cmd.aspx", ".\\inetpub\\wwwroot\\aspnet_client", "FileCreate");
    expect(r.ruleIds).toContain(CREATED);
    expect(r.severity).toBe("Medium");
  });

  it("leaves a USN overwrite of an existing page alone — only a CREATE is graded", () => {
    expect(usn("default.aspx", ".\\inetpub\\wwwroot", "DataOverwrite").ruleIds).toEqual([]);
  });

  it("leaves an MFT listing of a web root alone — a site holds thousands of pages", () => {
    const csv = [
      "EntryNumber,ParentPath,FileName,Extension,Created0x10,InUse,IsDirectory",
      "5,.\\inetpub\\wwwroot,default.aspx,.aspx,2026-09-22 14:37:51,True,False",
    ].join("\n");
    expect(tag(parseKapeCsv(csv).events[0]).ruleIds).toEqual([]);
  });

  for (const [image, target] of [
    [W3WP, "C:\\inetpub\\wwwroot\\App_Data\\session.log"],
    [W3WP, "C:\\inetpub\\temp\\IIS Temporary Compressed Files\\x.tmp"],
    [W3WP, "C:\\Users\\Public\\cmd.aspx.txt"],
    [EXPLORER, "C:\\Users\\a\\Documents\\wwwroot-notes.aspx.bak"],
  ]) {
    it(`leaves ${target.split("\\").pop()} alone`, () => {
      const r = sysmonWrite(image, target);
      expect(r.ruleIds).not.toContain(WRITE_BY_SERVER);
      expect(r.ruleIds).not.toContain(CREATED);
    });
  }
});
