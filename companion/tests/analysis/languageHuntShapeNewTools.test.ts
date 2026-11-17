import { describe, expect, it } from "vitest";
import { isPlausibleHuntQuery, sanitizeLanguageHunts } from "../../src/analysis/languageHuntSuggest.js";
import { languageHuntResponseSchema } from "../../src/analysis/languageHuntSuggest.js";

// #2667: the shape check for the five new languages. Each accepts its own samples and rejects VQL,
// SPL, KQL and another new language's sample.

const VALID = {
  cbc: [
    "process_name:powershell.exe AND process_cmdline:*-enc*",
    "parent_name:winword.exe AND (process_name:cmd.exe OR process_name:powershell.exe)",
    "netconn_domain:evil.example.com AND device_name:WKS01",
    "// recent\nregmod_name:*\\\\CurrentVersion\\\\Run* AND -process_name:explorer.exe",
  ],
  "wazuh-dql": [
    "data.win.eventdata.image:*powershell.exe and data.win.system.eventID:1",
    "agent.name:WKS01 and rule.level >= 10",
    'full_log:"mimikatz"',
    'syscheck.path:"C:\\Windows\\Temp\\*" and not rule.id:550',
    'data.win.eventdata.commandLine:"a | b"',
  ],
  "s1-pq": [
    "event.type = 'Process Creation' src.process.cmdline contains 'enc' | columns endpoint.name, src.process.cmdline",
    "tgt.file.path contains:anycase 'temp' and src.process.name = 'powershell.exe'",
    "dst.ip.address = '203.0.113.5' | group count() by endpoint.name",
    "event.dns.request contains 'evil.example.com'",
  ],
  xql: [
    'dataset = xdr_data | filter event_type = ENUM.PROCESS and action_process_image_name ~= "powershell" | fields agent_hostname',
    'preset = xdr_process | filter action_process_image_command_line contains "-enc"',
    'config case_sensitive = false | dataset = xdr_data | filter dns_query_name contains "evil"',
    "// sweep\ndataset = xdr_data | limit 10",
  ],
  aql: [
    "SELECT sourceip, destinationip, username FROM events WHERE username ILIKE '%admin%' LAST 7 DAYS",
    "SELECT QIDNAME(qid), LOGSOURCENAME(logsourceid) FROM events WHERE \"Process CommandLine\" ILIKE '%-enc%' LAST 24 HOURS",
    "select sourceip, sum(bytes) from flows where destinationport = 3389 group by sourceip last 1 days",
  ],
} as const;

type NewLanguage = keyof typeof VALID;

const VQL = "SELECT Name, CommandLine FROM pslist() WHERE Name =~ 'powershell'";
const SPL = 'index=* process_name="powershell.exe" | table _time host CommandLine';
const KQL = 'DeviceProcessEvents | where FileName =~ "powershell.exe"';

// "One other new language" for each, chosen to be the closest look-alike.
const OTHER_NEW: Record<NewLanguage, string> = {
  cbc: VALID["wazuh-dql"][0],
  "wazuh-dql": VALID.cbc[0],
  "s1-pq": VALID.xql[0],
  xql: VALID["s1-pq"][0],
  aql: VALID.xql[0],
};

const LANGS = Object.keys(VALID) as NewLanguage[];

describe("isPlausibleHuntQuery — new languages (#2667)", () => {
  for (const lang of LANGS) {
    it.each(VALID[lang].map((q) => [q]))(`${lang} accepts %s`, (q) => {
      expect(isPlausibleHuntQuery(lang, q)).toBe(true);
    });
    it.each([
      ["VQL", VQL],
      ["SPL", SPL],
      ["KQL", KQL],
      ["another new language", OTHER_NEW[lang]],
    ])(`${lang} rejects %s`, (_name, q) => {
      expect(isPlausibleHuntQuery(lang, q)).toBe(false);
    });
  }

  it("each new language rejects every other new language's samples", () => {
    for (const lang of LANGS)
      for (const other of LANGS.filter((l) => l !== lang))
        for (const q of VALID[other])
          expect([lang, other, q, isPlausibleHuntQuery(lang, q)]).toEqual([lang, other, q, false]);
  });

  it("AQL needs FROM events or FROM flows, and VQL plugin calls never pass", () => {
    expect(isPlausibleHuntQuery("aql", "SELECT * FROM events() WHERE 1")).toBe(false);
    expect(isPlausibleHuntQuery("aql", "SELECT * FROM assets")).toBe(false);
  });

  it("the existing languages reject the new ones too", () => {
    expect(isPlausibleHuntQuery("spl", VALID.xql[0])).toBe(false);
    expect(isPlausibleHuntQuery("spl", VALID.xql[2])).toBe(false);
    expect(isPlausibleHuntQuery("spl", VALID.aql[0])).toBe(false);
    expect(isPlausibleHuntQuery("cql", VALID.xql[0])).toBe(false);
    expect(isPlausibleHuntQuery("esql", VALID.aql[0])).toBe(false);
  });
});

describe("sanitizeLanguageHunts — new languages (#2667)", () => {
  const raw = (over: Record<string, unknown>) =>
    languageHuntResponseSchema.parse({ suggestions: [{ title: "t", rationale: "r", ...over }] }).suggestions;

  it("keeps a hunt echoed under the language id or the platform key, drops one for another tool", () => {
    expect(sanitizeLanguageHunts(raw({ platform: "aql", query: VALID.aql[0] }), "aql", {})).toHaveLength(1);
    expect(
      sanitizeLanguageHunts(raw({ platform: "qradar", query: VALID.aql[0] }), "aql", {})[0],
    ).toMatchObject({
      language: "aql",
      platform: "qradar",
    });
    expect(
      sanitizeLanguageHunts(raw({ platform: "wazuh-dql", query: VALID["wazuh-dql"][0] }), "wazuh-dql", {}),
    ).toHaveLength(1);
    expect(sanitizeLanguageHunts(raw({ platform: "splunk", query: VALID.cbc[0] }), "cbc", {})).toHaveLength(
      0,
    );
  });
});
