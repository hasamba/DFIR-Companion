import { describe, it, expect } from "vitest";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { parseCiscoAsaLog } from "../../src/analysis/ciscoAsaImport.js";
import { parseSyslog } from "../../src/analysis/syslogImport.js";
import { parseAuditdLog } from "../../src/analysis/auditdImport.js";
import { parseJournald } from "../../src/analysis/journaldImport.js";
import { parseSysdig } from "../../src/analysis/sysdigImport.js";
import { parseCombinedLog } from "../../src/analysis/combinedLogImport.js";
import { parseShellHistoryFile } from "../../src/analysis/bashHistoryImport.js";
import { parseWazuhAlerts } from "../../src/analysis/wazuhImport.js";
import { parseTheHive } from "../../src/analysis/theHiveImport.js";
import { parseSocrates } from "../../src/analysis/socratesImport.js";

// Every value carries "zqmark" so one substring check proves no row VALUE reached the summary.
const MARK = "zqmark";
const ndjson = (...o: unknown[]): string => o.map((x) => JSON.stringify(x)).join("\n");

/** Run the parser with and without a recorder: same result, and no marker in the summary. */
function run<T>(parse: (debug?: ImportDebugRecorder) => T): ReturnType<ImportDebugRecorder["summary"]> {
  const debug = createImportDebugRecorder();
  expect(parse(debug)).toEqual(parse(undefined));
  const s = debug.summary();
  expect(JSON.stringify(s).toLowerCase()).not.toContain(MARK);
  return s;
}

describe("line-log parsers record what they skipped (#1736)", () => {
  it("Cisco ASA: a non-ASA line is not_asa_line", () => {
    const text = [
      `<166>May 15 06:42:06 ${MARK}fw %ASA-6-302013: Built outbound TCP connection 1 for inside:10.30.20.30/45083 (203.0.113.114/21267) to outside:198.51.100.140/443 (198.51.100.140/443)`,
      `${MARK} not a firewall line`,
    ].join("\n");
    const s = run((debug) => parseCiscoAsaLog(text, { assumeYear: 2024, debug }));
    expect(s.skipped).toEqual({ not_asa_line: 1 });
  });

  it("syslog: an unparseable line is skipped and a year-less stamp is observed", () => {
    const text = [
      `May 16 13:40:26 ${MARK}host sshd[1234]: Failed password for invalid user ${MARK} from 203.0.113.9 port 41022 ssh2`,
      `${MARK} free text that is not syslog`,
    ].join("\n");
    const s = run((debug) => parseSyslog(text, { assumeYear: 2024, debug }));
    expect(s.skipped).toEqual({ unparseable_line: 1 });
    expect(s.observations).toEqual({ timestamp_year_inferred: 1 });
    expect(s.counts.total).toBe(1);
  });

  it("auditd: a line that is neither an audit record nor an aureport row is skipped", () => {
    const text = [
      "type=PROCTITLE msg=audit(1490451217.272:270): proctitle=636174002F6574632F736861646F77",
      `${MARK} garbage line`,
    ].join("\n");
    const s = run((debug) => parseAuditdLog(text, { debug }));
    expect(s.skipped).toEqual({ unparseable_line: 1 });
  });

  it("journald: a record without the journal shape is skipped", () => {
    const text = ndjson(
      {
        __REALTIME_TIMESTAMP: "1717200000000000",
        PRIORITY: "3",
        MESSAGE: `${MARK} I/O error`,
        _TRANSPORT: "kernel",
        _HOSTNAME: `${MARK}host`,
      },
      { unrelated: `${MARK}` },
    );
    const s = run((debug) => parseJournald(text, { debug }));
    expect(s.skipped).toEqual({ not_a_journal_entry: 1 });
  });

  it("sysdig: a record that is neither Falco nor sysdig is skipped; the mapper is recorded", () => {
    const text = ndjson(
      {
        time: "2024-06-01T00:00:00.123456789Z",
        rule: "Terminal shell in container",
        priority: "Warning",
        output: `A shell was spawned (user=${MARK})`,
        hostname: `${MARK}node`,
      },
      { unrelated: MARK },
    );
    const s = run((debug) => parseSysdig(text, { debug }));
    expect(s.skipped).toEqual({ not_sysdig_or_falco: 1 });
    expect(s.fallbacks).toEqual({ falco_mapper: 1 });
  });

  it("combined log: a non-access-log line is skipped", () => {
    const text = [
      `10.30.20.11 - - [14/May/2024:19:00:00 +0000] "GET /${MARK} HTTP/1.1" 200 83 "-" "${MARK}agent"`,
      `${MARK} not an access log line`,
    ].join("\n");
    const s = run((debug) => parseCombinedLog(text, { debug }));
    expect(s.skipped).toEqual({ unparseable_line: 1 });
  });

  it("shell history: an undated command is kept and observed as no_timestamp", () => {
    const text = [`#1715688062`, `curl http://${MARK}.example.com/x`, `ls /${MARK}`].join("\n");
    const s = run((debug) => parseShellHistoryFile(text, { user: `${MARK}user`, debug }));
    expect(s.observations).toEqual({ no_timestamp: 1 });
  });
});

describe("platform parsers record what they skipped (#1736)", () => {
  const alert = (level: number) => ({
    timestamp: "2024-01-15T10:30:00.123+0000",
    rule: { level, description: `${MARK} rule`, id: "5712" },
    agent: { id: "001", name: `${MARK}agent` },
  });

  it("Wazuh: an alert below the rule level is skipped as below_rule_level", () => {
    const s = run((debug) => parseWazuhAlerts(JSON.stringify([alert(10), alert(1)]), { debug }));
    expect(s.skipped).toEqual({ below_rule_level: 1 });
  });

  it("TheHive: an unknown record type is skipped, observables are counted", () => {
    const text = JSON.stringify([
      { _type: "case", _createdAt: 1706400000000, title: `${MARK} case`, severity: 3 },
      { _type: "Observable", dataType: "ip", data: "203.0.113.5", ioc: true },
      { somethingElse: MARK },
    ]);
    const s = run((debug) => parseTheHive(text, { debug }));
    expect(s.skipped).toEqual({ unknown_record_type: 1 });
    expect(s.fallbacks).toEqual({ observable_records: 1 });
  });

  it("TheHive: unparseable JSON is recorded", () => {
    const s = run((debug) => parseTheHive(`{${MARK}`, { debug }));
    expect(s.skipped).toEqual({ unparseable_json: 1 });
  });

  it("SO-CRATES: an unknown record shape is skipped; each mapper is counted", () => {
    const text = ndjson(
      { rule_title: `${MARK} sigma rule`, rule_level: "high", timestamp: "2024-01-01T00:00:00Z" },
      { unrelated: MARK },
    );
    const s = run((debug) => parseSocrates(text, { debug }));
    expect(s.skipped).toEqual({ unknown_record_shape: 1 });
    expect(s.fallbacks).toEqual({ sigma_mapper: 1 });
  });
});
