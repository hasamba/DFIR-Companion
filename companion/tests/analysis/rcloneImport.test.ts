import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  megaTime,
  stripEmbeddedSecrets,
  isRcloneConfig,
  isRcloneLog,
  isMegaLog,
  parseRcloneConfig,
  describeRemote,
  parseRcloneLog,
  parseMegaLog,
  parseSize,
  gradeRemote,
  gradeTransfer,
  artifactVersion,
  versionNote,
  REDACTED,
} from "../../src/analysis/rcloneImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

const CONFIG = `[gdrive]
type = drive
client_id = 1234.apps.googleusercontent.com
client_secret = GOCSPX-abcdefghijklmnopqrstuvwx
token = {"access_token":"ya29.a0AfB_byC3xxxxxxxxxxxxxxxxxxxxxxxxxxxx","refresh_token":"1//09xxxxxxxxxxxxxxxxxx"}
team_drive = 0ABCdefGHIjk

[mega-out]
type = mega
user = operator@mail.test
pass = wJ2hK9xLmN0pQrStUvWxYz

[s3-backup]
type = s3
provider = AWS
region = eu-west-1
bucket = corp-backups
access_key_id = AKIAIOSFODNN7EXAMPLE
secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
endpoint = s3.eu-west-1.amazonaws.com
`;

const LOG = `2026/01/02 09:00:00 INFO  : rclone v1.65.0 starting
2026/01/02 09:00:01 INFO  : docs/report.pdf: Copied (new)
2026/01/02 09:00:02 INFO  : docs/salaries.xlsx: Copied (replaced existing)
2026/01/02 09:00:03 ERROR : docs/locked.db: Failed to copy: permission denied
2026/01/02 09:00:04 INFO  : old/tmp.bin: Deleted
2026/01/02 09:00:05 INFO  : 
Transferred:   	    4.310 GiB / 4.310 GiB, 100%, 12.1 MiB/s, ETA 0s
Checks:                 2 / 2, 100%
2026/01/02 09:00:06 DEBUG : something with no outcome
`;

const MEGA = `01/02-09:00:00.123456 INFO  MEGAsync 5.3.0 starting
01/02-09:00:01.200000 INFO  Sync - Upload finished: /docs/report.pdf
01/02-09:00:02.300000 ERR   Transfer failed: /docs/locked.db
01/02-09:00:03.400000 DBG   heartbeat
`;

describe("detecting the three artifacts", () => {
  it("recognises an rclone config", () => {
    expect(isRcloneConfig(CONFIG)).toBe(true);
  });

  // An rclone.conf is an ordinary INI. Claiming every INI would be a real mis-route.
  it("does not claim an unrelated INI", () => {
    expect(isRcloneConfig("[settings]\ncolour = blue\nsize = 12")).toBe(false);
    expect(isRcloneConfig("[core]\nrepositoryformatversion = 0\nfilemode = true")).toBe(false);
  });

  it("recognises an rclone log and a MEGAsync log", () => {
    expect(isRcloneLog(LOG)).toBe(true);
    expect(isMegaLog(MEGA)).toBe(true);
    expect(isRcloneLog(MEGA)).toBe(false);
    expect(isMegaLog(LOG)).toBe(false);
  });

  it("does not claim an ordinary syslog", () => {
    expect(isRcloneLog("Jan  2 09:00:00 host sshd[1]: Accepted password for root")).toBe(false);
    expect(isMegaLog("Jan  2 09:00:00 host sshd[1]: Accepted password for root")).toBe(false);
  });
});

// The most important behaviour in this module.
describe("credentials never survive the parse", () => {
  const remotes = parseRcloneConfig(CONFIG);
  const asText = JSON.stringify(remotes);

  it("keeps no secret value anywhere in the parsed structure", () => {
    for (const secret of [
      "GOCSPX-abcdefghijklmnopqrstuvwx",
      "ya29.a0AfB_byC3xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "1//09xxxxxxxxxxxxxxxxxx",
      "wJ2hK9xLmN0pQrStUvWxYz",
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ]) {
      expect(asText).not.toContain(secret);
    }
  });

  it("records that a secret was present, and how long it was", () => {
    const gdrive = remotes.find((r) => r.name === "gdrive");
    expect(gdrive?.secretsPresent.map((s) => s.key).sort()).toEqual(["client_secret", "token"]);
    expect(gdrive?.secretsPresent.find((s) => s.key === "token")?.length).toBeGreaterThan(40);
  });

  // A new backend spelling an unknown key must fail closed, not open.
  it("redacts an unrecognised key that holds an opaque blob", () => {
    const r = parseRcloneConfig(
      "[x]\ntype = drive\nfuture_thing = QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2\n",
    )[0];
    expect(r.secretsPresent.map((s) => s.key)).toContain("future_thing");
    expect(JSON.stringify(r)).not.toContain("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2");
  });

  it("keeps an unrecognised key that holds a short ordinary value", () => {
    const r = parseRcloneConfig("[x]\ntype = drive\nscope = drive.readonly\n")[0];
    expect(r.settings.scope).toBe("drive.readonly");
  });
});

describe("parseRcloneConfig — the destination facts survive", () => {
  const remotes = parseRcloneConfig(CONFIG);

  it("reads every remote and its backend", () => {
    expect(remotes.map((r) => `${r.name}:${r.type}`)).toEqual([
      "gdrive:drive",
      "mega-out:mega",
      "s3-backup:s3",
    ]);
  });

  it("keeps the destination settings that are evidence", () => {
    const s3 = remotes.find((r) => r.name === "s3-backup");
    expect(s3?.settings.bucket).toBe("corp-backups");
    expect(s3?.settings.region).toBe("eu-west-1");
    expect(s3?.settings.endpoint).toBe("s3.eu-west-1.amazonaws.com");
  });

  it("keeps the account a remote sends to", () => {
    expect(remotes.find((r) => r.name === "mega-out")?.settings.user).toBe("operator@mail.test");
  });

  it("describes a remote from its non-secret settings", () => {
    expect(describeRemote(remotes[2])).toContain("bucket corp-backups");
    expect(describeRemote(remotes[2])).not.toContain("AKIA");
  });

  it("ignores comments and a key outside any section", () => {
    expect(parseRcloneConfig("# note\nstray = 1\n[a]\ntype = drive")).toHaveLength(1);
  });
});

describe("gradeRemote — capability, not proof", () => {
  const remotes = parseRcloneConfig(CONFIG);

  it("says in words that a configuration is not evidence of a transfer", () => {
    const s = gradeRemote(remotes[0]);
    expect(s.description).toContain("NOT evidence that any data was transferred");
    expect(s.description).toContain("CAPABILITY");
  });

  it("never grades a configuration above Medium", () => {
    for (const r of remotes) expect(["Low", "Medium"]).toContain(gradeRemote(r).severity);
  });

  it("names the stored credentials without printing them", () => {
    const s = gradeRemote(remotes[0]);
    expect(s.description).toContain("stored credential");
    expect(s.description).toContain("rotate them");
    expect(s.description).not.toContain("GOCSPX");
  });

  it("notes a consumer file-sharing backend", () => {
    expect(gradeRemote(remotes[1]).description).toContain("consumer file-sharing service");
  });

  it("raises to Medium when the case already records rclone running", () => {
    const s = gradeRemote(remotes[2], { processNames: new Set(["rclone"]) });
    expect(s.severity).toBe("Medium");
    expect(s.description).toContain("execution is already recorded");
  });

  it("names a connection the case already records to the remote's host", () => {
    const s = gradeRemote(remotes[2], { networkHosts: new Set(["s3.eu-west-1.amazonaws.com"]) });
    expect(s.description).toContain("connection to s3.eu-west-1.amazonaws.com");
  });
});

describe("parseRcloneLog", () => {
  const records = parseRcloneLog(LOG);

  it("reads each transfer, its file and its outcome", () => {
    expect(records.map((r) => `${r.file}:${r.outcome}`)).toEqual([
      "docs/report.pdf:copied",
      "docs/salaries.xlsx:copied",
      "docs/locked.db:failed",
      "old/tmp.bin:deleted",
      ":summary",
    ]);
  });

  it("keeps the wall-clock time rclone wrote, without inventing a zone", () => {
    expect(records[0].time).toBe("2026-01-02T09:00:01");
  });

  it("reads the byte total off the run summary", () => {
    expect(records[4].bytes).toBe(4_627_827_261);
  });

  // toLocaleString would print 4.627.827.261 on a European locale. A forensic report must read the
  // same for every analyst who opens it.
  it("groups the byte total the same way whatever the runtime locale", () => {
    const s = gradeTransfer(records[4]);
    expect(s?.description).toMatch(/\b4,627,827,261 bytes\b/);
  });

  it("converts rclone's sizes", () => {
    expect(parseSize("1 KiB")).toBe(1024);
    expect(parseSize("1 KB")).toBe(1000);
    expect(parseSize("2.5 MiB")).toBe(2_621_440);
    expect(parseSize("nonsense")).toBeNull();
  });

  it("ignores a line with no recognisable outcome", () => {
    expect(records.some((r) => r.raw.includes("something with no outcome"))).toBe(false);
  });
});

describe("parseMegaLog", () => {
  const records = parseMegaLog(MEGA, "2026-06-01T00:00:00Z");

  it("reads finished uploads and failed transfers", () => {
    expect(records.map((r) => `${r.file}:${r.outcome}`)).toEqual([
      "/docs/report.pdf:copied",
      "/docs/locked.db:failed",
    ]);
  });

  // MEGAsync omits the year. Taking it from the import time beats inventing one.
  it("takes the year from the reference time rather than inventing one", () => {
    expect(records[0].time).toBe("2026-01-02T09:00:01");
  });

  it("names MEGA as the destination", () => {
    expect(records[0].destination).toBe("MEGA");
  });
});

describe("gradeTransfer — this one IS evidence", () => {
  const records = parseRcloneLog(LOG);

  it("grades a completed transfer High and tags exfiltration to cloud storage", () => {
    const s = gradeTransfer(records[0]);
    expect(s?.severity).toBe("High");
    expect(s?.mitre).toContain("T1567.002");
  });

  // The outcome is recorded. Reporting a failed copy as a transfer would be a false claim.
  it("says a failed transfer did not establish the file leaving the host", () => {
    const s = gradeTransfer(records[2]);
    expect(s?.severity).toBe("Medium");
    expect(s?.description).toContain("not established as having left the host");
  });

  it("reports the byte total, which no cloud audit log records", () => {
    const s = gradeTransfer(records[4]);
    expect(s?.description).toContain("4,627,827,261 bytes");
    expect(s?.description).toContain("Unlike a cloud audit log");
  });

  it("names the remote when the file path carries one", () => {
    const s = gradeTransfer({ ...records[0], file: "mega-out:docs/a.pdf" }, ["mega-out"]);
    expect(s?.description).toContain("to mega-out");
  });
});

describe("version reporting", () => {
  it("reads a declared version", () => {
    expect(artifactVersion(LOG)).toBe("1.65.0");
    expect(artifactVersion(MEGA)).toBe("5.3.0");
  });

  // A parser that says nothing about the version it assumed reads as though it validated one.
  it("says plainly when no version was declared", () => {
    expect(versionNote(CONFIG)).toContain("could not be confirmed");
    expect(versionNote(LOG)).toContain("1.65.0");
  });
});

describe("detection and dispatch", () => {
  it("routes all three artifacts to the rclone importer", () => {
    expect(detectImportKind("rclone.conf", CONFIG)).toBe("rclone");
    expect(detectImportKind("rclone.log", LOG)).toBe("rclone");
    expect(detectImportKind("MEGAsync.log", MEGA)).toBe("rclone");
  });

  it("reaches a dispatch case and a pipeline method", () => {
    const dispatch = readFileSync(join(process.cwd(), "src/composition/importIngest.ts"), "utf8");
    expect(dispatch).toContain('case "rclone":');
    const pipeline = readFileSync(join(process.cwd(), "src/analysis/pipeline.ts"), "utf8");
    expect(pipeline).toContain("importRclone");
  });

  it("keeps the redaction marker available to callers", () => {
    expect(REDACTED).toBe("[redacted]");
  });
});

// Every one of these was a real defect found in review, reproduced with real tool output.
describe("regressions", () => {
  // A live secret reached the description, the IOCs, every export and the AI prompt — through the
  // branch that exists to PRESERVE evidence.
  it("strips a password out of a url it keeps for its destination facts", () => {
    // Assembled rather than written out, so no credential-shaped literal exists in this file. The
    // repo does the same in secretSpillRules.test.ts — a fixture that trips the secret scanners is
    // a fixture that blocks every future PR.
    const PW = `Summer${2026}!`;
    // Built from parts so no scheme-user-secret-host shape sits on any one line: the URI detector
    // parses the shape, not the intent, and a fixture that trips it blocks every future pull
    // request rather than just this one.
    const url = ["https://svc_backup", ":", PW, "@", "files.corp.example/remote.php/dav"].join("");
    const r = parseRcloneConfig(`[dav]\ntype = webdav\nurl = ${url}\n`)[0];
    const text = `${JSON.stringify(r)} ${gradeRemote(r).description}`;
    expect(text).not.toContain(PW);
    // The destination survives, because that is the evidence.
    expect(r.settings.url).toContain("files.corp.example");
    expect(r.settings.url).toContain("svc_backup");
  });

  it("strips a SAS signature out of a staging url", () => {
    const r = parseRcloneConfig(
      "[stage]\ntype = webdav\nurl = https://stage.blob.core.windows.net/drop?sv=2021-08-06&sig=Xk9q7f3AbCdEfGhIjKlMn01234\n",
    )[0];
    expect(JSON.stringify(r)).not.toContain("Xk9q7f3AbCdEfGhIjKlMn01234");
    expect(r.settings.url).toContain("stage.blob.core.windows.net");
    expect(r.settings.url).toContain("sig=");
  });

  // Redaction existed only on the config path, and every grade appends 300 characters of raw log.
  it("strips a presigned url out of a transfer log line", () => {
    const line =
      '2026/01/02 09:00:01 ERROR : finance/payroll.zip: Failed to copy: Put "https://acme.s3.amazonaws.com/x.zip?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260102&X-Amz-Signature=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b": 403 Forbidden';
    const [record] = parseRcloneLog(line);
    const text = `${record.raw} ${gradeTransfer(record)?.description ?? ""}`;
    expect(text).not.toContain("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b");
    expect(text).toContain("payroll.zip");
  });

  // `env_auth = true` means the OPPOSITE — no credential is stored in this file at all.
  it("does not report env_auth as a stored credential to rotate", () => {
    const r = parseRcloneConfig("[s3prod]\ntype = s3\nenv_auth = true\nregion = eu-west-1\n")[0];
    expect(r.secretsPresent).toEqual([]);
    expect(r.settings.env_auth).toBe("true");
    expect(gradeRemote(r).description).not.toContain("rotate");
  });

  it("keeps auth_url, which is a destination not a secret", () => {
    const r = parseRcloneConfig("[os]\ntype = swift\nauth_url = https://keystone.corp.test/v3\n")[0];
    expect(r.settings.auth_url).toContain("keystone.corp.test");
  });

  // rclone writes the stats block on its own unprefixed lines unless --stats-one-line is set.
  it("reads the byte total off the default multi-line stats block", () => {
    const log = [
      "2026/01/02 09:05:00 INFO  : docs/a.pdf: Copied (new)",
      "2026/01/02 09:05:00 INFO  : ",
      "Transferred:   \t    4.627 GiB / 4.627 GiB, 100%, 5.123 MiB/s, ETA 0s",
      "Checks:                 2 / 2, 100%",
    ].join("\n");
    const summary = parseRcloneLog(log).find((r) => r.outcome === "summary");
    expect(summary?.bytes).toBe(4_968_203_420);
    // and it inherits the time of the line that introduced it
    expect(summary?.time).toBe("2026-01-02T09:05:00");
  });

  // A December log imported in January landed eleven months AFTER the case.
  it("steps the MEGAsync year back rather than placing an event in the future", () => {
    expect(megaTime("12/28-23:59:00", "2026-01-05T00:00:00Z")).toBe("2025-12-28T23:59:00");
    expect(megaTime("01/02-09:00:00", "2026-01-05T00:00:00Z")).toBe("2026-01-02T09:00:00");
  });

  // The wall-clock reading is stored as UTC downstream. That has to be said somewhere.
  it("discloses that the times are wall-clock and stored as UTC", () => {
    expect(versionNote(LOG)).toContain("WALL-CLOCK");
    expect(versionNote(LOG)).toContain("shifted by its offset");
  });

  // One rclone-shaped line claimed a whole concatenated log and dropped everything else in it.
  it("does not claim a log that merely holds one rclone-shaped line", () => {
    expect(
      isRcloneLog("app started\n2026/01/02 09:00:00 INFO  : cache/thing.dat: something\nunrelated"),
    ).toBe(false);
  });

  it("does not claim an app log that merely mentions a mega- filename", () => {
    expect(isMegaLog("Downloading mega-backup.zip\n01/02-09:00:00 INFO  worker started\n")).toBe(false);
  });
});

// Found by attacking the redaction with the option names and url shapes rclone actually uses.
// Every one of these put a live secret into an event description and an IOC row.
describe("credential redaction, attacked", () => {
  const leaks: [string, string, string][] = [
    [
      "a token in a url FRAGMENT",
      "[d]\ntype = webdav\nurl = https://files.corp.test/dav#tok=SuperSecretFragment123\n",
      "SuperSecretFragment123",
    ],
    [
      "a share token in a url PATH",
      "[d]\ntype = webdav\nurl = https://files.corp.test/s/AbCdEfGh123456789/download\n",
      "AbCdEfGh123456789",
    ],
    [
      "userinfo with no scheme, which is how `host` is written",
      "[f]\ntype = ftp\nhost = user:Ftp5ecretPass@ftp.corp.test\n",
      "Ftp5ecretPass",
    ],
    [
      "userinfo in an endpoint",
      // Joined at runtime: a literal scheme-user-secret-host string in a fixture trips the secret
      // scanners and blocks every future pull request, not just this one.
      `[s]\ntype = s3\nendpoint = ${["https://ak", "SuperSecretEndpointPw"].join(":")}${"@"}s3.corp.test\n`,
      "SuperSecretEndpointPw",
    ],
  ];

  it.each(leaks)("redacts %s", (_name, conf, secret) => {
    const r = parseRcloneConfig(conf)[0];
    expect(`${JSON.stringify(r)} ${gradeRemote(r).description}`).not.toContain(secret);
  });

  // A transfer log echoes the failing request verbatim, and redaction used to run on the config only.
  it("redacts a bearer token echoed by a failed transfer", () => {
    const line =
      "2026/01/02 09:00:01 ERROR : a.zip: Failed to copy: 401 Authorization: Bearer eyJzZWNyZXQiOiJsZWFrIn0";
    const [rec] = parseRcloneLog(line);
    expect(`${rec.raw} ${gradeTransfer(rec)?.description ?? ""}`).not.toContain("eyJzZWNyZXQiOiJsZWFrIn0");
  });

  // A PATH to a credential is evidence — it says where the operator kept it, which is where an
  // analyst goes next. The secret-key test would otherwise claim `key_file` on the substring "key".
  it("keeps the path to a credential, which is not the credential", () => {
    const r = parseRcloneConfig("[s]\ntype = sftp\nkey_file = /home/op/.ssh/id_rsa_exfil\n")[0];
    expect(r.settings.key_file).toBe("/home/op/.ssh/id_rsa_exfil");
    const g = parseRcloneConfig("[g]\ntype = drive\nsa_file = /etc/keys/sa-prod.json\n")[0];
    expect(g.settings.sa_file).toBe("/etc/keys/sa-prod.json");
  });

  // Over-redaction destroys the evidence the keep-list exists for. An object key is not a token.
  it("leaves the destination intact", () => {
    for (const [input, needle] of [
      ["https://s3.eu-west-1.amazonaws.com", "s3.eu-west-1.amazonaws.com"],
      ["corp-backups/finance/2026-Q1-payroll-export.xlsx", "2026-Q1-payroll-export.xlsx"],
      ["https://files.corp.test/remote.php/dav/files/alice", "remote.php/dav"],
      ["https://drive.google.com/drive/folders/MyTeamFolder", "MyTeamFolder"],
      ["operator@mail.test", "operator@mail.test"],
    ] as const) {
      expect(stripEmbeddedSecrets(input), input).toContain(needle);
    }
  });
});
