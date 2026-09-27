import { describe, it, expect } from "vitest";
import {
  createSupportRedactor,
  collectEnvSecrets,
  secretVariants,
  type SupportRedactorInput,
} from "../../src/analysis/supportLogRedact.js";
import { SECRET_PLACEHOLDER } from "../../src/analysis/anonymize.js";

// Credential-shaped fixtures are ASSEMBLED at runtime: a literal key or a user:password URL in the
// source trips the repo's secret scanners (betterleaks, trufflehog) on every PR. They are fake.
const join = (...parts: string[]): string => parts.join("");
const FTP_PASS = join("Hunter", "2", "Pass");
const RAW_SECRET = join("sk", "-test-", "9f8e7d6c5b4a");
const JSON_SECRET = 'p@ss"w\\rd-XYZ123';
const URL_SECRET = "tok en/+=secret99";
const B64_SECRET = "base64-me-please-42";

function input(): SupportRedactorInput {
  return {
    cases: [
      { caseId: "INC-2026-001", title: "חקירת פריצה" },
      { caseId: "acme-breach", title: "Acme Breach!" },
      { caseId: "withheld-case" },
    ],
    fileNames: ["0003_host1_security.evtx", "host1_security.evtx", "0007_Prefetch_dump.csv", "README"],
    secrets: [RAW_SECRET, JSON_SECRET, URL_SECRET, B64_SECRET],
    roots: ["/srv/dfir-data"],
    known: {
      hosts: ["dc01.corp.example.com", "WKS-ALICE", "WKS-BOB"],
      accounts: ["CORP\\alice", "bob@corp.example.com"],
      internalDomains: ["corp.example.com", "corp"],
      suppressed: ["wks-bob"],
    },
  };
}

const LOG = [
  `2026-09-27T10:00:00Z info [INC-2026-001] import started for host1_security.evtx from WKS-ALICE`,
  `2026-09-27T10:00:01Z info [acme-breach] stored as 0003_host1_security.evtx and 0007_Prefetch_dump.csv`,
  `2026-09-27T10:00:02Z warn case "חקירת פריצה" and "Acme Breach!" loaded; README present`,
  `2026-09-27T10:00:03Z debug logon CORP\\alice and bob@corp.example.com on dc01.corp.example.com and WKS-BOB`,
  `2026-09-27T10:00:04Z debug peers 10.1.2.3 192.168.50.7 203.0.113.45 198.51.100.9 2001:db8::1234`,
  `2026-09-27T10:00:05Z debug mail from carol@example.org via c2.evil.example.net and dave@corp.example.com`,
  `2026-09-27T10:00:06Z error ENOENT open 'C:\\Users\\alice\\Documents\\evidence\\report.docx'`,
  `2026-09-27T10:00:07Z error read /home/alice/dfir/cases/INC-2026-001/state.json failed`,
  `2026-09-27T10:00:08Z error share \\\\fileserver01\\share\\hr\\salaries.xlsx unreachable`,
  `2026-09-27T10:00:09Z error root /srv/dfir-data/logs/debug.log rotated`,
  `2026-09-27T10:00:10Z info GET https://api.example.com/v1/scan?token=abc123secretvalue ok`,
  `2026-09-27T10:00:11Z info fetch ftp://svc_user${":"}${FTP_PASS}${"@"}files.example.org/pub done`,
  `2026-09-27T10:00:12Z debug env raw=${RAW_SECRET} json=${JSON.stringify(JSON_SECRET)} url=${encodeURIComponent(URL_SECRET)}`,
  `2026-09-27T10:00:13Z debug b64=${Buffer.from(B64_SECRET).toString("base64")}`,
  `2026-09-27T10:00:14Z debug already tokenized ANON_HOST_1 stays inert`,
].join("\n");

const SEEDED = [
  "INC-2026-001",
  "חקירת פריצה",
  "acme-breach",
  "Acme Breach",
  "host1_security",
  "Prefetch_dump",
  "README",
  "WKS-ALICE",
  "WKS-BOB",
  "alice",
  "bob@",
  "corp.example.com",
  "dc01",
  "10.1.2.3",
  "192.168.50.7",
  "203.0.113.45",
  "198.51.100.9",
  "2001:db8::1234",
  "carol",
  "example.org",
  "evil-example",
  "dave",
  "Documents",
  "report.docx",
  "/home/",
  "fileserver01",
  "salaries",
  "/srv/dfir-data",
  "api.example.com",
  "abc123secretvalue",
  "svc_user",
  FTP_PASS,
  RAW_SECRET,
  JSON_SECRET,
  JSON.stringify(JSON_SECRET).slice(1, -1),
  URL_SECRET,
  encodeURIComponent(URL_SECRET),
  B64_SECRET,
  Buffer.from(B64_SECRET).toString("base64"),
];

function expectNoSeeded(out: string): void {
  const lower = out.toLowerCase();
  for (const v of SEEDED) expect(lower, `leaked ${v}`).not.toContain(v.toLowerCase());
}

describe("createSupportRedactor", () => {
  it("removes every seeded real value from a realistic log", () => {
    const r = createSupportRedactor(input());
    const out = r.redactLog(LOG);
    expectNoSeeded(out);
    expect(out.split("\n")).toHaveLength(LOG.split("\n").length);
    expect(out).toContain(SECRET_PLACEHOLDER);
    expect(out).toMatch(/ANON_URL_\d+/);
    expect(out).toMatch(/ANON_PATH_\d+/);
    expect(out).toMatch(/ANON_CASE_\d+/);
    expect(out).toMatch(/ANON_IP_\d+/);
    expect(out).toMatch(/ANON_EXTIP_\d+/);
    expect(out).toMatch(/ANON_EMAIL_\d+/);
    expect(out).toMatch(/ANON_HOST_\d+/);
    expect(out).toMatch(/ANON_USER_\d+/);
  });

  it("maps the same value to the same token across separate calls", () => {
    const r = createSupportRedactor(input());
    const a = r.redactText("host WKS-ALICE case INC-2026-001 file host1_security.evtx ip 10.1.2.3");
    const b = r.redactText("ip 10.1.2.3 file host1_security.evtx case INC-2026-001 host WKS-ALICE");
    const tokens = (s: string) => (s.match(/ANON_[A-Z]+_\d+(?:\.[a-z0-9]+)?/g) ?? []).sort();
    expect(tokens(a)).toEqual(tokens(b));
    expect(tokens(a)).toHaveLength(4);
  });

  it("gives a case id and its title the same number", () => {
    const r = createSupportRedactor(input());
    expect(r.redactText("INC-2026-001")).toBe(r.redactText("חקירת פריצה"));
    expect(r.redactText("acme-breach")).toBe(r.redactText("Acme Breach!"));
    expect(r.redactText("acme-breach")).not.toBe(r.redactText("INC-2026-001"));
  });

  it("keeps the lowercase extension and shares a token between stored and original names", () => {
    const r = createSupportRedactor(input());
    const stored = r.redactText("0003_host1_security.evtx");
    expect(stored).toMatch(/^ANON_FILE_\d+\.evtx$/);
    expect(r.redactText("host1_security.evtx")).toBe(stored);
    expect(r.redactText("Prefetch_dump.csv")).toMatch(/^ANON_FILE_\d+\.csv$/);
    expect(r.redactText("README")).toMatch(/^ANON_FILE_\d+$/);
  });

  it("does not match a case id or file name glued inside a longer word", () => {
    const r = createSupportRedactor(input());
    expect(r.redactText("xacme-breachy")).toBe("xacme-breachy");
  });

  it("redacts a suppressed value anyway", () => {
    const r = createSupportRedactor(input());
    expect(r.redactText("seen on WKS-BOB")).not.toContain("WKS-BOB");
  });

  it("omits an overlong line before redaction", () => {
    const r = createSupportRedactor(input());
    const long = `x ${RAW_SECRET} ` + "a".repeat(100);
    const out = r.redactLog(`short line\n${long}\nend`, { maxLineBytes: 50 });
    expect(out.split("\n")).toEqual([
      "short line",
      `<line omitted: ${Buffer.byteLength(long)} bytes>`,
      "end",
    ]);
  });

  it("withholds every line scoped to a withheld case", () => {
    const r = createSupportRedactor(input());
    const log = [
      "[withheld-case] secret stuff on HOSTX",
      "[import] withheld-case: 3 rows",
      "[INC-2026-001] fine",
    ].join("\n");
    const out = r.redactLog(log, { withheldCaseIds: ["withheld-case"] }).split("\n");
    expect(out[0]).toBe("<line withheld: case vocabulary unavailable>");
    expect(out[1]).toBe("<line withheld: case vocabulary unavailable>");
    expect(out[2]).toMatch(/^\[ANON_CASE_\d+\] fine$/);
  });

  it("keeps CRLF line endings", () => {
    const r = createSupportRedactor(input());
    expect(r.redactLog("a WKS-ALICE\r\nb\r\n")).toMatch(/^a ANON_HOST_\d+\r\nb\r\n$/);
  });

  it("neutralizes a token-looking literal so it cannot collide with a minted token", () => {
    const r = createSupportRedactor(input());
    const out = r.redactText("literal ANON_HOST_1 then WKS-ALICE");
    const minted = /then (ANON_HOST_\d+)/.exec(out)?.[1];
    expect(minted).toBeDefined();
    expect(out.split(minted as string)).toHaveLength(2);
  });

  it("reports distinct counts per category and never a value", () => {
    const r = createSupportRedactor(input());
    r.redactLog(LOG);
    r.redactLog(LOG);
    const summary = r.summary();
    expect(summary.CASE).toBe(2);
    expect(summary.FILE).toBe(3);
    expect(summary.SECRET).toBeGreaterThanOrEqual(4);
    expect(summary.URL).toBe(2);
    expect(summary.PATH).toBeGreaterThanOrEqual(4);
    const json = JSON.stringify(summary).toLowerCase();
    for (const v of SEEDED) expect(json).not.toContain(v.toLowerCase());
  });

  it("redacts residual paths, URLs and blobs it was never told about", () => {
    const r = createSupportRedactor({
      cases: [],
      fileNames: [],
      secrets: [],
      roots: [],
      known: { hosts: [], accounts: [], internalDomains: [] },
    });
    const out = r.redactText(
      "a /work/evidence/x.bin b D:/data/y c file:///etc/passwd d rel\\dir\\sub e 0123456789abcdef0123456789abcdef01",
    );
    for (const v of ["/work/evidence", "D:/data", "/etc/passwd", "rel\\dir", "0123456789abcdef"])
      expect(out).not.toContain(v);
  });
});

describe("secretVariants / collectEnvSecrets", () => {
  it("expands raw, JSON-escaped, URL-encoded and base64 forms, longest first, skipping short ones", () => {
    const v = secretVariants([JSON_SECRET, "short"]);
    expect(v).toContain(JSON_SECRET);
    expect(v).toContain(JSON.stringify(JSON_SECRET).slice(1, -1));
    expect(v).toContain(encodeURIComponent(JSON_SECRET));
    expect(v).toContain(Buffer.from(JSON_SECRET).toString("base64"));
    expect(v).not.toContain("short");
    for (let i = 1; i < v.length; i++) expect(v[i - 1].length).toBeGreaterThanOrEqual(v[i].length);
  });

  it("takes every non-flag value of a secret-named env key — numbers too, since a name cannot tell", () => {
    const out = collectEnvSecrets({
      DFIR_OPENAI_API_KEY: "sk-abcdef123456",
      DFIR_AUTH_TOKEN: "tok-987654",
      SMTP_PASSWORD: "hunter22",
      SENTRY_DSN: "https://k@sentry.example.com/1",
      DFIR_AI_MAX_TOKENS: "4000",
      DFIR_REQUIRE_AUTH: "true",
      DFIR_EMPTY_SECRET: "",
      DFIR_CASES_ROOT: "/srv/cases",
      UNSET_KEY: undefined,
    });
    expect(out.sort()).toEqual(
      ["https://k@sentry.example.com/1", "hunter22", "sk-abcdef123456", "tok-987654", "4000"].sort(),
    );
  });
});

describe("labelled credentials and prose", () => {
  const empty = (): SupportRedactorInput => ({
    cases: [],
    fileNames: [],
    secrets: [],
    roots: [],
    known: { hosts: [], accounts: [], internalDomains: [] },
  });

  it("redacts a value by its label, and a bare Bearer token", () => {
    const r = createSupportRedactor(empty());
    const out = r.redactText(
      'Cookie: session=zz81yy72xx; {"apiKey":"k-551aa"} Authorization Bearer q1w2e3r4t5y6',
    );
    for (const v of ["zz81yy72xx", "k-551aa", "q1w2e3r4t5y6"]) expect(out).not.toContain(v);
  });

  it("keeps route prose readable around a POSIX path", () => {
    const r = createSupportRedactor(empty());
    const out = r.redactText("GET /cases/x/import 200 12ms; content-type application/json");
    expect(out).toMatch(/^GET ANON_PATH_\d+ 200 12ms; content-type application\/json$/);
  });
});

describe("support redactor — fail-closed gaps from the code review (#1735)", () => {
  it("replaces short and numeric secrets from secret-named settings, as whole words only", () => {
    const secrets = collectEnvSecrets({
      DFIR_SMTP_PASSWORD: "48213",
      DFIR_X_TOKEN: "ab1",
      DFIR_AUTH_ON: "true",
    });
    expect(secrets.sort()).toEqual(["48213", "ab1"]);
    const r = createSupportRedactor({ ...input(), secrets });
    const out = r.redactText("login pw=48213 then code ab1 at 2026-09-27T14:48:21Z id 1482130");
    expect(out).not.toMatch(/\b48213\b/);
    expect(out).not.toMatch(/\bab1\b/);
    expect(out).toContain("1482130"); // a longer number is not a match
  });

  it("replaces a domain whatever its suffix", () => {
    const r = createSupportRedactor(input());
    const out = r.redactText("lookup victim.company and c2.photography and portal.systems failed");
    for (const d of ["victim.company", "c2.photography", "portal.systems"]) expect(out).not.toContain(d);
  });

  it("replaces an unknown file name in an [import] line by position, and a residual name.ext", () => {
    const r = createSupportRedactor(input());
    const out = r.redactLog(
      "2026-09-27T10:00:00Z WARN [import] acme-breach Acme Payroll Q3.csv: FAILED (csv) — bad row\n" +
        "2026-09-27T10:00:01Z INFO opened Acme.csv for reading",
    );
    expect(out).not.toContain("Payroll");
    expect(out).not.toContain("Acme.csv");
    expect(out).toMatch(/\[import\] ANON_CASE_\d+ ANON_FILE_\d+\.csv: FAILED/);
    expect(out).toMatch(/opened ANON_FILE_\d+\.csv/);
  });
});
