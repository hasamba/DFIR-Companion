import { describe, it, expect } from "vitest";
import { expectLinearScan } from "../helpers/growth.js";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3005 — a vendor secret glued to other text (a word before it, `_x` or one letter after it) and a
// `password=` pair directly after a backslash went to the AI in clear. Every fixture secret is
// assembled at runtime from split parts, so the repo's secret scanners never see a vendor literal.
const join = (...parts: string[]) => parts.join("");
const rep = (s: string, n: number) => s.repeat(Math.ceil(n / s.length)).slice(0, n);

const AWS = join("AK", "IA", "QZ7WXCVBNMLKJHGF");
const ACCA = join("AC", "CA", "Q2W3E4R5T6Y7U2I3");
const GHP = join("gh", "p_", rep("a1B2", 36));
const GHPAT = join("github", "_pat_", rep("A1b2C3d4", 32));
const SLACK = join("xo", "xb-", "1234567890-abcdefghij");
const GOOGLE = join("AI", "za", rep("Qw", 35));
const STRIPE = join("sk", "_live_", rep("Lm12No34", 24));
const ANTHROPIC = join("sk-", "ant-", "api03-", rep("Ab12Cd34", 40));
const ANTHROPIC_ADMIN = join("sk-", "ant-", "admin01-", rep("Ab12Cd34", 40));
const OPENAI = join("sk-", rep("Ab12Cd34", 20), "T3Blbk", "FJ", rep("Kl12Mn34", 20));
const OPENAI_PROJ = join("sk-", "proj-", rep("Ab12Cd34", 40), "T3Blbk", "FJ", rep("Kl12Mn34", 40));
const OPENAI_SVC = join("sk-", "svcacct-", rep("Ab12Cd34", 40), "T3Blbk", "FJ", rep("Kl12Mn34", 40));
const OPENAI_ADMIN = join("sk-", "admin-", rep("Ab12Cd34", 40), "T3Blbk", "FJ", rep("Kl12Mn34", 40));
const SENDGRID = join("S", "G.", rep("Ab12Cd34", 22), ".", rep("Mn34Op56", 43));
const NPM = join("np", "m_", rep("N1p2", 36));
const JWT = join(
  "ey",
  "J",
  "hbGciOiJIUzI1NiJ9",
  ".",
  "ey",
  "JzdWIiOiIxMjM0In0",
  ".",
  "Sf1KxwRJSMeKKF2QT4fwpM",
);
// GitHub App installation token, 2026 format: ghs_<app id>_<JWT>, ~520 characters.
const GHS_JWT = join("gh", "s_", "123456_", JWT);
const SLACK_ROTATED = join("xo", "xe-", "1-", rep("Ab12Cd34", 40));
const SLACK_APP = join("xa", "pp-", "1-", "A0123BCDE-", rep("0123456789", 13));

const hidden = (input: string, secret: string) => {
  const out = redactSecretText(input);
  expect(out).not.toContain(secret);
  expect(out).toContain(PH);
  return out;
};

describe("redactSecretText — a vendor secret glued to text (#3005)", () => {
  const glued: [string, string][] = [
    ["AWS key after a lower-case word", `bob${AWS}`],
    ["AWS key before one more letter", `${AWS}x`],
    ["AWS key before _x", `${AWS}_x`],
    ["AWS ACCA key between lower-case words", `bob${ACCA}end`],
    ["GitHub classic token before _x", `${GHP}_x`],
    ["GitHub classic token after a word", `bob${GHP}`],
    ["GitHub fine-grained token after a word", `bob${GHPAT}`],
    ["Slack token before _x", `${SLACK}_x`],
    ["Slack token after a word", `bob${SLACK}`],
    ["Google key after a word", `bob${GOOGLE}`],
    ["Stripe live key after a word", `bob${STRIPE}`],
    ["Anthropic key after a word", `bob${ANTHROPIC}`],
    ["Anthropic admin key after a word", `bob${ANTHROPIC_ADMIN}`],
    ["OpenAI legacy key after a word", `bob${OPENAI}`],
    ["OpenAI project key after a word", `bob${OPENAI_PROJ}`],
    ["SendGrid key after a word", `bob${SENDGRID}`],
    ["npm token after a word", `bob${NPM}`],
    ["JWT after a word", `bob${JWT}`],
  ];
  it.each(glued)("hides a %s", (_name, input) => {
    const secret = input.replace(/^bob/, "").replace(/(?:_x|x|end)$/, "");
    hidden(`4624 ${input} logon`, secret.slice(4));
  });

  it.each([
    ["GitHub App installation token (ghs_<app id>_<JWT>)", GHS_JWT],
    ["OpenAI service-account key", OPENAI_SVC],
    ["OpenAI admin key", OPENAI_ADMIN],
    ["rotated Slack token", SLACK_ROTATED],
    ["Slack app-level token", SLACK_APP],
  ])("hides a %s", (_name, secret) => {
    expect(redactSecretText(`found ${secret} in config`)).toBe(`found ${PH} in config`);
  });
});

describe("redactSecretText — a secret key directly after a backslash (#3005)", () => {
  const value = join("Hunt", "er2Value77");
  it.each([
    "CONTOSO\\password=",
    "CONTOSO\\Password = ",
    "CORP\\pwd=",
    "CORP\\secret=",
    "CONTOSO\\token=",
    "C:\\Temp\\password=",
    "\\\\FS01\\share\\password=",
  ])("hides the value of %s", (key) => {
    hidden(`${key}${value}`, value);
  });

  it.each([
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PasswordManager=C:\\Users\\Public\\pm.exe",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecretUpdater=C:\\ProgramData\\su.exe",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential=1",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse=0",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange=1",
  ])("keeps the registry IOC %s", (row) => {
    expect(redactSecretText(row)).toBe(row);
  });
});

describe("anonymizer — a bare secret value stops before an encoded command (#3005)", () => {
  const value = join("Hunt", "er2Value77");
  const blob = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
  const cats = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true };
  const anon = () =>
    createAnonymizer(
      { enabled: true, redactSecrets: true, maskPublicIps: true, categories: cats } as AnonPolicy,
      { hosts: [], accounts: [], internalDomains: [] },
    );
  it.each(["password=", "CONTOSO\\password=", "CORP\\pwd="])("%s value, then a pipe and -enc", (key) => {
    for (const cue of ["|-enc ", "|-EncodedCommand ", "|-e ", " | powershell -ec "]) {
      const out = anon().apply(`${key}${value}${cue}${blob}`);
      expect(out).not.toContain(value);
      expect(out).not.toContain(blob);
      expect(out).toMatch(/ANON_CMD_\d+/);
    }
  });
  it.each(["password=", "CONTOSO\\password="])("%s value glued to FromBase64String", (key) => {
    const out = anon().apply(`${key}${value}xFromBase64String('${blob}==')`);
    expect(out).not.toContain(value);
    expect(out).not.toContain(blob);
    expect(out).toContain("FromBase64String('ANON_CMD_");
  });
  it("redacts the separator with the secret and keeps the cue", () => {
    expect(redactSecretText(`password=${value}|-enc ${blob}`)).toBe(`password=${PH}-enc ${blob}`);
    // No cue: the value still runs through a pipe, so a secret that contains one is hidden whole.
    expect(redactSecretText(`password=${value}|tail`)).toBe(`password=${PH}`);
  });
});

describe("redactSecretText — a vendor shape plus a tail under a key (#3005)", () => {
  it("hides the whole value, tail included", () => {
    expect(redactSecretText(`--password ${GHP}_x next`)).toBe(`--password ${PH} next`);
    expect(redactSecretText(`password=${AWS}-suffix`)).toBe(`password=${PH}`);
  });
});

describe("redactSecretText — IOCs stay readable beside the glued patterns (#3005)", () => {
  const hex = "0123456789ABCDEF";
  const upperHash = (seed: number) => Array.from({ length: 64 }, (_, i) => hex[(i * 7 + seed) % 16]).join("");
  const planted = [0, 5, 17, 30, 44, 60].map((at) => {
    const h = upperHash(at);
    return h.slice(0, at) + "ACCA" + h.slice(at + 4);
  });
  const kept = [
    ...planted,
    ...planted.map((h) => `SHA256=${h}_x`),
    ...planted.map((h) => `file${h}x`),
    "{3F2504E0-4F89-11D3-9A0C-0305E82C3301}",
    "3F2504E04F8911D39A0C0305E82C3301",
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    "C.1a2b3c4d5e6f7a8b F.CTB0J7P4QK3EA H.CTB0J7P4QK3EB",
    "ASIAPACIFICFILESERVER01 SLOVAKIAFILESRV2024",
    "desk-Ab12Cd34Ef56Gh78Ij90Kl12Mn34 task_test_Ab12Cd34Ef56Gh78Ij90 MSG.Ab12Cd34Ef56Gh78.Ij90Kl12Mn34Op",
    "C:\\Users\\Public\\report.docx:Zone.Identifier:$DATA",
    // Traps that shaped the glued rules: each is a name or a hash, not a key.
    ...planted.map(
      (h) => `highs_2024_report.final.docx xoxo-${h.toLowerCase()} task_live_${h.toLowerCase()}`,
    ),
    ...planted.map((h) => `MSG.${h.toLowerCase()}.${h.slice(0, 40)} task-ant-ab12-${h.toLowerCase()}`),
    "/usr/libexec/xapps/xapp-sn-watcher --daemon xapp-gtk3-module xwfp-workflow-helper-service",
    // Lower-case host names after an OpenAI-style prefix, assembled at runtime for the secret scan.
    join("host ", "sk", "-admin-", "fileserver-prod01 ", "sk", "-svcacct-", "backup-runner-node02 logon"),
  ];
  it.each(kept)("keeps %s", (row) => {
    expect(redactSecretText(row)).toBe(row);
  });
});

describe("redactSecretText — glued patterns scan in linear time (#3005)", () => {
  it.each([
    ["eyJ run", (n: number) => "eyJ".repeat(n)],
    ["eyJ dotted run", (n: number) => "eyJabcdefgh.".repeat(n)],
    ["sk- run", (n: number) => "sk-".repeat(n)],
    ["sk- word run", (n: number) => "sk-abcdefgh".repeat(n)],
    ["ghs_ run", (n: number) => "ghs_1_eyJ".repeat(n)],
    ["sk-ant- run", (n: number) => "sk-ant-ab12-".repeat(n)],
    ["sk_live_ run", (n: number) => "sk_live_".repeat(n)],
    ["sk-admin- run", (n: number) => "sk-admin-".repeat(n)],
    ["SG. run", (n: number) => "SG.".repeat(n)],
  ])("%s", (name, bait) => {
    expectLinearScan(name, (n) => redactSecretText(bait(n)), 2000);
  });
});
