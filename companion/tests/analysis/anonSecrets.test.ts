import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { isSecretKey } from "../../src/analysis/anonSecretKeys.js";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// Every fixture secret is assembled at runtime from a split vendor prefix and a word-like body, so
// the repo's secret scanners never see a vendor-shaped literal in this file.
const body = (n: number, alphabet = "FakeValueForTests") =>
  alphabet.repeat(Math.ceil(n / alphabet.length)).slice(0, n);
const join = (...parts: string[]) => parts.join("");
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

const SHA256 = "2eeba4c80a6f91f06784c0c699512c22ff132233c71af336a423414cc84f574a";
const SHA1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
const MD5 = "5d41402abc4b2a76b9719d911017c592";

describe("redactSecretText — vendor shapes", () => {
  const vendor: [string, string][] = [
    ["AWS ASIA key id", join("AS", "IA", "FAKEFAKEFAKEFAKE")],
    ["AWS ACCA key id", join("AC", "CA", "FAKEFAKEFAKEFAKE")],
    ["GitHub fine-grained token", join("github", "_pat_", body(30))],
    ["Google API key", join("AI", "za", body(35))],
    ["Stripe live key", join("sk", "_live_", body(24))],
    ["Stripe restricted test key", join("rk", "_test_", body(24))],
    ["OpenAI project key", join("sk", "-proj-", body(30))],
    ["Anthropic key", join("sk", "-ant-", body(30))],
    ["OpenAI legacy key", join("sk", "-", body(40))],
    ["SendGrid key", join("SG", ".", body(16), ".", body(20))],
    ["npm token", join("npm", "_", body(36))],
  ];
  it.each(vendor)("redacts a %s", (_name, secret) => {
    const out = redactSecretText(`found ${secret} in config`);
    expect(out).toBe(`found ${PH} in config`);
  });

  it("redacts a Twilio SID only beside a Twilio label", () => {
    const sid = join("AC", "0123456789abcdef0123456789ABCDEF");
    expect(redactSecretText(`twilio client sid ${sid}`)).toBe(`twilio client sid ${PH}`);
    expect(redactSecretText(`AccountSid=${sid}`)).toBe(`AccountSid=${PH}`);
    // On its own the shape is just hex — it must survive.
    expect(redactSecretText(`blob ${sid} end`)).toBe(`blob ${sid} end`);
  });

  it("keeps the Slack webhook host and redacts its path", () => {
    const path = `${body(9)}/${body(11)}/${body(24)}`;
    expect(redactSecretText(`POST https://hooks.slack.com/services/${path}?x=1 done`)).toBe(
      `POST https://hooks.slack.com/services/${PH}?x=1 done`,
    );
  });

  it("redacts an Azure SAS signature only in a query that carries the SAS version", () => {
    const sas = `https://acct.blob.example.com/c/f.zip?sv=2022-11-02&sp=r&sig=${body(43)}&se=2026`;
    expect(redactSecretText(sas)).toBe(
      `https://acct.blob.example.com/c/f.zip?sv=2022-11-02&sp=r&sig=${PH}&se=2026`,
    );
    const other = `https://example.com/dl?sig=${body(20)}&id=7`;
    expect(redactSecretText(other)).toBe(other);
  });
});

describe("redactSecretText — auth schemes", () => {
  it("redacts a bare Basic credential that decodes to user:pass", () => {
    const cred = b64("analyst:hunter2hunter2");
    expect(redactSecretText(`hdr Basic ${cred} x`)).toBe(`hdr Basic ${PH} x`);
  });
  it("keeps prose that only looks like a Basic or Bearer header", () => {
    expect(redactSecretText("Basic authentication failed for user")).toBe(
      "Basic authentication failed for user",
    );
    expect(redactSecretText("Authorization: Basic authentication failed")).toBe(
      "Authorization: Basic authentication failed",
    );
    expect(redactSecretText("uses bearer authentication only")).toBe("uses bearer authentication only");
  });
  it("keeps the scheme and redacts the credential under an Authorization key", () => {
    expect(redactSecretText("Authorization: Bearer OpaqueLettersOnlyToken")).toBe(
      `Authorization: Bearer ${PH}`,
    );
    expect(redactSecretText('{"authorization":"Negotiate YIIFakeBlob=="}')).toBe(
      `{"authorization":"Negotiate ${PH}"}`,
    );
  });
  it("redacts a bare Bearer token that carries a digit or symbol", () => {
    expect(redactSecretText("curl -H Bearer fake.token-value_123 url")).toBe(`curl -H Bearer ${PH} url`);
  });
});

describe("redactSecretText — command-line flags", () => {
  it.each([
    ["bare", "tool --password hunter2 --verbose", `tool --password ${PH} --verbose`],
    ["equals", "tool --api-key=hunter2key run", `tool --api-key=${PH} run`],
    ["double quoted", 'tool --password "two words" run', `tool --password "${PH}" run`],
    ["single quoted", "tool --client-secret 'two words' run", `tool --client-secret '${PH}' run`],
    ["escaped quote", 'tool --token "a\\"b c" run', `tool --token "${PH}" run`],
    ["short value", "tool --password abc", `tool --password ${PH}`],
    ["shell punctuation", "tool --token abc123;whoami", `tool --token ${PH};whoami`],
  ])("redacts a %s flag value", (_name, input, expected) => {
    expect(redactSecretText(input)).toBe(expected);
  });
  it("does not treat the next option as the value", () => {
    expect(redactSecretText("tool --password --interactive")).toBe("tool --password --interactive");
  });
});

describe("redactSecretText — secret-named keys", () => {
  it.each([
    ["snake-case key", "client_secret=hunter2hunter2 next", `client_secret=${PH} next`],
    ["prefixed key", "my_password=hunter2 next", `my_password=${PH} next`],
    ["AWS secret key", "aws_secret_access_key = FakeAwsSecretValue", `aws_secret_access_key = ${PH}`],
    ["dotted key", "db.Password: hunter2", `db.Password: ${PH}`],
    ["Python repr", "{'accessToken': 'abc def'}", `{'accessToken': '${PH}'}`],
    ["connection string", 'connectionString="Server=x;Password=y"', `connectionString="${PH}"`],
    ["quoted none", '{"password":"none"}', `{"password":"${PH}"}`],
  ])("redacts a %s", (_name, input, expected) => {
    expect(redactSecretText(input)).toBe(expected);
  });

  it("keeps JSON parseable and redacts numeric, array and nested values", () => {
    const input = JSON.stringify({
      user: "analyst",
      password: 12345,
      apiKey: "hunter2",
      recoveryCodes: ["aaa111", "bbb222"],
      credentials: { username: "svc", secret: "hunter2" },
      enabled: true,
    });
    const out = redactSecretText(input);
    const parsed = JSON.parse(out);
    expect(parsed.user).toBe("analyst");
    expect(parsed.password).toBe(PH);
    expect(parsed.apiKey).toBe(PH);
    expect(parsed.recoveryCodes).toEqual([PH, PH]);
    expect(parsed.credentials).toEqual({ username: "svc", secret: PH });
    expect(parsed.enabled).toBe(true);
    expect(out).not.toMatch(/hunter2|12345|aaa111|bbb222/);
  });

  it("finds a credential nested inside a non-secret field", () => {
    expect(redactSecretText('message="login password=hunter2 ok"')).toBe(`message="login password=${PH} ok"`);
    expect(redactSecretText('{"log":"{\\"password\\":\\"hunter2\\",\\"u\\":\\"x\\"}"}')).toBe(
      `{"log":"{\\"password\\":\\"${PH}\\",\\"u\\":\\"x\\"}"}`,
    );
  });

  it("redacts a truncated quoted value to the end of the line", () => {
    expect(redactSecretText('{"password":"hunter2 and the rest\nnext line')).toBe(
      `{"password":"${PH}\nnext line`,
    );
  });

  it("keeps unquoted flag values", () => {
    expect(redactSecretText("password=false token: null")).toBe("password=false token: null");
  });
});

describe("isSecretKey", () => {
  it.each(["passwordResetToken", "storageSecret", "accountPassword", "clientSecret", "pwdHash", "X-Api-Key"])(
    "treats %s as a secret",
    (k) => expect(isSecretKey(k)).toBe(true),
  );
  it.each([
    "passwordLastSet",
    "PasswordNeverExpires",
    "PasswordNotRequired",
    "credentialDumpPath",
    "privateKeyFile",
    "secretName",
    "Signature",
    "auth",
    "SHA256",
    "Hashes",
    "message",
  ])("treats %s as metadata, not a secret", (k) => expect(isSecretKey(k)).toBe(false));
});

describe("redactSecretText — forensic evidence survives", () => {
  it("keeps file hashes, SIDs, IPs and detection names", () => {
    const line = [
      `Hashes: SHA256=${SHA256},SHA1=${SHA1},MD5=${MD5}`,
      "Signature: Trojan:Win32/Emotet.A",
      "passwordLastSet: 2026-01-02T03:04:05Z",
      "PasswordNeverExpires: True",
      "User SID S-1-5-21-1111111111-2222222222-3333333333-1001 from 10.1.2.3 and fe80::1",
      `md5 ${MD5} beside the word password`,
    ].join("\n");
    expect(redactSecretText(line)).toBe(line);
  });

  it("scans adversarial text in linear time", () => {
    const bait = (n: number) => `"password":"${"\\\\".repeat(n)}` + ` password= ${" ".repeat(n)}`;
    const time = (n: number) => {
      const t = Date.now();
      redactSecretText(bait(n).repeat(20));
      return Date.now() - t;
    };
    time(500);
    const small = Math.max(time(2000), 1);
    expect(time(8000) / small).toBeLessThan(8);
  });
});

describe("anonymizer — secrets win over tokenizing", () => {
  const ALL_ON: AnonPolicy["categories"] = {
    IP: true,
    EMAIL: true,
    USER: true,
    HOST: true,
    DOMAIN: true,
    PATH: true,
    CMD: true,
    REG: true,
    CARD: true,
    PHONE: true,
    NATID: true,
  };
  const policy: AnonPolicy = { enabled: true, redactSecrets: true, maskPublicIps: false, categories: ALL_ON };

  it("never mints a reversible token for a secret that is also a custom entity", () => {
    const known: KnownEntities = {
      hosts: ["REDACTED_SECRET"],
      accounts: [],
      internalDomains: [],
      custom: [{ value: "hunter2hunter2", category: "OTHER" }],
    };
    const a = createAnonymizer(policy, known);
    const out = a.apply("db password=hunter2hunter2 on host WS01");
    expect(out).toContain(`password=${PH}`);
    expect(a.restore(out)).not.toContain("hunter2hunter2");
    expect(a.discoveries().map((d) => d.value)).not.toContain("hunter2hunter2");
    expect(a.apply(out)).toBe(out); // idempotent
  });

  it("strips a forged sentinel instead of turning it into a placeholder", () => {
    const a = createAnonymizer(
      { ...policy, redactSecrets: false },
      { hosts: [], accounts: [], internalDomains: [] },
    );
    expect(a.apply("xy")).toBe("xy");
  });
});

describe("redactSecretText — pretty-printed and nested values", () => {
  it("redacts across newlines around a JSON separator", () => {
    expect(redactSecretText('{"password":\n      "hunter2hunter2"}')).toBe(`{"password":\n      "${PH}"}`);
    expect(redactSecretText('{"password"\n  : "hunter2hunter2"}')).toBe(`{"password"\n  : "${PH}"}`);
  });

  it("does not take the next line for an unquoted prompt", () => {
    expect(redactSecretText("Enter password:\nconnection closed")).toBe("Enter password:\nconnection closed");
  });

  it("redacts every value in a multi-line or nested secret array", () => {
    const pretty = JSON.stringify({ tokens: ["firstCredential1", "secondCredential2"] }, null, 2);
    expect(JSON.parse(redactSecretText(pretty))).toEqual({ tokens: [PH, PH] });
    const nested = '{"tokens":[{"value":"opaqueCredential123"},"secondCredential456",["third789"]],"u":"x"}';
    expect(JSON.parse(redactSecretText(nested))).toEqual({ tokens: [{ value: PH }, PH, [PH]], u: "x" });
  });

  it("stops a truncated array before the log lines after it", () => {
    expect(redactSecretText("tokens: [abc\n2026-01-01 INFO started pid=5")).toBe(
      `tokens: [${PH}\n2026-01-01 INFO started pid=5`,
    );
  });
});
