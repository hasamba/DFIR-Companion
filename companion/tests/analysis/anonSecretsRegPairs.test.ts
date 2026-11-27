import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3021 — a stored-credential registry value whose NAME and DATA arrive in separate fields went to
// the AI in clear: Hayabusa's `TgtObj=…\DefaultPassword Details=<pw>`, the Sysmon message
// `TargetObject: …\DefaultPassword` + `Details: <pw>`, Velociraptor `ValueName=… - ValueData=…`,
// and `reg query` output. Every fixture value is built at runtime.
const join = (...parts: string[]) => parts.join("");
const VALUE = join("Hunt", "er2Value77");
const SPACED = join("Zq7 ", "Vbn4 ", "Kp9x");
const WINLOGON = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const TV = "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer";
const LSA = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa";
const RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const WDIGEST = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
const IMG = "C:\\Windows\\regedit.exe";
const policy: AnonPolicy = {
  enabled: true,
  redactSecrets: true,
  maskPublicIps: true,
  categories: {
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
  },
};

const hayabusa = (key: string, data: string) =>
  `Hayabusa: Autologon (EID 13 Sysmon) — EventType=SetValue TgtObj=${key} Details=${data} Proc=${IMG} PID=4242 @ ws01`;
const sysmonMessage = (key: string, data: string) =>
  `Registry value set:\nRuleName: -\nEventType: SetValue\nImage: ${IMG}\nTargetObject: ${key}\nDetails: ${data}\nUser: CORP\\bob`;
const velo = (name: string, data: string) =>
  `Velociraptor [Windows.Registry.Hunter]: Fqdn=ws01 - Key=${WINLOGON} - ValueName=${name} - ValueData=${data} - Type=REG_SZ`;
const regQuery = (name: string, type: string, data: string) =>
  `${WINLOGON}\n    ${name}    ${type}    ${data}\n`;

describe("redactSecretText — stored-credential registry values in paired fields (#3021)", () => {
  it.each([
    ["Hayabusa TgtObj/Details", hayabusa(`${WINLOGON}\\DefaultPassword`, VALUE)],
    ["Sysmon message TargetObject/Details", sysmonMessage(`${WINLOGON}\\DefaultPassword`, VALUE)],
    [
      "TargetObject=/Details=",
      `EventType: SetValue TargetObject=${WINLOGON}\\DefaultPassword Details=${VALUE}`,
    ],
    ["Velociraptor ValueName/ValueData", velo("DefaultPassword", VALUE)],
    ["ValueName:/ValueData:", `Key: ${WINLOGON} ValueName: DefaultPassword ValueData: ${VALUE}`],
    [
      "JSON ValueName/ValueData",
      JSON.stringify({ Key: WINLOGON, ValueName: "DefaultPassword", ValueData: VALUE }),
    ],
    ["TeamViewer AES via TgtObj", hayabusa(`${TV}\\OptionsPasswordAES`, VALUE)],
    ["reg query REG_SZ", regQuery("DefaultPassword", "REG_SZ", VALUE)],
    [
      "reg query flattened on one line",
      `${WINLOGON}    DefaultPassword    REG_SZ    ${VALUE}    DefaultUserName    REG_SZ    svc`,
    ],
    ["reg query REG_BINARY", regQuery("SecurityPasswordAES", "REG_BINARY", VALUE)],
  ])("hides the data in the %s shape", (_label, text) => {
    const out = redactSecretText(text);
    expect(out).not.toContain(VALUE);
    expect(out).toContain(PH);
  });

  it.each([
    ["Hayabusa", hayabusa(`${WINLOGON}\\DefaultPassword`, SPACED)],
    ["Sysmon message", sysmonMessage(`${WINLOGON}\\DefaultPassword`, SPACED)],
    ["Velociraptor", velo("DefaultPassword", SPACED)],
    ["reg query", regQuery("DefaultPassword", "REG_SZ", SPACED)],
  ])("hides a password with spaces whole in the %s shape", (_label, text) => {
    const out = redactSecretText(text);
    for (const part of SPACED.split(" ")) expect(out).not.toContain(part);
  });

  it("keeps the fields after the redacted data readable", () => {
    expect(redactSecretText(hayabusa(`${WINLOGON}\\DefaultPassword`, VALUE))).toBe(
      hayabusa(`${WINLOGON}\\DefaultPassword`, PH),
    );
    expect(redactSecretText(velo("DefaultPassword", VALUE))).toBe(velo("DefaultPassword", PH));
    expect(redactSecretText(sysmonMessage(`${WINLOGON}\\DefaultPassword`, VALUE))).toBe(
      sysmonMessage(`${WINLOGON}\\DefaultPassword`, PH),
    );
    const flat = `${WINLOGON}    DefaultPassword    REG_SZ    ${VALUE}    DefaultUserName    REG_SZ    svc`;
    expect(redactSecretText(flat)).toBe(flat.replace(VALUE, PH));
  });

  it("stops before a command-line option so its encoded argument is still masked", () => {
    const b64 = join("SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi==");
    const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
    for (const sep of [" ", "|"]) {
      const out = anon.apply(`TgtObj=${WINLOGON}\\DefaultPassword Details=${VALUE}${sep}-enc ${b64}`);
      expect(out).not.toContain(VALUE);
      expect(out).not.toContain(b64);
    }
  });

  it("does not swallow an address after the data, so it is still tokenized and restored", () => {
    const email = `${join("jd", "oe")}@${join("corp", ".local")}`;
    const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
    const out = anon.apply(`ValueName=DefaultPassword - ValueData=${VALUE} ${email} `);
    expect(out).not.toContain(VALUE);
    expect(out).not.toContain(email);
    expect(anon.restore(out)).toContain(email);
  });

  it("never splits a card number after or inside the data: no block of it goes out", () => {
    const card = ["4111", "1111", "1111", "1111"].join(" ");
    for (const head of ["5 ", "5|", "x·", "", "0 "]) {
      const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
      const out = anon.apply(`TgtObj=${WINLOGON}\\DefaultPassword Details=${head}${card}.0.0.5 x`);
      expect(out).not.toContain("1111");
      expect(out).toContain(PH);
    }
  });

  it("keeps a JSON row valid", () => {
    const out = redactSecretText(JSON.stringify({ ValueName: "DefaultPassword", ValueData: VALUE }));
    expect(JSON.parse(out)).toEqual({ ValueName: "DefaultPassword", ValueData: PH });
  });

  it.each([
    hayabusa(`${LSA}\\LimitBlankPasswordUse`, "DWORD (0x00000000)"),
    hayabusa(`${RUN}\\PasswordManager`, "C:\\pm.exe"),
    hayabusa(`${RUN}\\DefaultPasswordHelper`, "C:\\x.exe"),
    hayabusa(`${WDIGEST}\\UseLogonCredential`, "DWORD (0x00000001)"),
    hayabusa(`${WINLOGON}\\AutoAdminLogon`, "1"),
    sysmonMessage(`${RUN}\\PasswordManager`, "C:\\pm.exe"),
    sysmonMessage(
      "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange",
      "DWORD (0x00000001)",
    ),
    velo("UseLogonCredential", "1"),
    velo("DefaultUserName", "svc_backup"),
    velo("AutoAdminLogon", "1"),
    regQuery("AutoAdminLogon", "REG_SZ", "1"),
    regQuery("LimitBlankPasswordUse", "REG_DWORD", "0x0"),
  ])("keeps the data of a security setting or persistence value: %s", (text) => {
    expect(redactSecretText(text)).toBe(text);
  });

  it("pairs only within one record: a setting followed by a credential, and the reverse", () => {
    const mixed = `${velo("AutoAdminLogon", "1")}\n${velo("DefaultPassword", VALUE)}\n${velo("DefaultUserName", "svc")}`;
    expect(redactSecretText(mixed)).toBe(
      `${velo("AutoAdminLogon", "1")}\n${velo("DefaultPassword", PH)}\n${velo("DefaultUserName", "svc")}`,
    );
  });

  it("does not reach the next record's data when the credential row has none", () => {
    const text = `TgtObj=${WINLOGON}\\DefaultPassword Proc=${IMG}\nTgtObj=${RUN}\\Updater Details=C:\\u.exe`;
    expect(redactSecretText(text)).toBe(text);
    const json = `{"ValueName":"DefaultPassword","Type":"REG_SZ"}\n{"ValueName":"Updater","ValueData":"C:\\\\u.exe"}`;
    expect(redactSecretText(json)).toBe(json);
  });

  it("leaves an already-redacted or empty data field alone", () => {
    expect(redactSecretText(velo("DefaultPassword", PH))).toBe(velo("DefaultPassword", PH));
    const empty = `TgtObj=${WINLOGON}\\DefaultPassword Details= Proc=${IMG}`;
    expect(redactSecretText(empty)).toBe(empty);
  });
});

describe("full anonymizer — paired registry credential (#3021)", () => {
  it.each([
    hayabusa(`${WINLOGON}\\DefaultPassword`, VALUE),
    sysmonMessage(`${WINLOGON}\\DefaultPassword`, VALUE),
    velo("DefaultPassword", VALUE),
    regQuery("DefaultPassword", "REG_SZ", VALUE),
  ])("sends no password and restore cannot bring it back: %s", (text) => {
    const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
    const out = anon.apply(text);
    expect(out).not.toContain(VALUE);
    expect(anon.restore(out)).not.toContain(VALUE);
    expect(anon.restore(out)).toContain(PH);
  });
});
