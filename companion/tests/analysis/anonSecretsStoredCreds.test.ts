import { describe, it, expect } from "vitest";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3017 — a registry value that stores a credential, written as `<key path>\<Name>=<value>`, went
// to the AI in clear: after a backslash only an exact secret key name counts, and these names were
// not on the list. Sources: Microsoft Learn "Configure Windows to automate logon" (DefaultPassword
// is stored in plain text) and the CVE-2019-18988 write-up (TeamViewer *PasswordAES values, one
// shared AES key). Every fixture value is built at runtime.
const join = (...parts: string[]) => parts.join("");
const VALUE = join("Hunt", "er2Value77");
const HEX = join("0a1b2c3d", "4e5f6a7b");
const WINLOGON = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const TEAMVIEWER = "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer";

describe("redactSecretText — stored-credential registry values (#3017)", () => {
  it.each([
    [`${WINLOGON}\\DefaultPassword=`, VALUE],
    [`${WINLOGON}\\DefaultPassword = `, VALUE],
    ["Winlogon\\DefaultPassword=", VALUE],
    [`${TEAMVIEWER}\\OptionsPasswordAES=`, HEX],
    [`${TEAMVIEWER}\\SecurityPasswordAES=`, HEX],
    [`${TEAMVIEWER}\\ServerPasswordAES=`, HEX],
    [`${TEAMVIEWER}\\ProxyPasswordAES=`, HEX],
    ["HKLM\\SOFTWARE\\TeamViewer\\OptionsPasswordAES=", HEX],
  ])("hides the value of %s", (key, value) => {
    const out = redactSecretText(`${key}${value}`);
    expect(out).not.toContain(value);
    expect(out).toContain(PH);
  });

  it.each([
    `${WINLOGON}\\AutoAdminLogon=1`,
    `${WINLOGON}\\DefaultUserName=svc_backup`,
    `${WINLOGON}\\DefaultDomainName=CORP`,
    `${WINLOGON}\\AutoLogonCount=3`,
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse=0",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange=1",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MaximumPasswordAge=30",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PasswordManager=C:\\pm.exe",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential=1",
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\AllowDefaultCredentials=1",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds=0",
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredUI\\DisablePasswordReveal=1",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=0",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DefaultPasswordHelper=C:\\x.exe",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ProxyPasswordSync=C:\\y.exe",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisablePasswordReveal=0",
    "HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\default\\Settings\\AllowSignInOptions\\value=1",
    "\\Services\\CredentialManager\\ImagePath=C:\\Windows\\Temp\\cm.exe",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe\\AuditLevel=8",
  ])("keeps the security setting or persistence name %s", (row) => {
    expect(redactSecretText(row)).toBe(row);
  });
});

describe("anonymizer — a Winlogon DefaultPassword value never reaches the AI (#3017)", () => {
  const cats = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true };
  const policy = { enabled: true, redactSecrets: true, maskPublicIps: true, categories: cats } as AnonPolicy;

  it("hides the password one way, and restore keeps the placeholder", () => {
    const anon = createAnonymizer(policy, { hosts: [], accounts: [], internalDomains: [] });
    const out = anon.apply(`${WINLOGON}\\DefaultPassword=${VALUE}`);
    expect(out).not.toContain(VALUE);
    expect(out).toContain(PH);
    expect(anon.restore(out)).not.toContain(VALUE);
  });
});
