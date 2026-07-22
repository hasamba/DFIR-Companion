import { describe, it, expect } from "vitest";
import { createAnonymizer, isInternalIp, SECRET_PLACEHOLDER, deriveKnownEntities, isNoiseDomain, isNoiseAccount, isLocalAiProvider, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function policy(over: Partial<AnonPolicy["categories"]> = {}, redactSecrets = false): AnonPolicy {
  return {
    enabled: true,
    redactSecrets,
    categories: { IP: false, EMAIL: false, USER: false, HOST: false, DOMAIN: false, PATH: false, CMD: false, REG: false, ...over },
  };
}

describe("isInternalIp", () => {
  it("classifies RFC1918 / loopback / link-local as internal", () => {
    expect(isInternalIp("10.0.0.5")).toBe(true);
    expect(isInternalIp("192.168.1.20")).toBe(true);
    expect(isInternalIp("172.16.4.9")).toBe(true);
    expect(isInternalIp("172.31.0.1")).toBe(true);      // last /12 octet
    expect(isInternalIp("127.0.0.1")).toBe(true);
    expect(isInternalIp("169.254.10.1")).toBe(true);
    expect(isInternalIp("100.64.0.1")).toBe(true);      // CGNAT 100.64/10
    expect(isInternalIp("100.127.255.255")).toBe(true); // CGNAT upper bound
  });
  it("classifies public IPs as NOT internal (adversary C2 must survive)", () => {
    expect(isInternalIp("8.8.8.8")).toBe(false);
    expect(isInternalIp("45.61.136.10")).toBe(false);
    expect(isInternalIp("172.32.0.1")).toBe(false);  // just outside 172.16/12
    expect(isInternalIp("100.128.0.1")).toBe(false); // just outside CGNAT 100.64/10
  });
});

describe("anonymizer — internal IPs", () => {
  it("tokenizes internal IPs and preserves public ones; restore reverses", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("victim 10.0.0.5 beaconed to 45.61.136.10");
    expect(out).not.toContain("10.0.0.5");
    expect(out).toContain("45.61.136.10");
    expect(out).toMatch(/ANON_IP_1/);
    expect(a.restore(out)).toBe("victim 10.0.0.5 beaconed to 45.61.136.10");
  });
  it("gives the same token to repeated values (within-call correlation)", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("10.0.0.5 -> 10.0.0.9 ; 10.0.0.5 again");
    const first = out.match(/ANON_IP_\d+/g)!;
    expect(first[0]).toBe(first[2]);   // both 10.0.0.5
    expect(first[0]).not.toBe(first[1]); // 10.0.0.9 differs
  });
  it("restore leaves unknown/hallucinated tokens untouched and is case-insensitive", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    a.apply("10.0.0.5");
    expect(a.restore("see ANON_IP_99")).toBe("see ANON_IP_99");
    expect(a.restore("see anon_ip_1")).toBe("see 10.0.0.5");
  });
  it("restoreDeep walks arrays and object string fields", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    a.apply("10.0.0.5");
    const restored = a.restoreDeep({ items: [{ description: "src ANON_IP_1" }], n: 3 });
    expect(restored).toEqual({ items: [{ description: "src 10.0.0.5" }], n: 3 });
  });
  it("apply is a no-op when the category is disabled", () => {
    const a = createAnonymizer(policy({ IP: false }), NONE);
    expect(a.apply("10.0.0.5")).toBe("10.0.0.5");
  });
});

const ADATUM: KnownEntities = { hosts: [], accounts: [], internalDomains: ["adatumlab", "adatumlab.local"] };

describe("anonymizer — emails", () => {
  it("tokenizes email addresses and restores them", () => {
    const a = createAnonymizer(policy({ EMAIL: true }), NONE);
    const out = a.apply("phish from attacker@evil.com to jdoe@victim.com");
    expect(out).not.toContain("attacker@evil.com");
    expect(out).not.toContain("jdoe@victim.com");
    expect(out).toMatch(/ANON_EMAIL_1/);
    expect(out).toMatch(/ANON_EMAIL_2/);
    expect(a.restore(out)).toBe("phish from attacker@evil.com to jdoe@victim.com");
  });
});

describe("anonymizer — accounts/usernames", () => {
  it("tokenizes NETBIOS DOMAIN\\user", () => {
    const a = createAnonymizer(policy({ USER: true }), ADATUM);
    const out = a.apply("logon by ADATUMLAB\\srv on the DC");
    expect(out).not.toContain("ADATUMLAB\\srv");
    expect(out).toMatch(/ANON_USER_1/);
    expect(a.restore(out)).toBe("logon by ADATUMLAB\\srv on the DC");
  });
  it("tokenizes an internal UPN as USER but leaves a third-party address for EMAIL", () => {
    const a = createAnonymizer(policy({ USER: true, EMAIL: true }), ADATUM);
    const out = a.apply("admin@adatumlab.local phished by attacker@evil.com");
    expect(out).toMatch(/ANON_USER_1/);   // internal UPN
    expect(out).toMatch(/ANON_EMAIL_1/);  // external sender
    expect(out).not.toContain("admin@adatumlab.local");
    expect(out).not.toContain("attacker@evil.com");
    expect(a.restore(out)).toBe("admin@adatumlab.local phished by attacker@evil.com");
  });
  it("does NOT treat a Windows path segment as DOMAIN\\user", () => {
    const a = createAnonymizer(policy({ USER: true }), ADATUM);
    expect(a.apply("path C:\\Users\\srv reading")).toContain("C:\\Users\\srv");
  });
});

describe("anonymizer — user paths", () => {
  it("tokenizes only the username segment, preserving the rest of the path", () => {
    const a = createAnonymizer(policy({ PATH: true }), NONE);
    const out = a.apply("dropped C:\\Users\\srv\\Downloads\\Rubeus.exe");
    expect(out).toContain("\\Downloads\\Rubeus.exe");
    expect(out).not.toMatch(/Users\\srv/);
    expect(out).toMatch(/Users\\ANON_USER_1\\Downloads/);
    expect(a.restore(out)).toBe("dropped C:\\Users\\srv\\Downloads\\Rubeus.exe");
  });
  it("leaves well-known profile names alone", () => {
    const a = createAnonymizer(policy({ PATH: true }), NONE);
    expect(a.apply("C:\\Users\\Public\\x")).toContain("Users\\Public");
    expect(a.apply("C:\\Users\\SYSTEM\\x")).toContain("Users\\SYSTEM");
    expect(a.apply("C:\\Users\\Guest\\x")).toContain("Users\\Guest");
  });
  it("handles POSIX home paths", () => {
    const a = createAnonymizer(policy({ PATH: true }), NONE);
    const out = a.apply("/home/alice/.ssh/id_rsa");
    expect(out).toMatch(/\/home\/ANON_USER_1\/\.ssh/);
  });
});

describe("anonymizer — hosts", () => {
  it("tokenizes known hostnames and FQDNs (case-insensitive), restores them", () => {
    const known: KnownEntities = { hosts: ["dc01.adatumlab.local", "ALCLIENT07"], accounts: [], internalDomains: [] };
    const a = createAnonymizer(policy({ HOST: true }), known);
    const out = a.apply("logon on ALCLIENT07 then to dc01.adatumlab.local");
    expect(out).not.toContain("ALCLIENT07");
    expect(out).not.toContain("dc01.adatumlab.local");
    expect(out).toMatch(/ANON_HOST_/);
    expect(a.restore(out)).toBe("logon on ALCLIENT07 then to dc01.adatumlab.local");
  });
  it("restores hostnames in the text's own casing (round-trip on case mismatch)", () => {
    const known: KnownEntities = { hosts: ["DC01"], accounts: [], internalDomains: [] };
    const a = createAnonymizer(policy({ HOST: true }), known);
    const out = a.apply("logon on dc01");
    expect(out).not.toContain("dc01");
    expect(a.restore(out)).toBe("logon on dc01");
  });
});

describe("anonymizer — internal domains", () => {
  it("tokenizes internal domains but preserves a public/adversary domain", () => {
    const known: KnownEntities = { hosts: [], accounts: [], internalDomains: ["adatumlab.local", "adatumlab"] };
    const a = createAnonymizer(policy({ DOMAIN: true }), known);
    const out = a.apply("auth in ADATUMLAB to adatumlab.local; C2 at evil-c2.com");
    expect(out).toContain("evil-c2.com");        // adversary preserved
    expect(out).not.toMatch(/adatumlab\.local/i);
    expect(out).toMatch(/ANON_DOMAIN_/);
    expect(a.restore(out)).toBe("auth in ADATUMLAB to adatumlab.local; C2 at evil-c2.com");
  });
});

describe("anonymizer — secret redaction (one-way)", () => {
  it("redacts AWS keys, JWTs and key=value credentials", () => {
    const a = createAnonymizer(policy({}, true), NONE);
    const out = a.apply("AKIAIOSFODNN7EXAMPLE and password=Hunter2! token: eyJabc12345.eyJdef67890.sigsigsig9");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).not.toContain("Hunter2!");
    expect(out).toContain(SECRET_PLACEHOLDER);
    expect(out).toContain("password="); // key name kept, value redacted
    expect(a.restore(out)).toBe(out);   // one-way: nothing to restore
  });
  it("PRESERVES a SHA-256 hash (it's an IOC, not a secret)", () => {
    const sha = "2eeba4c80a6f91f06784c0c699512c22ff132233c71af336a423414cc84f574a";
    const a = createAnonymizer(policy({}, true), NONE);
    expect(a.apply(`malware sha256 ${sha}`)).toContain(sha);
  });
  it("redacts a URL userinfo password", () => {
    const a = createAnonymizer(policy({}, true), NONE);
    const out = a.apply("conn https://svc:s3cr3tPW@10.0.0.5/api"); // trufflehog:ignore
    expect(out).not.toContain("s3cr3tPW");
    expect(out).toContain(SECRET_PLACEHOLDER);
  });
  it("redacts an opaque (non-JWT) Bearer token in an Authorization header", () => {
    const a = createAnonymizer(policy({}, true), NONE);
    const out = a.apply("Authorization: Bearer ABCDEF1234567890ABCDEF");
    expect(out).not.toContain("ABCDEF1234567890ABCDEF");
    expect(out).toContain(SECRET_PLACEHOLDER);
  });
});

describe("deriveKnownEntities", () => {
  it("pulls hosts from asset, accounts + internal domains from descriptions and FQDNs", () => {
    const s = emptyState("c1");
    s.forensicTimeline = [
      { id: "e1", timestamp: "", description: "logon ADATUMLAB\\srv", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "dc01.adatumlab.local" },
    ];
    const k = deriveKnownEntities(s);
    expect(k.hosts).toContain("dc01.adatumlab.local");
    expect(k.accounts).toContain("ADATUMLAB\\srv");
    expect(k.internalDomains).toContain("adatumlab");        // NETBIOS domain
    expect(k.internalDomains).toContain("adatumlab.local");  // from the FQDN host
  });
});

describe("isNoiseDomain / isNoiseAccount", () => {
  it("flags Windows principals, registry hives and ATT&CK tactic words as noise", () => {
    for (const d of ["builtin", "authority", "service", "hku", "hklm", "persistence",
      "escalation", "execution", "discovery", "movement", "evasion", "ransomware",
      "defender", "explorer", "vgauth", "access", "impact", "tools", "code", "local"]) {
      expect(isNoiseDomain(d)).toBe(true);
    }
  });
  it("keeps real victim domains — single-label NETBIOS and dotted FQDNs", () => {
    for (const d of ["windomain.local", "acme", "artifacts-main", "evtx-main", "win11", "adatumlab"]) {
      expect(isNoiseDomain(d)).toBe(false);
    }
  });
  it("isNoiseAccount keys off the DOMAIN / UPN-domain half", () => {
    expect(isNoiseAccount("HKU\\Software")).toBe(true);
    expect(isNoiseAccount("BUILTIN\\Administrators")).toBe(true);
    expect(isNoiseAccount("AUTHORITY\\SYSTEM")).toBe(true);   // captured from "NT AUTHORITY\SYSTEM"
    expect(isNoiseAccount("ACME\\jdoe")).toBe(false);
    expect(isNoiseAccount("jdoe@acme.local")).toBe(false);
  });
});

describe("deriveKnownEntities — noise filtering", () => {
  it("drops registry hives, Windows principals and tactic folders; keeps real entities", () => {
    const s = emptyState("c1");
    s.forensicTimeline = [
      { id: "e1", timestamp: "", description: "HKU\\Software autorun; BUILTIN\\Administrators; NT AUTHORITY\\SYSTEM ran from Execution\\evil.exe", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "win11.windomain.local" },
      { id: "e2", timestamp: "", description: "logon ACME\\jdoe", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    ];
    const k = deriveKnownEntities(s);
    expect(k.internalDomains).toContain("acme");             // real NETBIOS domain kept
    expect(k.internalDomains).toContain("windomain.local");  // real FQDN parent kept
    for (const noise of ["hku", "builtin", "authority", "execution"]) {
      expect(k.internalDomains).not.toContain(noise);
    }
    expect(k.accounts).toContain("ACME\\jdoe");
    expect(k.accounts).not.toContain("HKU\\Software");
    expect(k.accounts).not.toContain("BUILTIN\\Administrators");
  });
});

describe("isLocalAiProvider", () => {
  it("treats ollama and localhost base URLs as local", () => {
    expect(isLocalAiProvider("ollama", undefined)).toBe(true);
    expect(isLocalAiProvider("litellm", "http://127.0.0.1:4000/v1")).toBe(true);
    expect(isLocalAiProvider("openrouter", "https://openrouter.ai/api/v1")).toBe(false);
  });
});

describe("anonymizer — custom entities", () => {
  it("tokenizes analyst-added exact-match entities even when that category's detector is OFF", () => {
    const known: KnownEntities = { hosts: [], accounts: [], internalDomains: [], custom: [
      { value: "203.0.113.9", category: "IP" },        // public IP the analyst marks as theirs
      { value: "ProjectFalcon", category: "OTHER" },    // free-form codename
    ]};
    const a = createAnonymizer(policy({ IP: false }), known); // IP pattern detector OFF — custom still applies
    const out = a.apply("beacon from 203.0.113.9 tagged ProjectFalcon");
    expect(out).not.toContain("203.0.113.9");
    expect(out).not.toContain("ProjectFalcon");
    expect(out).toMatch(/ANON_IP_1/);
    expect(out).toMatch(/ANON_OTHER_1/);
    expect(a.restore(out)).toBe("beacon from 203.0.113.9 tagged ProjectFalcon");
  });
  it("no custom entities → unchanged", () => {
    const a = createAnonymizer(policy({}), NONE);
    expect(a.apply("nothing here")).toBe("nothing here");
  });
});

describe("anonymizer — suppression (analyst removed a wrong entity)", () => {
  it("never tokenizes a suppressed value, even when a pattern would match it", () => {
    // config\PowershellInfo.log is a relative path the USER (DOMAIN\user) pattern mis-matches.
    const known: KnownEntities = { ...NONE, suppressed: ["config\\powershellinfo.log"] };
    const a = createAnonymizer(policy({ USER: true }), known);
    const out = a.apply("Out-File config\\PowershellInfo.log by WIN11\\vagrant");
    expect(out).toContain("config\\PowershellInfo.log"); // suppressed → left verbatim
    expect(out).not.toContain("WIN11\\vagrant");          // a real account is still tokenized
    expect(out).toMatch(/ANON_USER_1/);
  });
  it("suppression is case-insensitive", () => {
    const a = createAnonymizer(policy({ HOST: true }), { hosts: ["WIN11"], accounts: [], internalDomains: [], suppressed: ["win11"] });
    expect(a.apply("host WIN11 online")).toBe("host WIN11 online");
  });
});

describe("anonymizer — discoveries()", () => {
  it("reports each tokenized entity with its category, deduped", () => {
    const a = createAnonymizer(policy({ USER: true, IP: true }), NONE);
    a.apply("WIN11\\vagrant on 10.0.0.5");
    a.apply("WIN11\\vagrant again"); // dup → not repeated
    const disc = a.discoveries();
    expect(disc).toContainEqual({ value: "WIN11\\vagrant", category: "USER" });
    expect(disc).toContainEqual({ value: "10.0.0.5", category: "IP" });
    expect(disc.filter((e) => e.value === "WIN11\\vagrant")).toHaveLength(1);
  });
  it("never reports one-way secrets (they are placeholder-redacted, not tokenized)", () => {
    const a = createAnonymizer(policy({}, true), NONE);
    a.apply("password = hunter2trustno1");
    expect(a.discoveries()).toEqual([]);
  });
});

describe("anonymizer — encoded command-line blobs (CMD)", () => {
  const B64 = "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=";
  it("tokenizes the base64 after -enc but keeps the readable command; restore reverses", () => {
    const a = createAnonymizer(policy({ CMD: true }), NONE);
    const out = a.apply(`powershell -enc ${B64}`);
    expect(out).not.toContain(B64);
    expect(out).toMatch(/^powershell -enc ANON_CMD_1$/);
    expect(a.restore(out)).toBe(`powershell -enc ${B64}`);
  });
  it("matches the -e / -ec / -EncodedCommand variants case-insensitively", () => {
    const a = createAnonymizer(policy({ CMD: true }), NONE);
    expect(a.apply(`pwsh -e ${B64}`)).toMatch(/-e ANON_CMD_1/);
    expect(a.apply(`pwsh -ec ${B64}`)).toMatch(/-ec ANON_CMD_1/);
    expect(a.apply(`pwsh -EncodedCommand ${B64}`)).toMatch(/-EncodedCommand ANON_CMD_1/);
  });
  it("tokenizes the blob inside FromBase64String('…')", () => {
    const a = createAnonymizer(policy({ CMD: true }), NONE);
    const out = a.apply(`[Convert]::FromBase64String('${B64}')`);
    expect(out).not.toContain(B64);
    expect(out).toMatch(/FromBase64String\('ANON_CMD_1'\)/);
    expect(a.restore(out)).toBe(`[Convert]::FromBase64String('${B64}')`);
  });
  it("does NOT touch a short flag like -Encoding UTF8", () => {
    const a = createAnonymizer(policy({ CMD: true }), NONE);
    expect(a.apply("Out-File -Encoding UTF8 out.txt")).toBe("Out-File -Encoding UTF8 out.txt");
  });
  it("no-op when CMD is disabled", () => {
    const a = createAnonymizer(policy({ CMD: false }), NONE);
    expect(a.apply(`powershell -enc ${B64}`)).toBe(`powershell -enc ${B64}`);
  });
});

describe("anonymizer — user SIDs (REG)", () => {
  const SID = "S-1-5-21-1004336348-1177238915-682003330-1003";
  it("tokenizes a machine/domain-issued SID and restores it", () => {
    const a = createAnonymizer(policy({ REG: true }), NONE);
    const out = a.apply(`profile ${SID} loaded`);
    expect(out).not.toContain(SID);
    expect(out).toMatch(/profile ANON_REG_1 loaded/);
    expect(a.restore(out)).toBe(`profile ${SID} loaded`);
  });
  it("PRESERVES well-known SIDs (not victim-identifying)", () => {
    const a = createAnonymizer(policy({ REG: true }), NONE);
    expect(a.apply("ran as S-1-5-18")).toContain("S-1-5-18");
    expect(a.apply("group S-1-5-32-544")).toContain("S-1-5-32-544");
  });
  it("no-op when REG is disabled", () => {
    const a = createAnonymizer(policy({ REG: false }), NONE);
    expect(a.apply(`profile ${SID}`)).toBe(`profile ${SID}`);
  });
});
