import { describe, it, expect } from "vitest";
import { createAnonymizer, isInternalIp, isInternalIpv6, SECRET_PLACEHOLDER, deriveKnownEntities, isNoiseDomain, isNoiseAccount, isLocalAiProvider, isMaskableIpv4, isAnonToken, ALL_TOKEN_CATEGORIES, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function policy(over: Partial<AnonPolicy["categories"]> = {}, redactSecrets = false): AnonPolicy {
  return {
    enabled: true,
    redactSecrets,
    maskPublicIps: true,
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

describe("anonymizer — public IPs", () => {
  it("tokenizes public IPs as EXTIP and internal ones as IP; restore reverses both", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("victim 10.0.0.5 beaconed to 45.61.136.10");
    expect(out).not.toContain("10.0.0.5");
    expect(out).not.toContain("45.61.136.10");
    expect(out).toMatch(/ANON_IP_1/);
    expect(out).toMatch(/ANON_EXTIP_1/);
    expect(a.restore(out)).toBe("victim 10.0.0.5 beaconed to 45.61.136.10");
  });

  it("preserves public IPs when maskPublicIps is off", () => {
    const a = createAnonymizer({ ...policy({ IP: true }), maskPublicIps: false }, NONE);
    const out = a.apply("victim 10.0.0.5 beaconed to 45.61.136.10");
    expect(out).toContain("45.61.136.10");
    expect(out).toMatch(/ANON_IP_1/);
  });

  it("tokenizes public IPv6 as EXTIP", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("callback to 2001:db8::1");
    expect(out).not.toContain("2001:db8::1");
    expect(out).toMatch(/ANON_EXTIP_1/);
    expect(a.restore(out)).toBe("callback to 2001:db8::1");
  });

  it("leaves octet-invalid and reserved dotted quads alone", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("build 999.1.1.1 and group 224.0.0.251 and zero 0.1.2.3");
    expect(out).toContain("999.1.1.1");
    expect(out).toContain("224.0.0.251");
    expect(out).toContain("0.1.2.3");
  });
});

describe("isMaskableIpv4", () => {
  it("accepts routable public addresses", () => {
    expect(isMaskableIpv4("45.61.136.10")).toBe(true);
    expect(isMaskableIpv4("8.8.8.8")).toBe(true);
  });
  it("rejects octets above 255, 0/8, multicast and reserved", () => {
    expect(isMaskableIpv4("999.1.1.1")).toBe(false);
    expect(isMaskableIpv4("1.2.3.999")).toBe(false);
    expect(isMaskableIpv4("0.1.2.3")).toBe(false);
    expect(isMaskableIpv4("224.0.0.251")).toBe(false);
    expect(isMaskableIpv4("255.255.255.255")).toBe(false);
  });
});

describe("token category coverage", () => {
  it("mints and restores a token for every declared category", () => {
    for (const category of ALL_TOKEN_CATEGORIES) {
      const known: KnownEntities = { hosts: [], accounts: [], internalDomains: [], custom: [{ value: "marker", category }] };
      const a = createAnonymizer(policy(), known);
      const out = a.apply("left marker right");
      expect(out, `category ${category} was not tokenized`).toContain(`ANON_${category}_1`);
      expect(a.restore(out), `category ${category} did not restore`).toBe("left marker right");
    }
  });

  it("recognises every category token via isAnonToken", () => {
    for (const category of ALL_TOKEN_CATEGORIES) {
      expect(isAnonToken(`ANON_${category}_7`), `category ${category}`).toBe(true);
    }
    expect(isAnonToken("ANON_NOTACATEGORY_1")).toBe(false);
    expect(isAnonToken("hostname-01")).toBe(false);
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

  // Investigated as part of the veridia-deep-pass false positive (2026-07-22): the model's own synthesis
  // guessed "anonymization-token collision" as the cause of two hostnames being conflated in an IOC list.
  // Traced to assign() in anonymize.ts, which keys the token map by the lowercased REAL value (not by an
  // index alone) — so two distinct real hosts can never be minted the same token within one Anonymizer
  // instance, and every apply() call gets a fresh instance whose response is restored before persisting
  // (pipeline.ts analyzeRestored). No collision was found; this locks in the invariant.
  it("never assigns the same token to two different real hosts", () => {
    const known: KnownEntities = { hosts: ["ws-mktg-01.veridia.io", "ws-dev-01.veridia.io"], accounts: [], internalDomains: [] };
    const a = createAnonymizer(policy({ HOST: true }), known);
    const out = a.apply("seen on ws-mktg-01.veridia.io and separately on ws-dev-01.veridia.io");
    const tokens = out.match(/ANON_HOST_\d+/g) ?? [];
    expect(new Set(tokens).size).toBe(2); // two distinct real hosts → two distinct tokens
    expect(a.restore(out)).toBe("seen on ws-mktg-01.veridia.io and separately on ws-dev-01.veridia.io");
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
  // Every armor a private key realistically arrives in. All fixture bodies below are fake.
  const KEY_BODY = "MIIEowIBAAKCAQEAnotarealkey";
  const keyForms: [string, string][] = [
    ["RSA",                `-----BEGIN RSA PRIVATE KEY-----\n${KEY_BODY}\n-----END RSA PRIVATE KEY-----`],
    ["EC",                 `-----BEGIN EC PRIVATE KEY-----\n${KEY_BODY}\n-----END EC PRIVATE KEY-----`],
    ["DSA",                `-----BEGIN DSA PRIVATE KEY-----\n${KEY_BODY}\n-----END DSA PRIVATE KEY-----`],
    ["OPENSSH",            `-----BEGIN OPENSSH PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----`],
    ["PKCS#8 bare",        `-----BEGIN PRIVATE KEY-----\n${KEY_BODY}\n-----END PRIVATE KEY-----`],
    ["PKCS#8 encrypted",   `-----BEGIN ENCRYPTED PRIVATE KEY-----\n${KEY_BODY}\n-----END ENCRYPTED PRIVATE KEY-----`],
    // PGP's armor ends "PRIVATE KEY BLOCK", not "PRIVATE KEY" — a pattern written for the PEM
    // spelling silently misses every PGP key.
    ["PGP armor",          `-----BEGIN PGP PRIVATE KEY BLOCK-----\n${KEY_BODY}\n-----END PGP PRIVATE KEY BLOCK-----`],
    // SSH2 export uses FOUR dashes and spaces inside the delimiter.
    ["SSH2 export",        `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n${KEY_BODY}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----`],
    ["with Proc-Type",     `-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB\n\n${KEY_BODY}\n-----END RSA PRIVATE KEY-----`],
    ["all on one line",    `-----BEGIN OPENSSH PRIVATE KEY----- ${KEY_BODY} -----END OPENSSH PRIVATE KEY-----`],
  ];
  it.each(keyForms)("redacts a %s private key block", (_name, key) => {
    const a = createAnonymizer(policy({}, true), NONE);
    const out = a.apply(`found key: ${key} in log`);
    expect(out).not.toContain(KEY_BODY);
    expect(out).toContain(SECRET_PLACEHOLDER);
  });

  it("redacts a TRUNCATED key block that never reaches its END delimiter", () => {
    // The case that matters most in a log: the line was cut off. Requiring a matching END marker
    // would redact nothing at all here and ship the whole body to the model in cleartext.
    const a = createAnonymizer(policy({}, true), NONE);
    const out = a.apply(`2026-07-24 ERROR key=-----BEGIN RSA PRIVATE KEY-----\n${KEY_BODY}`);
    expect(out).not.toContain(KEY_BODY);
    expect(out).toContain(SECRET_PLACEHOLDER);
  });

  it("does not let a stray key header swallow the log text that follows it", () => {
    // The truncated-key fallback is length-bounded and stops at the first non-base64 character, so
    // it takes the key material without eating the rest of the artifact.
    const a = createAnonymizer(policy({}, true), NONE);
    const out = a.apply(`-----BEGIN PRIVATE KEY-----\n${KEY_BODY}\n\nchild process: rundll32.exe /s\n`);
    expect(out).not.toContain(KEY_BODY);
    expect(out).toContain("rundll32.exe");
  });

  it("scans a log full of key headers in linear time", () => {
    // A lazy scan with no length bound re-walks the rest of the input for every BEGIN marker, so
    // artifact text full of them costs O(n^2). Over a 4x input, linear is ~4x and quadratic ~16x.
    const a = createAnonymizer(policy({}, true), NONE);
    const bait = (n: number) => "-----BEGIN PRIVATE KEY-----\n.\n".repeat(n);
    const time = (n: number) => { const t = Date.now(); a.apply(bait(n)); return Date.now() - t; };
    time(500);                                       // warm up
    const small = Math.max(time(2000), 1);
    expect(time(8000) / small).toBeLessThan(8);
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

  it("never tokenizes a persisted EXTIP custom entity when maskPublicIps is off (redacted export)", () => {
    // A public IP discovered earlier (e.g. from a screenshot) and persisted into known.custom as
    // category EXTIP must NOT be exact-match-tokenized by the redacted export policy, which always
    // sets maskPublicIps: false so adversary infrastructure stays visible/actionable to the
    // recipient. anonCustom() runs unconditionally in apply(), before any category gate, so this
    // guard has to live there — filtering it only at a caller (e.g. the export builder) would miss
    // every other caller that reuses the same known.custom list.
    const known: KnownEntities = { hosts: [], accounts: [], internalDomains: [], custom: [
      { value: "45.61.136.10", category: "EXTIP" },
    ]};
    const a = createAnonymizer({ ...policy({ IP: true }), maskPublicIps: false }, known);
    const out = a.apply("C2 was 45.61.136.10 and 1.1.1.1");
    expect(out).toBe("C2 was 45.61.136.10 and 1.1.1.1");
  });

  it("still tokenizes a persisted EXTIP custom entity when maskPublicIps is on (AI wire)", () => {
    const known: KnownEntities = { hosts: [], accounts: [], internalDomains: [], custom: [
      { value: "45.61.136.10", category: "EXTIP" },
    ]};
    const a = createAnonymizer(policy({ IP: true }), known); // maskPublicIps: true by default
    const out = a.apply("C2 was 45.61.136.10");
    expect(out).toBe("C2 was ANON_EXTIP_1");
    expect(a.restore(out)).toBe("C2 was 45.61.136.10");
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

describe("anonymizer — IPv6 internal IPs", () => {
  it("tokenizes unique-local IPv6 addresses", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("connected from fd00:db8::1 to fd00:db8::a3c");
    expect(out).not.toContain("fd00:db8::1");
    expect(out).not.toContain("fd00:db8::a3c");
    expect(out).toMatch(/ANON_IP_1/);
    expect(out).toMatch(/ANON_IP_2/);
  });

  it("tokenizes link-local IPv6 addresses", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("gateway fe80::1");
    expect(out).not.toContain("fe80::1");
    expect(out).toMatch(/ANON_IP_1/);
  });

  it("tokenizes IPv4-mapped IPv6 loopback", () => {
    // Asserts the FULL output string, not just toContain/toMatch: the embedded dotted quad
    // "127.0.0.1" must be consumed as part of ONE ipv6-mapped match, not tokenized separately by
    // IPV4_RE first — that ordering bug used to leave a dangling "::ffff:" for IPV6_RE to (mis)match
    // on a later pass, corrupting the just-minted token (e.g. "ANON_EXTIP_1:ANON_IP_1" instead of
    // one clean token). A toContain/toMatch check here would not have caught that regression.
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("mapped ::ffff:127.0.0.1");
    expect(out).toBe("mapped ANON_IP_1");
    expect(a.discoveries()).toEqual([{ value: "::ffff:127.0.0.1", category: "IP" }]);
    expect(a.restore(out)).toBe("mapped ::ffff:127.0.0.1");
  });

  it("tokenizes an IPv4-mapped IPv6 address given in hex-canonical form (not just dotted)", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const out = a.apply("mapped ::ffff:7f00:1"); // hex-canonical form of ::ffff:127.0.0.1
    expect(out).not.toContain("::ffff:7f00:1");
    expect(out).toMatch(/ANON_IP_1/);
  });

  it("restores IPv6 tokens back to real values", () => {
    const a = createAnonymizer(policy({ IP: true }), NONE);
    const orig = "from fd00:db8::1";
    expect(a.restore(a.apply(orig))).toBe(orig);
  });
});

describe("isInternalIpv6", () => {
  it("detects loopback, unique-local, link-local, and IPv4-mapped", () => {
    expect(isInternalIpv6("::1")).toBe(true);
    expect(isInternalIpv6("fd00:db8::1")).toBe(true);
    expect(isInternalIpv6("fc00::1")).toBe(true);
    expect(isInternalIpv6("fe80::1")).toBe(true);
    expect(isInternalIpv6("fe90::1")).toBe(true);
    expect(isInternalIpv6("fea0::1")).toBe(true);
    expect(isInternalIpv6("::ffff:127.0.0.1")).toBe(true);
    expect(isInternalIpv6("::ffff:10.0.0.1")).toBe(true);
  });

  it("preserves public IPv6", () => {
    expect(isInternalIpv6("2001:4860:4860::8888")).toBe(false);
    expect(isInternalIpv6("2606:4700:4700::1111")).toBe(false);
  });

  // A naive IPv4-mapped check that only recognizes the dotted-decimal spelling
  // ("::ffff:127.0.0.1") misses the hex-canonical form of the SAME address ("::ffff:7f00:1") —
  // the form anything that re-serializes an IPv6 address (e.g. new URL(), or some logging
  // libraries) always produces. A victim IPv6 address logged/serialized in that form would
  // otherwise reach the external AI provider unredacted.
  it("detects IPv4-mapped/compatible addresses in their hex-canonical form, not just dotted", () => {
    expect(isInternalIpv6("::ffff:7f00:1")).toBe(true);  // hex form of ::ffff:127.0.0.1
    expect(isInternalIpv6("::ffff:a00:1")).toBe(true);   // hex form of ::ffff:10.0.0.1
    expect(isInternalIpv6("::ffff:808:808")).toBe(false); // hex form of ::ffff:8.8.8.8 — public
  });
});

describe("anonymizer — base64url encoded commands", () => {
  it("tokenizes base64url-encoded PowerShell commands (using - and _)", () => {
    const a = createAnonymizer(policy({ CMD: true }), NONE);
    const b64url = "SQBFAFgAIAAtAGkAcAAgAEgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBt";
    const out = a.apply(`powershell -enc ${b64url}`);
    expect(out).not.toContain(b64url);
    expect(out).toMatch(/ANON_CMD_1/);
    expect(a.restore(out)).toBe(`powershell -enc ${b64url}`);
  });

  it("tokenizes FromBase64String with base64url alphabet", () => {
    const a = createAnonymizer(policy({ CMD: true }), NONE);
    const b64url = "dwBoAG8AYQBtAGkAXwBzAGMAaABlAG0AYQAtAA";
    const out = a.apply(`[System.Convert]::FromBase64String("${b64url}")`);
    expect(out).not.toContain(b64url);
    expect(out).toMatch(/ANON_CMD_1/);
  });
});

describe("anonymizer — /root/ paths", () => {
  it("tokenizes the username in /root/ paths", () => {
    const a = createAnonymizer(policy({ PATH: true }), NONE);
    const out = a.apply("copied from /root/secret/file");
    expect(out).not.toContain("/root/secret");
    expect(out).toMatch(/\/root\/ANON_USER_1/);
  });
});

describe("anonymizer — IDN/Punycode emails", () => {
  it("tokenizes emails with Punycode IDN domains", () => {
    const a = createAnonymizer(policy({ EMAIL: true }), NONE);
    const out = a.apply("contact user@example.xn--caf-dma.com");
    expect(out).not.toContain("user@example.xn--caf-dma.com");
    expect(out).toMatch(/ANON_EMAIL_1/);
  });

  it("still tokenizes standard ASCII emails", () => {
    const a = createAnonymizer(policy({ EMAIL: true }), NONE);
    const out = a.apply("contact user@victim.example.com");
    expect(out).not.toContain("user@victim.example.com");
    expect(out).toMatch(/ANON_EMAIL_1/);
  });
});
