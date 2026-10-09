import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #2073: an admin-share path such as \\DC-QA-01\C$ was matched by the DOMAIN\user pass starting
// mid-way through the host name, so it came out as \\DC-ANON_DOMAIN_n\ANON_USER_n — the "DC-"
// prefix of the real host leaked, and share names (ADMIN$, IPC$) were learned as usernames.

const KNOWN: KnownEntities = { hosts: ["dc-qa-01.sub.example"], accounts: [], internalDomains: [] };

function policy(over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: false,
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
      ...over,
    },
  };
}

describe("UNC admin-share paths (#2073)", () => {
  it("tokenizes the whole server name of \\\\DC-QA-01\\C$ as a HOST and round-trips", () => {
    const a = createAnonymizer(policy(), KNOWN);
    const input = "\\\\DC-QA-01\\C$";
    const out = a.apply(input);
    expect(out).toMatch(/^\\\\ANON_HOST_\d+\\C\$$/);
    expect(out).not.toContain("DC-");
    expect(out).not.toContain("ANON_DOMAIN");
    expect(out).not.toContain("ANON_USER");
    expect(a.restore(out)).toBe(input);
  });

  it("does not learn a share name as a username or a host fragment as a domain", () => {
    const a = createAnonymizer(policy(), KNOWN);
    const out = a.apply("\\\\DC-QA-01\\ADMIN$ then ADMIN$ later");
    expect(out).toMatch(/^\\\\ANON_HOST_\d+\\ADMIN\$ then ADMIN\$ later$/);
    const found = a.discoveries();
    expect(found.some((d) => d.value.toLowerCase() === "admin$")).toBe(false);
    expect(found.some((d) => d.value.toLowerCase() === "qa-01")).toBe(false);
  });

  it("tokenizes an unknown single-label UNC server", () => {
    const a = createAnonymizer(policy(), KNOWN);
    const out = a.apply("net use \\\\WS-FIN-07\\IPC$");
    expect(out).toMatch(/^net use \\\\ANON_HOST_\d+\\IPC\$$/);
    expect(out).not.toContain("WS-");
  });

  it("gives the same HOST token to a UNC server and the same name in prose", () => {
    const a = createAnonymizer(policy(), { ...KNOWN, hosts: [...KNOWN.hosts, "FS01"] });
    const out = a.apply("\\\\FS01\\C$ and FS01");
    const tok = /ANON_HOST_\d+/.exec(out)?.[0];
    expect(tok).toBeDefined();
    expect(out).toBe(`\\\\${tok}\\C$ and ${tok}`);
  });

  it.each([
    "\\\\tsclient\\C\\x",
    "\\\\localhost\\C$",
    "\\\\wsl\\Ubuntu",
    "\\\\?\\C:\\Windows\\a.exe",
    "\\\\.\\pipe\\x",
    "\\\\attacker.example\\webdav",
    "\\\\12345\\share",
  ])("leaves %s unchanged", (input) => {
    const a = createAnonymizer(policy(), KNOWN);
    expect(a.apply(input)).toBe(input);
  });

  it("leaves a dotted IP server to the IP pass", () => {
    const a = createAnonymizer(policy(), KNOWN);
    const out = a.apply("\\\\10.0.0.5\\C$");
    expect(out).not.toContain("ANON_HOST");
    expect(out).not.toContain("ANON_USER");
    expect(out.endsWith("\\C$")).toBe(true);
  });

  it.each(["ACME-CORP\\jdoe", "WIN-ABC\\svc_x"])("still tokenizes the account %s", (input) => {
    const a = createAnonymizer(policy(), KNOWN);
    expect(a.apply(input)).toMatch(/^ANON_DOMAIN_\d+\\ANON_USER_\d+$/);
  });

  it("leaves the path verbatim with HOST off and USER on", () => {
    const a = createAnonymizer(policy({ HOST: false }), KNOWN);
    expect(a.apply("\\\\DC-QA-01\\C$")).toBe("\\\\DC-QA-01\\C$");
  });
});
