import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  deriveKnownEntities,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import { collectUsernames, isGuardedUsername, usernameRegExp } from "../../src/analysis/anonUsernames.js";
import { extractAccounts } from "../../src/analysis/assetGraph.js";
import { redactedExportPolicy } from "../../src/analysis/redactedExport.js";
import { createSupportRedactor } from "../../src/analysis/supportLogRedact.js";
import { buildRedactedExport, type RedactedExportDeps } from "../../src/reports/redactedExportBuilder.js";
import { DEFAULT_REDACTED_EXPORT_OPTIONS } from "../../src/analysis/redactedExport.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1780: a bare victim username ("jdoe") survived redaction, and one person got two tokens
// (CORP\jdoe → ANON_USER_1, /home/jdoe → ANON_USER_2).

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function userPolicy(): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: false,
    categories: {
      IP: false,
      EMAIL: true,
      USER: true,
      HOST: true,
      DOMAIN: true,
      PATH: true,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE: false,
      NATID: false,
    },
  };
}

function event(id: string, description: string) {
  return {
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description,
    severity: "High" as const,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function caseState(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline = [
    event("e1", "logon CORP\\jdoe on WS01"),
    event("e2", "read /home/msmith/.ssh/id_rsa"),
  ];
  return s;
}

describe("anonymizer — one token per person (#1780)", () => {
  it("gives CORP\\jdoe, /home/jdoe, jdoe@corp.example and bare jdoe the same USER token", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, internalDomains: ["corp.example", "corp"] });
    const out = a.apply("CORP\\jdoe; /home/jdoe/x; jdoe@corp.example; then JDOE ran scp");
    expect(out).toBe(
      "ANON_DOMAIN_1\\ANON_USER_1; /home/ANON_USER_1/x; ANON_USER_1@ANON_DOMAIN_2; then ANON_USER_1 ran scp",
    );
    expect(out.toLowerCase()).not.toContain("jdoe");
  });

  it("round-trips through restore()", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, internalDomains: ["corp"] });
    const text = "logon by CORP\\jdoe from /home/jdoe";
    expect(a.restore(a.apply(text))).toBe(text);
  });

  it("replaces a bare name seen in an EARLIER apply() call's qualified form", () => {
    const a = createAnonymizer(userPolicy(), NONE);
    const first = a.apply("C:\\Users\\jdoe\\Desktop");
    const second = a.apply("the account jdoe then logged in");
    expect(first).toBe("C:\\Users\\ANON_USER_1\\Desktop");
    expect(second).toBe("the account ANON_USER_1 then logged in");
  });

  it("replaces a bare name named by known.usernames before any qualified form appears", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, usernames: ["jdoe"] });
    expect(a.apply("user jdoe logged in via ssh")).toBe("user ANON_USER_1 logged in via ssh");
  });

  it("never replaces a guarded common word globally, but still tokenizes its qualified form", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, usernames: ["admin", "test", "root"] });
    const out = a.apply("CORP\\admin opened the admin share for a test run as root");
    expect(out).toMatch(/^ANON_DOMAIN_1\\ANON_USER_1 opened the admin share for a test run as root$/);
  });

  it("does not match inside a longer word or inside a token", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, usernames: ["jdoe"] });
    expect(a.apply("jdoes xjdoe jdoe_backup")).toBe("jdoes xjdoe jdoe_backup");
  });

  it("never rewrites a label of an untokenized URL or host — adversary IOCs stay intact", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, usernames: ["jdoe", "john.smith"] });
    const out = a.apply("jdoe hit jdoe.evil.example and https://evil.example/u/jdoe/p; john.smith too");
    expect(out).toBe("ANON_USER_1 hit jdoe.evil.example and https://evil.example/u/jdoe/p; ANON_USER_2 too");
  });

  it("lets a known host claim its span first", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, hosts: ["jdoe-laptop"], usernames: ["jdoe"] });
    expect(a.apply("jdoe on jdoe-laptop")).toBe("ANON_USER_1 on ANON_HOST_1");
  });

  it("tokenizes the qualifier as HOST when it is a known machine", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, hosts: ["WIN11"] });
    expect(a.apply("WIN11\\alice on WIN11")).toBe("ANON_HOST_1\\ANON_USER_1 on ANON_HOST_1");
  });

  it("leaves a suppressed account verbatim — the bare pass does not reach inside it", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, usernames: ["jdoe"], suppressed: ["corp\\jdoe"] });
    expect(a.apply("CORP\\jdoe; and jdoe alone")).toBe("CORP\\jdoe; and ANON_USER_1 alone");
  });

  it("leaves a suppressed bare username verbatim everywhere", () => {
    const a = createAnonymizer(userPolicy(), { ...NONE, usernames: ["jdoe"], suppressed: ["jdoe"] });
    expect(a.apply("jdoe from /home/jdoe")).toBe("jdoe from /home/jdoe");
  });

  it("does not run the bare pass when the USER category is off", () => {
    const p = userPolicy();
    p.categories.USER = false;
    const a = createAnonymizer(p, { ...NONE, usernames: ["jdoe"] });
    expect(a.apply("jdoe ran scp")).toBe("jdoe ran scp");
  });

  it("keeps a tactic folder or Folder\\file.exe as one whole token and learns nothing from it", () => {
    const a = createAnonymizer(userPolicy(), NONE);
    const out = a.apply("Execution\\evil.exe then Sysinternals\\procdump.exe; evil.exe and procdump.exe ran");
    expect(out).toBe("ANON_USER_1 then ANON_USER_2; evil.exe and procdump.exe ran");
    expect(a.discoveries().map((d) => d.category)).toEqual(["USER", "USER"]);
  });

  it("routes a persisted USER custom entity through the same token", () => {
    const a = createAnonymizer(userPolicy(), {
      ...NONE,
      custom: [{ value: "CORP\\jdoe", category: "USER" }],
    });
    expect(a.apply("CORP\\jdoe and jdoe")).toBe("ANON_DOMAIN_1\\ANON_USER_1 and ANON_USER_1");
  });
});

describe("username vocabulary", () => {
  it("guards common words, short names and numbers", () => {
    for (const w of ["admin", "Administrator", "test", "user", "guest", "system", "root", "al", "1234"]) {
      expect(isGuardedUsername(w)).toBe(true);
    }
    expect(isGuardedUsername("jdoe")).toBe(false);
  });

  it("collects the user half of NETBIOS accounts, internal UPNs and profile paths — not external emails", () => {
    const names = collectUsernames({
      texts: [
        "CORP\\jdoe and BUILTIN\\Administrators",
        "msmith@corp.example sent mail to attacker@evil.example",
        "C:\\Users\\kpatel\\AppData and C:\\Users\\Public",
      ],
      accountsOf: extractAccounts,
      internalDomains: ["corp.example"],
    });
    expect(names.sort()).toEqual(["jdoe", "kpatel", "msmith"]);
  });

  it("builds no regex for an empty or all-guarded list", () => {
    expect(usernameRegExp([])).toBeNull();
    expect(usernameRegExp(["admin", "root"])).toBeNull();
  });

  it("deriveKnownEntities lists usernames from the timeline, findings and IOCs", () => {
    const s = caseState();
    s.findings = [
      {
        id: "f1",
        title: "Staging by C:\\Users\\rlee",
        description: "x",
        severity: "High",
      } as unknown as InvestigationState["findings"][number],
    ];
    const k = deriveKnownEntities(s);
    expect(k.usernames).toEqual(expect.arrayContaining(["jdoe", "msmith", "rlee"]));
  });
});

describe("every redaction surface replaces the bare name (#1780)", () => {
  it("AI anonymization built from deriveKnownEntities", () => {
    const a = createAnonymizer(userPolicy(), deriveKnownEntities(caseState()));
    const out = a.apply("The account msmith (and jdoe) went by scp.");
    expect(out).not.toMatch(/msmith|jdoe/i);
    expect(out).toMatch(/ANON_USER_\d+/);
  });

  it("the redacted case package", async () => {
    const d: RedactedExportDeps = {
      store: {} as RedactedExportDeps["store"],
      stateStore: { load: async () => caseState() } as unknown as RedactedExportDeps["stateStore"],
      customEntities: { load: async () => [] } as unknown as RedactedExportDeps["customEntities"],
      discoveredEntities: {
        load: async () => ({ discovered: [], suppressed: [] }),
      } as unknown as RedactedExportDeps["discoveredEntities"],
      ocrRunner: { recognize: async () => [] },
      reportWriter: {
        redactedReportContents: async (_c: string, redact: (s: string) => string) => ({
          markdown: redact("The account jdoe (CORP\\jdoe) went by scp. msmith too."),
          html: redact("<p>jdoe</p>"),
          findingsCsv: redact("f,jdoe"),
          iocsCsv: "i",
          timelineCsv: "t",
          forensicTimelineCsv: "ft",
          stateJson: redact('{"who":"jdoe"}'),
        }),
      },
      listScreenshots: async () => [],
      readScreenshot: async () => Buffer.alloc(0),
    };
    const { zip } = await buildRedactedExport(d, "c1", DEFAULT_REDACTED_EXPORT_OPTIONS);
    const md = readZip(zip)
      .find((e) => e.path === "report/report.md")!
      .data.toString("utf8");
    expect(md).not.toMatch(/jdoe|msmith/i);
    // One person, one token: the bare and the qualified mention share ANON_USER_n.
    const bare = /The account (ANON_USER_\d+) \(ANON_DOMAIN_\d+\\(ANON_USER_\d+)\)/.exec(md);
    expect(bare?.[1]).toBe(bare?.[2]);
    for (const e of readZip(zip)) expect(e.data.toString("utf8")).not.toMatch(/jdoe/i);
    expect(redactedExportPolicy().categories.USER).toBe(true);
  });

  it("the support bundle redactor, with a host that contains a username", () => {
    const r = createSupportRedactor({
      cases: [{ caseId: "c1" }],
      fileNames: [],
      secrets: [],
      roots: [],
      known: {
        hosts: ["WKS-JDOE"],
        accounts: ["CORP\\jdoe"],
        usernames: ["msmith"],
        internalDomains: ["corp"],
      },
    });
    const out = r.redactText("CORP\\jdoe on WKS-JDOE; jdoe and msmith and admin");
    expect(out).not.toMatch(/jdoe|msmith/i);
    expect(out).toContain("admin");
    const users = out.match(/ANON_USER_\d+/g) ?? [];
    // CORP\jdoe and the bare jdoe share a token; msmith has its own.
    expect(new Set(users).size).toBe(2);
    expect(out).toMatch(/ANON_HOST_\d+/);
  });
});
