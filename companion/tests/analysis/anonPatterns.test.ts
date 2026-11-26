import { describe, it, expect } from "vitest";
import { expectLinearScan } from "../helpers/growth.js";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";
import {
  isPatternShaped,
  patternMatchesWhole,
  validatePatternEntity,
} from "../../src/analysis/anonPatterns.js";
import { sanitizeCustomEntities } from "../../src/analysis/anonEntities.js";

// #2946: custom entities accept wildcard patterns (any category) and CIDR ranges (IP / EXTIP).

function policy(over: Partial<AnonPolicy["categories"]> = {}, maskPublicIps = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
    categories: {
      IP: false,
      EMAIL: false,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE: false,
      NATID: false,
      ...over,
    },
  };
}
const pat = (value: string, category: CustomEntity["category"]): CustomEntity => ({
  value,
  category,
  match: "pattern",
});
const known = (custom: CustomEntity[], extra: Partial<KnownEntities> = {}): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom,
  ...extra,
});
const mask = (custom: CustomEntity[], text: string, p: AnonPolicy = policy()) => {
  const a = createAnonymizer(p, known(custom));
  const out = a.apply(text);
  return { out, back: a.restore(out), a };
};

describe("validatePatternEntity", () => {
  it.each([
    ["prod-*", "HOST"],
    ["*-dev", "HOST"],
    ["svc_*", "USER"],
    ["*\\finance\\*", "PATH"],
    ["*.corp.example", "DOMAIN"],
    ["prod-*-web", "HOST"],
    ["10.20.0.0/16", "IP"],
    ["10.20.3.4/32", "IP"],
    ["fd00:abcd::/32", "IP"],
    ["203.0.113.0/24", "EXTIP"],
  ] as const)("accepts %s (%s)", (value, category) => {
    expect(validatePatternEntity(pat(value, category))).toBeNull();
  });

  it.each([
    ["*", "HOST"],
    ["**", "HOST"],
    ["*.*", "DOMAIN"],
    ["a*", "HOST"],
    ["*ab*", "HOST"],
    ["pr*od*web", "HOST"],
    ["ANON_*", "OTHER"],
    ["10.20.*", "IP"],
    ["10.20.0.0/40", "IP"],
    ["10.20.0/16", "IP"],
    ["10.0.0.0/7", "IP"],
    ["fd00::/8", "IP"],
    ["10.20.0.0", "IP"],
    ["prod", "HOST"],
  ] as const)("refuses %s (%s) with a reason", (value, category) => {
    const reason = validatePatternEntity(pat(value, category));
    expect(typeof reason).toBe("string");
    expect(reason!.length).toBeGreaterThan(10);
  });

  it("isPatternShaped: `*` anywhere, or a `/` in an IP category", () => {
    expect(isPatternShaped("prod-*", "HOST")).toBe(true);
    expect(isPatternShaped("10.20.0.0/16", "IP")).toBe(true);
    expect(isPatternShaped("10.20.0/99", "EXTIP")).toBe(true);
    expect(isPatternShaped("C:/Users/x", "PATH")).toBe(false);
    expect(isPatternShaped("dc01", "HOST")).toBe(false);
  });
});

describe("sanitizeCustomEntities keeps the pattern flag only when it is exactly 'pattern'", () => {
  it("keeps match:'pattern' and drops anything else", () => {
    expect(
      sanitizeCustomEntities([
        { value: "prod-*", category: "HOST", match: "pattern" },
        { value: "x*y", category: "HOST", match: "regex" },
        { value: "dc01", category: "HOST" },
      ]),
    ).toEqual([
      { value: "prod-*", category: "HOST", match: "pattern" },
      { value: "x*y", category: "HOST" },
      { value: "dc01", category: "HOST" },
    ]);
  });
});

describe("wildcard patterns in the anonymizer", () => {
  it("gives each matched host its own token and restores both", () => {
    const { out, back } = mask([pat("prod-*", "HOST")], "login from prod-web01 to prod-db02 ok");
    expect(out).toBe("login from ANON_HOST_1 to ANON_HOST_2 ok");
    expect(back).toBe("login from prod-web01 to prod-db02 ok");
  });

  it("never fires inside a longer word", () => {
    const { out } = mask([pat("prod-*", "HOST")], "myprod-web01 and xprod-db");
    expect(out).toBe("myprod-web01 and xprod-db");
  });

  it("matches a leading star and an interior star", () => {
    expect(mask([pat("*-dev", "HOST")], "on app-dev now").out).toBe("on ANON_HOST_1 now");
    expect(mask([pat("prod-*-web", "HOST")], "x prod-eu-web y").out).toBe("x ANON_HOST_1 y");
  });

  it("does not take the sentence-ending dot or cross whitespace", () => {
    const { out, back } = mask([pat("prod-*", "HOST")], "seen on prod-web01. Then prod-db02 later");
    expect(out).toBe("seen on ANON_HOST_1. Then ANON_HOST_2 later");
    expect(back).toBe("seen on prod-web01. Then prod-db02 later");
  });

  it("USER pattern covers service accounts", () => {
    const { out } = mask([pat("svc_*", "USER")], "svc_backup logged on");
    expect(out).toBe("ANON_USER_1 logged on");
  });

  it("PATH pattern takes the whole path up to whitespace", () => {
    const { out, back } = mask([pat("*\\finance\\*", "PATH")], "opened C:\\Share\\finance\\q1.xlsx today");
    expect(out).toBe("opened ANON_PATH_1 today");
    expect(back).toBe("opened C:\\Share\\finance\\q1.xlsx today");
  });

  it("DOMAIN pattern masks every host under the suffix", () => {
    const { out } = mask([pat("*.corp.example", "DOMAIN")], "dc01.corp.example, mail.corp.example");
    expect(out).toBe("ANON_DOMAIN_1, ANON_DOMAIN_2");
  });

  it("an exact value and a pattern never nest tokens (one pass over the original text)", () => {
    const { out, back } = mask(
      [{ value: "web01", category: "OTHER" }, pat("prod-*", "HOST")],
      "prod-web01 and web01",
    );
    expect(out).toBe("ANON_HOST_1 and ANON_OTHER_1");
    expect(back).toBe("prod-web01 and web01");
  });

  it("a legacy entity with `*` but no pattern flag stays a literal (Presidio values like ****1234)", () => {
    const { out } = mask([{ value: "****1234", category: "OTHER" }], "card ****1234 and 99991234");
    expect(out).toBe("card ANON_OTHER_1 and 99991234");
  });

  it("a pattern beats a suppressed value (the stricter choice wins)", () => {
    const a = createAnonymizer(
      policy({ USER: true }),
      known([pat("svc_*", "USER")], { suppressed: ["svc_backup"] }),
    );
    expect(a.apply("svc_backup ran")).toBe("ANON_USER_1 ran");
  });

  it("an invalid stored pattern still masks its literal spelling", () => {
    const { out } = mask([pat("*", "HOST")], "a * b");
    expect(out).toBe("a ANON_HOST_1 b");
  });

  it("stays linear on a long run with no whitespace", () => {
    const a = createAnonymizer(policy(), known([pat("*-dev", "HOST"), pat("prod-*-web", "HOST")]));
    expectLinearScan("wildcard scan", (n) => a.apply("A".repeat(n * 100)), 500);
  });
});

describe("CIDR ranges in the anonymizer", () => {
  it("masks every IPv4 address inside the range, each with its own token", () => {
    const { out, back } = mask([pat("10.20.0.0/16", "IP")], "10.20.3.4 -> 10.20.9.9, not 10.21.0.1");
    expect(out).toBe("ANON_IP_1 -> ANON_IP_2, not 10.21.0.1");
    expect(back).toBe("10.20.3.4 -> 10.20.9.9, not 10.21.0.1");
  });

  it("masks IPv6 addresses in a prefix, including a terminal ::, brackets and a zone", () => {
    const { out } = mask(
      [pat("fd00:abcd::/32", "IP")],
      "a fd00:abcd:: b [fd00:abcd::1]:443 c fd00:abcd::2%eth0 d fd00:abce::1",
    );
    expect(out).toBe("a ANON_IP_1 b [ANON_IP_2]:443 c ANON_IP_3%eth0 d fd00:abce::1");
  });

  it("works when the IP category is off, and with it on", () => {
    expect(mask([pat("fd00:abcd::/32", "IP")], "x fd00:abcd::5", policy({ IP: true })).out).toBe(
      "x ANON_IP_1",
    );
    expect(mask([pat("10.20.0.0/16", "IP")], "x 10.20.0.5", policy({ IP: true })).out).toBe("x ANON_IP_1");
  });

  it("an IPv4-mapped IPv6 address inside an IPv4 range is masked", () => {
    expect(mask([pat("10.20.0.0/16", "IP")], "from ::ffff:10.20.1.1 ok").out).toBe("from ANON_IP_1 ok");
  });

  it("an EXTIP range is not applied when public-IP masking is off", () => {
    expect(mask([pat("203.0.113.0/24", "EXTIP")], "c2 203.0.113.7", policy({}, false)).out).toBe(
      "c2 203.0.113.7",
    );
    expect(mask([pat("203.0.113.0/24", "EXTIP")], "c2 203.0.113.7").out).toBe("c2 ANON_EXTIP_1");
  });
});

describe("patternMatchesWhole", () => {
  it("tests a whole value against a pattern or a range", () => {
    expect(patternMatchesWhole(pat("prod-*", "HOST"), "PROD-web01")).toBe(true);
    expect(patternMatchesWhole(pat("prod-*", "HOST"), "myprod-web01")).toBe(false);
    expect(patternMatchesWhole(pat("10.20.0.0/16", "IP"), "10.20.1.1")).toBe(true);
    expect(patternMatchesWhole(pat("10.20.0.0/16", "IP"), "10.21.1.1")).toBe(false);
    expect(patternMatchesWhole(pat("fd00:abcd::/32", "IP"), "fd00:abcd::9")).toBe(true);
  });
});

describe("Codex review regressions (#2946)", () => {
  it("merges crossing matches so no part of either value stays in clear", () => {
    const { out, back } = mask(
      [pat("*.corp.example", "DOMAIN"), { value: "corp.example/sensitive-path-long", category: "OTHER" }],
      "see payroll.corp.example/sensitive-path-long now",
    );
    expect(out).toBe("see ANON_OTHER_1 now");
    expect(back).toBe("see payroll.corp.example/sensitive-path-long now");
  });

  it("an IPv6 range does not stop a longer custom value that encloses the address", () => {
    const custom = [
      pat("fd00:abcd::/32", "IP"),
      { value: "[fd00:abcd::1]:secret", category: "OTHER" as const },
    ];
    expect(mask(custom, "x [fd00:abcd::1]:secret y").out).toBe("x ANON_OTHER_1 y");
  });

  it("an IPv6 range still applies with the IP category on, including a terminal ::", () => {
    expect(mask([pat("fd00:abcd::/32", "IP")], "a fd00:abcd:: b", policy({ IP: true })).out).toBe(
      "a ANON_IP_1 b",
    );
  });

  it("whole-value matching stays linear on a crafted value", () => {
    const covers = (n: number) => patternMatchesWhole(pat("*a*aab*", "OTHER"), "a".repeat(n * 50));
    expectLinearScan("pattern whole-value match", covers, 40);
  });

  it("whole-value matching agrees with masking", () => {
    expect(patternMatchesWhole(pat("prod-*-web", "HOST"), "prod-a-web")).toBe(true);
    // Masking stops at the first "-web", so the tail would stay visible: not covered.
    expect(patternMatchesWhole(pat("prod-*-web", "HOST"), "prod-a-web-b-web")).toBe(false);
  });
});
