import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3049: the account pattern read at most 20 ASCII characters of the user half of DOMAIN\user. A longer
// user went out in clear whole, a cut one left its tail in clear (`.local`, a SID's last numbers), and a
// non-ASCII letter ended the user or let a bogus qualifier start after it (`dave élan\x` read `lan\x`).

const LOCAL = ["corp", "local"].join("."); // built at runtime: a synthetic internal domain
const KNOWN: KnownEntities = { hosts: [], accounts: [], internalDomains: [LOCAL] };
const USERS = ["C:", "Users", ""].join("\\"); // a profile-path prefix, built at runtime
const SID = ["S", "1", "5", "21", "12", "5", "5", "1001"].join("-"); // a synthetic domain SID
function policy(): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps: true,
    categories: { ...on, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}

function fresh(text: string, known: KnownEntities = KNOWN) {
  const a = createAnonymizer(policy(), known);
  const out = a.apply(text);
  return { out, a, restored: a.restore(out), saved: a.discoveries() };
}
/** The text again, on a call seeded with what a first call over `first` saved. */
function seeded(first: string, text: string) {
  const f = createAnonymizer(policy(), KNOWN);
  f.apply(first);
  return fresh(text, { ...KNOWN, custom: f.discoveries() });
}

describe("the user half of DOMAIN\\user is masked whole (#3049)", () => {
  it("masks a user half longer than 20 characters whole", () => {
    const user = "averyveryverylongusername01";
    const r = fresh(`logon CORP\\${user} ok`);
    expect(r.out).toBe("logon ANON_DOMAIN_1\\ANON_USER_1 ok");
    expect(r.restored).toBe(`logon CORP\\${user} ok`);
  });

  it("keeps a dotted tail inside the user half", () => {
    const r = fresh(`logon CORP\\${["jdoe-alpha", LOCAL].join(".")} ok`);
    expect(r.out).toBe("logon ANON_DOMAIN_1\\ANON_USER_1 ok");
    expect(r.out).not.toContain("local");
  });

  it("masks a user half that holds non-ASCII letters whole", () => {
    for (const user of ["Øyvind", "kåre", "bob.élan", "zoë"]) {
      const r = fresh(`logon CORP\\${user} ran`);
      expect(r.out).toBe("logon ANON_DOMAIN_1\\ANON_USER_1 ran");
      expect(r.restored).toBe(`logon CORP\\${user} ran`);
    }
  });

  it("stops before a SID glued to the end and gives the SID its own token", () => {
    const r = fresh(`logon CORP\\jdoe-${SID} ok`);
    expect(r.out).toBe("logon ANON_DOMAIN_1\\ANON_USER_1-ANON_REG_1 ok");
    expect(r.saved).toContainEqual({ value: "jdoe", category: "USER" });
    expect(r.saved).toContainEqual({ value: SID, category: "REG" });
    expect(r.restored).toBe(`logon CORP\\jdoe-${SID} ok`);
  });

  it("leaves no SID numbers in clear behind a user glued to the SID", () => {
    const r = fresh(`Name\\xjd${SID}`);
    expect(r.out).not.toMatch(/\d{3}/);
    expect(r.restored).toBe(`Name\\xjd${SID}`);
  });

  it("masks a SID glued to text", () => {
    const r = fresh(`sid ${SID}bob end`);
    expect(r.out).toBe("sid ANON_REG_1bob end");
  });
});

describe("a profile name with a non-ASCII letter is not cut into a bogus qualifier (#3049)", () => {
  it("reads the whole word before the backslash as the qualifier", () => {
    const text = `open ${USERS}dave zoë\\xeve`;
    const r = fresh(text);
    expect(r.out).toBe(`open ${USERS}ANON_USER_2\\ANON_USER_1`);
    expect(r.saved).toContainEqual({ value: "zoë", category: "DOMAIN" });
    expect(r.saved.map((e) => e.value)).not.toContain("e");
    expect(r.restored).toBe(text);
  });

  it("never saves the part after the letter as an account (`lan\\xeve`)", () => {
    const text = `open ${USERS}dave élan\\xeve`;
    const r = fresh(text);
    expect(r.out).toBe(`open ${USERS}ANON_USER_2`);
    expect(r.saved.map((e) => e.value)).not.toContain("lan\\xeve");
    expect(r.restored).toBe(text);
  });

  it("reads a qualifier cut behind a non-ASCII letter back to the start of its word", () => {
    const text = `${USERS}Øyvind.carol\\xb-02`;
    const r = fresh(text);
    expect(r.out).toBe(`${USERS}ANON_USER_2\\ANON_USER_1`);
    expect(r.saved).toContainEqual({ value: "Øyvind.carol", category: "DOMAIN" });
  });

  it("keeps the component after the profile name masked on a seeded call", () => {
    const text = `${USERS}dave élan\\x5-bobbob-carol`;
    const r = seeded(`first ${text}`, text);
    expect(r.out).not.toContain("bobbob");
    expect(r.restored).toBe(text);
  });

  it("still masks a profile name with a space and an ASCII one", () => {
    expect(fresh(`open ${USERS}John Smith\\Documents`).out).toBe(`open ${USERS}ANON_USER_2\\ANON_USER_1`);
    expect(fresh(`open ${USERS}zoë\\xa`).out).toBe(`open ${USERS}ANON_USER_1\\xa`);
  });
});

describe("glued user halves stay masked on a seeded call (#3049)", () => {
  it("masks an e-mail local part glued in front of a DOMAIN qualifier", () => {
    const text = `ab@${LOCAL}CORP\\jdoe x`;
    const r = fresh(text);
    expect(r.out).toBe("ANON_USER_1@ANON_DOMAIN_1\\ANON_USER_2 x");
    expect(r.restored).toBe(text);
  });

  it("still saves the shorter user the old pattern read, so a later call masks it", () => {
    const r = fresh("logon CORP\\bobélan-x ok");
    expect(r.out).toBe("logon ANON_DOMAIN_1\\ANON_USER_1 ok");
    expect(r.saved).toContainEqual({ value: "bob", category: "USER" });
  });

  it("masks the user behind a saved e-mail glued to a DOMAIN qualifier", () => {
    const mail = ["ann", LOCAL].join("@");
    const text = `${mail}-CORP\\007 x`;
    const r = seeded(`first ${text}`, text);
    expect(r.out).not.toContain("007");
    expect(r.restored).toBe(text);
  });

  it("masks a SID glued to text behind an account on a seeded call", () => {
    const text = `CORP\\007-${SID}b-02.lab`;
    const r = seeded(`first ${text}`, text);
    expect(r.out).not.toMatch(/1001|007/);
    expect(r.restored).toBe(text);
  });
});

describe("the unbounded user half stays linear (#3049)", () => {
  it("reads a 100k-character user run and a long backslash chain quickly", () => {
    const t0 = Date.now();
    fresh(`CORP\\${"a".repeat(100_000)}\\x`);
    fresh("a\\".repeat(50_000));
    fresh(`CORP\\${"é".repeat(100_000)} x`);
    expect(Date.now() - t0).toBeLessThan(4000);
  });
});
