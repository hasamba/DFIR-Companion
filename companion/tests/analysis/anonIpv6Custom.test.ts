import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #2950: with the IP category on, IPv6 addresses are set aside before custom entities are matched.
// A custom value that encloses (or partly overlaps) an address must still be hidden as ONE token,
// and an address must never be split. Synthetic values only.

function policy(over: Partial<AnonPolicy> = {}, cats: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: true,
    ...over,
    categories: {
      IP: true,
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
      ...cats,
    },
  };
}
const known = (custom: CustomEntity[]): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom,
});
const mask = (custom: CustomEntity[], text: string, p: AnonPolicy = policy()) => {
  const a = createAnonymizer(p, known(custom));
  const out = a.apply(text);
  return { out, back: a.restore(out), a };
};
const other = (value: string): CustomEntity => ({ value, category: "OTHER" });
const [KEY_HEAD, KEY_TAIL] = ["BEGIN", "END"].map((edge) => `-----${edge} PRIVATE KEY-----`);

describe("custom entity enclosing an IPv6 address (IP category on)", () => {
  it("hides an exact custom value that contains an IPv6 address as one token", () => {
    const { out, back } = mask([other("[fd00:abcd::1]:secret")], "x [fd00:abcd::1]:secret y");
    expect(out).toBe("x ANON_OTHER_1 y");
    expect(back).toBe("x [fd00:abcd::1]:secret y");
  });

  it("hides the whole value every time it appears, and a bare address on its own as IP", () => {
    const { out, back } = mask(
      [other("[fd00:abcd::1]:secret")],
      "a [fd00:abcd::1]:secret b fd00:abcd::1 c [fd00:abcd::1]:secret",
    );
    expect(out).toBe("a ANON_OTHER_1 b ANON_IP_1 c ANON_OTHER_1");
    expect(back).toBe("a [fd00:abcd::1]:secret b fd00:abcd::1 c [fd00:abcd::1]:secret");
  });

  it("hides a value enclosing a public address kept visible on its own (public IPs not masked)", () => {
    const p = policy({ maskPublicIps: false });
    const { out, back } = mask([other("[2a01:4f8::5]:secret")], "x [2a01:4f8::5]:secret y 2a01:4f8::5", p);
    expect(out).toBe("x ANON_OTHER_1 y 2a01:4f8::5");
    expect(back).toBe("x [2a01:4f8::5]:secret y 2a01:4f8::5");
  });

  it("a value that starts inside an address takes the whole address with it", () => {
    const { out, back } = mask([other("abcd::1]:secret")], "x [fd00:abcd::1]:secret y");
    expect(out).toBe("x [ANON_OTHER_1 y");
    expect(back).toBe("x [fd00:abcd::1]:secret y");
  });

  it("a value that partly overlaps an IPv4-mapped address takes the whole address", () => {
    const { out, back } = mask([other("10.0.0.5]:secret")], "x [::ffff:10.0.0.5]:secret y");
    expect(out).toBe("x [ANON_OTHER_1 y");
    expect(back).toBe("x [::ffff:10.0.0.5]:secret y");
  });

  it("an address bridged by two custom values becomes one token", () => {
    const { out, back } = mask([other("host[fd00"), other("7]port")], "a host[fd00::7]port b");
    expect(out).toBe("a ANON_OTHER_1 b");
    expect(back).toBe("a host[fd00::7]port b");
  });

  it("a USER custom value enclosing an address round-trips", () => {
    const custom: CustomEntity[] = [{ value: "svc[fd00::9]", category: "USER" }];
    const { out, back } = mask(custom, "logon svc[fd00::9] ok");
    expect(out).not.toContain("fd00");
    expect(out).not.toContain("svc");
    expect(back).toBe("logon svc[fd00::9] ok");
  });

  it("an IPv4-mapped address alone is one IP token, never split", () => {
    const { out, back } = mask([], "from ::ffff:10.0.0.5 to ::ffff:10.0.0.6");
    expect(out).toBe("from ANON_IP_1 to ANON_IP_2");
    expect(back).toBe("from ::ffff:10.0.0.5 to ::ffff:10.0.0.6");
  });

  it("a custom IPv4 value inside an IPv4-mapped address still leaves the address whole", () => {
    const { out, a } = mask([{ value: "10.0.0.5", category: "HOST" }], "mapped ::ffff:10.0.0.5");
    expect(out).toBe("mapped ANON_IP_1");
    expect(a.discoveries()).toEqual([{ value: "::ffff:10.0.0.5", category: "IP" }]);
  });

  it("a custom value equal to the address keeps the address path", () => {
    const { out } = mask([{ value: "fd00:abcd::1", category: "HOST" }], "x fd00:abcd::1 y");
    expect(out).toBe("x ANON_IP_1 y");
  });

  it("with the IP category off the enclosing value is still hidden whole", () => {
    const p = policy({}, { IP: false });
    const { out, back } = mask([other("[fd00:abcd::1]:secret")], "x [fd00:abcd::1]:secret y", p);
    expect(out).toBe("x ANON_OTHER_1 y");
    expect(back).toBe("x [fd00:abcd::1]:secret y");
  });

  it("a secret inside the enclosing value never becomes a reversible token", () => {
    const p = policy({ redactSecrets: true });
    const { out, a } = mask([other("abc1defgz:fd00::1")], "Bearer abc1defgz:fd00::1 z", p);
    expect(out).not.toContain("abc1defgz");
    expect(out).not.toContain("fd00");
    expect(out).toContain("[REDACTED_SECRET]");
    for (const pair of a.pairs()) expect(pair.value).not.toContain("abc1defgz");
  });

  it("a forged placeholder in the input never invents a value", () => {
    const text = "x IPV6:0 y [fd00:abcd::1]:secret";
    const { out } = mask([other("[fd00:abcd::1]:secret")], text);
    expect(out).toBe("x IPV6:0 y ANON_OTHER_1");
  });

  it("a custom value that touches an address is hidden with it", () => {
    const { out, back } = mask([other("host")], "x host::1 y host z");
    expect(out).toBe("x ANON_OTHER_2 y ANON_OTHER_1 z"); // groups mint after plain custom matches
    expect(back).toBe("x host::1 y host z");
  });

  it("a wildcard pattern enclosing an address hides it whole", () => {
    const custom: CustomEntity[] = [{ value: "*]:secret", category: "OTHER", match: "pattern" }];
    // The star stops at "[" for OTHER, so the match starts inside the brackets; the address goes whole.
    const { out, back } = mask(custom, "x [fd00:abcd::1]:secret y");
    expect(out).toBe("x [ANON_OTHER_1 y");
    expect(back).toBe("x [fd00:abcd::1]:secret y");
  });

  it("an IPv6 range still names the category of an address on its own", () => {
    const custom: CustomEntity[] = [{ value: "fd00:abcd::/32", category: "EXTIP", match: "pattern" }];
    const { out } = mask(custom, "x fd00:abcd::1 y");
    expect(out).toBe("x ANON_EXTIP_1 y");
  });

  it("a chain over two addresses takes the category of its longest custom match", () => {
    const custom: CustomEntity[] = [
      { value: "x[fd00", category: "HOST" },
      { value: "1]mid[fd00", category: "OTHER" },
    ];
    const { out, back } = mask(custom, "a x[fd00::1]mid[fd00::2] b");
    expect(out).toBe("a ANON_OTHER_1] b");
    expect(back).toBe("a x[fd00::1]mid[fd00::2] b");
  });

  it("a qualified USER value still teaches the bare-username pass", () => {
    const custom: CustomEntity[] = [{ value: "jdoe@[fd00::1]", category: "USER" }];
    const p = policy({}, { USER: true });
    const { out, back } = mask(custom, "jdoe logged in as jdoe@[fd00::1]", p);
    expect(out).not.toContain("jdoe");
    expect(out).not.toContain("fd00");
    expect(back).toBe("jdoe logged in as jdoe@[fd00::1]");
  });

  it("a custom value inside a private-key block is redacted one way, never tokenized", () => {
    const p = policy({ redactSecrets: true });
    const text = `${KEY_HEAD}\nabc [fd00::1]:secret def\n${KEY_TAIL} tail`;
    const { out, a } = mask([other("[fd00::1]:secret")], text, p);
    expect(out).toBe("[REDACTED_SECRET] tail");
    expect(a.pairs()).toEqual([]);
    expect(a.discoveries()).toEqual([]);
  });
});
