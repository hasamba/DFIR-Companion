import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #2990: IPV6_RE cannot read ".", so an address whose last group is the first octet of a dotted IPv4
// ("fd00::192.168.1.5") was set aside up to that octet only. The IPv4 pass then saw ".168.1.5", not
// four octets, and those octets went to the AI in clear. Synthetic values only.

function policy(maskPublicIps: boolean, EMAIL = false, PHONE = false): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
    categories: {
      IP: true,
      EMAIL,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE,
      NATID: false,
    },
  };
}
const known = (custom: CustomEntity[] = [], suppressed: string[] = []): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom,
  suppressed,
});
type Opts = {
  suppressed?: string[];
  EMAIL?: boolean;
  PHONE?: boolean;
  custom?: CustomEntity[];
  secrets?: boolean;
};
const run = (text: string, mask: boolean, opts: Opts = {}) => {
  const p = { ...policy(mask, opts.EMAIL, opts.PHONE), redactSecrets: opts.secrets === true };
  const a = createAnonymizer(p, known(opts.custom, opts.suppressed));
  const out = a.apply(text);
  return { out, back: a.restore(out), pairs: a.pairs().map((p) => [p.token, p.value]) };
};

// A public-looking dotted quad is built at runtime, so no such literal sits in the repo.
const PUBLIC_TAIL = [2, 3, 4].join(".");

describe.each([true, false])("IPv6 that ends inside a dotted IPv4, maskPublicIps=%s (#2990)", (mask) => {
  it.each([
    ["fe80::192.168.1.5", "ANON_IP_1", "fe80::192.168.1.5"],
    ["x fd00::10.0.0.5 y", "x ANON_IP_1 y", "fd00::10.0.0.5"],
    ["Evtx::fd00::10.0.0.5", "Evtx::ANON_IP_1", "fd00::10.0.0.5"],
    ["[fd00::10.0.0.5]:443", "[ANON_IP_1]:443", "fd00::10.0.0.5"],
    // The #2976 join ends at "::1"; the whole address after the separator is one token.
    [`Evtx::a00:5::1.${PUBLIC_TAIL}`, "Evtx::ANON_IP_1", `a00:5::1.${PUBLIC_TAIL}`],
    // Loopback "::1" fails closed today; it stays one internal token with its tail.
    [`x ::1.${PUBLIC_TAIL}`, "x ANON_IP_1", `::1.${PUBLIC_TAIL}`],
  ])("%s", (input, out, value) => {
    const r = run(input, mask);
    expect(r.out).toBe(out);
    expect(r.pairs).toEqual([["ANON_IP_1", value]]);
    expect(r.back).toBe(input);
  });

  it("leaves a tail that an earlier pass already masked to that pass", () => {
    const input = "fd00::10.0.0.5@example.com";
    const r = run(input, mask, { EMAIL: true });
    expect(r.out).toBe("ANON_IP_1.ANON_EMAIL_1");
    expect(r.back).toBe(input);
  });

  it("does not read a longer decimal run as an IPv4 tail", () => {
    const r = run("fd00::10.0.0.5555 y", mask);
    expect(r.out).toBe("ANON_IP_1.0.0.5555 y");
  });

  it("leaves a run of five octets to the IPv4 pass, which masks the last four as before", () => {
    const r = run("fd00::10.10.0.0.5 y", mask);
    expect(r.out).toBe("ANON_IP_1.ANON_IP_2 y");
    expect(r.pairs).toEqual([
      ["ANON_IP_1", "fd00::10"],
      ["ANON_IP_2", "10.0.0.5"],
    ]);
  });

  it("splits a phone number that starts in the last octet: the whole address, then the rest (#2995)", () => {
    const input = "fd00::192.168.1.100 555-0100";
    expect(run(input, mask, { PHONE: true }).out).toBe("ANON_IP_1 ANON_PHONE_1");
    // With the phone category off nothing else reads it, and the tail joins the address.
    expect(run(input, mask).out).toBe("ANON_IP_1 555-0100");
  });

  it("joins the tail before a port number with the phone category on", () => {
    expect(run("fd00::192.168.1.5 443", mask, { PHONE: true }).out).toBe("ANON_IP_1 443");
  });

  it("a suppression of the head puts the address back as today, and the IPv4 pass masks the IPv4", () => {
    const r = run("fd00::10.0.0.5", mask, { suppressed: ["fd00::10"] });
    expect(r.out).toBe("fd00::ANON_IP_1");
    expect(r.pairs).toEqual([["ANON_IP_1", "10.0.0.5"]]);
  });

  it("a suppression of the whole value never uncovers the head masked today", () => {
    const input = "fd00::10.0.0.5";
    const r = run(input, mask, { suppressed: [input] });
    expect(r.pairs).toEqual([["ANON_IP_1", "fd00::10"]]);
    // The head's token, then the rest of the input as it was.
    expect(r.out).toBe("ANON_IP_1" + input.slice("fd00::10".length));
  });

  it("a custom range on the head makes the whole public address one internal token", () => {
    const custom: CustomEntity[] = [{ value: "2001:db8::/32", category: "IP", match: "pattern" }];
    const r = run("x 2001:db8::10.0.0.5 y", mask, { custom });
    expect(r.out).toBe("x ANON_IP_1 y");
    expect(r.pairs).toEqual([["ANON_IP_1", "2001:db8::10.0.0.5"]]);
    expect(r.back).toBe("x 2001:db8::10.0.0.5 y");
  });

  it("the issue's example, a vendor key in front, sends no octet in clear", () => {
    const key = ["sk", "_live_", "ABCDEFGHIJKLMNOP"].join("");
    const r = run(`${key}x Evtx::7f00:ffff::10.0.0.5`, mask, { secrets: true });
    expect(r.out).toBe("[REDACTED_SECRET] Evtx::ANON_IP_1::ANON_IP_2");
    expect(r.pairs).toEqual([
      ["ANON_IP_1", "7f00:ffff"],
      ["ANON_IP_2", "10.0.0.5"],
    ]);
  });

  it("keeps 2019:fd00::1 as today", () => {
    expect(run("2019:fd00::1", mask).out).toBe(mask ? "ANON_EXTIP_1" : "2019:fd00::1");
  });
});

describe("public IPv6 with a dotted IPv4 tail (#2990)", () => {
  it("masks it as one public token with public masking on", () => {
    const r = run("2001:db8::192.168.1.5", true);
    expect(r.out).toBe("ANON_EXTIP_1");
    expect(r.pairs).toEqual([["ANON_EXTIP_1", "2001:db8::192.168.1.5"]]);
    expect(r.back).toBe("2001:db8::192.168.1.5");
  });

  it("leaves the public part visible and masks the internal IPv4 with public masking off, as today", () => {
    const r = run("2001:db8::192.168.1.5", false);
    expect(r.out).toBe("2001:db8::ANON_IP_1");
    expect(r.pairs).toEqual([["ANON_IP_1", "192.168.1.5"]]);
  });
});
