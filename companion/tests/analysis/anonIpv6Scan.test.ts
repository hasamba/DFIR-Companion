import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #2953: with the IP category on, two IPv6 spellings reached the AI in clear — an address that
// ends in "::", and an address joined to a word by a colon (a false match swallowed it). Every
// widening of the IPv6 detector also needs negative tests for forensic text. Synthetic values only.

function policy(maskPublicIps: boolean, IP = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
    categories: {
      IP,
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
    },
  };
}
const known = (custom: CustomEntity[] = []): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom,
});
const run = (text: string, maskPublicIps = true, custom: CustomEntity[] = [], IP = true) => {
  const a = createAnonymizer(policy(maskPublicIps, IP), known(custom));
  const out = a.apply(text);
  return { out, back: a.restore(out), pairs: a.pairs() };
};

describe.each([true, false])("IPv6 set-aside, maskPublicIps=%s (#2953)", (mask) => {
  it.each([
    ["x fd00:abcd:: y", "x ANON_IP_1 y", "fd00:abcd::"],
    ["[fd00:abcd::]:443", "[ANON_IP_1]:443", "fd00:abcd::"],
    ["route fd00:abcd::/64 via", "route ANON_IP_1/64 via", "fd00:abcd::"],
    ["iface fe80:: up", "iface ANON_IP_1 up", "fe80::"],
    ["x node12:fd00::1 y", "x node12:ANON_IP_1 y", "fd00::1"],
    ["Windows.EventLogs.Evtx::fd00::1", "Windows.EventLogs.Evtx::ANON_IP_1", "fd00::1"],
    ["win2019:fd00::1", "win2019:ANON_IP_1", "fd00::1"],
    ["dc:fd00::1 up", "dc:ANON_IP_1 up", "fd00::1"],
    ["peer node12:fd00:abcd:: down", "peer node12:ANON_IP_1 down", "fd00:abcd::"],
    ["srvé:fd00::1", "srvé:ANON_IP_1", "fd00::1"],
    ["x ::ffff:10.0.0.5 y", "x ANON_IP_1 y", "::ffff:10.0.0.5"],
    ["x node12:::ffff:a00:5 y", "x node12:ANON_IP_1 y", "::ffff:a00:5"],
    ["win2019:::ffff:a00:5", "win2019:ANON_IP_1", "::ffff:a00:5"],
    ["x node12:::1 y", "x node12:ANON_IP_1 y", "::1"],
    ["said \u201cfd00:abcd::\u201d", "said \u201cANON_IP_1\u201d", "fd00:abcd::"],
    ["fd00:abcd::\u00a0up", "ANON_IP_1\u00a0up", "fd00:abcd::"],
    ["fd00:abcd::\u200f", "ANON_IP_1\u200f", "fd00:abcd::"],
    ["fd00:abcd::\uff0c x", "ANON_IP_1\uff0c x", "fd00:abcd::"],
    ["node12:fd00:abcd::\u201d", "node12:ANON_IP_1\u201d", "fd00:abcd::"],
  ])("%s -> %s", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs).toEqual([expect.objectContaining({ token: "ANON_IP_1", value, category: "IP" })]);
  });

  it("a public address glued to a word is still masked whole when public IPs are masked", () => {
    const { out, back } = run("x node12:2001:db8::1 y", mask);
    expect(out).toBe(mask ? "x node12:ANON_EXTIP_1 y" : "x node12:2001:db8::1 y");
    expect(back).toBe("x node12:2001:db8::1 y");
  });

  it("a real global address that contains an fd00 group is never split", () => {
    const { out } = run("x 2001:fd00::1 y", mask);
    expect(out).toBe(mask ? "x ANON_EXTIP_1 y" : "x 2001:fd00::1 y");
  });

  it("a public prefix ending in :: is masked when public IPs are masked", () => {
    expect(run("x 2001:db8:: y", mask).out).toBe(mask ? "x ANON_EXTIP_1 y" : "x 2001:db8:: y");
  });

  it.each([
    "mac 00:1a:2b:3c:4d:5e seen",
    "at 12:34:56 local",
    "2026-11-27T12:34:56Z logon",
    "C::Foo",
    "C:\\Windows\\System32\\svchost.exe",
    "a::b",
    "sep :: sep",
    "Artifact::Windows.Sys.Users",
    "[Convert]::FromBase64String(",
    "std::cout << x",
    "WIN11::admin",
    "std::os::fd::AsRawFd",
    "std::os::fd::OwnedFd",
    "use std::os::fd:: x",
    "namespace fd:: {",
    "fd:: x",
    "fc::é",
    "fd00:abcd::é",
    "Win2019:: x",
    "Server2022:: x",
    "Interface:: x",
    "fp 12:34:fd:56:78:9a:bc:de:f0:11:22:33",
    "SHA1 ab:cd:fd:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:01",
    "MD5:16:27:ac:fd:00:11:22:33:44:55:66:77:88:99:aa:bb",
    "eui 02:1a:2b:fd:fe:3c:4d:5e",
    "node12:fd00::1xyz",
  ])("leaves %s byte-identical", (input) => {
    expect(run(input, mask).out).toBe(input);
  });
});

describe("custom IPv6 range with the IP category off (#2953)", () => {
  const range: CustomEntity[] = [{ value: "fd00::/16", category: "IP", match: "pattern" }];
  it.each([
    ["x node12:fd00::1 y", "x node12:ANON_IP_1 y"],
    ["Windows.EventLogs.Evtx::fd00::1", "Windows.EventLogs.Evtx::ANON_IP_1"],
    ["x fd00:abcd:: y", "x ANON_IP_1 y"],
    ["x fd00::1 y", "x ANON_IP_1 y"],
  ])("%s -> %s", (input, expected) => {
    const { out, back } = run(input, true, range, false);
    expect(out).toBe(expected);
    expect(back).toBe(input);
  });

  it.each(["x fd00::beefMethod y", "x fd00::1:2:3:4:5:6:7:8 y", "x node12:fd00::1xyz y"])(
    "never hides the front of a longer token: %s",
    (input) => {
      expect(run(input, true, range, false).out).toBe(input);
    },
  );

  it("never hides part of an address outside the range", () => {
    expect(run("x 2001:fd00::1 y", true, range, false).out).toBe("x 2001:fd00::1 y");
  });
});

// #2959: a colon-separated byte run that starts with "fd:" or "fc:" was read as a unique-local
// address (only the first characters were checked), and "Server2016::Foo" lost "2016::F" to a
// public-address token. Narrowing those must never let a real internal address through.
describe.each([true, false])("IPv6 false positives, maskPublicIps=%s (#2959)", (mask) => {
  it.each([
    "fp fd:3a:11:22:33:44:55:66 seen",
    "fd:3a:11:22:33:44:55:66",
    "FD:3A:11:22:33:44:55:66",
    "fc:3a:11:22:33:44:55:66",
    "fp fd:3a:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:01 x",
    "fp 11:22:33:44:55:66:77:88:fd:3a:11:22:33:44:55:66 x",
    "x fd0::1 y",
    "Server2016::Foo",
    "Server2016::Foo()",
  ])("leaves %s byte-identical", (input) => {
    expect(run(input, mask).out).toBe(input);
  });

  it.each([
    ["x fd00::1 y", "x ANON_IP_1 y", "fd00::1"],
    ["x fc00:1::5 y", "x ANON_IP_1 y", "fc00:1::5"],
    ["x FD00::1 y", "x ANON_IP_1 y", "FD00::1"],
    ["x fdff:1:2:3:4:5:6:7 y", "x ANON_IP_1 y", "fdff:1:2:3:4:5:6:7"],
    ["x fd:fd00::1 y", "x fd:ANON_IP_1 y", "fd00::1"],
    ["x fc:fc00:1::5 y", "x fc:ANON_IP_1 y", "fc00:1::5"],
    ["x fd:fd00:1:2:3:4:5:6:7 y", "x fd:ANON_IP_1 y", "fd00:1:2:3:4:5:6:7"],
    ["Server2016::fd00::1", "Server2016::ANON_IP_1", "fd00::1"],
    ["fd:fd00::1Method", "fd:ANON_IP_1Method", "fd00::1"],
    ["fd:fd00:1:2:3:4:5:6:7_eth0", "fd:ANON_IP_1_eth0", "fd00:1:2:3:4:5:6:7"],
    ["fd:fe80::1_eth0", "fd:ANON_IP_1_eth0", "fe80::1"],
    ["fd:fd00::1:", "fd:ANON_IP_1:", "fd00::1"],
    ["xfc:fd00::1Method", "xfc:ANON_IP_1Method", "fd00::1"],
    ["fd0:fd00::1Method", "fd0:ANON_IP_1Method", "fd00::1"],
    ["fc0:fe80::1_eth0", "fc0:ANON_IP_1_eth0", "fe80::1"],
    ["fd0:::1Method", "fd0:ANON_IP_1Method", "::1"],
    ["fd0:64:ff9b::a00:1_eth0", "fd0:ANON_IP_1_eth0", "64:ff9b::a00:1"],
  ])("still tokenizes the internal address in %s", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs).toEqual([expect.objectContaining({ token: "ANON_IP_1", value, category: "IP" })]);
  });

  it("a public address between underscores is still masked when public IPs are masked", () => {
    const input = "dump_2001:db8::1_eth0";
    expect(run(input, mask).out).toBe(mask ? "dump_ANON_EXTIP_1_eth0" : input);
  });
});
