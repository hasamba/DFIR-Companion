import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  findReservableIpv6Spans,
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
    // #2956: a retried internal address followed by a word character fails CLOSED, as an unglued
    // "fd00::1xyz" already does; label + full 8-group address, the colon run running on.
    ["node12:fd00::1xyz", "node12:ANON_IP_1xyz", "fd00::1"],
    ["dc:fd00::1xyz up", "dc:ANON_IP_1xyz up", "fd00::1"],
    ["dc:fd00:1:2:3:4:5:6:7 up", "dc:ANON_IP_1 up", "fd00:1:2:3:4:5:6:7"],
    ["x 0:fe80:1:2:3:4:5:6:7 y", "x 0:ANON_IP_1 y", "fe80:1:2:3:4:5:6:7"],
    ["node12:fd00:1:2:3:4:5:6:7", "node12:ANON_IP_1", "fd00:1:2:3:4:5:6:7"],
    ["x 2019:fd00:1:2:3:4:5:6:7 y", "x 2019:ANON_IP_1 y", "fd00:1:2:3:4:5:6:7"],
    ["x 2019:fe80:1:2:3:4:5:6:7 y", "x 2019:ANON_IP_1 y", "fe80:1:2:3:4:5:6:7"],
    // Recorded tradeoff: an internal-looking address followed by a word fails CLOSED, as the
    // unglued "fd00::Bar" -> "ANON_IP_1r" already does.
    ["node12:fd00::Bar", "node12:ANON_IP_1r", "fd00::Ba"],
    ["dc:fe80::CafeFactory", "dc:ANON_IP_1Factory", "fe80::Cafe"],
    // #2965: an address that opens with "::" after a label, followed by a word, fails CLOSED too.
    ["node12:::1xyz", "node12:ANON_IP_1xyz", "::1"],
    ["x node12:::ffff:10.0.0.5xyz y", "x node12:ANON_IP_1xyz y", "::ffff:10.0.0.5"],
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

  // #2956 records why this stays: "2019:fd00::1" and the real global "2001:fd00::1" cannot be told
  // apart. Masked whole with public masking on; left as written, like any public address, with it off.
  it("a digit label that forms a global address with an internal one is read as one address", () => {
    const { out, back } = run("x 2019:fd00::1 y", mask);
    expect(out).toBe(mask ? "x ANON_EXTIP_1 y" : "x 2019:fd00::1 y");
    expect(back).toBe("x 2019:fd00::1 y");
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
    // #2956: byte runs longer than eight groups, with an fd byte where the retry would look.
    "x 12:fd:00:11:22:33:44:55:66 y",
    "x 12:34:fd:00:11:22:33:44:55:66 y",
    "fp 12:34:56:78:9a:bc:de:f0:fd:00:11",
    "1:2:3:4:5:6:7:8:9",
    "std::os::fd::AsRawFdx",
    "Foo::fd::Bar",
    "node12:fe8::Bar",
    "x node12:fd00::1:y",
    // #2956 records why this stays: after the label, "fd00:1:2:3:4:5:6" is seven groups with no
    // "::", so it is not an address; the whole run is a literal in unallocated space.
    "dc:fd00:1:2:3:4:5:6",
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
    // #2965: a label that is not glued to a word, in front of an in-range address. A short first
    // group is a label, never the front of a real global address; nine groups are never one.
    ["dc:fd00::1 up", "dc:ANON_IP_1 up"],
    ["x dc:fd00::1 y", "x dc:ANON_IP_1 y"],
    ["x dc:fd00:1:2:3:4:5:6:7 y", "x dc:ANON_IP_1 y"],
    ["x 0:fd00:abcd:: y", "x 0:ANON_IP_1 y"],
    ["x 2019:fd00:1:2:3:4:5:6:7 y", "x 2019:ANON_IP_1 y"],
    // #2968: a single colon that closes a phrase ends the address.
    ["x fd00::1: y", "x ANON_IP_1: y"],
    ["x dc:fd00::1: y", "x dc:ANON_IP_1: y"],
    ["peer fd00::1: connection reset", "peer ANON_IP_1: connection reset"],
    ["x fd00::1:", "x ANON_IP_1:"],
    ["(fd00:abcd::1:)", "(ANON_IP_1:)"],
  ])("%s -> %s", (input, expected) => {
    const { out, back } = run(input, true, range, false);
    expect(out).toBe(expected);
    expect(back).toBe(input);
  });

  it.each([
    "x fd00::beefMethod y",
    "x fd00::1:2:3:4:5:6:7:8 y",
    "x node12:fd00::1xyz y",
    "x dc:fd00::1xyz y",
    "x fd:fd00::1xyz y",
    "x fc:fd00::1Method y",
    "x fd0:fd00::1_eth0 y",
    "x dc:fd00:1:2:3:4:5:6:7:8 y",
    "x fd00::1:: y",
    "x dc:fd00::1:y",
  ])("never hides the front of a longer token: %s", (input) => {
    expect(run(input, true, range, false).out).toBe(input);
  });

  it("never hides part of an address outside the range", () => {
    expect(run("x 2001:fd00::1 y", true, range, false).out).toBe("x 2001:fd00::1 y");
    expect(run("x 2001:fd00:1:2:3:4:5:6 y", true, range, false).out).toBe("x 2001:fd00:1:2:3:4:5:6 y");
    // #2968: a closing colon is not a colon run that goes on.
    expect(run("x 2001:fd00::1: y", true, range, false).out).toBe("x 2001:fd00::1: y");
    expect(run("x 2001:fd00:1:2:3:4:5:6: y", true, range, false).out).toBe("x 2001:fd00:1:2:3:4:5:6: y");
  });

  it.each([
    "mac 00:1a:2b:3c:4d:5e seen",
    "at 12:34:56 local",
    "2026-11-27T12:34:56Z logon",
    "std::os::fd::AsRawFd",
    "namespace fd:: {",
    "fp 12:34:fd:00:11:22:33:44:55:66 x",
    "SHA1 ab:cd:fd:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:01",
    "fp fd:3a:11:22:33:44:55:66 seen",
    "dc:fd00:1:2:3:4:5:6",
    // #2968: the same shapes followed by a closing colon.
    "mac 00:1a:2b:3c:4d:5e: seen",
    "at 12:34:56: local",
    "use std::os::fd:: x",
    "fp 12:34:fd:00:11:22:33:44:55:66: x",
    "fp fd:3a:11:22:33:44:55:66: seen",
  ])("leaves %s byte-identical (#2965)", (input) => {
    expect(run(input, true, range, false).out).toBe(input);
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

// #2966: link-local fe80::/10 is a first group of fe80-febf, always four hex digits. A byte run that
// opens with "fe8:" (0x0fe8) is not one. A short fe8-feb label was hidden whole before, so an
// internal address inside it must stay hidden whatever follows it.
describe.each([true, false])("IPv6 link-local first group, maskPublicIps=%s (#2966)", (mask) => {
  it.each([
    "x fe8:3a:11:22:33:44:55:66 y",
    "fe8:1:2:3:4:5:6:7",
    "FEB:3A:11:22:33:44:55:66",
    "x fe9::1 y",
    "fp fea:11:22:33:44:55:66:77 x",
  ])("leaves %s byte-identical", (input) => {
    expect(run(input, mask).out).toBe(input);
  });

  it.each([
    ["x fe80::1 y", "x ANON_IP_1 y", "fe80::1"],
    ["fe80::1%eth0", "ANON_IP_1%eth0", "fe80::1"],
    ["x febf:1:2:3:4:5:6:7 y", "x ANON_IP_1 y", "febf:1:2:3:4:5:6:7"],
    ["fe8:fe80::1Method", "fe8:ANON_IP_1Method", "fe80::1"],
    ["fea:fe80::1_eth0", "fea:ANON_IP_1_eth0", "fe80::1"],
    ["fe8:fe80::1:x", "fe8:ANON_IP_1:x", "fe80::1"],
    ["feb:fd00:1:2:3:4:5:6:7_eth0", "feb:ANON_IP_1_eth0", "fd00:1:2:3:4:5:6:7"],
  ])("still tokenizes the internal address in %s", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs).toEqual([expect.objectContaining({ token: "ANON_IP_1", value, category: "IP" })]);
  });
});

// #2968: with the IP category on, an internal address after a label and before a closing colon
// ("x dc:fd00::1: y") was sent in clear; a plain "x fd00::1: y" was already masked.
describe.each([true, false])("IPv6 before a closing colon, maskPublicIps=%s (#2968)", (mask) => {
  it.each([
    ["x fd00::1: y", "x ANON_IP_1: y", "fd00::1"],
    ["x dc:fd00::1: y", "x dc:ANON_IP_1: y", "fd00::1"],
    ["peer node12:fe80::1: reset", "peer node12:ANON_IP_1: reset", "fe80::1"],
    ["x dc:fd00::1:", "x dc:ANON_IP_1:", "fd00::1"],
  ])("%s -> %s", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs).toEqual([expect.objectContaining({ token: "ANON_IP_1", value, category: "IP" })]);
  });

  it("a public address before a closing colon is masked whole, never split", () => {
    const input = "x 2001:fd00::1: y";
    expect(run(input, mask).out).toBe(mask ? "x ANON_EXTIP_1: y" : input);
  });

  it.each([
    "mac 00:1a:2b:3c:4d:5e: seen",
    "at 12:34:56: local",
    "use std::os::fd:: x",
    "fp fd:3a:11:22:33:44:55:66: x",
  ])("leaves %s byte-identical", (input) => {
    expect(run(input, mask).out).toBe(input);
  });
});

// #2969: an address that ends in "::" followed by a closing colon ("x fd00:abcd::: y") stayed in clear
// on both paths — the terminal-"::" detector branches refused any following ":". ":::" before a space,
// punctuation or the end reads as "::" plus a closing colon; before a word character it is not one.
describe.each([true, false])("IPv6 ending in :: before a closing colon, maskPublicIps=%s (#2969)", (mask) => {
  it.each([
    ["x fd00:abcd::: y", "x ANON_IP_1: y", "fd00:abcd::"],
    ["route fe80::: down", "route ANON_IP_1: down", "fe80::"],
    ["x fd00::: y", "x ANON_IP_1: y", "fd00::"],
    ["x dc:fd00:abcd::: y", "x dc:ANON_IP_1: y", "fd00:abcd::"],
    ["peer node12:fd00:abcd::: down", "peer node12:ANON_IP_1: down", "fd00:abcd::"],
    ["x fd00:abcd:::", "x ANON_IP_1:", "fd00:abcd::"],
    ["(fd00:abcd:::)", "(ANON_IP_1:)", "fd00:abcd::"],
  ])("%s -> %s", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs).toEqual([expect.objectContaining({ token: "ANON_IP_1", value, category: "IP" })]);
  });

  it("a public address ending in :: before a closing colon is masked like one before a space", () => {
    expect(run("x 2001:db8::: y", mask).out).toBe(mask ? "x ANON_EXTIP_1: y" : "x 2001:db8::: y");
  });

  it.each([
    "x fd00:abcd:::y",
    "x fd00:abcd:::: y",
    "use std::: x",
    "use std::os::fd::: x",
    "fd::: x",
    "C::: x",
    "Win2019::: x",
    "Server2016::: x",
    "mac 00:1a:2b:3c:4d:5e::: seen",
    "at 12:34:56::: local",
    "fp fd:3a:11:22:33:44:55:66::: x",
  ])("leaves %s byte-identical", (input) => {
    expect(run(input, mask).out).toBe(input);
  });
});

describe("custom IPv6 range ending in :: before a closing colon, IP category off (#2969)", () => {
  const ranges: CustomEntity[] = [
    { value: "fd00::/16", category: "IP", match: "pattern" },
    { value: "fe80::/16", category: "IP", match: "pattern" },
  ];
  it.each([
    ["x fd00:abcd::: y", "x ANON_IP_1: y"],
    ["route fe80::: down", "route ANON_IP_1: down"],
    ["x dc:fd00:abcd::: y", "x dc:ANON_IP_1: y"],
    ["x fd00:abcd:::", "x ANON_IP_1:"],
  ])("%s -> %s", (input, expected) => {
    const { out, back } = run(input, true, ranges, false);
    expect(out).toBe(expected);
    expect(back).toBe(input);
  });

  it.each(["x fd00:abcd:::y", "x fd00:abcd:::: y", "use std::os::fd::: x", "x 2001:fd00::: y"])(
    "leaves %s byte-identical",
    (input) => {
      expect(run(input, true, ranges, false).out).toBe(input);
    },
  );
});

// #2971: with public masking on, a public address after a short label that runs into a word
// ("dc:2001:db8::1Method") stayed in clear, though the same address at token start is masked
// ("x 2001:db8::1Method"). A match GLUED to a word ("Server2016::Foo", #2959) still never qualifies.
describe("public IPv6 after a short label that runs into a word (#2971)", () => {
  it.each([
    ["dc:2001:db8::1Method", "dc:ANON_EXTIP_1Method", "2001:db8::1"],
    ["fd:2001:db8::1Method", "fd:ANON_EXTIP_1Method", "2001:db8::1"],
    ["fe8:2001:db8::1Method", "fe8:ANON_EXTIP_1Method", "2001:db8::1"],
    ["x dc:2001:db8::1_eth0 y", "x dc:ANON_EXTIP_1_eth0 y", "2001:db8::1"],
    ["x dc:2001:db8::1Method y", "x dc:ANON_EXTIP_1Method y", "2001:db8::1"],
  ])("masks %s when public IPs are masked", (input, expected, value) => {
    const { out, back, pairs } = run(input, true);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs.map((p) => [p.token, p.value, p.category])).toEqual([["ANON_EXTIP_1", value, "EXTIP"]]);
  });

  it.each(["dc:2001:db8::1Method", "fd:2001:db8::1Method", "fe8:2001:db8::1Method"])(
    "leaves %s alone when public IPs are kept, with identical set-aside spans",
    (input) => {
      expect(run(input, false).out).toBe(input);
      expect(findReservableIpv6Spans(input, false)).toEqual([]);
      const start = input.indexOf("2001");
      expect(findReservableIpv6Spans(input, true)).toEqual([{ start, end: start + "2001:db8::1".length }]);
    },
  );

  it.each([
    "Server2016::Foo",
    "Server2016::Foo()",
    "Win2019:: x",
    "x dc:2001:db8::1:y",
    "x dc:2001:db8::1::y",
    "fp dc:20:11:22:33:44:55:66Method",
    "mac 00:1a:2b:3c:4d:5e seen",
    "at 12:34:56 local",
    "fp fd:3a:11:22:33:44:55:66 seen",
  ])("leaves %s byte-identical with public IPs masked", (input) => {
    expect(run(input, true).out).toBe(input);
  });
});

// #2974: with public masking on, a public address after a label GLUED to a word that runs into a word
// ("node12:2001:db8::1Method") stayed in clear; #2971 covered only an unglued label. The outer match is
// ungraded, so #2959's glued PUBLIC match ("Server2016::Foo") still never qualifies.
describe("public IPv6 after a word-glued label that runs into a word (#2974)", () => {
  it.each([
    ["node12:2001:db8::1Method", "node12:ANON_EXTIP_1Method", "2001:db8::1"],
    ["x node12:2001:db8::1_eth0 y", "x node12:ANON_EXTIP_1_eth0 y", "2001:db8::1"],
  ])("masks %s when public IPs are masked", (input, expected, value) => {
    const { out, back, pairs } = run(input, true);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs.map((p) => [p.token, p.value, p.category])).toEqual([["ANON_EXTIP_1", value, "EXTIP"]]);
  });

  it("leaves node12:2001:db8::1Method alone when public IPs are kept, with no set-aside span", () => {
    const input = "node12:2001:db8::1Method";
    expect(run(input, false).out).toBe(input);
    expect(findReservableIpv6Spans(input, false)).toEqual([]);
  });

  it("over-masks a word-glued label before 2016::Foo, as dc:2016::Foo already is (recorded tradeoff)", () => {
    expect(run("node12:2016::Foo", true).out).toBe("node12:ANON_EXTIP_1oo");
    expect(run("node12:2016::Foo", false).out).toBe("node12:2016::Foo");
  });
});

// #2974: a "::" separator glued to a word before an address ("Evtx::2001:db8::1Method", the
// Velociraptor artifact::field shape) cut the address in two: "::2001:db8" (an IPv4-compatible
// spelling of a public IPv4) and "::1" (loopback). The address after the separator is one token.
describe.each([true, false])("IPv6 after a word:: separator, maskPublicIps=%s (#2974)", (mask) => {
  it.each([
    ["Evtx::2001:db8::1Method", "Evtx::ANON_EXTIP_1Method", "2001:db8::1"],
    ["x Evtx::2001:db8::1 y", "x Evtx::ANON_EXTIP_1 y", "2001:db8::1"],
    ["Data::2001:db8::1Method", "Data::ANON_EXTIP_1Method", "2001:db8::1"],
    ["Evtx::2001:db8:: x", "Evtx::ANON_EXTIP_1 x", "2001:db8::"],
    ["Windows.EventLogs.Evtx::2001:db8::5", "Windows.EventLogs.Evtx::ANON_EXTIP_1", "2001:db8::5"],
    ["Evtx::2001:db8::abcd:1Method", "Evtx::ANON_EXTIP_1Method", "2001:db8::abcd:1"],
    ["Evtx::2001:fd00::1Method", "Evtx::ANON_EXTIP_1Method", "2001:fd00::1"],
  ])("%s is one address, masked whole or left whole", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(mask ? expected : input);
    expect(back).toBe(input);
    expect(pairs.map((p) => [p.token, p.value, p.category])).toEqual(
      mask ? [["ANON_EXTIP_1", value, "EXTIP"]] : [],
    );
    const start = input.indexOf(value);
    expect(findReservableIpv6Spans(input, mask)).toEqual([{ start, end: start + value.length }]);
  });

  it.each([
    ["Windows.EventLogs.Evtx::fd00::1", "Windows.EventLogs.Evtx::ANON_IP_1"],
    ["Evtx::fd00::1Method", "Evtx::ANON_IP_1Method"],
    ["Server2016::fd00::1", "Server2016::ANON_IP_1"],
  ])("an internal address after the separator still fails closed: %s", (input, expected) => {
    expect(run(input, mask).out).toBe(expected);
  });

  // Code review: an internal address the retry finds BEFORE the "::" wins over the restart past it.
  it.each([
    ["xfd:fd00::2001:db8::1", "fd00::2001:db8"],
    ["xfe8:fe80::2001:db8::1", "fe80::2001:db8"],
  ])("an internal address before the separator still fails closed: %s", (input, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(back).toBe(input);
    expect(out.startsWith(input.slice(0, input.indexOf(value)) + "ANON_IP_1")).toBe(true);
    expect(pairs[0]).toEqual(expect.objectContaining({ token: "ANON_IP_1", value, category: "IP" }));
  });

  it.each([
    "Server2016::Foo",
    "Server2016::Foo()",
    "Win2019:: x",
    "std::cout",
    "use std::os::fd::AsRawFd",
    "[Convert]::FromBase64String",
    "mac 00:1a:2b:3c:4d:5e seen",
    "at 12:34:56 local",
    "fp fd:3a:11:22:33:44:55:66 seen",
  ])("leaves %s byte-identical", (input) => {
    expect(run(input, mask).out).toBe(input);
  });

  it("2019:fd00::1 keeps today's behavior", () => {
    expect(run("2019:fd00::1", mask).out).toBe(mask ? "ANON_EXTIP_1" : "2019:fd00::1");
  });
});

describe("custom IPv6 range after a word:: separator, IP category off (#2974)", () => {
  const ranges: CustomEntity[] = [{ value: "2001:db8::/32", category: "IP", match: "pattern" }];
  it.each([
    ["Evtx::2001:db8::1 x", "Evtx::ANON_IP_1 x"],
    ["Evtx::2001:db8:: x", "Evtx::ANON_IP_1 x"],
    ["Evtx::2001:db8::1: x", "Evtx::ANON_IP_1: x"],
  ])("%s -> %s", (input, expected) => {
    const { out, back } = run(input, true, ranges, false);
    expect(out).toBe(expected);
    expect(back).toBe(input);
  });

  it.each(["Evtx::2001:db8::1Method", "Evtx::2002:db8::1 x"])("leaves %s byte-identical", (input) => {
    expect(run(input, true, ranges, false).out).toBe(input);
  });
});

// #2976: "Evtx::a00:5::1" (an internal address in the IPv4-compatible spelling "::a00:5", then "::1")
// became two internal tokens and lost the "Evtx::" separator. The address after the separator,
// "a00:5::1", grades as nothing by its value, so it is one token that FAILS CLOSED (ANON_IP) on both
// masking settings: never restored in clear, never uncovered by a suppression of the joined value.
describe.each([true, false])("internal IPv6 after a word:: separator, maskPublicIps=%s (#2976)", (mask) => {
  it.each([
    ["Evtx::a00:5::1", "Evtx::ANON_IP_1", "a00:5::1"],
    ["x Evtx::a00:5::1 y", "x Evtx::ANON_IP_1 y", "a00:5::1"],
    ["Evtx::a00:5::1Method", "Evtx::ANON_IP_1Method", "a00:5::1"],
    ["Windows.EventLogs.Evtx::c0a8:101::1", "Windows.EventLogs.Evtx::ANON_IP_1", "c0a8:101::1"],
  ])("%s keeps the separator and masks one address", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs.map((p) => [p.token, p.value, p.category])).toEqual([["ANON_IP_1", value, "IP"]]);
    const start = input.indexOf(value);
    expect(findReservableIpv6Spans(input, mask)).toEqual([
      { start, end: start + value.length, failClosed: true },
    ]);
  });

  it("a suppression of the joined value never uncovers it", () => {
    const a = createAnonymizer(policy(mask), { ...known(), suppressed: ["a00:5::1"] });
    expect(a.apply("Evtx::a00:5::1")).toBe("Evtx::ANON_IP_1");
  });

  it.each([["xfd00::a00:5::1", "xANON_IP_1ANON_IP_2"]])("leaves %s as it is today", (input, expected) => {
    const { out, back } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
  });

  it("a custom value inside the joined address is masked with it", () => {
    const { out, back } = run("Evtx::a00:5::1", mask, [{ value: "a00:5", category: "HOST" }]);
    expect(out).not.toMatch(/a00|::1$/);
    expect(out.startsWith("Evtx::")).toBe(true);
    expect(back).toBe("Evtx::a00:5::1");
  });

  it("a secret that runs up to the separator leaves none of the address in clear", () => {
    const a = createAnonymizer({ ...policy(mask), redactSecrets: true }, known());
    const out = a.apply(`password=${["hun", "ter2"].join("")}Evtx::a00:5::1 y`);
    expect(out).toContain("[REDACTED_SECRET]");
    expect(out).not.toMatch(/a00|hunter2/);
    expect(out.endsWith(" y")).toBe(true);
  });

  it("a custom value that crosses the separator hides the whole group", () => {
    const { out, back } = run("Evtx::a00:5::1", mask, [{ value: "Evtx::a00", category: "OTHER" }]);
    expect(out).toBe("ANON_OTHER_1");
    expect(back).toBe("Evtx::a00:5::1");
  });
});

describe("custom IPv6 range, IP category off, before Evtx::a00:5::1 (#2976)", () => {
  it("is byte-identical to today", () => {
    const ranges: CustomEntity[] = [{ value: "::a00:0/112", category: "IP", match: "pattern" }];
    expect(run("Evtx::a00:5::1", true, ranges, false).out).toBe("Evtx::a00:5::1");
  });
});

// #2979: more "Evtx::" shapes lost the separator (all failed closed). An internal address after the
// separator alone ("Evtx::a00:5"), one whose tail is not internal ("Evtx::7f00:1::5"), and one after a
// redacted secret that ran up to the separator. The address after "::" is one token that fails closed
// (ANON_IP) on both masking settings. A secret stays one way: the letters it swallowed stay redacted.
describe.each([true, false])("more word:: separator shapes, maskPublicIps=%s (#2979)", (mask) => {
  it.each([
    ["Evtx::a00:5", "Evtx::ANON_IP_1", "a00:5"],
    ["x Evtx::a00:5 y", "x Evtx::ANON_IP_1 y", "a00:5"],
    ["Evtx::0:a00:5", "Evtx::ANON_IP_1", "0:a00:5"],
    ["Evtx::a00:5Method", "Evtx::ANON_IP_1Method", "a00:5"],
    ["Evtx::ffff:10.0.0.5", "Evtx::ANON_IP_1", "ffff:10.0.0.5"],
    ["Evtx::7f00:1::5", "Evtx::ANON_IP_1", "7f00:1::5"],
    ["x Evtx::7f00:1::5 y", "x Evtx::ANON_IP_1 y", "7f00:1::5"],
  ])("%s keeps the separator and masks one address", (input, expected, value) => {
    const { out, back, pairs } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
    expect(pairs.map((p) => [p.token, p.value, p.category])).toEqual([["ANON_IP_1", value, "IP"]]);
    const start = input.indexOf(value);
    const separated = value.includes("::") ? "joined" : "alone";
    expect(findReservableIpv6Spans(input, mask)).toEqual([
      { start, end: start + value.length, failClosed: true, separated },
    ]);
  });

  // A bare "1" minted as a token would be learned by screenshot auto-discovery and mask every "1" later.
  it.each([
    ["Evtx::1", "EvtxANON_IP_1"],
    ["xfd00::a00:5::1", "xANON_IP_1ANON_IP_2"],
  ])("leaves %s as it is today", (input, expected) => {
    const { out, back } = run(input, mask);
    expect(out).toBe(expected);
    expect(back).toBe(input);
  });

  // Code review: only an address alone was one address before; a joined one was two.
  it("a suppression of a joined address with the separator in front never uncovers it", () => {
    for (const [input, value] of [
      ["Evtx::7f00:1::5", "::7f00:1::5"],
      ["Evtx::a00:5::1", "::a00:5::1"],
    ]) {
      const a = createAnonymizer(policy(mask), { ...known(), suppressed: [value] });
      expect(a.apply(input)).toBe("Evtx::ANON_IP_1");
    }
    const key = ["sk", "_live_", "ABCDEFGHIJKLMNOP"].join("");
    const a = createAnonymizer(
      { ...policy(mask), redactSecrets: true },
      { ...known(), suppressed: ["::a00:5::1"] },
    );
    expect(a.apply(`x ${key}Evtx::a00:5::1 y`)).toBe("x [REDACTED_SECRET]::ANON_IP_1 y");
  });

  it("a suppression of the value after the separator never uncovers the address", () => {
    for (const input of ["Evtx::a00:5", "Evtx::7f00:1::5"]) {
      const a = createAnonymizer(policy(mask), { ...known(), suppressed: [input.slice(6)] });
      expect(a.apply(input)).toBe("Evtx::ANON_IP_1");
    }
  });

  // The analyst left "::a00:5" visible before the split; it stays visible, so later passes read the same
  // text: "10.0.0.5" right after it is still masked by the IPv4 pass, not cut in two.
  it("a suppression of the address as it was read before still leaves it visible", () => {
    const a = createAnonymizer(policy(mask), { ...known(), suppressed: ["::abc:10"] });
    expect(a.apply("Evtx::abc:10.0.0.5")).toBe("Evtx::abc:ANON_IP_1");
  });

  // Code review: a #2976 join keeps its extent when custom values group with what touches it.
  it("an email before a #2976 join keeps its own token", () => {
    const a = createAnonymizer(
      { ...policy(mask), categories: { ...policy(mask).categories, EMAIL: true } },
      known([{ value: "a00:5::1 tail", category: "HOST" }]),
    );
    expect(a.apply("foo@example.com::a00:5::1 tail")).toBe("ANON_EMAIL_1::ANON_HOST_1");
  });

  // The analyst left "::1" visible: a custom value that touches the join must not group it away.
  it("a custom value before a #2976 join does not group an address a suppression left in clear", () => {
    const a = createAnonymizer(policy(mask), {
      ...known([{ value: "x:", category: "HOST" }]),
      suppressed: ["::1"],
    });
    expect(a.apply("x::a00:5::1::1")).toBe("ANON_HOST_1:ANON_IP_1::1");
  });

  it.each([
    ["Evtx::7f00:1::10.0.0.5", "Evtx::ANON_IP_1::ANON_IP_2"],
    ["Evtx::7f00:1::4111 1111 1111 1111", "Evtx::ANON_IP_1::4111 1111 1111 1111"],
    ["Evtx::7f00:1::5, y", "Evtx::ANON_IP_1::5, y"],
  ])("does not join %s where the join would cut what a later pass reads", (input, expected) => {
    expect(run(input, mask).out).toBe(expected);
    expect(findReservableIpv6Spans(input, mask)).toEqual([
      { start: 6, end: 12, failClosed: true, separated: "alone" },
    ]);
  });

  it("a custom value inside the address is masked with it", () => {
    const { out, back } = run("Evtx::7f00:1::5", mask, [{ value: "7f00", category: "HOST" }]);
    expect(out).not.toMatch(/7f00|::5$/);
    expect(out.startsWith("Evtx::")).toBe(true);
    expect(back).toBe("Evtx::7f00:1::5");
  });

  it("the first call's discoveries keep the address masked on the next call", () => {
    const first = createAnonymizer(policy(mask), known());
    first.apply("Evtx::a00:5 and Evtx::7f00:1::5");
    const next = createAnonymizer(policy(mask), known(first.discoveries()));
    const out = next.apply("Evtx::a00:5 and Evtx::7f00:1::5");
    expect(out).toBe("Evtx::ANON_IP_1 and Evtx::ANON_IP_2");
  });

  // A vendor key whose letters stop at ":" swallows "Evtx" too; the address after it is the IPv6 pass's.
  it.each([
    ["Evtx::a00:5::1", "a00:5::1"],
    ["Evtx::a00:5", "a00:5"],
    ["Evtx::7f00:1::5", "7f00:1::5"],
  ])("a secret that runs up to the separator in %s stays one way", (tail, value) => {
    const key = ["sk", "_live_", "ABCDEFGHIJKLMNOP"].join("");
    const a = createAnonymizer({ ...policy(mask), redactSecrets: true }, known());
    const out = a.apply(`x ${key}${tail} y`);
    expect(out).toBe("x [REDACTED_SECRET]::ANON_IP_1 y");
    expect(a.pairs().map((p) => [p.token, p.value, p.category])).toEqual([["ANON_IP_1", value, "IP"]]);
    expect(a.restore(out)).toBe("x [REDACTED_SECRET]::" + value + " y");
  });

  it("2019:fd00::1 still goes in clear only with public masking off", () => {
    expect(run("x 2019:fd00::1 y", mask).out).toBe(mask ? "x ANON_EXTIP_1 y" : "x 2019:fd00::1 y");
  });
});

describe("custom IPv6 range, IP category off, before the #2979 shapes", () => {
  it.each([
    ["Evtx::a00:5", "EvtxANON_IP_1"],
    ["Evtx::7f00:1::5", "Evtx::7f00:1::5"],
  ])("%s is masked as it is today", (input, expected) => {
    const ranges: CustomEntity[] = [{ value: "::a00:0/112", category: "IP", match: "pattern" }];
    expect(run(input, true, ranges, false).out).toBe(expected);
  });
});
