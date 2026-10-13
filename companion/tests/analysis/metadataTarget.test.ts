import { describe, it, expect } from "vitest";
import {
  isMetadataOrLinkLocalHost,
  metadataTargetError,
  urlHostIsMetadataOrLinkLocal,
} from "../../src/analysis/metadataTarget.js";

// Issue #2146: the one class of address an outbound channel must never reach, whatever the
// operator types — cloud instance-metadata services and link-local space. LAN and loopback stay
// allowed; only this list is refused.
describe("isMetadataOrLinkLocalHost", () => {
  it.each([
    "169.254.169.254",
    "169.254.0.1",
    "169.254.170.2", // ECS task metadata
    "100.100.100.200", // Alibaba, inside CGNAT
    "fd00:ec2::254", // AWS IMDS over IPv6, inside ULA
    "[fd00:ec2::254]",
    "fe80::1",
    "FE80::abcd%eth0",
    "febf::1",
    "::ffff:169.254.169.254",
    "::ffff:a9fe:a9fe",
    "[::ffff:a9fe:a9fe]",
    "::169.254.169.254",
    "::ffff:6464:64c8", // mapped 100.100.100.200
    "64:ff9b::a9fe:a9fe", // NAT64 spelling
    "2852039166", // decimal spelling of 169.254.169.254
    "0xa9fea9fe",
    "0251.0376.0251.0376",
    "169.254.169.254.",
    "metadata.google.internal",
    "METADATA.GOOGLE.INTERNAL.",
    "metadata",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
  ])("refuses %s", (host) => {
    expect(isMetadataOrLinkLocalHost(host)).toBe(true);
  });

  it.each([
    "10.0.0.5",
    "192.168.1.20",
    "172.16.4.4",
    "127.0.0.1",
    "localhost",
    "::1",
    "fd00::1",
    "fd00:ec2::253",
    "100.64.0.1",
    "100.100.100.201",
    "hooks.slack.com",
    "mattermost.lan",
    "metadata.example.com",
    "fec0::1",
    "8.8.8.8",
    "",
  ])("allows %s", (host) => {
    expect(isMetadataOrLinkLocalHost(host)).toBe(false);
  });
});

describe("urlHostIsMetadataOrLinkLocal", () => {
  it("reads the host out of a URL, in any spelling the URL parser accepts", () => {
    expect(urlHostIsMetadataOrLinkLocal("http://169.254.169.254/latest")).toBe(true);
    expect(urlHostIsMetadataOrLinkLocal("http://[::ffff:a9fe:a9fe]/x")).toBe(true);
    expect(urlHostIsMetadataOrLinkLocal("http://2852039166/x")).toBe(true);
    expect(urlHostIsMetadataOrLinkLocal("http://user@metadata.google.internal:80/x")).toBe(true);
    expect(urlHostIsMetadataOrLinkLocal("https://hooks.slack.com/services/x")).toBe(false);
    expect(urlHostIsMetadataOrLinkLocal("http://192.168.1.20:8065/hooks/x")).toBe(false);
  });

  it("is false for an unparsable URL — the caller's own URL check owns that error", () => {
    expect(urlHostIsMetadataOrLinkLocal("not a url")).toBe(false);
  });
});

describe("metadataTargetError", () => {
  it("says plainly why the address is blocked", () => {
    expect(metadataTargetError("169.254.169.254")).toMatch(
      /169\.254\.169\.254.*blocked because it is a cloud-metadata or link-local address/,
    );
  });
});
