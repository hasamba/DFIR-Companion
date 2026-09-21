// The analyst's "asset for this import" (#1496): what is accepted as a host name, how a drop-folder
// path declares one, and how the guard answers a bad value.
import { describe, it, expect } from "vitest";
import { parseAssetHost, assetHostFromDropRelpath } from "../../src/analysis/assetHost.js";

describe("parseAssetHost — a host name, or a reason it is not", () => {
  it.each([
    ["DESKTOP-16OJFO6", "DESKTOP-16OJFO6"],
    ["  ws01.example.com  ", "ws01.example.com"],
    ["ws01.example.com.", "ws01.example.com"], // a root dot is stripped
    ["WIN_SRV01", "WIN_SRV01"], // NetBIOS allows an underscore inside a label
    ["a1", "a1"],
  ])("accepts %j", (input, host) => {
    expect(parseAssetHost(input)).toEqual({ ok: true, host });
  });

  it("an absent or blank value is no declaration at all", () => {
    expect(parseAssetHost(undefined)).toEqual({ ok: true, host: "" });
    expect(parseAssetHost("")).toEqual({ ok: true, host: "" });
    expect(parseAssetHost("   ")).toEqual({ ok: true, host: "" });
    expect(parseAssetHost(42)).toEqual({ ok: true, host: "" });
  });

  it.each([
    [".host", "empty label"],
    ["host..example", "empty label"],
    ["-host", "start or end"],
    ["host-", "start or end"],
    ["_host", "start or end"],
    ["ho st", "character"],
    ["host\\share", "character"],
    ["a".repeat(64), "63"],
    [`${"a".repeat(63)}.`.repeat(4) + "a", "253"],
  ])("refuses %j with a reason", (input, reason) => {
    const r = parseAssetHost(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain(reason);
  });
});

describe("assetHostFromDropRelpath — a drop subfolder named asset=<HOST>", () => {
  it("reads the host from the first path segment, on either separator", () => {
    expect(assetHostFromDropRelpath("asset=DESKTOP-16OJFO6/Windows.EventLogs.Chainsaw.json")).toBe(
      "DESKTOP-16OJFO6",
    );
    expect(assetHostFromDropRelpath("ASSET=ws01.example.com\\sub\\Security.evtx")).toBe("ws01.example.com");
  });

  it("is empty for an ordinary path, a deeper asset= folder, or an invalid name", () => {
    expect(assetHostFromDropRelpath("Windows.EventLogs.Chainsaw.json")).toBe("");
    expect(assetHostFromDropRelpath("tool/asset=HOST/x.json")).toBe("");
    expect(assetHostFromDropRelpath("asset=-bad/x.json")).toBe("");
    expect(assetHostFromDropRelpath("asset=/x.json")).toBe("");
  });
});
