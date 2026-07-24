import { describe, it, expect } from "vitest";
import { validateBaseUrl, isLoopbackHost } from "../../src/providers/urlValidation.js";

describe("isLoopbackHost", () => {
  it("recognizes localhost and 127.x.x.x", () => {
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("127.0.0.1:8080")).toBe(true);
    expect(isLoopbackHost("127.1.2.3:443")).toBe(true);
  });

  it("recognizes IPv6 loopback", () => {
    expect(isLoopbackHost("::1")).toBe(true);
    expect(isLoopbackHost("[::1]")).toBe(true);
    expect(isLoopbackHost("[::1]:8080")).toBe(true);
  });

  it("recognizes 0.0.0.0", () => {
    expect(isLoopbackHost("0.0.0.0")).toBe(true);
    expect(isLoopbackHost("0.0.0.0:11434")).toBe(true);
  });

  it("rejects non-loopback hosts", () => {
    expect(isLoopbackHost("api.openai.com")).toBe(false);
    expect(isLoopbackHost("api.openai.com:443")).toBe(false);
    expect(isLoopbackHost("192.168.1.1")).toBe(false);
    expect(isLoopbackHost("10.0.0.1:8080")).toBe(false);
  });
});

describe("validateBaseUrl", () => {
  it("accepts https URLs to any host", () => {
    expect(validateBaseUrl("https://api.openai.com/v1")).toBeNull();
    expect(validateBaseUrl("https://generativelanguage.googleapis.com/v1beta")).toBeNull();
    expect(validateBaseUrl("https://evil.example.com/v1")).toBeNull();
  });

  it("accepts http URLs to loopback hosts", () => {
    expect(validateBaseUrl("http://localhost:4000/v1")).toBeNull();
    expect(validateBaseUrl("http://127.0.0.1:11434/v1")).toBeNull();
    expect(validateBaseUrl("http://0.0.0.0:4000/v1")).toBeNull();
  });

  it("rejects http URLs to non-loopback hosts (cleartext key exfiltration risk)", () => {
    const err = validateBaseUrl("http://api.openai.com/v1");
    expect(err).not.toBeNull();
    expect(err).toContain("http://");
    expect(err).toContain("cleartext");
  });

  it("rejects http URLs to attacker-controlled hosts", () => {
    const err = validateBaseUrl("http://attacker.example.com/v1");
    expect(err).not.toBeNull();
    expect(err).toContain("cleartext");
  });

  it("accepts undefined/empty (uses provider default https)", () => {
    expect(validateBaseUrl(undefined)).toBeNull();
    expect(validateBaseUrl("")).toBeNull();
    expect(validateBaseUrl("  ")).toBeNull();
  });

  it("rejects non-http schemes", () => {
    expect(validateBaseUrl("ftp://example.com")).not.toBeNull();
    expect(validateBaseUrl("file:///etc/passwd")).not.toBeNull();
    expect(validateBaseUrl("javascript:alert(1)")).not.toBeNull();
  });

  it("rejects invalid URLs", () => {
    expect(validateBaseUrl("not a url")).not.toBeNull();
    expect(validateBaseUrl("http://")).not.toBeNull();
  });
});