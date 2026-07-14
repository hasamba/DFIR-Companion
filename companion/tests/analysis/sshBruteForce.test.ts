import { describe, it, expect, afterEach } from "vitest";
import {
  parseSshAuth,
  markSshBruteForce,
  sshMinFailures,
  sshWindowMs,
  DEFAULT_SSH_MIN_FAILURES,
  type SshAuthEvent,
} from "../../src/analysis/sshBruteForce.js";

describe("parseSshAuth", () => {
  it("parses an accepted password login", () => {
    expect(parseSshAuth("Accepted password for jordan.lee from 10.66.10.23 port 58209 ssh2"))
      .toEqual({ result: "accepted", user: "jordan.lee", ip: "10.66.10.23" });
  });
  it("parses accepted publickey and keyboard-interactive/pam", () => {
    expect(parseSshAuth("Accepted publickey for root from 203.0.113.9 port 22 ssh2")?.result).toBe("accepted");
    expect(parseSshAuth("Accepted keyboard-interactive/pam for bob from 8.8.8.8 port 22 ssh2")?.result).toBe("accepted");
  });
  it("parses failed password (incl. invalid user) and 'Invalid user' as failures", () => {
    expect(parseSshAuth("Failed password for invalid user admin from 203.0.113.9 port 41022 ssh2"))
      .toEqual({ result: "failed", user: "admin", ip: "203.0.113.9" });
    expect(parseSshAuth("Invalid user oracle from 203.0.113.9 port 5000")?.result).toBe("failed");
  });
  it("returns null for non-auth chatter", () => {
    expect(parseSshAuth("Received disconnect from 10.0.0.1 port 22:11: disconnected by user")).toBeNull();
    expect(parseSshAuth("Server listening on 0.0.0.0 port 22.")).toBeNull();
  });
});

const t = (s: string) => Date.parse(`2024-05-16T${s}Z`);
const ev = (key: number, hhmmss: string, ip: string, result: "accepted" | "failed"): SshAuthEvent<number> =>
  ({ key, ms: t(hhmmss), ip, result });

describe("markSshBruteForce", () => {
  it("flags an accepted login after >= minFailures failures from the same IP", () => {
    const events = [
      ev(0, "10:00:00", "203.0.113.9", "failed"),
      ev(1, "10:00:05", "203.0.113.9", "failed"),
      ev(2, "10:00:10", "203.0.113.9", "failed"),
      ev(3, "10:00:15", "203.0.113.9", "failed"),
      ev(4, "10:00:20", "203.0.113.9", "failed"),
      ev(5, "10:00:25", "203.0.113.9", "accepted"),
    ];
    const hits = markSshBruteForce(events);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ key: 5, ip: "203.0.113.9", failures: 5 });
  });

  it("does NOT flag a success with only a few prior failures (fat-fingered password)", () => {
    const events = [
      ev(0, "10:00:00", "10.0.0.5", "failed"),
      ev(1, "10:00:05", "10.0.0.5", "failed"),
      ev(2, "10:00:10", "10.0.0.5", "accepted"),
    ];
    expect(markSshBruteForce(events)).toHaveLength(0);
  });

  it("only counts failures from the SAME source IP", () => {
    const events = [
      ev(0, "10:00:00", "1.1.1.1", "failed"),
      ev(1, "10:00:01", "2.2.2.2", "failed"),
      ev(2, "10:00:02", "3.3.3.3", "failed"),
      ev(3, "10:00:03", "4.4.4.4", "failed"),
      ev(4, "10:00:04", "5.5.5.5", "failed"),
      ev(5, "10:00:05", "9.9.9.9", "accepted"), // different IP, no prior failures
    ];
    expect(markSshBruteForce(events)).toHaveLength(0);
  });

  it("ignores failures older than the lookback window", () => {
    const events = [
      ev(0, "08:00:00", "203.0.113.9", "failed"),
      ev(1, "08:00:01", "203.0.113.9", "failed"),
      ev(2, "08:00:02", "203.0.113.9", "failed"),
      ev(3, "08:00:03", "203.0.113.9", "failed"),
      ev(4, "08:00:04", "203.0.113.9", "failed"),
      ev(5, "10:00:00", "203.0.113.9", "accepted"), // 2h later, default window is 1h
    ];
    expect(markSshBruteForce(events)).toHaveLength(0);
  });

  it("skips undated events (ms <= 0) from correlation", () => {
    const events: SshAuthEvent<number>[] = [
      { key: 0, ms: 0, ip: "203.0.113.9", result: "failed" },
      { key: 1, ms: 0, ip: "203.0.113.9", result: "accepted" },
    ];
    expect(markSshBruteForce(events)).toHaveLength(0);
  });
});

describe("thresholds — env overrides", () => {
  afterEach(() => {
    delete process.env.DFIR_SSH_BRUTEFORCE_MIN_FAILS;
    delete process.env.DFIR_SSH_BRUTEFORCE_WINDOW_MIN;
  });

  it("defaults to 5 failures / 60 min", () => {
    expect(sshMinFailures()).toBe(DEFAULT_SSH_MIN_FAILURES);
    expect(sshWindowMs()).toBe(60 * 60 * 1000);
  });

  it("honours DFIR_SSH_BRUTEFORCE_MIN_FAILS", () => {
    process.env.DFIR_SSH_BRUTEFORCE_MIN_FAILS = "3";
    expect(sshMinFailures()).toBe(3);
    const events = [
      ev(0, "10:00:00", "1.2.3.4", "failed"),
      ev(1, "10:00:01", "1.2.3.4", "failed"),
      ev(2, "10:00:02", "1.2.3.4", "failed"),
      ev(3, "10:00:03", "1.2.3.4", "accepted"),
    ];
    expect(markSshBruteForce(events, { minFailures: sshMinFailures() })).toHaveLength(1);
  });
});
