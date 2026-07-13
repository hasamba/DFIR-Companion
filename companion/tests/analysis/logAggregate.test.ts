import { describe, it, expect } from "vitest";
import { aggregateLogLines, templateizeLine, splitLeadingTimestamp, type AggregateStats } from "../../src/analysis/logAggregate.js";

describe("aggregateLogLines stats out-param (#10 trigger b)", () => {
  it("reports distinct vs kept so a cap-hit is detectable", () => {
    // 5 distinct patterns, cap at 3 → 2 dropped.
    const lines = ["alpha 1", "beta 2", "gamma 3", "delta 4", "epsilon 5"];
    const stats: AggregateStats = { distinctTemplates: 0, keptTemplates: 0 };
    const kept = aggregateLogLines(lines, { maxTemplates: 3 }, stats);
    expect(kept).toHaveLength(3);
    expect(stats.distinctTemplates).toBe(5);
    expect(stats.keptTemplates).toBe(3);
  });
  it("reports distinct === kept when under the cap (no truncation)", () => {
    const stats: AggregateStats = { distinctTemplates: 0, keptTemplates: 0 };
    aggregateLogLines(["a 1", "a 2", "b 3"], { maxTemplates: 400 }, stats);  // 2 distinct patterns, under cap
    expect(stats.distinctTemplates).toBe(2);
    expect(stats.keptTemplates).toBe(2);
    expect(stats.distinctTemplates > stats.keptTemplates).toBe(false);   // → no cap_hit warning
  });
});

describe("splitLeadingTimestamp", () => {
  it("strips an ISO-8601 timestamp", () => {
    const { timestamp, rest } = splitLeadingTimestamp("2026-05-19T00:00:13Z starting keying attempt 269");
    expect(timestamp).toBe("2026-05-19T00:00:13Z");
    expect(rest).toBe("starting keying attempt 269");
  });

  it("strips an RFC 3164 syslog timestamp", () => {
    const { timestamp, rest } = splitLeadingTimestamp("May 28 09:00:01 host sshd[1]: Failed password");
    expect(timestamp).toBe("May 28 09:00:01");
    expect(rest).toBe("host sshd[1]: Failed password");
  });

  it("strips an Apache bracketed timestamp", () => {
    const { timestamp } = splitLeadingTimestamp("[28/May/2026:09:00:01 +0000] GET /");
    expect(timestamp).toBe("[28/May/2026:09:00:01 +0000]");
  });

  it("returns empty timestamp + original line when none present", () => {
    const { timestamp, rest } = splitLeadingTimestamp("no time here just text");
    expect(timestamp).toBe("");
    expect(rest).toBe("no time here just text");
  });
});

describe("templateizeLine", () => {
  it("masks digit runs, #ids and hex but PRESERVES IP addresses", () => {
    expect(templateizeLine("Failed password for root from 10.0.0.5 port 22"))
      .toBe("Failed password for root from 10.0.0.5 port N");
    expect(templateizeLine("initiating Main Mode to replace #871204 for 'S_REF_Ips2office_0'."))
      .toBe("initiating Main Mode to replace #N for 'S_REF_IpsNoffice_N'.");
    expect(templateizeLine("dropped 0xDEADBEEF flags")).toBe("dropped HEX flags");
  });

  it("groups lines that differ only by volatile numbers into the same template", () => {
    const a = templateizeLine("starting keying attempt 269 of an unlimited number for 'S_REF_Ips2asihome_0'.");
    const b = templateizeLine("starting keying attempt 1315 of an unlimited number for 'S_REF_Ips2asihome_0'.");
    expect(a).toBe(b);
  });

  it("keeps different message structures (and different IPs) as distinct templates", () => {
    expect(templateizeLine("Failed password from 1.1.1.1"))
      .not.toBe(templateizeLine("Failed password from 2.2.2.2"));
  });
});

describe("aggregateLogLines", () => {
  it("collapses repeated lines into counted patterns, most frequent first", () => {
    const lines = [
      ...Array.from({ length: 20 }, (_, i) => `May 28 09:00:${String(i).padStart(2, "0")} sshd: Failed password for root from 10.0.0.5`),
      "May 28 09:05:00 sshd: Accepted password for admin from 10.0.0.9",
    ];
    const out = aggregateLogLines(lines);
    expect(out).toHaveLength(2);
    expect(out[0].count).toBe(20);            // most frequent first
    expect(out[1].count).toBe(1);
    expect(out[0].firstTimestamp).toBe("May 28 09:00:00");
    expect(out[0].lastTimestamp).toBe("May 28 09:00:19");
    expect(out[0].example).toContain("Failed password");
  });

  it("respects maxTemplates by dropping the MOST frequent, keeping rare ones — #6 needle-in-haystack fix", () => {
    // A naive "most frequent first" cap would keep "a"(3)+"b"(2) and drop "c"(1) — exactly backwards:
    // the rare, count=1 template is the one most likely to be a one-off signal, and the frequent ones
    // are the least likely to need close reading. Truncation must protect the rare end instead.
    const lines = [
      "a 1", "a 2", "a 3",   // template "a N" ×3
      "b 1", "b 2",          // template "b N" ×2
      "c 1",                 // template "c N" ×1
    ];
    const out = aggregateLogLines(lines, { maxTemplates: 2 });
    expect(out.map((t) => t.count)).toEqual([2, 1]); // "a" (noisiest) dropped, "b" and "c" survive
  });

  it("keeps a single rare line even when it's vastly outnumbered by repetitive baseline noise", () => {
    const lines = [
      ...Array.from({ length: 500 }, (_, i) => `GET /health ${i}`),   // 500x repetitive health-check noise
      "CONNECT vault.cloudpear.io:443 arjun.mehta",                    // the one rare, high-signal line
    ];
    const out = aggregateLogLines(lines, { maxTemplates: 1 });
    expect(out).toHaveLength(1);
    expect(out[0].example).toContain("vault.cloudpear.io");
  });

  it("returns [] for no lines", () => {
    expect(aggregateLogLines([])).toEqual([]);
  });
});
