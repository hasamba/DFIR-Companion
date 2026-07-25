import { describe, it, expect } from "vitest";
import {
  parseSlashCommand,
  formatFindingsCommand,
  formatFindingCommand,
  formatIocsCommand,
  formatStatusCommand,
  formatHelpCommand,
  resolveCaseId,
  isAllowed,
  isActionCommand,
  READ_ONLY_COMMANDS,
  ACTION_COMMANDS,
  type ParsedSlashCommand,
} from "../../src/analysis/slashCommand.js";
import { verifySlackSignature, verifyTeamsToken } from "../../src/analysis/slashCommandAuth.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { Finding, IOC, IocEnrichment, InvestigationState } from "../../src/analysis/stateTypes.js";

describe("parseSlashCommand", () => {
  it("returns help for empty input", () => {
    expect(parseSlashCommand("").name).toBe("help");
    expect(parseSlashCommand("   ").name).toBe("help");
  });

  it("returns help for an unrecognized command", () => {
    expect(parseSlashCommand("/dfir frobnicate x").name).toBe("help");
  });

  it("parses /dfir findings <caseId>", () => {
    const c = parseSlashCommand("/dfir findings case-42");
    expect(c.name).toBe("findings");
    expect(c.caseId).toBe("case-42");
  });

  it("parses /dfir finding <caseId> <id>", () => {
    const c = parseSlashCommand("/dfir finding case-42 f3");
    expect(c.name).toBe("finding");
    expect(c.caseId).toBe("case-42");
    expect(c.arg).toBe("f3");
  });

  it("parses /dfir iocs <caseId> [filter]", () => {
    expect(parseSlashCommand("/dfir iocs case-1 malicious")).toEqual(expect.objectContaining({ name: "iocs", caseId: "case-1", iocFilter: "malicious" }));
    expect(parseSlashCommand("/dfir iocs case-1 flagged")).toEqual(expect.objectContaining({ name: "iocs", caseId: "case-1", iocFilter: "flagged" }));
    expect(parseSlashCommand("/dfir iocs case-1").iocFilter).toBeUndefined();
  });

  it("parses /dfir ask <caseId> <question> (multi-word question)", () => {
    const c = parseSlashCommand("/dfir ask case-1 what was the initial access vector?");
    expect(c.name).toBe("ask");
    expect(c.caseId).toBe("case-1");
    expect(c.arg).toBe("what was the initial access vector?");
  });

  it("parses /dfir hunt <caseId> <technique>", () => {
    const c = parseSlashCommand("/dfir hunt case-1 T1059.001");
    expect(c.name).toBe("hunt");
    expect(c.arg).toBe("T1059.001");
  });

  it("parses status, synthesize (caseId only), bind, unbind, help", () => {
    expect(parseSlashCommand("/dfir status c1")).toEqual(expect.objectContaining({ name: "status", caseId: "c1" }));
    expect(parseSlashCommand("/dfir synthesize c1")).toEqual(expect.objectContaining({ name: "synthesize", caseId: "c1" }));
    expect(parseSlashCommand("/dfir bind c1")).toEqual(expect.objectContaining({ name: "bind", caseId: "c1" }));
    expect(parseSlashCommand("/dfir unbind").name).toBe("unbind");
    expect(parseSlashCommand("/dfir help").name).toBe("help");
  });

  it("tolerates a bare command without the /dfir prefix", () => {
    expect(parseSlashCommand("findings c1")).toEqual(expect.objectContaining({ name: "findings", caseId: "c1" }));
  });
});

describe("command formatters", () => {
  const finding = (id: string, severity: Finding["severity"], title: string, extra: Partial<Finding> = {}): Finding => ({
    id,
    severity,
    title,
    description: extra.description ?? "desc",
    relatedIocs: extra.relatedIocs ?? [],
    sourceScreenshots: [],
    mitreTechniques: extra.mitreTechniques ?? [],
    firstSeen: "2026-07-01T00:00:00Z",
    lastUpdated: "2026-07-25T00:00:00Z",
    status: extra.status ?? "open",
    confidence: extra.confidence,
    ...extra,
  });

  const ioc = (id: string, value: string, enrichments: IocEnrichment[] = []): IOC => ({
    id, type: "ip", value, firstSeen: "2026-07-01T00:00:00Z", enrichments,
  });

  const state: InvestigationState = {
    ...emptyState("case-1"),
    findings: [
      finding("f1", "Critical", "Ransomware encryption", { confidence: 90, mitreTechniques: ["T1486"] }),
      finding("f2", "High", "Lateral movement", { confidence: 70, mitreTechniques: ["T1021"] }),
      finding("f3", "Medium", "Suspicious PowerShell", { confidence: 55, status: "dismissed" }),
    ],
    iocs: [
      ioc("i1", "5.6.7.8", [{ source: "VirusTotal", verdict: "malicious", fetchedAt: "2026-07-01T00:00:00Z", detections: 47, total: 60 }]),
      ioc("i2", "evil.com", [{ source: "MISP", verdict: "suspicious", fetchedAt: "2026-07-01T00:00:00Z" }]),
      ioc("i3", "clean.com", [{ source: "VirusTotal", verdict: "harmless", fetchedAt: "2026-07-01T00:00:00Z" }]),
    ],
  };

  it("formatFindingsCommand returns top 5 by severity, excluding dismissed", () => {
    const r = formatFindingsCommand(state);
    expect(r.lines.length).toBe(2);
    expect(r.lines[0]).toContain("Critical");
    expect(r.lines[0]).toContain("f1");
    expect(r.lines[0]).toContain("T1486");
    expect(r.lines[1]).toContain("High");
  });

  it("formatFindingsCommand on an empty case tells the analyst to synthesize", () => {
    const r = formatFindingsCommand(emptyState("c"));
    expect(r.lines[0]).toMatch(/synthesis/i);
  });

  it("formatFindingCommand returns a single finding card by id", () => {
    const r = formatFindingCommand(state, "f1");
    expect(r.title).toContain("Ransomware encryption");
    expect(r.lines.some((l) => l.includes("Critical"))).toBe(true);
  });

  it("formatFindingCommand reports a clear not-found for an unknown id", () => {
    const r = formatFindingCommand(state, "f99");
    expect(r.title).toMatch(/not found/);
  });

  it("formatIocsCommand with no filter lists all IOCs", () => {
    const r = formatIocsCommand(state, undefined);
    expect(r.lines.length).toBe(3);
  });

  it("formatIocsCommand malicious filter returns only malicious IOCs", () => {
    const r = formatIocsCommand(state, "malicious");
    expect(r.lines.length).toBe(1);
    expect(r.lines[0]).toContain("5.6.7.8");
  });

  it("formatIocsCommand flagged filter returns malicious + suspicious", () => {
    const r = formatIocsCommand(state, "flagged");
    expect(r.lines.length).toBe(2);
  });

  it("formatStatusCommand reports event/finding/IOC counts", () => {
    const r = formatStatusCommand(state);
    expect(r.title).toContain("case-1");
    expect(r.lines.some((l) => l.includes("Findings: 3"))).toBe(true);
    expect(r.lines.some((l) => l.includes("IOCs: 3"))).toBe(true);
  });

  it("formatHelpCommand lists every command", () => {
    const r = formatHelpCommand();
    expect(r.lines.length).toBeGreaterThanOrEqual(9);
    expect(r.lines.some((l) => l.includes("/dfir bind"))).toBe(true);
  });
});

describe("resolveCaseId", () => {
  it("prefers the explicit caseId over the channel binding", () => {
    const cmd: ParsedSlashCommand = { name: "findings", caseId: "explicit", raw: "" };
    expect(resolveCaseId(cmd, { caseId: "bound", boundAt: "" })).toBe("explicit");
  });

  it("falls back to the channel binding when no explicit caseId is given", () => {
    const cmd: ParsedSlashCommand = { name: "status", caseId: undefined, raw: "" };
    expect(resolveCaseId(cmd, { caseId: "bound", boundAt: "" })).toBe("bound");
  });

  it("returns empty when neither is present", () => {
    const cmd: ParsedSlashCommand = { name: "status", caseId: undefined, raw: "" };
    expect(resolveCaseId(cmd, undefined)).toBe("");
  });
});

describe("access control", () => {
  it("read-only commands are always allowed (no allowlist needed)", () => {
    for (const name of READ_ONLY_COMMANDS) {
      expect(isAllowed(name, "anyone", ["admin"])).toBe(true);
      expect(isAllowed(name, "anyone", [])).toBe(true);
      expect(isAllowed(name, "anyone", undefined)).toBe(true);
    }
  });

  it("action commands are denied to a user not in the allowlist", () => {
    for (const name of ACTION_COMMANDS) {
      expect(isAllowed(name, "outsider", ["admin"])).toBe(false);
    }
  });

  it("action commands are allowed to a user in the allowlist", () => {
    for (const name of ACTION_COMMANDS) {
      expect(isAllowed(name, "admin", ["admin"])).toBe(true);
    }
  });

  it("action commands are open (allowed) when no allowlist is configured", () => {
    for (const name of ACTION_COMMANDS) {
      expect(isAllowed(name, "anyone", undefined)).toBe(true);
      expect(isAllowed(name, "anyone", [])).toBe(true);
    }
  });

  it("isActionCommand correctly classifies the three action commands", () => {
    expect(isActionCommand("ask")).toBe(true);
    expect(isActionCommand("hunt")).toBe(true);
    expect(isActionCommand("synthesize")).toBe(true);
    expect(isActionCommand("findings")).toBe(false);
    expect(isActionCommand("status")).toBe(false);
  });
});

describe("verifySlackSignature", () => {
  const secret = "shhhh";
  // The base string Slack signs is `v0:<timestamp>:<rawBody>`, HMAC-SHA256, hex, prefixed with "v0=".
  // Compute a valid signature for a known body so we can verify the verifier accepts it.
  const ts = "1700000000";
  const rawBody = "token=abc&team_id=T1&channel_id=C1&user_id=U1&text=findings%20case-1&response_url=https%3A%2F%2Fhooks.slack.com%2Fx";
  const validSig = "v0=" + hmacSha256Hex(secret, `v0:${ts}:${rawBody}`);

  it("accepts a valid signature within the replay window", () => {
    const r = verifySlackSignature({ signingSecret: secret, timestamp: ts, rawBody, signature: validSig, now: () => Number(ts) });
    expect(r.ok).toBe(true);
  });

  it("rejects a tampered body (signature mismatch)", () => {
    const r = verifySlackSignature({ signingSecret: secret, timestamp: ts, rawBody: rawBody + "tampered", signature: validSig, now: () => Number(ts) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/mismatch/);
  });

  it("rejects a stale timestamp (outside the 5-minute replay window)", () => {
    const stale = Number(ts) + 600; // 10 min later
    const r = verifySlackSignature({ signingSecret: secret, timestamp: ts, rawBody, signature: validSig, now: () => stale });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/replay/);
  });

  it("rejects when no signing secret is configured", () => {
    const r = verifySlackSignature({ signingSecret: "", timestamp: ts, rawBody, signature: validSig, now: () => Number(ts) });
    expect(r.ok).toBe(false);
  });
});

describe("verifyTeamsToken", () => {
  it("accepts a matching bearer token", () => {
    const r = verifyTeamsToken("Bearer my-token", "my-token");
    expect(r.ok).toBe(true);
  });

  it("rejects a wrong token", () => {
    const r = verifyTeamsToken("Bearer wrong", "my-token");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/mismatch/);
  });

  it("rejects when no token is configured", () => {
    const r = verifyTeamsToken("Bearer x", "");
    expect(r.ok).toBe(false);
  });

  it("rejects a missing Authorization header", () => {
    const r = verifyTeamsToken(undefined, "my-token");
    expect(r.ok).toBe(false);
  });
});

function hmacSha256Hex(secret: string, data: string): string {
  // Use the same machinery the verifier does — node:crypto — so the test signature is correct.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHmac } = require("node:crypto") as typeof import("node:crypto");
  return createHmac("sha256", secret).update(data).digest("hex");
}