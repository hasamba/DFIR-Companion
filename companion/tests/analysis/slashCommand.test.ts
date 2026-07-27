import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import {
  parseSlashCommand,
  resolveCommand,
  formatFindingsCommand,
  formatFindingCommand,
  formatIocsCommand,
  formatStatusCommand,
  formatHelpCommand,
  isAllowed,
  isCaseAccessAllowed,
  isPrivilegedCommand,
  isAsyncCommand,
  READ_ONLY_COMMANDS,
  PRIVILEGED_COMMANDS,
  ASYNC_COMMANDS,
  type ChannelBinding,
} from "../../src/analysis/slashCommand.js";
import {
  verifySlackSignature,
  verifyTeamsToken,
  verifyTelegramSecret,
  isAllowedResponseUrl,
  parseHostList,
} from "../../src/analysis/slashCommandAuth.js";
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

  it("splits the command word from its argument tokens", () => {
    expect(parseSlashCommand("/dfir findings case-42")).toEqual(
      expect.objectContaining({ name: "findings", tokens: ["case-42"] }),
    );
    expect(parseSlashCommand("/dfir finding case-42 f3")).toEqual(
      expect.objectContaining({ name: "finding", tokens: ["case-42", "f3"] }),
    );
    expect(parseSlashCommand("/dfir ask case-1 what was the initial access vector?").tokens).toEqual([
      "case-1", "what", "was", "the", "initial", "access", "vector?",
    ]);
  });

  it("tolerates a bare command, a leading slash, and the echoed trigger word", () => {
    for (const text of ["findings c1", "/findings c1", "dfir findings c1", "/dfir findings c1"]) {
      expect(parseSlashCommand(text), text).toEqual(expect.objectContaining({ name: "findings", tokens: ["c1"] }));
    }
  });

  it("strips Telegram's @BotName suffix from the command word", () => {
    expect(parseSlashCommand("/findings@DfirCompanionBot c1")).toEqual(
      expect.objectContaining({ name: "findings", tokens: ["c1"] }),
    );
    expect(parseSlashCommand("/dfir@DfirCompanionBot findings c1")).toEqual(
      expect.objectContaining({ name: "findings", tokens: ["c1"] }),
    );
  });

  it("recognizes every command name", () => {
    for (const name of ["ask", "findings", "finding", "iocs", "hunt", "status", "synthesize", "bind", "unbind", "help"]) {
      expect(parseSlashCommand(`/dfir ${name} c1`).name, name).toBe(name);
    }
  });
});

describe("resolveCommand", () => {
  const bound: ChannelBinding = { caseId: "case-42", boundAt: "2026-07-25T00:00:00Z" };
  const parse = parseSlashCommand;

  it("uses the first token as the caseId when it names a real case", () => {
    const r = resolveCommand(parse("/dfir ask case-1 what happened?"), bound, true);
    expect(r.caseId).toBe("case-1");
    expect(r.arg).toBe("what happened?");
    expect(r.usedBinding).toBe(false);
  });

  // The bug this function exists for: positional parsing ate the first word of every argument.
  // `/dfir ask what happened?` used to resolve to a case called "what" — which passes
  // isValidCaseId, so nothing errored and the analyst got an answer about the wrong case.
  it("falls back to the channel binding when the first token is NOT a case", () => {
    const r = resolveCommand(parse("/dfir ask what was the initial access vector?"), bound, false);
    expect(r.caseId).toBe("case-42");
    expect(r.arg).toBe("what was the initial access vector?");
    expect(r.usedBinding).toBe(true);
  });

  it("reads an ioc filter as a filter, not as a caseId, on a bound channel", () => {
    const r = resolveCommand(parse("/dfir iocs malicious"), bound, false);
    expect(r.caseId).toBe("case-42");
    expect(r.iocFilter).toBe("malicious");
  });

  it("keeps the ioc filter after an explicit caseId", () => {
    const r = resolveCommand(parse("/dfir iocs case-1 flagged"), bound, true);
    expect(r.caseId).toBe("case-1");
    expect(r.iocFilter).toBe("flagged");
  });

  it("ignores a non-filter word instead of treating it as a filter", () => {
    expect(resolveCommand(parse("/dfir iocs"), bound, false).iocFilter).toBeUndefined();
    expect(resolveCommand(parse("/dfir iocs case-1"), bound, true).iocFilter).toBeUndefined();
  });

  it("passes a finding id through as the argument on a bound channel", () => {
    const r = resolveCommand(parse("/dfir finding f1"), bound, false);
    expect(r.caseId).toBe("case-42");
    expect(r.arg).toBe("f1");
  });

  it("keeps the typed token as the caseId when there is no binding, so the error names it", () => {
    const r = resolveCommand(parse("/dfir status nosuchcase"), undefined, false);
    expect(r.caseId).toBe("nosuchcase");
    expect(r.usedBinding).toBe(false);
  });

  it("never falls back to the binding for bind — that would re-bind to the current case", () => {
    expect(resolveCommand(parse("/dfir bind case-7"), bound, false).caseId).toBe("case-7");
    expect(resolveCommand(parse("/dfir bind"), bound, false).caseId).toBe("");
  });

  it("resolves no caseId for help and unbind", () => {
    expect(resolveCommand(parse("/dfir help"), bound, false).caseId).toBe("");
    expect(resolveCommand(parse("/dfir unbind"), bound, false).caseId).toBe("");
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
    expect(formatFindingCommand(state, "f99").title).toMatch(/not found/);
  });

  it("formatFindingCommand asks for an id instead of reporting \"not found\" for a blank one", () => {
    expect(formatFindingCommand(state, "").title).toMatch(/which finding/i);
  });

  it("formatIocsCommand with no filter lists all IOCs", () => {
    expect(formatIocsCommand(state, undefined).lines.length).toBe(3);
  });

  it("formatIocsCommand malicious filter returns only malicious IOCs", () => {
    const r = formatIocsCommand(state, "malicious");
    expect(r.lines.length).toBe(1);
    expect(r.lines[0]).toContain("5.6.7.8");
  });

  it("formatIocsCommand flagged filter returns malicious + suspicious", () => {
    expect(formatIocsCommand(state, "flagged").lines.length).toBe(2);
  });

  it("formatStatusCommand reports event/finding/IOC counts", () => {
    const r = formatStatusCommand(state);
    expect(r.title).toContain("case-1");
    expect(r.lines.some((l) => l.includes("Findings: 3"))).toBe(true);
    expect(r.lines.some((l) => l.includes("IOCs: 3"))).toBe(true);
  });

  it("formatHelpCommand lists every command and does not promise hunt deployment", () => {
    const r = formatHelpCommand();
    expect(r.lines.length).toBeGreaterThanOrEqual(9);
    expect(r.lines.some((l) => l.includes("/dfir bind"))).toBe(true);
    expect(r.lines.find((l) => l.startsWith("/dfir hunt"))).toMatch(/dashboard/);
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

  it("privileged commands are denied to a user not in the allowlist", () => {
    for (const name of PRIVILEGED_COMMANDS) {
      expect(isAllowed(name, "outsider", ["admin"]), name).toBe(false);
    }
  });

  it("privileged commands are allowed to a user in the allowlist", () => {
    for (const name of PRIVILEGED_COMMANDS) {
      expect(isAllowed(name, "admin", ["admin"]), name).toBe(true);
    }
  });

  it("privileged commands are open when no allowlist is configured", () => {
    for (const name of PRIVILEGED_COMMANDS) {
      expect(isAllowed(name, "anyone", undefined), name).toBe(true);
      expect(isAllowed(name, "anyone", []), name).toBe(true);
    }
  });

  // bind chooses which case the whole room can then read, so it is a privileged act — not the
  // read-only one the first cut of this bot treated it as.
  it("classifies bind as privileged but not async", () => {
    expect(isPrivilegedCommand("bind")).toBe(true);
    expect(isAsyncCommand("bind")).toBe(false);
    expect(READ_ONLY_COMMANDS).not.toContain("bind");
  });

  it("classifies the async commands", () => {
    expect(ASYNC_COMMANDS).toEqual(["ask", "hunt", "synthesize"]);
    for (const name of ASYNC_COMMANDS) expect(isAsyncCommand(name), name).toBe(true);
    expect(isAsyncCommand("findings")).toBe(false);
    expect(isAsyncCommand("status")).toBe(false);
  });
});

describe("isCaseAccessAllowed", () => {
  it("is open when no allowlist is configured", () => {
    expect(isCaseAccessAllowed({ userId: "u", caseId: "any", boundCaseId: "other", actionAllowlist: [] })).toBe(true);
    expect(isCaseAccessAllowed({ userId: "u", caseId: "any", boundCaseId: undefined, actionAllowlist: undefined })).toBe(true);
  });

  it("lets an allowlisted responder reach any case", () => {
    expect(isCaseAccessAllowed({ userId: "admin", caseId: "unrelated", boundCaseId: "c1", actionAllowlist: ["admin"] })).toBe(true);
  });

  // Without this, any chat member could read any case on the server just by naming it.
  it("confines everyone else to the channel's bound case", () => {
    const allowlist = ["admin"];
    expect(isCaseAccessAllowed({ userId: "u", caseId: "c1", boundCaseId: "c1", actionAllowlist: allowlist })).toBe(true);
    expect(isCaseAccessAllowed({ userId: "u", caseId: "secret", boundCaseId: "c1", actionAllowlist: allowlist })).toBe(false);
    expect(isCaseAccessAllowed({ userId: "u", caseId: "c1", boundCaseId: undefined, actionAllowlist: allowlist })).toBe(false);
  });
});

describe("verifySlackSignature", () => {
  const secret = "shhhh";
  // The base string Slack signs is `v0:<timestamp>:<rawBody>`, HMAC-SHA256, hex, prefixed "v0=".
  const ts = "1700000000";
  const rawBody = "token=abc&team_id=T1&channel_id=C1&user_id=U1&text=findings%20case-1&response_url=https%3A%2F%2Fhooks.slack.com%2Fx";
  const validSig = "v0=" + createHmac("sha256", secret).update(`v0:${ts}:${rawBody}`).digest("hex");

  it("accepts a valid signature within the replay window", () => {
    expect(verifySlackSignature({ signingSecret: secret, timestamp: ts, rawBody, signature: validSig, now: () => Number(ts) }).ok).toBe(true);
  });

  it("rejects a tampered body (signature mismatch)", () => {
    const r = verifySlackSignature({ signingSecret: secret, timestamp: ts, rawBody: rawBody + "tampered", signature: validSig, now: () => Number(ts) });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/mismatch/);
  });

  it("rejects a stale timestamp (outside the 5-minute replay window)", () => {
    const r = verifySlackSignature({ signingSecret: secret, timestamp: ts, rawBody, signature: validSig, now: () => Number(ts) + 600 });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/replay/);
  });

  it("rejects when no signing secret is configured", () => {
    expect(verifySlackSignature({ signingSecret: "", timestamp: ts, rawBody, signature: validSig, now: () => Number(ts) }).ok).toBe(false);
  });

  it("rejects a signature of the wrong length without throwing", () => {
    const r = verifySlackSignature({ signingSecret: secret, timestamp: ts, rawBody, signature: "v0=short", now: () => Number(ts) });
    expect(r.ok).toBe(false);
  });
});

describe("verifyTeamsToken", () => {
  it("accepts a matching bearer token", () => {
    expect(verifyTeamsToken("Bearer my-token", "my-token").ok).toBe(true);
    expect(verifyTeamsToken("my-token", "my-token").ok).toBe(true);
  });

  it("rejects a wrong token", () => {
    const r = verifyTeamsToken("Bearer wrong", "my-token");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/mismatch/);
  });

  it("rejects when no token is configured", () => {
    expect(verifyTeamsToken("Bearer x", "").ok).toBe(false);
  });

  it("rejects a missing Authorization header", () => {
    expect(verifyTeamsToken(undefined, "my-token").ok).toBe(false);
  });
});

describe("verifyTelegramSecret", () => {
  it("accepts the secret Telegram echoes back from setWebhook", () => {
    expect(verifyTelegramSecret("s3cret", "s3cret").ok).toBe(true);
  });

  it("rejects a wrong secret", () => {
    expect(verifyTelegramSecret("nope", "s3cret").ok).toBe(false);
  });

  it("rejects a missing header", () => {
    expect(verifyTelegramSecret(undefined, "s3cret").ok).toBe(false);
  });

  // Anyone who learns the webhook URL could otherwise post updates.
  it("refuses to run open when no secret is configured", () => {
    const r = verifyTelegramSecret("anything", "");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no Telegram webhook secret/);
  });
});

describe("isAllowedResponseUrl", () => {
  it("accepts Slack's own delivery host", () => {
    expect(isAllowedResponseUrl("slack", "https://hooks.slack.com/commands/T1/123/abc")).toBe(true);
  });

  it("accepts Teams delivery hosts, including subdomains", () => {
    expect(isAllowedResponseUrl("teams", "https://outlook.webhook.office.com/webhookb2/x")).toBe(true);
    expect(isAllowedResponseUrl("teams", "https://prod-1.westus.logic.azure.com/workflows/x")).toBe(true);
  });

  it("rejects an arbitrary host — the response_url is caller-supplied", () => {
    expect(isAllowedResponseUrl("slack", "https://evil.example.com/collect")).toBe(false);
    expect(isAllowedResponseUrl("slack", "http://169.254.169.254/latest/meta-data/")).toBe(false);
    expect(isAllowedResponseUrl("slack", "https://hooks.slack.com.evil.example.com/x")).toBe(false);
  });

  it("rejects plaintext http and unparseable input", () => {
    expect(isAllowedResponseUrl("slack", "http://hooks.slack.com/x")).toBe(false);
    expect(isAllowedResponseUrl("slack", "not a url")).toBe(false);
    expect(isAllowedResponseUrl("slack", "")).toBe(false);
  });

  it("honors an operator-configured extra host (self-hosted Mattermost)", () => {
    expect(isAllowedResponseUrl("slack", "https://chat.corp.example/hooks/x", ["chat.corp.example"])).toBe(true);
  });

  it("parseHostList trims and drops empties", () => {
    expect(parseHostList(" a.example , ,b.example ")).toEqual(["a.example", "b.example"]);
    expect(parseHostList(undefined)).toEqual([]);
  });
});
