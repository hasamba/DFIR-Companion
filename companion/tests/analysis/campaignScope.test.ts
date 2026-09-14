import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { campaignScope, ROWS_PER_DIGEST_MAX } from "../../src/analysis/campaignScope.js";
import { parseEmail } from "../../src/analysis/emailImport.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #930 item 2: per recipient — addressed / delivery indicated; per host — what the host's own
// rows establish about the attachment's own digest, on two axes; attribution only by the account
// the outcome-bearing row names; names are leads; bounds are said.

const T = "2017-12-01T08:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const pdf = Buffer.from("%PDF-1.4 evil\n", "utf8");
const SHA = createHash("sha256").update(pdf).digest("hex");
const ZIP = Buffer.from("PK zip", "utf8");
const ZIP_SHA = createHash("sha256").update(ZIP).digest("hex");

function eml(messageId: string, to: string[], extra: string[] = []): string {
  return [
    "Received: from relay.example (relay.example [203.0.113.50]) by mx.victim.com for <alice@victim.com>; Fri, 01 Dec 2017 08:00:02 +0000",
    ...extra,
    "From: service@evil.example",
    `To: ${to.join(", ")}`,
    "Subject: Invoice",
    "Date: Fri, 01 Dec 2017 08:00:00 +0000",
    `Message-ID: <${messageId}>`,
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="B"',
    "",
    "--B",
    "Content-Type: text/plain",
    "",
    "see attached",
    "--B",
    'Content-Type: application/pdf; name="invoice.pdf"',
    'Content-Disposition: attachment; filename="invoice.pdf"',
    "Content-Transfer-Encoding: base64",
    "",
    pdf.toString("base64"),
    "--B",
    'Content-Type: application/zip; name="pack.zip"',
    'Content-Disposition: attachment; filename="pack.zip"',
    "Content-Transfer-Encoding: base64",
    "",
    ZIP.toString("base64"),
    "--B--",
  ].join("\n");
}

const message = (id: string, to: string[], eventId = `m-${id}`): ForensicEvent => ({
  ...parseEmail(eml(id, to)).events[0],
  id: eventId,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e",
  timestamp: at(2),
  description: "d",
  severity: "Low",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["Sysmon"],
  ...over,
});
const start = (host: string, account: string | undefined, over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev({
    id: `s-${host}-${account ?? "none"}`,
    asset: host,
    path: "C:\\Users\\x\\Downloads\\invoice.pdf",
    sha256: SHA,
    canonical: {
      event: { category: "process", type: "start" },
      ...(account ? { account: { name: account } } : {}),
    } as never,
    ...over,
  });
const listing = (host: string, over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev({
    id: `l-${host}`,
    asset: host,
    sources: ["MFT"],
    path: "C:\\Users\\y\\Downloads\\invoice.pdf",
    sha256: SHA,
    fileModified: at(1),
    ...over,
  });
const defender = (host: string, disposition: string, sha: string | undefined, ts = at(3)): ForensicEvent =>
  ev({
    id: `d-${host}-${disposition}`,
    asset: host,
    timestamp: ts,
    sources: ["Microsoft Defender"],
    path: "C:\\Users\\x\\Downloads\\invoice.pdf",
    ...(sha ? { sha256: sha } : {}),
    canonical: {
      event: { category: "file", type: "action" },
      defender: {
        disposition,
        threat: "Trojan:PDF/X",
        eventType: "action",
        resources: ["C:\\Users\\x\\Downloads\\invoice.pdf"],
        resourcesTotal: 1,
        ...(sha ? { sha256: sha } : {}),
      },
    } as never,
  });

const stateOf = (events: ForensicEvent[]) => ({ ...emptyState("c1"), forensicTimeline: events });

describe("campaignScope", () => {
  it("recipients: addressed by To / Cc, delivery INDICATED by a header, an indicated-only address listed as such; never 'delivered'", () => {
    const s = campaignScope(stateOf([message("m1", ["alice@victim.com", "bob@victim.com"])]));
    expect(s.messages).toHaveLength(1);
    const m = s.messages[0];
    expect(m.attachments.map((a) => [a.name, a.sha256])).toEqual([
      ["invoice.pdf", SHA],
      ["pack.zip", ZIP_SHA],
    ]);
    expect(m.recipients.map((r) => [r.address, r.addressed, r.indicatedBy])).toEqual([
      ["alice@victim.com", "to", ["received-for"]],
      ["bob@victim.com", "to", undefined],
    ]);
    expect(JSON.stringify(s)).not.toMatch(/"delivered"/);
    // Alice: indicated by the topmost hop; Bob: addressed only. Neither has a host yet.
    expect(m.huntLeads.some((l) => l.startsWith("bob@victim.com: no endpoint row names this account"))).toBe(
      true,
    );
    const other = campaignScope(stateOf([message("m2", ["carol@victim.com"])])).messages[0];
    expect(other.recipients.map((r) => [r.address, r.addressed])).toEqual([
      ["carol@victim.com", "to"],
      ["alice@victim.com", "indicated-only"],
    ]);
  });

  it("hosts: a start of the digest under the recipient's exact account → execution observed, attributed; another account → present only, 'recipient not established'", () => {
    const s = campaignScope(
      stateOf([
        message("m1", ["alice@victim.com", "bob@victim.com"]),
        start("WS-A", "VICTIM\\alice"), // a bare domain\user: no SMTP domain on both sides → not attributed
        start("WS-B", "bob@victim.com"),
        listing("WS-C", {
          canonical: {
            event: { category: "file", type: "observation" },
            account: { name: "carol@victim.com" },
          } as never,
        }),
        start("WS-D", "SYSTEM"),
      ]),
    );
    const m = s.messages[0];
    const host = (h: string) => m.hosts.find((x) => x.host === h)!;
    expect(host("WS-B")).toMatchObject({
      recipient: "bob@victim.com",
      execution: "observed",
      present: false,
    });
    expect(host("WS-B").evidence.execution).toEqual(["s-WS-B-bob@victim.com"]);
    expect(host("WS-A")).toMatchObject({ recipient: null, execution: "observed" });
    expect(host("WS-C")).toMatchObject({ recipient: null, present: true, execution: "unknown" });
    expect(host("WS-D")).toMatchObject({ recipient: null, execution: "observed" });
    expect(m.recipients.find((r) => r.address === "bob@victim.com")!.hosts).toEqual(["WS-B"]);
    expect(m.recipients.find((r) => r.address === "alice@victim.com")!.hosts).toEqual([]);
    expect(host("WS-B").coverage).toContain("process");
  });

  it("two axes: a start then a remediated Defender record with its OWN digest keeps both; a Defender row without its own digest is no control", () => {
    const s = campaignScope(
      stateOf([
        message("m1", ["bob@victim.com"]),
        start("WS-B", "bob@victim.com", { timestamp: at(2) }),
        defender("WS-B", "remediated", SHA, at(3)),
        defender("WS-B", "blocked", undefined, at(1)),
        defender("WS-E", "allowed", SHA, at(4)),
      ]),
    );
    const m = s.messages[0];
    const b = m.hosts.find((h) => h.host === "WS-B")!;
    expect(b.execution).toBe("observed");
    expect(b.controls.map((c) => c.disposition)).toEqual(["remediated"]);
    const e = m.hosts.find((h) => h.host === "WS-E")!;
    expect(e).toMatchObject({ execution: "unknown", present: false });
    expect(e.controls.map((c) => c.disposition)).toEqual(["allowed"]);
  });

  it("a name-only row is a lead with no outcome; a zip's digest is not its member's; two ids with one attachment are two instances that say they share it", () => {
    const named = ev({
      id: "n1",
      asset: "WS-N",
      sources: ["Prefetch"],
      path: "C:\\Users\\z\\Downloads\\INVOICE.PDF",
    });
    const memberStart = start("WS-Z", "bob@victim.com", {
      id: "z1",
      sha256: "c".repeat(64),
      path: "C:\\tmp\\pack.zip\\member.exe",
    });
    const s = campaignScope(
      stateOf([message("m1", ["bob@victim.com"]), message("m2", ["dave@victim.com"]), named, memberStart]),
    );
    expect(s.messages).toHaveLength(2);
    const m1 = s.messages.find((m) => m.messageId === "m1")!;
    const n = m1.hosts.find((h) => h.host === "WS-N")!;
    expect(n).toMatchObject({ execution: "unknown", present: false, recipient: null });
    expect(n.leads[0]).toMatchObject({ kind: "name-only", eventId: "n1" });
    expect(n.leads[0].note).toContain("a name is not identity");
    expect(m1.hosts.some((h) => h.host === "WS-Z")).toBe(false);
    expect(m1.sharedWith).toEqual([s.messages.find((m) => m.messageId === "m2")!.instanceId]);
    expect(m1.huntLeads.some((l) => l.startsWith("WS-N: only a name-only lead"))).toBe(true);
  });

  it("bounds are deterministic and said: rows past the per-digest bound make the cell incomplete, never unknown", () => {
    const many = Array.from({ length: ROWS_PER_DIGEST_MAX + 5 }, (_, i) =>
      ev({ id: `r${i}`, asset: "WS-M", sources: ["MFT"], sha256: SHA, timestamp: at(1) }),
    );
    const late = start("WS-LATE", "bob@victim.com", { id: "late" });
    const s = campaignScope(stateOf([message("m1", ["bob@victim.com"]), ...many, late]));
    const m = s.messages[0];
    expect(m.hosts.find((h) => h.host === "WS-M")!.incomplete).toEqual({ rowsNotRead: 6 });
    // The late host shows only through its name-only lead; its digest row was not read, so the
    // cell is incomplete and no "only a name-only lead" hunt line claims an absence.
    const lateHost = m.hosts.find((h) => h.host === "WS-LATE")!;
    expect(lateHost).toMatchObject({ execution: "unknown", incomplete: { rowsNotRead: 6 } });
    expect(m.huntLeads.some((l) => l.includes("WS-LATE"))).toBe(false);
    expect(m.hosts.find((h) => h.host === "WS-M")!.evidence.more).toBeGreaterThan(0);
  });
});
