import { describe, it, expect } from "vitest";
import { parseEmail, parseMimeEmail, looksLikeMsg } from "../../src/analysis/emailImport.js";
import type { SiemEvent, SiemIoc } from "../../src/analysis/siemImport.js";

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const enc = (s: string): string => `=?UTF-8?B?${b64(s)}?=`;

function hasIoc(iocs: SiemIoc[], type: SiemIoc["type"], value: string): boolean {
  return iocs.some((i) => i.type === type && i.value.toLowerCase() === value.toLowerCase());
}
function only(events: SiemEvent[]): SiemEvent {
  expect(events).toHaveLength(1);
  return events[0];
}

// ── A full multipart phishing .eml: failing auth, a link, and an attachment ─────────────────
function phishingEml(): string {
  return [
    "Return-Path: <bounce@evil.example>",
    "Received: from mx.evil.example (mx.evil.example [203.0.113.7]) by mail.victim.com with ESMTP; Tue, 01 Dec 2017 08:00:00 +0000",
    "Authentication-Results: mail.victim.com; spf=fail (sender IP is 203.0.113.7) smtp.mailfrom=evil.example; dkim=fail; dmarc=fail",
    `From: ${enc("PayPal Support")} <service@evil.example>`,
    "Reply-To: refund@scammer.test",
    "To: victim@victim.com",
    `Subject: ${enc("Urgent: Account Locked")}`,
    "Date: Tue, 01 Dec 2017 08:00:00 +0000",
    "Message-ID: <deadbeef@evil.example>",
    "X-Originating-IP: [198.51.100.23]",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="BOUND"',
    "",
    "--BOUND",
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: quoted-printable",
    "",
    '<a href=3D"http://phish.evil.example/login">Verify now</a>',
    "--BOUND",
    'Content-Type: application/pdf; name="invoice.pdf"',
    'Content-Disposition: attachment; filename="invoice.pdf"',
    "Content-Transfer-Encoding: base64",
    "",
    "JVBERi0xLjQK",
    "--BOUND--",
  ].join("\n");
}

describe("parseMimeEmail — .eml structure", () => {
  it("parses headers, decodes the encoded-word subject, and reads the Date as UTC", () => {
    const p = parseMimeEmail(phishingEml());
    expect(p.format).toBe("eml");
    expect(p.subject).toBe("Urgent: Account Locked");
    expect(p.date).toBe("2017-12-01T08:00:00.000Z");
    expect(p.from?.address).toBe("service@evil.example");
    expect(p.from?.name).toBe("PayPal Support");
    expect(p.replyTo?.address).toBe("refund@scammer.test");
    expect(p.to.map((a) => a.address)).toContain("victim@victim.com");
    expect(p.auth).toEqual({ spf: "fail", dkim: "fail", dmarc: "fail" });
    expect(p.originatingIp).toBe("198.51.100.23");
  });

  it("walks the MIME tree for URLs and attachments", () => {
    const p = parseMimeEmail(phishingEml());
    expect(p.urls).toContain("http://phish.evil.example/login");
    expect(p.attachments.map((a) => a.filename)).toEqual(["invoice.pdf"]);
  });
});

describe("parseEmail — event + IOCs + severity", () => {
  it("emits one event at the Date header tagged Email with T1566 + sub-techniques", () => {
    const r = parseEmail(phishingEml());
    expect(r.format).toBe("eml");
    expect(r.total).toBe(1);
    const ev = only(r.events);
    expect(ev.timestamp).toBe("2017-12-01T08:00:00.000Z");
    expect(ev.sources).toEqual(["Email"]);
    expect(ev.mitreTechniques).toContain("T1566");
    expect(ev.mitreTechniques).toContain("T1566.001"); // attachment
    expect(ev.mitreTechniques).toContain("T1566.002"); // link
    expect(ev.description).toContain("Urgent: Account Locked");
    expect(ev.description).toContain("spf=fail");
  });

  it("auth failure → High severity", () => {
    expect(only(parseEmail(phishingEml()).events).severity).toBe("High");
  });

  it("harvests URL, domains, originating IP and attachment as IOCs", () => {
    const { iocs } = parseEmail(phishingEml());
    expect(hasIoc(iocs, "url", "http://phish.evil.example/login")).toBe(true);
    expect(hasIoc(iocs, "domain", "phish.evil.example")).toBe(true);
    expect(hasIoc(iocs, "domain", "evil.example")).toBe(true);     // sender domain
    expect(hasIoc(iocs, "domain", "scammer.test")).toBe(true);     // reply-to domain
    expect(hasIoc(iocs, "ip", "198.51.100.23")).toBe(true);        // X-Originating-IP
    expect(hasIoc(iocs, "file", "invoice.pdf")).toBe(true);
    // The victim's own recipient domain is NOT turned into an IOC.
    expect(hasIoc(iocs, "domain", "victim.com")).toBe(false);
  });
});

describe("parseEmail — severity heuristics", () => {
  const base = (extra: string[], body = "Hello"): string =>
    [
      "From: sender@trusted.com",
      "To: user@corp.com",
      "Subject: Hi",
      "Date: Mon, 02 Jan 2023 10:00:00 +0000",
      "Message-ID: <1@trusted.com>",
      "MIME-Version: 1.0",
      "Content-Type: text/plain",
      ...extra,
      "",
      body,
    ].join("\n");

  it("clean (spf/dkim/dmarc pass, no red flags) → Info", () => {
    const eml = base(["Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass"], "see https://trusted.com/news");
    const ev = only(parseEmail(eml).events);
    expect(ev.severity).toBe("Info");
    expect(ev.mitreTechniques).toEqual(["T1566", "T1566.002"]);
  });

  it("Reply-To in a different org than From → Medium (BEC reply-redirect)", () => {
    const eml = [
      "From: ceo@company.com",
      "Reply-To: ceo@gmail-secure.ru",
      "To: finance@company.com",
      "Subject: Wire transfer",
      "Date: Wed, 03 Jan 2023 09:00:00 +0000",
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass",
      "Message-ID: <2@company.com>",
      "",
      "Please wire $50,000.",
    ].join("\n");
    expect(only(parseEmail(eml).events).severity).toBe("Medium");
  });

  it("display-name that spoofs a different domain than the real sender → Medium", () => {
    const eml = [
      'From: "billing@paypal.com" <noreply@rando.xyz>',
      "To: u@corp.com",
      "Subject: invoice",
      "Date: Wed, 03 Jan 2023 09:00:00 +0000",
      "Message-ID: <3@rando.xyz>",
      "",
      "body",
    ].join("\n");
    expect(only(parseEmail(eml).events).severity).toBe("Medium");
  });
});

describe("parseEmail — body decoding + edges", () => {
  it("extracts URLs from a base64-encoded text body", () => {
    const eml = [
      "From: a@b.com",
      "Subject: x",
      "Date: Mon, 02 Jan 2023 10:00:00 +0000",
      "Message-ID: <4@b.com>",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=UTF-8",
      "Content-Transfer-Encoding: base64",
      "",
      b64("Please visit http://malware.test/x for details"),
    ].join("\n");
    expect(parseMimeEmail(eml).urls).toContain("http://malware.test/x");
  });

  it("re-fangs a defanged hxxp scheme", () => {
    const eml = [
      "From: a@b.com",
      "Subject: x",
      "Date: Mon, 02 Jan 2023 10:00:00 +0000",
      "Message-ID: <5@b.com>",
      "Content-Type: text/plain",
      "",
      "Visit hxxp://bad.test/login now",
    ].join("\n");
    const { iocs } = parseEmail(eml);
    expect(hasIoc(iocs, "url", "http://bad.test/login")).toBe(true);
    expect(hasIoc(iocs, "domain", "bad.test")).toBe(true);
  });

  it("decodes an RFC 2047 Q-encoded subject (underscore → space)", () => {
    const eml = ["From: a@b.com", "Subject: =?UTF-8?Q?Hello_World?=", "Date: Mon, 02 Jan 2023 10:00:00 +0000", "Message-ID: <6@b.com>", "", "x"].join("\n");
    expect(parseMimeEmail(eml).subject).toBe("Hello World");
  });

  it("returns an empty result for non-email junk", () => {
    const r = parseEmail("just some random text\nwith no headers at all");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
    expect(r.iocs).toHaveLength(0);
  });
});

describe("parseEmail — best-effort .msg recovery", () => {
  // Simulate an Outlook .msg as it arrives through File.text(): OLE/MAPI stream markers survive as
  // ASCII, the embedded transport-headers stream carries the RFC 822 headers.
  function fakeMsg(): string {
    return "���__substg1.0_007D001E" +
      [
        "Received: from mx.evil.example (mx.evil.example [203.0.113.7]) by victim",
        "From: attacker@evil.example",
        "To: victim@corp.com",
        "Subject: Invoice overdue",
        "Date: Tue, 01 Dec 2017 08:00:00 +0000",
        "Authentication-Results: victim; spf=fail; dmarc=fail",
      ].join("\r\n") +
      "\r\n\r\n�binary junk pay here http://evil.example/pay �\x00\x00";
  }

  it("detects a .msg by its MAPI markers", () => {
    expect(looksLikeMsg(fakeMsg())).toBe(true);
    expect(looksLikeMsg("plain .eml text")).toBe(false);
  });

  it("recovers headers + URLs from the embedded transport-headers stream", () => {
    const p = parseMimeEmail(fakeMsg());
    expect(p.format).toBe("msg");
    expect(p.from?.address).toBe("attacker@evil.example");
    expect(p.subject).toBe("Invoice overdue");
    expect(p.auth.spf).toBe("fail");
    expect(p.urls).toContain("http://evil.example/pay");
    expect(p.originatingIp).toBe("203.0.113.7");
  });

  it("auth failure recovered from .msg → High severity event", () => {
    const r = parseEmail(fakeMsg());
    expect(r.format).toBe("msg");
    expect(only(r.events).severity).toBe("High");
  });
});
