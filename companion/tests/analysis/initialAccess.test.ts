import { describe, it, expect } from "vitest";
import { linkEmailDelivery, emailLinkDomains } from "../../src/analysis/initialAccess.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const emailEv = (): ForensicEvent => ({
  id: "m1", timestamp: "2024-03-18T14:10:00Z",
  description: 'Email: "License Renewal" from billing@verilink-accounts.com to marcus.chen@veridia.io | 1 URL(s) linking mosaic-metrics.net',
  severity: "Info", mitreTechniques: ["T1566", "T1566.002"], relatedFindingIds: [], sourceScreenshots: [], sources: ["Email"],
});
const contact = (id: string, ts: string, desc: string, asset = "WS-DEV-01"): ForensicEvent => ({
  id, timestamp: ts, description: desc, severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset, sources: ["Zeek"],
});

describe("emailLinkDomains (#201)", () => {
  it("parses only the link host(s), never the sender/recipient domains", () => {
    expect(emailLinkDomains(emailEv())).toEqual(["mosaic-metrics.net"]);
  });
  it("returns nothing for a non-email event", () => {
    expect(emailLinkDomains(contact("c", "2024-03-18T15:00:00Z", "x"))).toEqual([]);
  });
});

describe("linkEmailDelivery (#201)", () => {
  it("tags a later host contact of the delivered domain as initial access", () => {
    const out = linkEmailDelivery([emailEv(), contact("c1", "2024-03-18T14:14:31Z", "browser connection to mosaic-metrics.net")]);
    const c = out.find((e) => e.id === "c1")!;
    expect(c.severity).toBe("Medium");
    expect(c.mitreTechniques).toContain("T1204.002");
    expect(c.mitreTechniques).toContain("T1566.002");
    expect(c.description).toContain("initial access");
  });

  it("does NOT tag the victim's own recipient domain (veridia.io) or an unrelated domain", () => {
    const out = linkEmailDelivery([
      emailEv(),
      contact("c1", "2024-03-18T14:20:00Z", "sync to update.veridia.io"),
      contact("c2", "2024-03-18T14:21:00Z", "connection to microsoft.com"),
    ]);
    expect(out.find((e) => e.id === "c1")!.severity).toBe("Info");
    expect(out.find((e) => e.id === "c2")!.severity).toBe("Info");
  });

  it("does NOT tag a contact that happened BEFORE the email", () => {
    const out = linkEmailDelivery([emailEv(), contact("c1", "2024-03-18T14:00:00Z", "connection to mosaic-metrics.net")]);
    expect(out.find((e) => e.id === "c1")!.severity).toBe("Info");
  });

  it("is idempotent — re-running does not double-tag or re-bump", () => {
    const once = linkEmailDelivery([emailEv(), contact("c1", "2024-03-18T14:14:31Z", "GET mosaic-metrics.net/dropper")]);
    const twice = linkEmailDelivery(once);
    const a = once.find((e) => e.id === "c1")!;
    const b = twice.find((e) => e.id === "c1")!;
    expect(b.description).toBe(a.description);
    expect((b.description.match(/initial access/g) || []).length).toBe(1);
  });

  it("uses boundary-aware matching (does not match a superstring domain)", () => {
    const out = linkEmailDelivery([emailEv(), contact("c1", "2024-03-18T14:30:00Z", "connection to notmosaic-metrics.network")]);
    expect(out.find((e) => e.id === "c1")!.severity).toBe("Info");
  });
});
