// Initial-access correlation (#201): stitch a phishing email to the host activity it caused.
// The email importer records the link HOST(s) on the email event ("… linking mosaic-metrics.net");
// when a host later CONTACTS one of those delivered domains (a browser connection, DNS, download),
// that pair is the delivery → execution chain. This pure pass tags the contact event as initial
// access (T1566.002 → T1204.002) and raises it to at least Medium, so synthesis gets a real entry
// vector root instead of "began before the first observed timestamp via an unknown vector".
//
// Conservative + idempotent: only email-sourced LINK domains are used (never the sender/recipient
// domains), only same-or-later host events match, the marker is appended once, and severity uses a
// worst() floor — so re-running over an already-merged timeline is a no-op. No AI, no network.

import type { ForensicEvent, Severity } from "./stateTypes.js";

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
function worst(a: Severity, b: Severity): Severity { return SEV_RANK[b] < SEV_RANK[a] ? b : a; }

const DOMAIN_RE = /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)+\b/gi;
const MARKER = "[initial access:";

function isEmail(e: ForensicEvent): boolean {
  return (e.sources ?? []).includes("Email");
}

// The delivered LINK domains carried on an email event — parsed only from the controlled
// "… linking <hosts>" suffix the email importer writes, so sender/recipient domains are excluded.
export function emailLinkDomains(e: ForensicEvent): string[] {
  if (!isEmail(e)) return [];
  const m = /\blinking\s+([^|]+)$/i.exec((e.description ?? "").trim());
  if (!m) return [];
  const out = new Set<string>();
  for (const mm of m[1].matchAll(DOMAIN_RE)) out.add(mm[0].toLowerCase());
  return [...out];
}

// Boundary-aware containment so "evil.com" doesn't match "notevil.com" / "evil.com.au".
function mentions(hay: string, domain: string): boolean {
  const esc = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^a-z0-9.-])${esc}([^a-z0-9-]|$)`, "i").test(hay);
}

export function linkEmailDelivery(events: ForensicEvent[]): ForensicEvent[] {
  // Earliest email-delivery time per delivered domain.
  const deliveredAt = new Map<string, number>();
  for (const e of events) {
    const t = Date.parse(e.timestamp ?? "") || 0;
    for (const d of emailLinkDomains(e)) {
      const cur = deliveredAt.get(d);
      if (cur === undefined || t < cur) deliveredAt.set(d, t);
    }
  }
  if (deliveredAt.size === 0) return events;

  return events.map((e) => {
    if (!e.asset || isEmail(e)) return e;
    if ((e.description ?? "").includes(MARKER)) return e; // idempotent
    const t = Date.parse(e.timestamp ?? "") || 0;
    const hay = `${e.description ?? ""} ${e.dstIp ?? ""}`.toLowerCase();
    for (const [domain, dt] of deliveredAt) {
      if (t >= dt && mentions(hay, domain)) {
        const mitre = [...new Set([...(e.mitreTechniques ?? []), "T1566.002", "T1204.002"])];
        return {
          ...e,
          severity: worst(e.severity, "Medium"),
          mitreTechniques: mitre,
          description: `${e.description ?? ""} ${MARKER} host contacted email-delivered domain ${domain}]`.slice(0, 600),
        };
      }
    }
    return e;
  });
}
