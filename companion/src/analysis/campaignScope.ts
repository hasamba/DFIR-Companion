import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import type { ControlDisposition } from "./stateTypes.js";
import { classifyHit, familyOf } from "./remediationShapes.js";
import type { TelemetryFamily } from "./remediationBoundary.js";

// Phishing campaign scope (#930 item 2): starting from an imported message, which addresses were
// ADDRESSED, which mailbox a header INDICATES it reached, and — per host — what the host's own
// rows establish about the attachment: present, a control's disposition, a process start.
//
// WHAT ONE RECORD ESTABLISHES, AND NOTHING MORE.
//   - A recipient address establishes that the address was addressed. `Delivered-To` and the
//     topmost `Received … for` hop INDICATE delivery to one mailbox; neither is authenticated in
//     an exported file, so the word is "indicated", never "delivered".
//   - An endpoint row establishes what ITS shape says about the attachment's OWN digest (the
//     digest computed from the decoded MIME part — never a hash seen in the body): a listing or
//     presence row → present; a Defender record whose own digest matches → its disposition; a
//     process start → execution observed. Execution and control are two axes and stay two
//     (stateTypes.ts): a payload that started and was later remediated is both.
//   - A row that matches by NAME only is a lead, never identity: shared filenames must not merge
//     unrelated activity. A container's digest is not its member's.
//   - A host is attributed to a recipient only when the OUTCOME-BEARING row itself names the
//     recipient's account exactly (the SMTP address, or a UPN with a domain on both sides). A
//     shared workstation, a service account, SYSTEM, an unrelated logon row: "recipient not
//     established", and the host stays in the table under that heading.
//   - A message INSTANCE is Message-ID + sender + the attachment digest set; two messages with
//     one id and different digests are two instances, said. A no-id message is its own instance.
//     Campaign linkage is explicit: instances that share an attachment digest are grouped as
//     "N messages carry this attachment" — never on subject or date.
//   - Bounds are deterministic and every unread count is said; a truncated cell reads
//     "incomplete", never "unknown" or "no telemetry".
//
// Never: contact a recipient, collect a mailbox, upload an attachment anywhere. Hunt leads are
// text the analyst can run.

export const MESSAGES_MAX = 200;
export const RECIPIENTS_PER_MESSAGE_MAX = 500;
export const ROWS_PER_DIGEST_MAX = 2_000;
export const HOSTS_MAX = 200;
export const EVIDENCE_PER_CELL_MAX = 20;

export interface ScopeAttachment {
  name: string;
  sha256?: string;
  md5?: string;
  digestUnavailable?: string;
}

export interface ScopeRecipient {
  address: string;
  addressed: "to" | "cc" | "indicated-only";
  indicatedBy?: ("delivered-to" | "received-for")[];
  hosts: string[];
}

export interface ScopeHost {
  host: string;
  /** The recipient whose account the outcome-bearing rows name, or null: "recipient not established". */
  recipient: string | null;
  execution: "observed" | "unknown";
  controls: { disposition: ControlDisposition; at: string; eventId: string }[];
  present: boolean;
  evidence: { execution: string[]; control: string[]; present: string[]; more: number };
  leads: { kind: "name-only" | "path-only"; eventId: string; note: string }[];
  coverage: TelemetryFamily[];
  incomplete?: { rowsNotRead: number };
}

export interface ScopeMessage {
  instanceId: string;
  eventId: string;
  messageId?: string;
  sender?: string;
  subject?: string;
  date: string;
  attachments: ScopeAttachment[];
  /** Other instances that carry one of this message's attachment digests. */
  sharedWith: string[];
  recipients: ScopeRecipient[];
  recipientsNotRead: number;
  hosts: ScopeHost[];
  hostsNotRead: number;
  huntLeads: string[];
}

export interface CampaignScope {
  messages: ScopeMessage[];
  messagesNotRead: number;
  generated: string;
}

const lower = (s: string | undefined): string => (s ?? "").trim().toLowerCase();
const baseOf = (p: string): string =>
  p.slice(Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")) + 1).toLowerCase();

/** An SMTP address or UPN with local part and domain; a bare name has no domain and matches nothing. */
function accountParts(name: string): { user: string; domain: string } | null {
  const s = lower(name);
  const at = s.indexOf("@");
  if (at > 0) return { user: s.slice(0, at), domain: s.slice(at + 1) };
  const bs = s.indexOf("\\");
  if (bs > 0) return { user: s.slice(bs + 1), domain: s.slice(0, bs) };
  return null;
}

const SERVICE_ACCOUNT = /^(system|local service|network service|nt authority\\.*|root|\$)$/i;

/** The recipient a row's own account names, exactly, or null. */
function recipientOfRow(e: ForensicEvent, recipients: readonly string[]): string | null {
  const c = e.canonical;
  const names = [c?.account?.name, c?.actor?.kind === "account" ? c.actor.name : undefined].filter(
    (n): n is string => !!n,
  );
  for (const n of names) {
    if (SERVICE_ACCOUNT.test(n.trim())) continue;
    const parts = accountParts(n);
    if (!parts) continue;
    for (const r of recipients) {
      const rp = accountParts(r);
      if (rp && rp.user === parts.user && rp.domain === parts.domain) return r;
    }
  }
  return null;
}

interface DigestRow {
  e: ForensicEvent;
  by: "sha256" | "md5";
}

/** Rows carrying each digest, bounded per digest, with the unread count. */
function indexByDigest(
  events: readonly ForensicEvent[],
): Map<string, { rows: DigestRow[]; notRead: number }> {
  const out = new Map<string, { rows: DigestRow[]; notRead: number }>();
  const add = (key: string, row: DigestRow) => {
    const b = out.get(key) ?? out.set(key, { rows: [], notRead: 0 }).get(key)!;
    if (b.rows.length < ROWS_PER_DIGEST_MAX) b.rows.push(row);
    else b.notRead += 1;
  };
  for (const e of events) {
    if (e.canonical?.mailbox) continue; // the message rows themselves are not endpoint rows
    const sha = lower(e.sha256 ?? e.canonical?.file?.sha256 ?? e.canonical?.defender?.sha256);
    const md5 = lower(e.md5 ?? e.canonical?.file?.md5);
    if (sha) add(sha, { e, by: "sha256" });
    if (md5) add(md5, { e, by: "md5" });
  }
  return out;
}

const isProcessStart = (e: ForensicEvent): boolean =>
  e.canonical?.event?.category === "process" && e.canonical.event.type === "start";

function hostOf(e: ForensicEvent): string {
  return (e.asset ?? "").trim();
}

/** Rows that name the attachment by NAME only, per host — leads, never identity. */
function nameLeads(
  events: readonly ForensicEvent[],
  names: ReadonlySet<string>,
): Map<string, ForensicEvent[]> {
  const out = new Map<string, ForensicEvent[]>();
  if (!names.size) return out;
  for (const e of events) {
    if (e.canonical?.mailbox || !e.asset) continue;
    const base = e.path ? baseOf(e.path) : lower(e.canonical?.file?.name);
    if (!base || !names.has(base)) continue;
    const list = out.get(e.asset) ?? out.set(e.asset, []).get(e.asset)!;
    if (list.length < EVIDENCE_PER_CELL_MAX) list.push(e);
  }
  return out;
}

function instanceIdOf(m: NonNullable<ForensicEvent["canonical"]>["mailbox"], eventId: string): string {
  const digests = (m?.attachments ?? [])
    .map((a) => a.sha256 ?? a.md5 ?? "")
    .filter(Boolean)
    .sort()
    .join(",");
  return m?.messageId ? `${lower(m.messageId)}|${lower(m.sender)}|${digests}` : `event:${eventId}`;
}

/** The campaign scope over the case, pure. */
export function campaignScope(
  state: InvestigationState,
  now: string = new Date().toISOString(),
): CampaignScope {
  const events = state.forensicTimeline;
  const messageRows = events.filter(
    (e) =>
      e.canonical?.mailbox &&
      (e.canonical.mailbox.attachments?.length || e.canonical.mailbox.recipients?.length),
  );
  const familiesByHost = new Map<string, Set<TelemetryFamily>>();
  for (const e of events) {
    if (!e.asset) continue;
    const f = familyOf(e);
    if (f) (familiesByHost.get(e.asset) ?? familiesByHost.set(e.asset, new Set()).get(e.asset)!).add(f);
  }
  const byDigest = indexByDigest(events);

  // Instances first, so shared attachments can be said across them.
  const instances = new Map<string, ForensicEvent>();
  for (const e of messageRows) {
    const id = instanceIdOf(e.canonical!.mailbox, e.id);
    if (!instances.has(id)) instances.set(id, e);
  }
  const ordered = [...instances.entries()].sort(
    (a, b) => (a[1].timestamp || "").localeCompare(b[1].timestamp || "") || a[0].localeCompare(b[0]),
  );
  const read = ordered.slice(0, MESSAGES_MAX);
  const digestToInstances = new Map<string, string[]>();
  for (const [id, e] of read)
    for (const a of e.canonical!.mailbox!.attachments ?? []) {
      const d = lower(a.sha256 ?? a.md5);
      if (d) (digestToInstances.get(d) ?? digestToInstances.set(d, []).get(d)!).push(id);
    }

  const messages: ScopeMessage[] = read.map(([instanceId, e]) => {
    const m = e.canonical!.mailbox!;
    const attachments: ScopeAttachment[] = (m.attachments ?? []).map((a) => ({
      name: a.name,
      ...(a.sha256 ? { sha256: a.sha256 } : {}),
      ...(a.md5 ? { md5: a.md5 } : {}),
      ...(a.digestUnavailable ? { digestUnavailable: a.digestUnavailable } : {}),
    }));
    // Recipients: To, Cc, and addresses a header indicates that are in neither.
    const recipientMap = new Map<string, ScopeRecipient>();
    const put = (address: string, addressed: ScopeRecipient["addressed"]) => {
      const a = lower(address);
      if (!a || recipientMap.has(a)) return;
      recipientMap.set(a, { address: a, addressed, hosts: [] });
    };
    for (const r of m.recipients ?? []) put(r, "to");
    for (const r of m.cc ?? []) put(r, "cc");
    for (const d of m.deliveryIndicated ?? []) {
      put(d.address, "indicated-only");
      const r = recipientMap.get(lower(d.address))!;
      r.indicatedBy = [...new Set([...(r.indicatedBy ?? []), d.by])];
    }
    const allRecipients = [...recipientMap.values()];
    const recipients = allRecipients.slice(0, RECIPIENTS_PER_MESSAGE_MAX);
    const recipientAddresses = recipients.map((r) => r.address);

    // Hosts: every host with a row carrying one of the attachment digests, plus name-only leads.
    const hosts = new Map<string, ScopeHost>();
    const hostFor = (host: string): ScopeHost =>
      hosts.get(host) ??
      hosts
        .set(host, {
          host,
          recipient: null,
          execution: "unknown",
          controls: [],
          present: false,
          evidence: { execution: [], control: [], present: [], more: 0 },
          leads: [],
          coverage: [...(familiesByHost.get(host) ?? [])],
        })
        .get(host)!;
    const pushEvidence = (h: ScopeHost, cell: "execution" | "control" | "present", id: string) => {
      if (h.evidence[cell].length < EVIDENCE_PER_CELL_MAX) h.evidence[cell].push(id);
      else h.evidence.more += 1;
    };
    // Rows past a digest's read bound may belong to any host: every host that has no digest
    // evidence of its own is then "incomplete", never "unknown".
    let unreadForMessage = 0;
    for (const a of attachments) {
      for (const d of [a.sha256, a.md5]) {
        const bucket = d ? byDigest.get(lower(d)) : undefined;
        if (!bucket) continue;
        unreadForMessage += bucket.notRead;
        for (const { e: row } of bucket.rows) {
          const host = hostOf(row);
          if (!host) continue;
          const h = hostFor(host);
          if (bucket.notRead) h.incomplete = { rowsNotRead: bucket.notRead };
          const who = recipientOfRow(row, recipientAddresses);
          const cls = classifyHit(row, 0).cls;
          const defender = row.canonical?.defender;
          if (defender && lower(defender.sha256) === lower(d)) {
            h.controls.push({ disposition: defender.disposition, at: row.timestamp, eventId: row.id });
            pushEvidence(h, "control", row.id);
            if (who) h.recipient ??= who;
          } else if (isProcessStart(row)) {
            h.execution = "observed";
            pushEvidence(h, "execution", row.id);
            if (who) h.recipient ??= who;
          } else if (
            cls === "presence" ||
            cls === "listing-of-older-object" ||
            cls === "activity" ||
            cls === "unclassified"
          ) {
            h.present = true;
            pushEvidence(h, "present", row.id);
            if (who) h.recipient ??= who;
          }
        }
      }
    }
    const names = new Set(attachments.map((a) => lower(a.name)).filter(Boolean));
    for (const [host, rows] of nameLeads(events, names)) {
      const h = hostFor(host);
      for (const row of rows)
        h.leads.push({
          kind: "name-only",
          eventId: row.id,
          note: "a file of this name — a name is not identity; no outcome is drawn from it",
        });
    }
    for (const h of hosts.values()) {
      if (unreadForMessage && !h.incomplete && h.execution === "unknown" && !h.controls.length && !h.present)
        h.incomplete = { rowsNotRead: unreadForMessage };
      h.controls.sort((x, y) => x.at.localeCompare(y.at) || x.eventId.localeCompare(y.eventId));
      if (h.recipient) {
        const r = recipientMap.get(h.recipient);
        if (r && !r.hosts.includes(h.host)) r.hosts.push(h.host);
      }
    }
    const hostList = [...hosts.values()].sort((a, b) => a.host.localeCompare(b.host));
    const huntLeads: string[] = [];
    for (const r of recipients)
      if (!r.hosts.length)
        huntLeads.push(
          `${r.address}: no endpoint row names this account — search the super-timeline for the account and for ${attachments.map((a) => a.sha256 ?? a.md5 ?? `"${a.name}" (name only)`).join(", ")}`,
        );
    for (const h of hostList.slice(0, HOSTS_MAX))
      if (h.execution === "unknown" && !h.controls.length && !h.present && !h.incomplete)
        huntLeads.push(
          `${h.host}: only a name-only lead — search the host for ${attachments.map((a) => a.sha256 ?? a.md5 ?? "(no digest)").join(", ")}`,
        );
    const sharedWith = [
      ...new Set(
        attachments
          .flatMap((a) => digestToInstances.get(lower(a.sha256 ?? a.md5)) ?? [])
          .filter((id) => id !== instanceId),
      ),
    ];
    return {
      instanceId,
      eventId: e.id,
      ...(m.messageId ? { messageId: m.messageId } : {}),
      ...(m.sender ? { sender: m.sender } : {}),
      ...(m.subject ? { subject: m.subject } : {}),
      date: e.timestamp,
      attachments,
      sharedWith,
      recipients,
      recipientsNotRead: Math.max(0, allRecipients.length - recipients.length),
      hosts: hostList.slice(0, HOSTS_MAX),
      hostsNotRead: Math.max(0, hostList.length - HOSTS_MAX),
      huntLeads,
    };
  });
  return { messages, messagesNotRead: Math.max(0, ordered.length - read.length), generated: now };
}
