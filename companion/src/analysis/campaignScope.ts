import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import type { ControlDisposition } from "./stateTypes.js";
import { classifyHit, familyOf } from "./remediationShapes.js";
import type { TelemetryFamily } from "./remediationBoundary.js";

// Phishing campaign scope (#930 item 2): starting from an imported message, which addresses were
// ADDRESSED, which mailbox a header INDICATES it reached, and — per host and per attributed
// recipient — what the host's own rows establish about the attachment: present, a control's
// disposition, a process start.
//
// WHAT ONE RECORD ESTABLISHES, AND NOTHING MORE.
//   - A recipient address establishes that the address was addressed. `Delivered-To` and the
//     topmost `Received … for` hop INDICATE delivery to one mailbox; neither is authenticated in
//     an exported file, so the word is "indicated", never "delivered".
//   - An endpoint row establishes what ITS shape says about the attachment's OWN digest (the
//     digest computed from the decoded base64 part — never a hash seen in the body): a listing,
//     presence or file-create row → present; a Defender record whose own digest matches → its
//     disposition; a process start → execution observed. A digest on a row of any other shape is a
//     lead. Execution and control are two axes and stay two (stateTypes.ts). An md5 match counts
//     only when neither side's sha256 disagrees.
//   - A row that matches by NAME only is a lead, never identity: shared filenames must not merge
//     unrelated activity. A container's digest is not its member's.
//   - Outcomes are kept PER HOST AND PER RECIPIENT: a row is attributed to a recipient only when
//     the row itself names that recipient's account as an SMTP address or UPN (a `DOMAIN\user`
//     logon name is not one; SYSTEM and service accounts never are); rows naming nobody or
//     someone else sit in the host's "recipient not established" entry. Two users' rows on one
//     workstation never share an entry, so nobody inherits another's execution.
//   - A message INSTANCE is Message-ID + sender + the attachment digest set; rows of one instance
//     are merged (recipients, indications, attachments unioned). A no-id message is its own
//     instance. Campaign linkage is explicit: instances that share an attachment digest are
//     "N other messages carry this attachment" — never on subject or date.
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
export const SHARED_WITH_MAX = 50;

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
  /** Hosts with an entry attributed to this recipient, among the hosts returned. */
  hosts: string[];
}

export interface ScopeHost {
  host: string;
  /** The recipient the entry's rows name, or null: "recipient not established". */
  recipient: string | null;
  execution: "observed" | "unknown";
  controls: { disposition: ControlDisposition; at: string; eventId: string }[];
  present: boolean;
  evidence: { execution: string[]; control: string[]; present: string[]; more: number };
  leads: { kind: "name-only" | "digest-on-other-shape"; eventId: string; note: string }[];
  coverage: TelemetryFamily[];
  /** Rows of this host and digest past the read bound: the entry may be missing outcomes. */
  incomplete?: { rowsNotRead: number };
}

export interface ScopeMessage {
  instanceId: string;
  eventIds: string[];
  messageId?: string;
  sender?: string;
  subject?: string;
  date: string;
  attachments: ScopeAttachment[];
  attachmentsNotRead: number;
  /** Other instances that carry one of this message's attachment digests (bounded, counted). */
  sharedWith: string[];
  sharedWithNotRead: number;
  recipients: ScopeRecipient[];
  recipientsNotRead: number;
  hosts: ScopeHost[];
  hostsNotRead: number;
  /** Hosts whose digest rows were ALL past the read bound: absent from `hosts`, counted here. */
  hostsUnread: number;
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

/** An SMTP address or UPN — local part and domain, joined by `@`. Anything else names no mailbox. */
function mailboxParts(name: string): { user: string; domain: string } | null {
  const s = lower(name);
  const at = s.indexOf("@");
  if (at <= 0 || at === s.length - 1 || s.includes("\\") || /\s/.test(s)) return null;
  return { user: s.slice(0, at), domain: s.slice(at + 1) };
}

const SERVICE_ACCOUNT = /^(system|local service|network service|nt authority\\.*|root|\$)$/i;

/** The recipient a row's own account names as an SMTP / UPN identity, exactly, or null. */
function recipientOfRow(e: ForensicEvent, recipients: ReadonlySet<string>): string | null {
  const c = e.canonical;
  const names = [c?.account?.name, c?.actor?.kind === "account" ? c.actor.name : undefined].filter(
    (n): n is string => !!n,
  );
  for (const n of names) {
    if (SERVICE_ACCOUNT.test(n.trim())) continue;
    const parts = mailboxParts(n);
    if (!parts) continue;
    const address = `${parts.user}@${parts.domain}`;
    if (recipients.has(address)) return address;
  }
  return null;
}

interface RowDigests {
  sha256?: string;
  md5?: string;
}

function digestsOf(e: ForensicEvent): RowDigests {
  const sha = lower(e.sha256 ?? e.canonical?.file?.sha256 ?? e.canonical?.defender?.sha256);
  const md5 = lower(e.md5 ?? e.canonical?.file?.md5);
  return { ...(sha ? { sha256: sha } : {}), ...(md5 ? { md5 } : {}) };
}

/** Whether a row's digests identify the attachment: sha256 equal, or md5 equal with no disagreeing sha256. */
function sameFile(row: RowDigests, a: ScopeAttachment): "sha256" | "md5" | null {
  const aSha = lower(a.sha256);
  const aMd5 = lower(a.md5);
  if (aSha && row.sha256 && row.sha256 === aSha) return "sha256";
  if (aMd5 && row.md5 && row.md5 === aMd5 && (!aSha || !row.sha256 || row.sha256 === aSha)) return "md5";
  return null;
}

interface DigestIndex {
  /** digest → host → rows read (bounded per digest, in timeline order). */
  rows: Map<string, Map<string, ForensicEvent[]>>;
  /** digest → host → rows past the bound. */
  notRead: Map<string, Map<string, number>>;
}

/** Rows carrying each digest, bounded per digest, with the unread count per host. */
function indexByDigest(events: readonly ForensicEvent[]): DigestIndex {
  const rows = new Map<string, Map<string, ForensicEvent[]>>();
  const notRead = new Map<string, Map<string, number>>();
  const readCount = new Map<string, number>();
  const add = (key: string, e: ForensicEvent) => {
    const host = (e.asset ?? "").trim();
    if (!host) return;
    const n = readCount.get(key) ?? 0;
    if (n < ROWS_PER_DIGEST_MAX) {
      readCount.set(key, n + 1);
      const byHost = rows.get(key) ?? rows.set(key, new Map()).get(key)!;
      (byHost.get(host) ?? byHost.set(host, []).get(host)!).push(e);
    } else {
      const byHost = notRead.get(key) ?? notRead.set(key, new Map()).get(key)!;
      byHost.set(host, (byHost.get(host) ?? 0) + 1);
    }
  };
  for (const e of events) {
    if (e.canonical?.mailbox) continue; // the message rows themselves are not endpoint rows
    const d = digestsOf(e);
    if (d.sha256) add(d.sha256, e);
    if (d.md5) add(d.md5, e);
  }
  return { rows, notRead };
}

const isProcessStart = (e: ForensicEvent): boolean =>
  e.canonical?.event?.category === "process" && e.canonical.event.type === "start";

/** Only an explicit file-presence shape says the file was present. */
function isPresenceShape(e: ForensicEvent): boolean {
  const cls = classifyHit(e, 0).cls;
  if (cls === "presence" || cls === "listing-of-older-object") return true;
  const ev = e.canonical?.event;
  if (ev?.category === "file" && ["create", "write", "modify", "observation", "listing"].includes(ev.type))
    return true;
  return /\bmft\b|mftecmd|amcache|shimcache|prefetch|directory listing|file listing/i.test(
    (e.sources ?? []).join(" "),
  );
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

type Mailbox = NonNullable<NonNullable<ForensicEvent["canonical"]>["mailbox"]>;

function instanceIdOf(m: Mailbox, eventId: string): string {
  const digests = (m.attachments ?? [])
    .map((a) => lower(a.sha256 ?? a.md5))
    .filter(Boolean)
    .sort()
    .join(",");
  return m.messageId ? `${lower(m.messageId)}|${lower(m.sender)}|${digests}` : `event:${eventId}`;
}

interface Instance {
  id: string;
  rows: ForensicEvent[];
  mailbox: Mailbox;
}

/** Rows of one instance merged: recipients, cc, indications and attachments unioned, first row's headers. */
function mergeInstance(rows: ForensicEvent[]): Mailbox {
  const first = rows[0].canonical!.mailbox!;
  const union = <T>(pick: (m: Mailbox) => T[] | undefined, key: (t: T) => string): T[] => {
    const seen = new Map<string, T>();
    for (const r of rows)
      for (const t of pick(r.canonical!.mailbox!) ?? []) if (!seen.has(key(t))) seen.set(key(t), t);
    return [...seen.values()];
  };
  const recipients = union((m) => m.recipients, lower);
  const cc = union((m) => m.cc, lower);
  const deliveryIndicated = union(
    (m) => m.deliveryIndicated,
    (d) => `${d.by}|${lower(d.address)}`,
  );
  const attachments = union(
    (m) => m.attachments,
    (a) => `${lower(a.name)}|${lower(a.sha256 ?? a.md5)}`,
  );
  const attachmentsNotRead = Math.max(...rows.map((r) => r.canonical!.mailbox!.attachmentsNotRead ?? 0));
  return {
    ...first,
    ...(recipients.length ? { recipients } : {}),
    ...(cc.length ? { cc } : {}),
    ...(deliveryIndicated.length ? { deliveryIndicated } : {}),
    ...(attachments.length ? { attachments } : {}),
    ...(attachmentsNotRead ? { attachmentsNotRead } : {}),
  };
}

/** The campaign scope over the case, pure. */
export function campaignScope(
  state: InvestigationState,
  now: string = new Date().toISOString(),
): CampaignScope {
  const events = state.forensicTimeline;
  const familiesByHost = new Map<string, Set<TelemetryFamily>>();
  for (const e of events) {
    if (!e.asset) continue;
    const f = familyOf(e);
    if (f) (familiesByHost.get(e.asset) ?? familiesByHost.set(e.asset, new Set()).get(e.asset)!).add(f);
  }
  const index = indexByDigest(events);

  // Instances: every row of one identity merged.
  const instances = new Map<string, Instance>();
  for (const e of events) {
    const m = e.canonical?.mailbox;
    if (!m || !(m.attachments?.length || m.recipients?.length)) continue;
    const id = instanceIdOf(m, e.id);
    const inst = instances.get(id) ?? instances.set(id, { id, rows: [], mailbox: m }).get(id)!;
    inst.rows.push(e);
  }
  for (const inst of instances.values()) inst.mailbox = mergeInstance(inst.rows);
  const ordered = [...instances.values()].sort(
    (a, b) =>
      (a.rows[0].timestamp || "").localeCompare(b.rows[0].timestamp || "") || a.id.localeCompare(b.id),
  );
  // Linkage over EVERY instance, so a displayed message's count is not smaller than the truth.
  const digestToInstances = new Map<string, string[]>();
  for (const inst of ordered)
    for (const a of inst.mailbox.attachments ?? []) {
      const d = lower(a.sha256 ?? a.md5);
      if (d) (digestToInstances.get(d) ?? digestToInstances.set(d, []).get(d)!).push(inst.id);
    }
  const read = ordered.slice(0, MESSAGES_MAX);

  const messages: ScopeMessage[] = read.map((inst) => {
    const m = inst.mailbox;
    const attachments: ScopeAttachment[] = (m.attachments ?? []).map((a) => ({
      name: a.name,
      ...(a.sha256 ? { sha256: lower(a.sha256) } : {}),
      ...(a.md5 ? { md5: lower(a.md5) } : {}),
      ...(a.digestUnavailable ? { digestUnavailable: a.digestUnavailable } : {}),
    }));
    // Recipients: To, Cc, and addresses a header indicates that are in neither. Every recipient
    // is matched against; only the LIST is bounded.
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
    const lookup = new Set(recipientMap.keys());
    const allRecipients = [...recipientMap.values()];
    const recipients = allRecipients.slice(0, RECIPIENTS_PER_MESSAGE_MAX);

    // Host entries keyed by (host, recipient | null).
    const entries = new Map<string, ScopeHost>();
    const entryFor = (host: string, recipient: string | null): ScopeHost => {
      const key = `${host} ${recipient ?? ""}`;
      return (
        entries.get(key) ??
        entries
          .set(key, {
            host,
            recipient,
            execution: "unknown",
            controls: [],
            present: false,
            evidence: { execution: [], control: [], present: [], more: 0 },
            leads: [],
            coverage: [...(familiesByHost.get(host) ?? [])],
          })
          .get(key)!
      );
    };
    const pushEvidence = (h: ScopeHost, cell: "execution" | "control" | "present", id: string) => {
      if (h.evidence[cell].length < EVIDENCE_PER_CELL_MAX) h.evidence[cell].push(id);
      else h.evidence.more += 1;
    };
    const unreadByHost = new Map<string, number>();
    const seenRows = new Set<string>();
    for (const a of attachments) {
      for (const d of [a.sha256, a.md5]) {
        if (!d) continue;
        for (const [host, n] of index.notRead.get(d) ?? [])
          unreadByHost.set(host, (unreadByHost.get(host) ?? 0) + n);
        for (const [host, rows] of index.rows.get(d) ?? []) {
          for (const row of rows) {
            const by = sameFile(digestsOf(row), a);
            if (!by) continue; // an md5 met with a disagreeing sha256 is another file
            const seenKey = `${a.name}|${row.id}`;
            if (seenRows.has(seenKey)) continue;
            seenRows.add(seenKey);
            const who = recipientOfRow(row, lookup);
            const h = entryFor(host, who);
            const defender = row.canonical?.defender;
            if (defender && lower(defender.sha256) === lower(a.sha256)) {
              h.controls.push({ disposition: defender.disposition, at: row.timestamp, eventId: row.id });
              pushEvidence(h, "control", row.id);
            } else if (isProcessStart(row)) {
              h.execution = "observed";
              pushEvidence(h, "execution", row.id);
            } else if (isPresenceShape(row)) {
              h.present = true;
              pushEvidence(h, "present", row.id);
            } else if (h.leads.length < EVIDENCE_PER_CELL_MAX)
              h.leads.push({
                kind: "digest-on-other-shape",
                eventId: row.id,
                note: `the digest (${by}) on a row whose shape establishes neither a start, a control nor presence`,
              });
          }
        }
      }
    }
    // Name-only leads for hosts with NO digest-bearing entry: where the digest already spoke, a
    // name adds nothing and must not read as a second sighting.
    const names = new Set(attachments.map((a) => lower(a.name)).filter(Boolean));
    const hostsWithDigest = new Set([...entries.values()].map((h) => h.host));
    for (const [host, rows] of nameLeads(events, names)) {
      if (hostsWithDigest.has(host)) continue;
      const h = entryFor(host, null);
      for (const row of rows)
        if (h.leads.length < EVIDENCE_PER_CELL_MAX)
          h.leads.push({
            kind: "name-only",
            eventId: row.id,
            note: "a file of this name — a name is not identity; no outcome is drawn from it",
          });
    }
    // Unread rows: an entry of that host is incomplete; a host with ONLY unread rows and no entry
    // is counted, never shown as absent.
    let hostsUnread = 0;
    for (const [host, n] of unreadByHost) {
      const own = [...entries.values()].filter((h) => h.host === host);
      if (own.length) for (const h of own) h.incomplete = { rowsNotRead: n };
      else hostsUnread += 1;
    }
    for (const h of entries.values())
      h.controls.sort((x, y) => x.at.localeCompare(y.at) || x.eventId.localeCompare(y.eventId));
    // Outcome-bearing entries first within the host budget; lead-only entries after.
    const hasOutcome = (h: ScopeHost) => h.execution === "observed" || h.controls.length > 0 || h.present;
    const sorted = [...entries.values()].sort(
      (a, b) =>
        Number(hasOutcome(b)) - Number(hasOutcome(a)) ||
        a.host.localeCompare(b.host) ||
        (a.recipient ?? "").localeCompare(b.recipient ?? ""),
    );
    const hosts = sorted.slice(0, HOSTS_MAX);
    for (const h of hosts) {
      if (!h.recipient) continue;
      const r = recipientMap.get(h.recipient);
      if (r && !r.hosts.includes(h.host)) r.hosts.push(h.host);
    }
    const huntLeads: string[] = [];
    const digestWords = attachments.map((a) => a.sha256 ?? a.md5 ?? `"${a.name}" (name only)`).join(", ");
    for (const r of recipients)
      if (!r.hosts.length)
        huntLeads.push(
          `${r.address}: no endpoint row names this account — search the super-timeline for the account and for ${digestWords}`,
        );
    for (const h of hosts)
      if (!hasOutcome(h) && !h.incomplete && h.leads.every((l) => l.kind === "name-only"))
        huntLeads.push(`${h.host}: only a name-only lead — search the host for ${digestWords}`);
    const linked = [
      ...new Set(
        attachments
          .flatMap((a) => digestToInstances.get(lower(a.sha256 ?? a.md5)) ?? [])
          .filter((id) => id !== inst.id),
      ),
    ];
    return {
      instanceId: inst.id,
      eventIds: inst.rows.map((r) => r.id),
      ...(m.messageId ? { messageId: m.messageId } : {}),
      ...(m.sender ? { sender: m.sender } : {}),
      ...(m.subject ? { subject: m.subject } : {}),
      date: inst.rows[0].timestamp,
      attachments,
      attachmentsNotRead: m.attachmentsNotRead ?? 0,
      sharedWith: linked.slice(0, SHARED_WITH_MAX),
      sharedWithNotRead: Math.max(0, linked.length - SHARED_WITH_MAX),
      recipients,
      recipientsNotRead: Math.max(0, allRecipients.length - recipients.length),
      hosts,
      hostsNotRead: Math.max(0, sorted.length - hosts.length),
      hostsUnread,
      huntLeads,
    };
  });
  return { messages, messagesNotRead: Math.max(0, ordered.length - read.length), generated: now };
}
