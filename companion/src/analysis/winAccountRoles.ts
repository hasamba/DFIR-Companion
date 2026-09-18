// Who a Windows record establishes as ACTING, who initiated when that differs, the acting SID,
// and the typed Kerberos ticket request (#930 item 6). Read from named fields only; the
// description is never a contract.
//
// Roles per record: 4624 the logged-on account (Target); 4648 the credential used (Target) with
// the initiating Subject as `subject`; 4688 the process's account (Target when present, else the
// creating Subject, who then also is the initiator); Sysmon 1 the `User`; 4697 / 5140 / everything
// else the Subject. A Target that is "-" or "*" is no account.

export interface RoleEntity {
  kind: "account";
  name: string;
  domain?: string;
  id?: string;
}

import { objectAccessBlocks } from "./objectAccess.js";

export interface RoleBlocks {
  actor?: RoleEntity;
  /** The raw fields the actor was read from (provenance). */
  actorFields?: string[];
  subject?: RoleEntity;
  account?: { id?: string; name: string; domain?: string };
  event?: {
    category: "authentication" | "network" | "file" | "process" | "other";
    type: string;
    outcome?: "success" | "failed";
  };
  authentication?: { protocol?: "kerberos"; mechanism?: string; sessionId?: string };
  object?: RoleEntity;
  /** A Security object-access record's object and rights (objectAccess.ts). */
  file?: ReturnType<typeof objectAccessBlocks>["file"];
  /** The accessing process (4663 / 4656 / 4660) or the ended one (4689 / Sysmon 5). */
  process?: ReturnType<typeof objectAccessBlocks>["process"];
}

type Field = (key: string) => string;

const EXPLICIT_CREDENTIAL_LOGON = 4648;
const SHARE_ACCESS = 5140;
const TGS_REQUEST = 4769;
const TGT_REQUEST = 4768;
const SYSMON_PROCESS_CREATE = 1;

function entity(name: string, domain: string, sid: string): RoleEntity | undefined {
  const user = name.trim();
  if (!user || user === "-" || user === "*") return undefined;
  const dom = domain.trim();
  const hasRealDomain = !!dom && dom !== "-";
  const upnRealm = user.includes("@") ? user.slice(user.lastIndexOf("@") + 1) : "";
  const full = user.includes("@") || user.includes("\\") || !dom || dom === "-" ? user : `${dom}\\${user}`;
  // A separately-recorded, real domain (e.g. a 4624's NetBIOS TargetDomainName) is preferred over a
  // UPN's own realm when the two differ — the realm is often a DNS suffix that a `domain\user`
  // caller for the SAME session elsewhere would never spell that way (#1253). `name`/`full` are
  // left as the raw UPN either way; only which domain is reported changes.
  const realm = hasRealDomain ? dom : upnRealm || (full.includes("\\") ? full.split("\\")[0] : "");
  const id = sid.trim();
  return {
    kind: "account",
    name: full,
    ...(realm ? { domain: realm } : {}),
    ...(id && id !== "-" && id !== "S-1-0-0" ? { id } : {}),
  };
}

function ticketBlocks(eid: number, field: Field): Pick<RoleBlocks, "event" | "authentication" | "object"> {
  const status = field("Status").trim().toLowerCase();
  const outcome = !status || status === "0x0" || status === "0" ? "success" : "failed";
  const enc = field("TicketEncryptionType").trim().toLowerCase();
  const service = field("ServiceName").trim();
  return {
    event: {
      category: "authentication",
      type: eid === TGS_REQUEST ? "ticket-request" : "tgt-request",
      outcome,
    },
    authentication: { protocol: "kerberos", ...(enc ? { mechanism: enc } : {}) },
    ...(eid === TGS_REQUEST && service ? { object: { kind: "account", name: service } } : {}),
  };
}

/** The role blocks for one Windows / Sysmon record; empty when the record names no account. */
export function winRoleBlocks(eid: number, isSysmon: boolean, field: Field): RoleBlocks {
  if (isSysmon) {
    const user = eid === SYSMON_PROCESS_CREATE ? entity(field("User"), "", "") : undefined;
    return {
      ...(user
        ? {
            actor: user,
            actorFields: ["EventData.User"],
            account: { name: user.name, ...(user.domain ? { domain: user.domain } : {}) },
          }
        : {}),
      ...objectAccessBlocks(eid, true, field),
    };
  }
  const target = entity(field("TargetUserName"), field("TargetDomainName"), field("TargetUserSid"));
  const subject = entity(field("SubjectUserName"), field("SubjectDomainName"), field("SubjectUserSid"));
  const acting = target ?? subject;
  const initiator =
    target && subject && subject.name.toLowerCase() !== target.name.toLowerCase() ? subject : undefined;
  const out: RoleBlocks = {};
  if (acting) {
    const { id, ...actor } = acting;
    out.actor = actor;
    out.actorFields = target
      ? ["EventData.TargetDomainName", "EventData.TargetUserName"]
      : ["EventData.SubjectDomainName", "EventData.SubjectUserName"];
    out.account = {
      ...(id ? { id } : {}),
      name: acting.name,
      ...(acting.domain ? { domain: acting.domain } : {}),
    };
  }
  if (initiator) out.subject = initiator;
  if (eid === EXPLICIT_CREDENTIAL_LOGON)
    out.event = { category: "authentication", type: "explicit-credential-logon" };
  if (eid === SHARE_ACCESS) out.event = { category: "network", type: "share-access" };
  if (eid === TGS_REQUEST || eid === TGT_REQUEST) Object.assign(out, ticketBlocks(eid, field));
  // Object access and lifecycle rows (4663 / 4656 / 4658 / 4660 / 5145 / 4689 / logoff / boot).
  const oa = objectAccessBlocks(eid, false, field);
  if (oa.event) out.event = oa.event;
  if (oa.file) out.file = oa.file;
  if (oa.process) out.process = oa.process;
  if (oa.authentication) out.authentication = { ...out.authentication, ...oa.authentication };
  return out;
}
