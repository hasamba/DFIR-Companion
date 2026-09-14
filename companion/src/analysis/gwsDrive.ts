// Google Drive audit records read for what they state (#931 item 11, record half): a sharing
// change's permission direction along the documented chain, Google's own overall-visibility
// direction (`visibility_change`), the resulting visibility, the target as recorded; an access
// record's meaning (`download recorded`, `previewed`, `item content synced`, …). The decoder
// supplies the words, the grade and the envelope block; googleWorkspaceImport.ts calls it for
// every `drive` event and keeps the generic path for the events it does not name.
//
// What one row rests on, and what it never says:
//   - direction is classified only along `none < can_view < can_comment < can_edit < organizer
//     < owner` and `private < people_within_domain_with_link < public_in_the_domain <
//     people_with_link < public_on_the_web`; a transition through a resource-specific or unknown
//     value is "direction not established" with both values shown;
//   - "newly external" comes only from `visibility_change = external`; a differing address
//     domain is said as "the recorded address domains differ" and grades nothing;
//   - `target_user` may be a user, a group or a domain — the record does not say which;
//   - a `*_hierarchy_reconciled` row and a `primary_event=false` row are events, not actions;
//   - a preview or a view is never a download; a missing actor is missing identity, never
//     "anonymous"; the document is identified by `doc_id` alone — a title is a label.

import type { Severity } from "./stateTypes.js";
import type { DriveAccessBlock, DriveDirection, DriveSharingBlock } from "./canonicalGwsDrive.js";
import type { GwsParam } from "./gwsOAuth.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";

const NAME_MAX = 80;
const TOTAL_MAX = 600;
const HEAD_MAX = 120;
const DIRECTION_MAX = 130;
const TARGET_MAX = 160;
const VISIBILITY_MAX = 80;
const OBJECT_MAX = 150;
const QUALIFIERS_MAX = 130;
const PRODUCT_NUMBER_MAX = 30;
const FORMAT_CHARS = /[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;

/** The documented permission chain — anything else is resource-specific or unknown. */
const PERMISSION_RANK: Record<string, number> = {
  none: 0,
  can_view: 1,
  can_comment: 2,
  can_edit: 3,
  organizer: 4,
  owner: 5,
};
/** The documented link / audience states, ranked apart. */
const VISIBILITY_RANK: Record<string, number> = {
  private: 0,
  people_within_domain_with_link: 1,
  public_in_the_domain: 2,
  people_with_link: 3,
  public_on_the_web: 4,
};
const AUDIENCE_WORDS: Record<string, string> = {
  people_with_link: "anyone with the link",
  people_within_domain_with_link: "anyone in the domain with the link",
  public_in_the_domain: "anyone in the domain",
  public_on_the_web: "anyone on the web",
  private: "no link audience",
};
/** Shared-drive roles in capability order (`none` lowest). */
const ROLE_RANK: Record<string, number> = {
  none: 0,
  viewer: 1,
  commenter: 2,
  editor: 3,
  content_manager: 4,
  organizer: 5,
};
const LINK_AUDIENCES = new Set(["people_with_link", "public_on_the_web"]);
const SHARING_EVENTS = new Set([
  "change_user_access",
  "change_document_visibility",
  "change_document_access_scope",
  "change_acl_editors",
  "change_owner",
  "shared_drive_membership_change",
  "change_user_access_hierarchy_reconciled",
  "change_document_visibility_hierarchy_reconciled",
  "change_document_access_scope_hierarchy_reconciled",
  "change_owner_hierarchy_reconciled",
  "disable_inherited_permissions",
  "enable_inherited_permissions",
]);
/** Access events with a stated meaning; any other `access` event keeps the importer's generic row. */
const ACCESS_MEANING: Record<string, string> = {
  view: "viewed",
  preview: "previewed",
  download: "download recorded",
  download_forms_response: "form responses download recorded",
  copy: "copied",
  source_copy: "copied from (source of a copy)",
  print: "printed",
  edit: "edited",
  email_as_attachment: "sent as an attachment",
  sync_item_content: "item content synced",
  access_item_content: "an application accessed content on behalf of the recorded user",
  prefetch_item_content: "an application prefetched content on behalf of the recorded user",
  access_url: "URL accessed",
};
const ACCESS_SEVERITY: Record<string, Severity> = {
  download: "Low",
  copy: "Low",
  download_forms_response: "Low",
  source_copy: "Low",
};
const ACCESS_MITRE: Record<string, string[]> = {
  download: ["T1530"],
  copy: ["T1530"],
  download_forms_response: ["T1530"],
  source_copy: ["T1530"],
};

export interface GwsDriveReading {
  kind: "sharing" | "access";
  severity: Severity;
  mitre: string[];
  /** The words after the head, in fixed bounded slots. */
  direction: string;
  target: string;
  visibility: string;
  object: string;
  qualifiers: string[];
  /** Key segment: every discriminator of the change, length-delimited, lowercased by the caller. */
  keySegment: string;
  docId: string;
  docTitle: string;
  /** No `doc_id` on the record — the row keys on its locator and never folds. */
  incomplete: boolean;
  actorIdentified: boolean;
  block: { sharing: DriveSharingBlock } | { access: DriveAccessBlock };
}

const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v.replace(FORMAT_CHARS, "")));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const lower = (s: string): string => s.trim().toLowerCase();
const seg = (v: string): string => `${v.length}:${v}`;
const find = (params: readonly GwsParam[], name: string): GwsParam | undefined =>
  params.find((p) => p.name.toLowerCase() === name.toLowerCase());
const text = (params: readonly GwsParam[], name: string): string => (find(params, name)?.value ?? "").trim();
const bool = (params: readonly GwsParam[], name: string, dflt: boolean): boolean =>
  find(params, name)?.boolValue ?? dflt;
const domainOf = (address: string): string => {
  const at = address.lastIndexOf("@");
  return at > 0 && at < address.length - 1 ? lower(address.slice(at + 1)) : "";
};

interface Doc {
  id: string;
  title: string;
  type: string;
  owner: string;
  ownerIsSharedDrive: boolean;
  sharedDriveId: string;
}
const readDoc = (params: readonly GwsParam[]): Doc => ({
  id: text(params, "doc_id"),
  title: text(params, "doc_title"),
  type: text(params, "doc_type"),
  owner: text(params, "owner"),
  ownerIsSharedDrive: bool(params, "owner_is_shared_drive", false),
  sharedDriveId: text(params, "shared_drive_id") || text(params, "owner_shared_drive_id"),
});
const docWords = (d: Doc): string => {
  const drive = d.sharedDriveId ? show(d.sharedDriveId, 30) : "";
  const owner = d.ownerIsSharedDrive
    ? `shared drive ${show(d.owner, 50) || "(unnamed)"}${drive ? ` (${drive})` : ""}`
    : `${d.owner ? `owner ${show(d.owner, 50)}` : ""}${drive ? `${d.owner ? ", " : ""}shared drive ${drive}` : ""}`;
  return d.id
    ? `on ${show(d.title, 60) || "(untitled)"} (doc ${show(d.id, 50)}${d.type ? `, ${show(d.type, 20)}` : ""}${owner ? `, ${owner}` : ""})`
    : `on ${show(d.title, 60) || "(untitled)"} — document not identified in this record`;
};

// ───────────────────────────── direction ─────────────────────────────

interface Direction {
  direction: DriveDirection;
  words: string;
}
/** Direction along a documented rank table; anything off the table is "not established" with the values shown. */
function directionOf(
  from: string,
  to: string,
  rank: Record<string, number>,
  toWords: (v: string) => string,
): Direction {
  const f = lower(from);
  const t = lower(to);
  const pair = `${show(from, 40) || "(not recorded)"} → ${show(to, 40) || "(not recorded)"}`;
  if (!f || !t) return { direction: "not-established", words: `direction not established: ${pair}` };
  if (f === t) return { direction: "same", words: `no change in level: ${pair}` };
  const rf = rank[f];
  const rt = rank[t];
  // `none` compares with anything: a grant from nothing broadens, a removal narrows.
  if (f === "none" && rt === undefined)
    return { direction: "broadens", words: `broadens: ${pair}${toWords(t)}` };
  if (t === "none" && rf === undefined)
    return { direction: "narrows", words: `narrows: ${pair} (access removed)` };
  if (rf === undefined || rt === undefined)
    return { direction: "not-established", words: `direction not established: ${pair}` };
  if (rt > rf) return { direction: "broadens", words: `broadens: ${pair}${toWords(t)}` };
  return {
    direction: "narrows",
    words: `narrows: ${pair}${t === "none" ? " (access removed)" : toWords(t)}`,
  };
}
const audience = (v: string): string => (AUDIENCE_WORDS[v] ? ` (${AUDIENCE_WORDS[v]})` : "");

function visibilityWords(change: string, visibility: string): string {
  const now = visibility ? `; now ${show(visibility, 40)}` : "";
  switch (lower(change)) {
    case "external":
      return `overall visibility newly external${now}`;
    case "internal":
      return `overall visibility back to internal${now}`;
    case "none":
      return `overall visibility unchanged${now}`;
    default:
      return visibility ? `visibility now ${show(visibility, 40)}` : "";
  }
}

// ───────────────────────────── the sharing reading ─────────────────────────────

function readSharing(name: string, params: readonly GwsParam[]): GwsDriveReading {
  const doc = readDoc(params);
  const reconciled = name.endsWith("_hierarchy_reconciled");
  const base = reconciled ? name.replace(/_hierarchy_reconciled$/, "") : name;
  const primary = bool(params, "primary_event", true);
  const from = text(params, "old_value");
  const to = text(params, "new_value");
  const target = text(params, "target_user");
  const targetDomain = text(params, "target_domain");
  const visibilityChange = text(params, "visibility_change");
  const visibility = text(params, "visibility");
  const oldVisibility = text(params, "old_visibility");
  const originatingApp = text(params, "originating_app_id");
  const collaborator = bool(params, "actor_is_collaborator_account", false);
  const membership = text(params, "membership_change_type");
  const addedRole = text(params, "added_role");
  const removedRole = text(params, "removed_role");
  const targetDomainDiffers = Boolean(
    domainOf(target) && domainOf(doc.owner) && domainOf(target) !== domainOf(doc.owner),
  );
  const targetWords = target
    ? `for ${show(target, 60)} (may be a user, a group or a domain${targetDomainDiffers ? "; the recorded address domains differ" : ""})`
    : "";

  let dir: Direction = { direction: "not-established", words: "" };
  let severity: Severity = "Low";
  const mitre: string[] = [];
  let targetLine = targetWords;
  switch (base) {
    case "change_user_access": {
      dir = directionOf(from, to, PERMISSION_RANK, () => "");
      severity =
        dir.direction === "broadens"
          ? (PERMISSION_RANK[lower(to)] ?? 0) >= PERMISSION_RANK.can_edit
            ? "Medium"
            : "Low"
          : dir.direction === "not-established"
            ? "Medium"
            : "Low";
      break;
    }
    case "change_document_visibility": {
      dir = directionOf(from, to, VISIBILITY_RANK, audience);
      severity =
        dir.direction === "broadens"
          ? LINK_AUDIENCES.has(lower(to))
            ? "High"
            : "Medium"
          : dir.direction === "not-established"
            ? "Medium"
            : "Low";
      targetLine = "";
      break;
    }
    case "change_document_access_scope": {
      dir = directionOf(from, to, PERMISSION_RANK, () => "");
      const all = lower(targetDomain) === "all";
      targetLine = targetDomain
        ? all
          ? "for the link across all domains with visibility"
          : `for the link in domain ${show(targetDomain, 60)}`
        : "for the link (domain not recorded)";
      severity =
        dir.direction === "broadens"
          ? all
            ? "High"
            : (PERMISSION_RANK[lower(to)] ?? 0) >= PERMISSION_RANK.can_edit
              ? "Medium"
              : "Low"
          : dir.direction === "not-established"
            ? "Medium"
            : "Low";
      break;
    }
    case "change_acl_editors": {
      const writers = lower(to) === "writers";
      dir = {
        direction: writers ? "broadens" : lower(to) === "owner" ? "narrows" : "not-established",
        words: writers
          ? `writers may now change sharing (was: ${show(from, 20) || "not recorded"})`
          : lower(to) === "owner"
            ? `only the owner may now change sharing (was: ${show(from, 20) || "not recorded"})`
            : `direction not established: ${show(from, 20) || "(not recorded)"} → ${show(to, 20) || "(not recorded)"}`,
      };
      severity = writers ? "Medium" : dir.direction === "not-established" ? "Medium" : "Low";
      targetLine = "";
      break;
    }
    case "change_owner": {
      const newOwner = to || target;
      dir = {
        direction: "broadens",
        words: `ownership transferred to ${show(newOwner, 60) || "(not recorded)"}${from ? ` (was: ${show(from, 60)})` : ""}`,
      };
      severity = "Medium";
      targetLine = "";
      break;
    }
    case "shared_drive_membership_change": {
      const kind = lower(membership);
      const added = lower(addedRole);
      const removed = lower(removedRole);
      const who = show(target, 60) || "(member not recorded)";
      const roleUp = (ROLE_RANK[added] ?? -1) > (ROLE_RANK[removed] ?? -1);
      if (kind === "add_to_shared_drive")
        dir = {
          direction: "broadens",
          words: `${kind}: ${who} added as ${show(addedRole, 20) || "(role not recorded)"}`,
        };
      else if (kind === "remove_from_shared_drive")
        dir = {
          direction: "narrows",
          words: `${kind}: ${who} removed from ${show(removedRole, 20) || "(role not recorded)"}`,
        };
      else if (kind === "change_roles" || kind === "re_share")
        dir = {
          direction:
            ROLE_RANK[added] === undefined || ROLE_RANK[removed] === undefined
              ? "not-established"
              : roleUp
                ? "broadens"
                : "narrows",
          words: `${kind}: ${who} ${show(removedRole, 20) || "(none)"} → ${show(addedRole, 20) || "(none)"}`,
        };
      else
        dir = {
          direction: "not-established",
          words: `membership change ${show(membership, 30) || "(type not recorded)"}: ${who}`,
        };
      severity =
        dir.direction === "broadens" ? "Medium" : dir.direction === "not-established" ? "Medium" : "Low";
      targetLine = "";
      break;
    }
    case "disable_inherited_permissions":
    case "enable_inherited_permissions": {
      dir = {
        direction: "not-established",
        words: `inherited permissions ${base === "disable_inherited_permissions" ? "disabled" : "enabled"} — direction not established by this record`,
      };
      severity = "Low";
      targetLine = "";
      break;
    }
  }
  // Google's own overall-visibility direction is the only source of "newly external".
  if (lower(visibilityChange) === "external") {
    severity = "High";
    mitre.push("T1537");
  } else if (severity === "High") mitre.push("T1537");
  const qualifiers = [
    ...(reconciled ? ["reconciled from a parent folder change — not an action on this item"] : []),
    ...(!primary && !reconciled ? ["side effect of another event (primary_event=false)"] : []),
    ...(originatingApp ? [`by application project ${show(originatingApp, PRODUCT_NUMBER_MAX)}`] : []),
    ...(collaborator ? ["actor is a collaborator account"] : []),
  ];
  // A reconciled child row or a side effect is an event, not an action: one folder change fans
  // out to thousands of these, so they never enter the forensic timeline on their own.
  if (reconciled || !primary) {
    severity = "Info";
    mitre.length = 0;
  }
  const block: DriveSharingBlock = {
    ...(doc.id ? { docId: doc.id } : {}),
    ...(doc.title ? { docTitle: doc.title } : {}),
    ...(doc.type ? { docType: doc.type } : {}),
    ...(doc.owner ? { owner: doc.owner } : {}),
    ownerIsSharedDrive: doc.ownerIsSharedDrive,
    ...(doc.sharedDriveId ? { sharedDriveId: doc.sharedDriveId } : {}),
    direction: dir.direction,
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    ...(target ? { target } : {}),
    ...(targetDomain ? { targetDomain } : {}),
    targetDomainDiffers,
    ...(visibilityChange ? { visibilityChange } : {}),
    ...(visibility ? { visibility } : {}),
    ...(oldVisibility ? { oldVisibility } : {}),
    ...(membership ? { membershipChange: membership } : {}),
    ...(addedRole ? { addedRole } : {}),
    ...(removedRole ? { removedRole } : {}),
    primary,
    reconciled,
    ...(originatingApp ? { originatingApp } : {}),
    collaboratorAccount: collaborator,
  };
  return {
    kind: "sharing",
    severity,
    mitre,
    direction: dir.words,
    target: targetLine,
    visibility: visibilityWords(visibilityChange, visibility),
    object: docWords(doc),
    qualifiers,
    keySegment: `|drive-sharing|${[doc.id, target, targetDomain, dir.direction, from, to, visibilityChange, membership, addedRole, removedRole, originatingApp, primary ? "p" : "s"].map(seg).join("|")}`,
    docId: doc.id,
    docTitle: doc.title,
    incomplete: !doc.id,
    actorIdentified: true,
    block: { sharing: block },
  };
}

// ───────────────────────────── the access reading ─────────────────────────────

function readAccess(name: string, params: readonly GwsParam[], actorIdentified: boolean): GwsDriveReading {
  const doc = readDoc(params);
  const meaning = ACCESS_MEANING[name];
  const originatingApp = text(params, "originating_app_id");
  const apiMethod = text(params, "api_method");
  const visibility = text(params, "visibility");
  const primary = bool(params, "primary_event", true);
  const words =
    name === "download" && originatingApp
      ? `download recorded by application project ${show(originatingApp, PRODUCT_NUMBER_MAX)} — an application's fetch, not shown to be a person's download`
      : meaning;
  const block: DriveAccessBlock = {
    ...(doc.id ? { docId: doc.id } : {}),
    ...(doc.title ? { docTitle: doc.title } : {}),
    ...(doc.type ? { docType: doc.type } : {}),
    ...(doc.owner ? { owner: doc.owner } : {}),
    meaning: words,
    ...(visibility ? { visibility } : {}),
    ...(originatingApp ? { originatingApp } : {}),
    ...(apiMethod ? { apiMethod } : {}),
    actorIdentified,
    primary,
  };
  return {
    kind: "access",
    severity: ACCESS_SEVERITY[name] ?? "Info",
    mitre: [...(ACCESS_MITRE[name] ?? [])],
    direction: words,
    target: "",
    visibility: visibility ? `visibility at the time: ${show(visibility, 40)}` : "",
    object: docWords(doc),
    qualifiers: [
      ...(originatingApp && !(name === "download")
        ? [`by application project ${show(originatingApp, PRODUCT_NUMBER_MAX)}`]
        : []),
      ...(apiMethod ? [`api_method ${show(apiMethod, 60)}`] : []),
      ...(actorIdentified ? [] : ["no actor identity in this record"]),
      ...(!primary ? ["side effect of another event (primary_event=false)"] : []),
    ],
    keySegment: `|drive-access|${[doc.id, originatingApp, apiMethod, visibility].map(seg).join("|")}`,
    docId: doc.id,
    docTitle: doc.title,
    incomplete: !doc.id,
    actorIdentified,
    block: { access: block },
  };
}

/** Decode a Drive audit event, or null when the decoder has no reading for its name. */
export function decodeGwsDrive(
  eventName: string,
  params: readonly GwsParam[],
  actorIdentified = true,
): GwsDriveReading | null {
  const name = lower(eventName);
  if (SHARING_EVENTS.has(name)) return readSharing(name, params);
  if (ACCESS_MEANING[name]) return readAccess(name, params, actorIdentified);
  return null;
}

/** The row's words: fixed, individually bounded slots — the head and the direction always survive. */
export function renderDriveDescription(head: string, r: GwsDriveReading): string {
  const clip = (s: string, max: number): string => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);
  // The direction and its target are one sentence; the other slots are joined with dashes.
  const sentence = [clip(r.direction.trim(), DIRECTION_MAX), clip(r.target.trim(), TARGET_MAX)]
    .filter(Boolean)
    .join(" ");
  const parts = [
    clip(head.trim(), HEAD_MAX),
    sentence,
    clip(r.visibility.trim(), VISIBILITY_MAX),
    clip(r.object.trim(), OBJECT_MAX),
  ].filter(Boolean);
  const qualifiers = clip(r.qualifiers.filter(Boolean).join("; "), QUALIFIERS_MAX);
  const body = parts.join(" — ");
  return `${body}${qualifiers ? ` [${qualifiers}]` : ""}`.slice(0, TOTAL_MAX);
}
