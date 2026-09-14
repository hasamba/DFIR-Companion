import type { InvestigationState } from "../analysis/stateTypes.js";
import { sensitiveAccess, type AccessRecord } from "../analysis/sensitiveAccess.js";
import { cellMd } from "./mdText.js";

/**
 * "Sensitive access" section (#930 item 7): per declared sensitive location, each object under
 * it with the stage the case establishes — access recorded (a 4663), data read (a read right on
 * an object evidenced as a file at that time), read by a candidate instance (one process start
 * with that pid and image on the host before the access), corroborated suspicious read (that
 * candidate's own process row or its session's logon graded High or above). Accessed, later
 * archive activity and later network connections are three columns; none implies the next.
 * A handle request is not an access; a listing is not a read; a filename is not sensitivity.
 */
export function sensitiveAccessSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Sensitive access", "");
  const locations = state.sensitiveLocations ?? [];
  if (!locations.length) {
    lines.push(
      "No sensitive location has been declared for this case — an object-access row is not a sensitive read without one.",
      "",
    );
    return;
  }
  const r = sensitiveAccess(state, locations);
  lines.push(
    "A 4663 establishes that a process exercised rights on an object; `0x1` is a read only when the object is evidenced as a file at that time, otherwise a read or a directory listing. The process instance and the logon session are candidates joined by pid and logon id on the host. Suspicious is what the candidate's own rows already carry. Later archive activity and later connections by the same process GUID are subsequent activity, not staging or transfer.",
    "",
  );
  for (const l of r.locations) {
    lines.push(
      `### ${cellMd(l.location.path)} (${l.location.kind}, ${l.location.host ? cellMd(l.location.host) : "any host"})`,
      "",
      `${cellMd(l.note)}.`,
      "",
    );
    if (!l.objects.length) continue;
    lines.push("| Object | Host | Stage | Accesses | Reason |", "|---|---|---|---|---|");
    for (const o of l.objects)
      lines.push(
        `| ${cellMd(o.path)} | ${cellMd(o.host)} | ${o.stage} | ${o.accessesTotal} (${o.evidenceTotals["data-read"]} data read(s), ${o.evidenceTotals["corroborated-suspicious-read"]} corroborated) | ${cellMd(o.stageReason)} |`,
      );
    if (l.objectsTotal > l.objects.length)
      lines.push(`| … | | | | ${l.objectsTotal - l.objects.length} more object(s) not shown |`);
    lines.push("");
    for (const o of l.objects) {
      if (!o.accesses.length) continue;
      lines.push(
        `#### ${cellMd(o.path)} — accesses`,
        "",
        "| Row | Time | Kind | Rights | Data read | Account | Process (pid) | Instance | Session | Corroboration | Later archive create | Later connection | Deletion candidate |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
      );
      for (const a of o.accesses) lines.push(accessRow(a));
      if (o.accessesTotal > o.accesses.length)
        lines.push(`| … | | | | | | | | | | | | ${o.accessesTotal - o.accesses.length} more not shown |`);
      lines.push("");
    }
    for (const h of l.hostsRead)
      if (h.accessRowsUnread || h.contextRowsUnread)
        lines.push(
          `- ${cellMd(h.host)}: ${h.accessRowsUnread} object-access row(s) and ${h.contextRowsUnread} handle-request / share-check row(s) past the read bound, not read.`,
        );
  }
  if (r.collections.length) {
    lines.push(
      "### Collection shapes",
      "",
      "| Host | Instance | Image | Objects | Window | State | Note |",
      "|---|---|---|---|---|---|---|",
    );
    for (const c of r.collections)
      lines.push(
        `| ${cellMd(c.host)} | ${cellMd(c.instance)} | ${cellMd(c.image ?? "")} | ${c.objects} | ${cellMd(c.from)} → ${cellMd(c.to)} | ${c.state} | ${cellMd(c.note)} |`,
      );
    lines.push("");
  }
  lines.push(
    "### Hosts",
    "",
    "| Host | Object-access rows | Handle-request / share-check rows | Span | Process starts | Logons | Note |",
    "|---|---|---|---|---|---|---|",
  );
  for (const h of r.hosts)
    lines.push(
      `| ${cellMd(h.host)} | ${h.accessRows}${h.accessRowsUnread ? ` (+${h.accessRowsUnread} unread)` : ""} | ${h.contextRows}${h.contextRowsUnread ? ` (+${h.contextRowsUnread} unread)` : ""} | ${h.span ? `${cellMd(h.span[0])} → ${cellMd(h.span[1])}` : "—"} | ${h.processStarts} | ${h.logons} | ${cellMd(h.note)} |`,
    );
  lines.push("");
}

function accessRow(a: AccessRecord): string {
  const inst = `${a.instance.state}${a.instance.startEventId ? ` (${cellMd(a.instance.startEventId)})` : ""}: ${cellMd(a.instance.reason)}`;
  const sess = `${a.session.state}${a.session.logonEventId ? ` (${cellMd(a.session.logonEventId)}${a.session.logonType !== undefined ? `, type ${a.session.logonType}` : ""}${a.session.sourceAddress ? `, from ${cellMd(a.session.sourceAddress)}` : ""})` : ""}: ${cellMd(a.session.reason)}`;
  return `| ${cellMd(a.eventId)} | ${cellMd(a.at)} | ${a.kind} | ${cellMd(a.rights.join(", ") || "—")}${a.mask ? ` (${a.mask})` : ""} | ${a.dataRead ? "yes" : "no"} — ${cellMd(a.fileEvidence)} | ${cellMd(a.account ?? "")}${a.sid ? ` [${cellMd(a.sid)}]` : ""} | ${cellMd(a.image ?? "")}${a.pid !== undefined ? ` (${a.pid})` : ""} | ${inst} | ${sess} | ${cellMd(a.corroboration.join("; ") || "—")} | ${a.pivots.archiveCreates.map(cellMd).join(", ") || "—"} | ${a.pivots.connections.map(cellMd).join(", ") || "—"} | ${a.deletionCandidates.map(cellMd).join(", ") || "—"} |`;
}
