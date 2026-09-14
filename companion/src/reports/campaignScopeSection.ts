import type { InvestigationState } from "../analysis/stateTypes.js";
import { campaignScope } from "../analysis/campaignScope.js";
import { cellMd } from "./mdText.js";

/**
 * "Campaign scope" section (#930 item 2): per imported message, the addresses it was addressed
 * to, the mailbox a header indicates it reached (an indication, never "delivered"), and — per
 * host — what the host's own rows establish about the attachment's digest on two axes: execution
 * (a process start) and control (each Defender disposition, in time order), plus whether the file
 * was present at all. A host is attributed to a recipient only by the account its rows name;
 * otherwise it is listed as "recipient not established". A name-only match is a lead, not an
 * outcome. Every bound is said; an unread cell is "incomplete", never "unknown".
 */
export function campaignScopeSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Campaign scope", "");
  const scope = campaignScope(state);
  if (!scope.messages.length) {
    lines.push("No imported message with recipients or attachments in this case.", "");
    return;
  }
  lines.push(
    "A recipient address establishes that the address was addressed. A header can only indicate delivery. A host's rows establish what they say about the attachment's own digest — present, a control's disposition, a process start — and nothing about hosts with no rows. A filename is not identity.",
    "",
  );
  for (const m of scope.messages) {
    lines.push(
      `### ${cellMd(m.subject ?? "(no subject)")} — from ${cellMd(m.sender ?? "(unknown sender)")}, ${cellMd(m.date || "(undated)")}`,
      "",
    );
    const attachments = m.attachments.map(
      (a) =>
        `${cellMd(a.name)}${a.sha256 ? ` (sha256 ${cellMd(a.sha256)})` : a.md5 ? ` (md5 ${cellMd(a.md5)})` : a.digestUnavailable ? ` (digest unavailable: ${cellMd(a.digestUnavailable)})` : ""}`,
    );
    lines.push(
      `- Message-ID: ${cellMd(m.messageId ?? "(none)")}; attachments: ${attachments.join("; ") || "none"}${m.sharedWith.length ? `; ${m.sharedWith.length} other message(s) carry one of these attachments` : ""}`,
    );
    lines.push(
      "",
      "| Recipient | Addressed | Delivery indicated by | Hosts attributed |",
      "|---|---|---|---|",
    );
    for (const r of m.recipients)
      lines.push(
        `| ${cellMd(r.address)} | ${cellMd(r.addressed)} | ${r.indicatedBy?.map(cellMd).join(", ") || "—"} | ${r.hosts.map(cellMd).join(", ") || "none: no endpoint row names this account"} |`,
      );
    if (m.recipientsNotRead) lines.push(`| … | | | +${m.recipientsNotRead} recipient(s) not read |`);
    if (m.hosts.length) {
      lines.push(
        "",
        "| Host | Recipient | Execution | Control (in time order) | Present | Evidence | Leads | Coverage |",
        "|---|---|---|---|---|---|---|---|",
      );
      for (const h of m.hosts) {
        const controls =
          h.controls.map((c) => `${cellMd(c.disposition)} at ${cellMd(c.at)}`).join("; ") || "—";
        const evidence =
          [...h.evidence.execution, ...h.evidence.control, ...h.evidence.present].map(cellMd).join(", ") +
          (h.evidence.more ? ` (+${h.evidence.more} more)` : "");
        const leads = h.leads.map((l) => `${cellMd(l.eventId)} (${cellMd(l.kind)})`).join(", ") || "—";
        const execution =
          h.incomplete && h.execution === "unknown"
            ? `incomplete (${h.incomplete.rowsNotRead} rows not read)`
            : h.execution;
        lines.push(
          `| ${cellMd(h.host)} | ${h.recipient ? cellMd(h.recipient) : "not established"} | ${cellMd(execution)} | ${controls} | ${h.present ? "yes" : h.incomplete ? "incomplete" : "no row"} | ${evidence || "—"} | ${leads} | ${h.coverage.map(cellMd).join(", ") || "none"} |`,
        );
      }
      if (m.hostsNotRead) lines.push(`| … | | | | | | | +${m.hostsNotRead} host entr(ies) not shown |`);
      if (m.hostsUnread)
        lines.push(
          `| … | | | | | | | ${m.hostsUnread} host(s) whose digest rows were all past the read bound — not read |`,
        );
    }
    if (m.huntLeads.length) {
      lines.push("", "Hunt leads (text to run; nothing is run for you):");
      for (const l of m.huntLeads.slice(0, 20)) lines.push(`- ${cellMd(l)}`);
    }
    lines.push("");
  }
  if (scope.messagesNotRead) lines.push(`${scope.messagesNotRead} further message(s) not read (bound).`, "");
}
