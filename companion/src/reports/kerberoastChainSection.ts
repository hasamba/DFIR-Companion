import type { InvestigationState } from "../analysis/stateTypes.js";
import { kerberoastChain, type AccountUse } from "../analysis/kerberoastChain.js";
import { cellMd } from "./mdText.js";

/**
 * "Kerberoast chain" section (#930 item 6): per service account a ticket request names, the
 * requests (RC4 is an offline-cracking-compatible type the KDC used, not the requester's intent),
 * the baseline before the earliest RC4 request, every later row where the EXACT account acts —
 * on a host it was already seen on (continuing operation) or first seen on in the available
 * evidence — and a same-observed-address facet. Whether a ticket was cracked is not in any row
 * and is never stated. Every negative reason says whether the read was complete.
 */
export function kerberoastChainSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Kerberoast chain", "");
  const chain = kerberoastChain(state);
  if (!chain.accounts.length) {
    lines.push(
      chain.toolLeads.length
        ? "No service account is named by a ticket request; roasting-tool rows are listed as leads below."
        : "No RC4-encrypted service-ticket request (4769) names a service account in this case.",
      "",
    );
    leads(chain.toolLeads, chain.gaps, lines);
    return;
  }
  lines.push(
    "A 4769 establishes that the KDC issued (or refused) a service ticket for the named account to the requester; whether it was cracked is not observable. A later row where the exact account acts is a use of the account — it does not prove cracking, and the account may be in normal operation or compromised another way. Identity is the account name with a compatible realm; a name alone is a candidate.",
    "",
    "| Service account | Realm | SIDs seen | Stage | Requests (RC4 issued / other / refused) | Earliest issued RC4 request | Baseline before it | Uses after | First-seen-host uses | Same observed address | Reason |",
    "|---|---|---|---|---|---|---|---|---|---|---|",
  );
  for (const a of chain.accounts) {
    const baseline = a.baseline.hostsBefore.length
      ? a.baseline.hostsBefore.map((h) => `${h.host} (${h.count})`).join(", ")
      : a.baseline.note;
    lines.push(
      `| ${cellMd(a.service)} | ${a.realm ? cellMd(a.realm) : "not established"} | ${a.sids.map(cellMd).join(", ") || "—"}${a.identityConflict ? " (conflict)" : ""} | ${a.stage} | ${a.requestsTotal} (${a.rc4Count} / ${a.aesCount} / ${a.refusedCount}) | ${a.t0 ? cellMd(a.t0) : "—"}${a.t0Anchors ? "" : " (anchors nothing)"} | ${cellMd(baseline)} | ${a.evidence["account-used-after"].length} | ${a.evidence["first-seen-host-use"].length} | ${a.sameObservedAddressCount} | ${cellMd(a.stageReason)} |`,
    );
  }
  lines.push("");
  for (const a of chain.accounts) {
    if (!a.uses.length && !a.candidates.length) continue;
    lines.push(
      `### ${cellMd(a.service)} — uses`,
      "",
      "| Row | Time | Host | Kind | Account | Placement | Host baseline | First seen on host | Same observed address | Detail |",
      "|---|---|---|---|---|---|---|---|---|---|",
    );
    for (const u of [...a.uses, ...a.candidates]) lines.push(useRow(u));
    if (a.usesTotal > a.uses.length || a.candidatesTotal > a.candidates.length)
      lines.push(
        `| … | | | | | | | | | ${a.usesTotal - a.uses.length + a.candidatesTotal - a.candidates.length} more not shown |`,
      );
    lines.push("");
    if (a.identityConflict) lines.push(`Identity conflict: ${cellMd(a.identityConflict)}.`, "");
    if (a.hostsWithoutBaseline.length)
      lines.push(
        `Baseline unavailable for ${a.hostsWithoutBaseline.map(cellMd).join(", ")}: no rows on that host before the request, so "first seen" cannot be said there.`,
        "",
      );
  }
  leads(chain.toolLeads, chain.gaps, lines);
  const excluded = Object.entries(chain.excluded);
  if (excluded.length)
    lines.push(`Ticket requests not joined: ${excluded.map(([k, v]) => `${k} (${v})`).join("; ")}.`, "");
}

function useRow(u: AccountUse): string {
  const same = u.sameObservedAddress
    ? `${u.sameObservedAddress.useAddress} (this host) and ${u.sameObservedAddress.requestAddress} (seen by ${u.sameObservedAddress.requestObserver}, request ${u.sameObservedAddress.requestEventId}) both read ${u.sameObservedAddress.normalised} — a shared address may be NAT / VPN / VDI`
    : "—";
  return `| ${cellMd(u.eventId)} | ${cellMd(u.at)} | ${cellMd(u.host)} | ${u.kind}${u.logonType !== undefined ? ` (type ${u.logonType})` : ""} | ${cellMd(u.account)}${u.sid ? ` [${cellMd(u.sid)}]` : ""}${u.realmState === "not-established" ? " (candidate: realm not established)" : ""}${u.initiator ? ` by ${cellMd(u.initiator)}` : ""} | ${u.placement} | ${u.hostBaseline} | ${u.firstSeenHost ? "yes" : "no"} | ${cellMd(same)} | ${cellMd(u.detail ?? "")} |`;
}

function leads(tool: ReturnType<typeof kerberoastChain>["toolLeads"], gaps: string[], lines: string[]): void {
  if (tool.length) {
    lines.push(
      "Roasting-tool rows not attached to a request (leads — tool presence alone does not establish that an attack ran):",
      "",
    );
    for (const t of tool)
      lines.push(
        `- ${cellMd(t.eventId)} at ${cellMd(t.at)} on ${cellMd(t.host)}${t.account ? ` by ${cellMd(t.account)}` : ""}${t.detail ? ` — ${cellMd(t.detail)}` : ""}`,
      );
    lines.push("");
  }
  for (const g of gaps) lines.push(`- ${cellMd(g)}`);
  if (gaps.length) lines.push("");
}
