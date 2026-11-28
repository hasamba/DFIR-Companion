import type { InvestigationState } from "../analysis/stateTypes.js";
import { buildSharedHostLinks } from "../analysis/sharedHostLinks.js";
import { cellMd } from "./mdText.js";

// Report §4.8 "Hosts that share a binary or account" (#3085): the same attacker-introduced file or
// account seen on several hosts. It has no direction, so it is never drawn as a From/To hop — the
// "Lateral movement" and "Lateral movement paths" tables hold only directed evidence. Every value
// is adversary-influenced (hostnames, file and account names) and goes through cellMd.
export function sharedHostLinksSection(state: InvestigationState): string[] {
  const links = buildSharedHostLinks(state);
  if (links.length === 0) return [];
  return [
    "**Hosts that share a binary or account**",
    "",
    "_The same file or account seen on each of these hosts. It does not say which host moved to which._",
    "",
    "| Hosts | Shared | Kind | First seen | Last seen |",
    "| --- | --- | --- | --- | --- |",
    ...links.map(
      (l) =>
        `| ${l.hosts.map((h) => cellMd(h)).join(", ")} | ${cellMd(l.actor)} | ${l.actorKind} | ${l.firstSeen || "—"} | ${l.lastSeen || "—"} |`,
    ),
    "",
  ];
}
