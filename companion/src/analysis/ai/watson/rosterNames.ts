import { isVictimSideHost } from "../../anonymize.js";
import type { PromptEntities } from "../maskRequest.js";
import type { RawNamesSource } from "../providerCallContext.js";
import { promptEntities } from "./pasteEntities.js";
import { IP_LIKE, type WatsonMaskRoster } from "./superRoster.js";
import type { WatsonChat } from "./types.js";

// Final review H3: the raw-only names Watson's super-timeline searches showed (the chat's masking
// roster, D2d) are masked on EVERY AI call on the case, not only on Watson's own. Watson may write
// such a name into a finding, a next step or report text that synthesis, the deep pass, Explain or
// Jev later send; the case anonymizer never saw it, because it comes from no forensic row. The names
// get the same short-label rule as Watson's own calls (pasteEntities.ts), so both mask alike.

// The roster comes from WatsonChatStore.loadRoster: the chat's and the durable sidecar's, merged, read
// through a shared cache. It throws WatsonRosterUnreadable when a file cannot be read, so the call fails.
type ChatLoader = { loadRoster(caseId: string): Promise<WatsonMaskRoster | undefined> };

/** The chat's roster as masking entities. An absent or empty roster gives none. */
export function rosterEntities(chat: Pick<WatsonChat, "maskRoster">): PromptEntities {
  const r = chat.maskRoster;
  if (!r || (!r.hosts.length && !r.users.length)) return { hosts: [], usernames: [] };
  return promptEntities("", r.hosts, r.users);
}

// The redacted export keeps adversary infrastructure readable (deriveKnownEntities, user decision
// 2026-11-15). Since F7 the roster also holds the domains of paste and history excerpts, public ones
// included, so the export drops each FQDN that is not victim-side. Every bare name stays: since final
// review F1 no derived label of a public FQDN is stored, so a bare name was found on its own (or is a
// legacy stored label) and stays masked. When a victim host shares an attacker domain's first label,
// the domain then reads ANON_HOST_n.evil.example. Masking fails closed, so the victim host wins.
const isAttackerFqdn = (h: string, internalDomains: readonly string[]): boolean =>
  h.includes(".") && !IP_LIKE.test(h) && !isVictimSideHost(h, internalDomains);

/** The roster as masking entities for the redacted export: attacker domains stay out. */
export function exportRosterEntities(
  roster: WatsonMaskRoster | undefined,
  internalDomains: readonly string[],
): PromptEntities {
  if (!roster) return { hosts: [], usernames: [] };
  const domains = internalDomains.map((d) => d.toLowerCase());
  const hosts = roster.hosts.map((h) => h.trim().toLowerCase()).filter((h) => !isAttackerFqdn(h, domains));
  return rosterEntities({ maskRoster: { ...roster, hosts } });
}

/** The RawNamesSource every case masker reads (providerCallContext.ts). Reads only; never writes. */
export class WatsonRosterNames implements RawNamesSource {
  constructor(private readonly chats: ChatLoader) {}

  async load(caseId: string): Promise<PromptEntities> {
    const maskRoster = await this.chats.loadRoster(caseId);
    return rosterEntities(maskRoster ? { maskRoster } : {});
  }
}
