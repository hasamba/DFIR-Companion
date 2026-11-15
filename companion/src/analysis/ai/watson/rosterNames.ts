import type { PromptEntities } from "../maskRequest.js";
import type { RawNamesSource } from "../providerCallContext.js";
import { promptEntities } from "./pasteEntities.js";
import type { WatsonMaskRoster } from "./superRoster.js";
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

/** The RawNamesSource every case masker reads (providerCallContext.ts). Reads only; never writes. */
export class WatsonRosterNames implements RawNamesSource {
  constructor(private readonly chats: ChatLoader) {}

  async load(caseId: string): Promise<PromptEntities> {
    const maskRoster = await this.chats.loadRoster(caseId);
    return rosterEntities(maskRoster ? { maskRoster } : {});
  }
}
