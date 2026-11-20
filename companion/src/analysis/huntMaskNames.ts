import type { ClientProfile } from "./clientProfile.js";
import type { HuntClientLink } from "./huntClientLink.js";

/**
 * Masking for client-profile values (#2670). The AI-call gate derives its known entities from the
 * case alone; a hunt case's CLIENT PROFILE adds values the case state never names — the client's name
 * and its approved / blocked domains. This source wraps Watson's roster source (the gate's
 * `rawNamesStore`) and registers those values for the linked client only, so they are masked before
 * every AI call and preview. Masking maps are per case and never shared between clients.
 *
 * Approval notes and audit text are free prose: no hunt entry or prompt block carries them, so they
 * never reach a model in the first place.
 */
export interface NamesSource {
  load(caseId: string): Promise<{ readonly hosts: readonly string[]; readonly usernames: readonly string[] }>;
}

export class HuntProfileNames implements NamesSource {
  constructor(
    private readonly inner: NamesSource,
    private readonly links: { load(caseId: string): Promise<HuntClientLink | null> },
    private readonly profiles: { get(id: string): Promise<ClientProfile | null> },
  ) {}

  async load(caseId: string) {
    const base = await this.inner.load(caseId);
    const link = await this.links.load(caseId).catch(() => null);
    const profile = link ? await this.profiles.get(link.clientId).catch(() => null) : null;
    if (!profile) return base;
    const extra = [profile.name, ...profile.baseline.approvedDomains, ...profile.baseline.blockedDomains];
    return {
      hosts: [...new Set([...base.hosts, ...extra.filter((v) => v.trim().length >= 3)])],
      usernames: base.usernames,
    };
  }
}
