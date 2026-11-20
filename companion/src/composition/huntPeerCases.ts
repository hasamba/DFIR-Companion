import type { AuthStore } from "../auth/authStore.js";
import { isAnalystCase } from "../storage/sweepCase.js";
import type { CaseMeta } from "../types.js";

/**
 * Which OTHER cases may feed a hunt case's cross-case parts (#2670): the "new since last hunt"
 * entries, the report's comparison with the last comparable hunt, and the pending items' age.
 *
 * Every one of those is PERSISTED into this case — grouped entries in the forensic timeline, the
 * inventory record's grades, the report files in reports/ — and read later by whoever can open this
 * case, with no request (and no requester) in sight when they are written: grading runs at the import
 * seam and in background report regeneration. So the per-request filter the earlier-hunt listing uses
 * (team visibility + this browser's unlock cookie, routes/huntClient.ts) cannot be applied here. The
 * request-independent rule is stricter instead: another case contributes only when EVERY reader of
 * this case could open it anyway —
 *   - never a password-protected case (its unlock is per browser, so no stored output may hint at it);
 *   - never a hidden sweep case;
 *   - in team mode, only a case whose role holders include every role holder of this case (instance
 *     administrators open every case, so their own case roles never narrow it).
 * A role revoked later is honoured on the next grading or report run, not retroactively.
 */
export interface HuntPeerDeps {
  listCases: () => Promise<CaseMeta[]>;
  /** Team mode only: the identities holding a role on a case, instance administrators left out. */
  roleHolders?: (caseId: string) => ReadonlySet<string>;
}

export function huntPeerCaseIds(d: HuntPeerDeps): (caseId: string) => Promise<string[]> {
  return async (caseId) => {
    const audience = d.roleHolders?.(caseId);
    const out: string[] = [];
    for (const meta of await d.listCases()) {
      if (meta.caseId === caseId || !isAnalystCase(meta) || meta.password) continue;
      if (audience && d.roleHolders) {
        const theirs = d.roleHolders(meta.caseId);
        if (![...audience].every((id) => theirs.has(id))) continue;
      }
      out.push(meta.caseId);
    }
    return out;
  };
}

/** The team store's role holders of one case, instance administrators left out. */
export function caseRoleHolders(store: Pick<AuthStore, "listCaseRoles">) {
  return (caseId: string): ReadonlySet<string> =>
    new Set(
      store
        .listCaseRoles(caseId)
        .filter((r) => r.identity.globalRole !== "administrator")
        .map((r) => r.identity.id),
    );
}
