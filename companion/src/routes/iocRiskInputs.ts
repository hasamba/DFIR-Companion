import type { scoreIocsFromState } from "../analysis/iocRiskScore.js";

/** The full-fidelity context GET /cases/:id/ioc-risk scores with (#63). */
export type IocRiskInputs = NonNullable<Parameters<typeof scoreIocsFromState>[1]>;

/** The stores each input comes from (AppOptions' fields of the same names). */
interface IocRiskStores {
  kevStore?: { loadCatalog(): Promise<NonNullable<IocRiskInputs["kevCatalog"]>> };
  nsrlStore?: { load(): Promise<NonNullable<IocRiskInputs["nsrlHashes"]>> };
  iocWhitelistStore?: { load(): Promise<NonNullable<IocRiskInputs["whitelistRules"]>> };
}

/**
 * The KEV catalog, the NSRL known-good set and the IOC-whitelist rules, each from its store when
 * wired, so whitelisted and NSRL hits read as `benign`. A store that is not wired adds nothing.
 */
export async function loadIocRiskInputs(options: IocRiskStores): Promise<IocRiskInputs> {
  const kevCatalog = options.kevStore ? await options.kevStore.loadCatalog() : undefined;
  const nsrlHashes = options.nsrlStore ? await options.nsrlStore.load() : new Set<string>();
  const whitelistRules = options.iocWhitelistStore ? await options.iocWhitelistStore.load() : [];
  return { kevCatalog, nsrlHashes, whitelistRules };
}
