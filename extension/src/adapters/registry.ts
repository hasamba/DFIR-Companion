import type { Adapter } from "./types.js";
import { splunkAdapter } from "./splunk.js";
import { velociraptorAdapter } from "./velociraptor.js";
import { elasticAdapter } from "./elastic.js";
import { crowdstrikeAdapter } from "./crowdstrike.js";
import { securityOnionAdapter } from "./securityonion.js";
import { socratesAdapter } from "./socrates.js";
import { volwebAdapter } from "./volweb.js";

// The known-tool registry. Order is significance-only (matchUrl is meant to be mutually exclusive
// across these consoles); the first matching adapter wins.
export const ADAPTERS: readonly Adapter[] = [
  splunkAdapter,
  velociraptorAdapter,
  securityOnionAdapter,
  socratesAdapter,
  elasticAdapter,
  crowdstrikeAdapter,
  volwebAdapter,
];

/**
 * Return the adapter that recognizes this page URL, or null. Pure — used by the content script as
 * the DEFAULT activation decision (on an unrecognized site, plain screenshot capture is used
 * unless the popup's manual override forces an adapter on — see adapters/override.ts). Invalid
 * URLs yield null rather than throwing.
 */
export function adapterForUrl(href: string): Adapter | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  // Only consider real web pages — never chrome:// / extension pages.
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  for (const adapter of ADAPTERS) {
    try {
      if (adapter.matchUrl(url)) return adapter;
    } catch {
      /* a misbehaving matcher must not break detection of the others */
    }
  }
  return null;
}

export function adapterById(id: string): Adapter | null {
  return ADAPTERS.find((a) => a.id === id) ?? null;
}
