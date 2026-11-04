import { setCollectorEndpointSource } from "../analysis/collectorEndpointSource.js";
import type { ServerSetStore } from "../integrations/serverSets/serverSetStore.js";

// Collector recognition counts the Velociraptor server of EVERY set: it only marks the analyst's
// own collector traffic, so a host from any of their sets is theirs. Reads no secret.
export function registerCollectorEndpoints(store: ServerSetStore): void {
  setCollectorEndpointSource(() => store.velociraptorSettings());
}
