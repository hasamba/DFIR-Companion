// Where collector recognition learns the analyst's own Velociraptor servers. analysis/ may not read
// the server set store, so composition registers a source here at startup (every set's Velociraptor
// GUI URL and API config path). Read at call time, so an edited set is seen without a restart.

export interface CollectorEndpoint {
  guiUrl?: string;
  apiConfigPath?: string;
}

let source: () => CollectorEndpoint[] = () => [];

export function setCollectorEndpointSource(fn: () => CollectorEndpoint[]): void {
  source = fn;
}

// A source that fails (a corrupt store) yields nothing: recognition then stays inert, never wrong.
export function collectorEndpoints(): CollectorEndpoint[] {
  try {
    return source();
  } catch {
    return [];
  }
}
