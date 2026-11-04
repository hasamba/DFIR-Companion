import { dirname, join } from "node:path";

// The one place that names the server set store directory: `server-sets` beside the cases root
// (`/data/server-sets` in the container image). Never inside a case folder.
export function serverSetStoreDir(casesRoot: string): string {
  return join(dirname(casesRoot), "server-sets");
}
