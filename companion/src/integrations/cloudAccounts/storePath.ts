import { dirname, join } from "node:path";

// The one place that names the cloud account store: `cloud-accounts` beside the cases root and
// beside `server-sets` (`/data/cloud-accounts` in the container image). Never inside a case folder.
// The key that opens it is NOT here — see vaultKeyFile.ts.
export function cloudAccountStoreDir(casesRoot: string): string {
  return join(dirname(casesRoot), "cloud-accounts");
}
