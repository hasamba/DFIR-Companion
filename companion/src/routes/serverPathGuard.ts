import { join } from "node:path";
import { openServerPath, type ServerPathOpen } from "../storage/serverPathGuard.js";

// The guard itself lives in storage/ (#1841) so the custody re-hash can use it too. Routes import it
// from here, which keeps one module to stub for the swap-race suite.
export {
  openServerPath,
  type GuardedFile,
  type ServerPathOpen,
  type ServerPathPolicy,
  type ServerPathRefusal,
} from "../storage/serverPathGuard.js";

/** The /import-file and /import-mac-login-item guard: in case storage, only the target case's drop folder. */
export function openImportPath(
  filePath: string,
  store: { casesRoot: string; caseDir(caseId: string): string },
  caseId: string,
): Promise<ServerPathOpen> {
  return openServerPath(filePath, {
    casesRoot: store.casesRoot,
    allowUnder: [join(store.caseDir(caseId), "drop")], // composition/dropFolder.ts dropDirOf
    allowedLabel: "this case's drop folder",
  });
}
