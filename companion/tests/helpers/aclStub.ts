import type { TransferRunner } from "../../src/integrations/mcp/mcpDelivery.js";

/** One ACE as PowerShell prints it: SID, [int]FileSystemRights, [int]AccessControlType (0 allow, 1 deny). */
export interface StubAce {
  s: string;
  r: number;
  t: number;
}

/** The paths the encoded ACL script asks about, in order (#1863). */
export function aclScriptPaths(args: string[]): string[] {
  const script = Buffer.from(args[args.indexOf("-EncodedCommand") + 1] ?? "", "base64").toString("utf16le");
  const list = /\$paths = @\((.*)\)/.exec(script)?.[1] ?? "";
  return [...list.matchAll(/'((?:[^']|'')*)'/g)].map((m) => m[1].replace(/''/g, "'"));
}

/**
 * A stand-in for powershell.exe that answers the ACL script: `aces(path)` gives each folder's entries.
 * The default is a private folder — no entry for any broad principal — so a test that is not about
 * Windows permissions does not depend on the CI runner's disk ACL.
 */
export function aclStub(aces: (path: string) => StubAce[] = () => [], seen?: string[][]): TransferRunner {
  return async (_binary, args) => {
    const paths = aclScriptPaths(args);
    seen?.push(paths);
    // The script answers with each requested path's INDEX, never its text.
    const records = paths.map((p, i) => ({ p: i, o: "S-1-5-21-1000-2000-3000-1001", n: false, a: aces(p) }));
    return { code: 0, stderr: "", stdout: JSON.stringify(records) };
  };
}
