import { basename, dirname } from "node:path";
import { openCaseFile, snapshotCaseFile, type CaseScope } from "../../storage/caseFileRead.js";

/**
 * How a local tool run gets the file it parses (#1857).
 *
 * The target was checked by TEXT (resolveContainedPath). The tool opens it by NAME, later — so a case
 * writer who swaps the name, or a folder above it, for a link to another case's file between the
 * check and the tool's open got that file parsed and imported into THIS case. So:
 *
 * - Always: the target is judged on an open handle at hand-over (openCaseFile): a link, a FIFO or a
 *   device, or a file with a second name elsewhere is refused before anything runs.
 * - `<targetdir>` tools already had a copy (Velociraptor --ROOT needs a folder); the copy now reads
 *   from the judged handle, not by name.
 * - Team mode: a `<target>` tool runs against a private snapshot of the judged bytes, in the run's own
 *   folder outside the case, and the snapshot's hash goes into the tool-run provenance.
 * - Single-user mode: `<target>` stays zero-copy — the evidence can be many GB and no second writer
 *   exists. The residual is a swap after the judgment, by the analyst's own hand.
 */

/** The bytes a staged copy handed the tool — recorded in the run's provenance. */
export interface ToolInputIdentity {
  sha256: string;
  bytes: number;
}

export interface StagedToolInput {
  /** The path for `<target>`: the staged copy when there is one, else the judged case path. */
  target: string;
  /** The folder for `<targetdir>`: holds only the staged copy, under the original name. */
  targetDir?: string;
  /** The staged copy's path, when one was made — mapped back to the case path in the output. */
  stagedPath?: string;
  input: ToolInputIdentity | null;
}

/**
 * Judge `targetPath` and, when the tool needs a copy, snapshot it into a folder under `runDir`. The
 * caller owns `runDir` and removes it (with the copy) when the run ends, on every path.
 */
export async function stageToolInput(opts: {
  scope: CaseScope;
  targetPath: string;
  runDir: string;
  needsTarget: boolean;
  needsTargetDir: boolean;
  teamMode: boolean;
}): Promise<StagedToolInput> {
  const { scope, targetPath, runDir } = opts;
  if (!opts.needsTargetDir && !(opts.needsTarget && opts.teamMode)) {
    const judged = await openCaseFile(scope, targetPath);
    await judged.handle.close();
    return { target: targetPath, input: null };
  }
  const snap = await snapshotCaseFile(scope, targetPath, runDir, { name: basename(targetPath) });
  return {
    target: snap.path,
    targetDir: dirname(snap.path),
    stagedPath: snap.path,
    input: { sha256: snap.sha256, bytes: snap.bytes },
  };
}

/**
 * Tools echo the path they scanned (YARA prints it on every match), and the importer turns it into
 * the event path, a file IOC and the aggregation key. A staged copy's path names a folder that is
 * deleted when the run ends, so it is mapped back to the case path — raw, and as it appears inside a
 * JSON string (Windows backslashes are doubled there). The staged path is unique to this run.
 */
export function mapStagedPath(text: string, stagedPath: string, casePath: string): string {
  const json = (s: string): string => JSON.stringify(s).slice(1, -1);
  let out = text.split(stagedPath).join(casePath);
  if (json(stagedPath) !== stagedPath) out = out.split(json(stagedPath)).join(json(casePath));
  return out;
}
