/**
 * One member of a hunt-export zip, imported the way a dropped file is (#2714): read, detected and
 * handed to the same ingest the sweep uses, with the host its client folder names. A member over
 * DFIR_DROP_MAX_BYTES is staged on disk and handed to the drop streamer instead of being read whole.
 * A failure is returned, never thrown, with the member extracted to `_failed/` where it can be.
 */
import { basename, posix } from "node:path";
import { decodeImportedText } from "../ingest/decodeText.js";
import { assetHostFromDropRelpath } from "../analysis/assetHost.js";
import { dropWholeReadLimitNote } from "../analysis/dropScan.js";
import { unknownImportHintFor } from "../analysis/importKindHints.js";
import type { ImportDebugRecorder } from "../analysis/importDebug.js";
import { emitImportDebug, logSiemFallback } from "../routes/importDebugEmit.js";
import { siemFallbackWarning } from "../routes/importNotes.js";
import { readZipMember, writeZipMember, type ZipFile, type ZipMember } from "../storage/zipMembers.js";
import { createStagingFile, extractFailedMember, moveStagedToFailed } from "./dropHuntExtract.js";
import type { MemberOutcome } from "./dropHuntZipLedger.js";
import type { StreamDropFile } from "./dropStreamed.js";
import type { ModelCallHooks } from "./importIngest.js";
import { rm } from "node:fs/promises";

export interface HuntMemberDeps {
  dropMaxBytes: number;
  resolveImportKind: (filename: string, text: string, debug?: ImportDebugRecorder) => string;
  ingestStreamed: (
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: undefined,
    provenance?: undefined,
    assetHost?: string,
    modelCall?: ModelCallHooks,
    debug?: ImportDebugRecorder,
  ) => Promise<{ analyzed: boolean }>;
  streamDropFile: StreamDropFile;
  recordImportFailure: (
    caseId: string,
    kind: string,
    filename: string,
    err: unknown,
    debug?: ImportDebugRecorder,
  ) => void;
}

export interface HuntMemberArgs {
  caseId: string;
  dropDir: string;
  zipRelpath: string;
  zip: ZipFile;
  member: ZipMember;
  modelCall?: ModelCallHooks;
  debug: ImportDebugRecorder;
}

const msg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** Where the member would sit had the zip been unzipped in place — the host rules read this path. */
function inPlaceRelpath(zipRelpath: string, member: string): string {
  const dir = posix.dirname(zipRelpath);
  return dir === "." ? member : `${dir}/${member}`;
}

export async function importHuntMember(deps: HuntMemberDeps, a: HuntMemberArgs): Promise<MemberOutcome> {
  if (a.member.entry.uncompressedSize > deps.dropMaxBytes) return importStaged(deps, a);
  let bytes: Buffer;
  try {
    bytes = await readZipMember(a.zip, a.member.entry, deps.dropMaxBytes);
  } catch (e) {
    return { ok: false, reason: `could not be read from the zip (${msg(e)}) — not extracted` };
  }
  const fail = async (reason: string): Promise<MemberOutcome> => {
    const where = await extractFailedMember(a.dropDir, a.zipRelpath, a.member.name, (out) =>
      out.writeFile(bytes),
    ).then(
      (rel) => ` — extracted to ${rel}`,
      (e) => ` — could not be extracted (${msg(e)})`,
    );
    return { ok: false, reason: reason + where };
  };
  const name = basename(a.member.name);
  try {
    const text = decodeImportedText(bytes);
    if (!text.trim()) return await fail("empty file");
    const kind = deps.resolveImportKind(name, text, a.debug);
    if (kind === "unknown") {
      emitImportDebug(a.caseId, a.debug, "failed");
      return await fail(
        unknownImportHintFor(name, text) ?? "unrecognized file type (not a supported import format)",
      );
    }
    const host = assetHostFromDropRelpath(inPlaceRelpath(a.zipRelpath, a.member.name));
    const r = await deps.ingestStreamed(
      a.caseId,
      kind,
      text,
      name,
      undefined,
      undefined,
      host || undefined,
      a.modelCall,
      a.debug,
    );
    if (!r.analyzed)
      return await fail("AI is off — saved as evidence but not analyzed; enable AI and re-import");
    logSiemFallback(a.caseId, a.member.name, kind, a.debug); // a guessed SIEM kind still imports (#1824)
    return { ok: true, ...siemFallbackWarning(kind, a.debug) };
  } catch (err) {
    deps.recordImportFailure(a.caseId, "drop", name, err, a.debug);
    return fail(msg(err));
  }
}

/** A member over the in-memory cap: staged on disk, streamed if its format streams, else failed. */
async function importStaged(deps: HuntMemberDeps, a: HuntMemberArgs): Promise<MemberOutcome> {
  const staged = await createStagingFile(a.dropDir);
  try {
    await writeZipMember(a.zip, a.member.entry, staged.handle);
  } catch (e) {
    await staged.handle.close().catch(() => undefined);
    await rm(staged.path, { force: true });
    return { ok: false, reason: `could not be read from the zip (${msg(e)}) — not extracted` };
  }
  await staged.handle.close();
  const relpath = inPlaceRelpath(a.zipRelpath, a.member.name);
  let reason: string;
  try {
    const r = await deps.streamDropFile(a.caseId, staged.path, relpath, a.debug);
    if (r?.ok) {
      await rm(staged.path, { force: true });
      return { ok: true, ...(r.warning ? { warning: r.warning } : {}) }; // coverage disclosures travel on
    }
    const mb = Math.round(deps.dropMaxBytes / 1048576);
    reason =
      r?.reason ??
      `larger than the drop folder's ${mb} MB in-memory cap${dropWholeReadLimitNote(deps.dropMaxBytes)} and not a format that streams from disk`;
  } catch (err) {
    deps.recordImportFailure(a.caseId, "drop", basename(a.member.name), err, a.debug);
    reason = msg(err);
  }
  const where = await moveStagedToFailed(a.dropDir, a.zipRelpath, a.member.name, staged.path).then(
    (rel) => ` — extracted to ${rel}`,
    async (e) => {
      await rm(staged.path, { force: true });
      return ` — could not be extracted (${msg(e)})`;
    },
  );
  return { ok: false, reason: reason + where };
}
