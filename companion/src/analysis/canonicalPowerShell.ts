import { z } from "zod";

// The envelope block a PowerShell-channel Windows record carries (#2078): the session it ran in, as
// the ENGINE stamped it. The key is the PowerShell host process id from the record's System block
// (`Execution ProcessID`), the one session fact a 4104 script block and a 4103 pipeline record both
// carry (a 4104 has no Host ID / Runspace ID). The engine writes it, not the script, so a script
// cannot forge it. A pid is recycled, so a reader treats one host + sessionId as one session only
// across a bounded time span (ai/synthPsSessionSeats.ts). Written by psSession.ts in siemImport's
// mapWindows, which every PowerShell-reading importer except Hayabusa funnels through.
export const powerShellBlockSchema = z.object({
  /** `pid:<n>`: the session identity selection groups on (with the host). */
  sessionId: z.string().min(1),
  /** The PowerShell host process id the engine wrote into the record. */
  processId: z.number().int().positive(),
});
export type PowerShellBlock = z.infer<typeof powerShellBlockSchema>;

/** The PowerShell session id an event carries, when its import recorded one. */
export function psSessionIdOf(e: { canonical?: { powershell?: PowerShellBlock } }): string | undefined {
  const id = e.canonical?.powershell?.sessionId?.trim();
  return id || undefined;
}
