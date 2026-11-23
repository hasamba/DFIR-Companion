/**
 * Stop or delete a hunt ON THE VELOCIRAPTOR SERVER — the server half of cancelling a bundle hunt from
 * its job card (routes/veloHuntCancel.ts).
 *
 * The VQL follows the current Velociraptor reference: `hunt_update()` is a function that takes
 * `stop=TRUE` (there is no `state` argument), and `hunt_delete()` is a plugin that only deletes when
 * `really_do_it=TRUE`. A delete needs SERVER_ADMIN; a stop needs START_HUNT.
 *
 * NEVER THROWS, AND NEVER HIDES A REFUSAL. A failed call resolves `{ ok: false, error }` with the
 * reason Velociraptor logged, so the analyst sees "cancelled here, but Velociraptor refused: …"
 * instead of believing the hunt was stopped when it is still collecting from the fleet.
 */

const HUNT_RE = /^H\.[A-Za-z0-9]+$/;

export interface HuntProgramRunner {
  runProgram(program: string): Promise<{ rows: unknown[]; reason: string }>;
}

export type HuntControlResult = { ok: true } | { ok: false; error: string };

async function run(
  client: HuntProgramRunner,
  program: string,
  answered: (rows: unknown[]) => boolean = () => true,
): Promise<HuntControlResult> {
  try {
    const { rows, reason } = await client.runProgram(program);
    if (reason) return { ok: false, error: reason };
    return answered(rows) ? { ok: true } : { ok: false, error: "Velociraptor did not confirm the stop" };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

function badId(huntId: string): HuntControlResult | null {
  return HUNT_RE.test(huntId) ? null : { ok: false, error: `not a Velociraptor hunt id: ${huntId}` };
}

/** Stop the hunt; its collected results stay on the server. */
export async function stopHuntOnServer(
  client: HuntProgramRunner,
  huntId: string,
): Promise<HuntControlResult> {
  return (
    badId(huntId) ??
    run(
      client,
      `SELECT hunt_update(hunt_id='${huntId}', stop=TRUE) AS Stopped FROM scope()`,
      // No row, or an explicit false, is a refusal even when nothing reached the log.
      (rows) => rows.length > 0 && (rows[0] as { Stopped?: unknown }).Stopped !== false,
    )
  );
}

/** Stop the hunt, then delete it and its collected results. A failed stop skips the delete. */
export async function deleteHuntOnServer(
  client: HuntProgramRunner,
  huntId: string,
): Promise<HuntControlResult> {
  const stopped = await stopHuntOnServer(client, huntId);
  if (!stopped.ok) return stopped;
  const deleted = await run(client, `SELECT * FROM hunt_delete(hunt_id='${huntId}', really_do_it=TRUE)`);
  // Say which half failed: the hunt IS stopped, so "may still be running" would be wrong.
  return deleted.ok ? deleted : { ok: false, error: `stopped, but not deleted: ${deleted.error}` };
}
