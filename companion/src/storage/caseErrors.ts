/**
 * The errors CaseStore throws for case lifecycle and id-reuse refusals. Split out of caseStore.ts
 * (#1855) and re-exported from there, so every caller keeps importing them from caseStore.js.
 */

/**
 * The case id is already owned by someone else. Thrown by createCase when its exclusive claim on
 * case.json loses — which is the ONLY way a caller can learn it lost, since a check-then-create
 * pair cannot: both racers pass the check.
 *
 * A distinct type rather than a message match so the route can answer 409 (someone else has it)
 * instead of 500 (we broke), and so a future caller cannot mistake it for a disk failure.
 */
export class CaseAlreadyExistsError extends Error {
  constructor(readonly caseId: string) {
    super(`case ${caseId} already exists`);
    this.name = "CaseAlreadyExistsError";
  }
}

/**
 * The case id is mid-delete: its folder may already be gone while the delete still clears the state
 * that outlives it (roles, jobs). Creating the id then would let that cleanup revoke the new case's
 * roles (#1826), so createCase refuses it. A kind of CaseAlreadyExistsError, so a create route
 * answers it with the same 409.
 */
export class CaseBeingDeletedError extends CaseAlreadyExistsError {
  constructor(caseId: string) {
    super(caseId);
    this.message = `case ${caseId} is being deleted — try again once the delete finishes`;
    this.name = "CaseBeingDeletedError";
  }
}

/**
 * A folder for the id is still on disk but holds no case.json — what a delete whose rm failed part
 * way leaves behind (#1831). Creating the id would adopt the old evidence files, so it is refused
 * until the folder is removed by hand. A kind of CaseAlreadyExistsError, so a create route answers
 * it with the same 409.
 */
export class CaseFolderLeftoverError extends CaseAlreadyExistsError {
  constructor(caseId: string, dir: string) {
    super(caseId);
    this.message = `a folder for case ${caseId} is still on disk (${dir}) from an earlier case — remove it before reusing the id`;
    this.name = "CaseFolderLeftoverError";
  }
}

/**
 * A lifecycle write refused because of the case's current state, with the HTTP status a route
 * answers it with. Thrown inside the per-case metadata lock, so the check and the write agree.
 */
export class CaseLifecycleError extends Error {
  constructor(
    message: string,
    readonly httpStatus: 404 | 409,
  ) {
    super(message);
    this.name = "CaseLifecycleError";
  }
}

/**
 * The case has no metadata (it was never created, or a delete removed it). Thrown by updateCaseMeta,
 * which used to write a default case.json instead — a write that landed during a delete's rm made
 * the rm fail and left a nameless "ghost" case after the evidence was already gone (#1808).
 */
export class CaseNotFoundError extends CaseLifecycleError {
  constructor(readonly caseId: string) {
    super(`case ${caseId} not found`, 404);
    this.name = "CaseNotFoundError";
  }
}

/** The case is archived (in _archived/); only restore may move it back to open or closed (#1809). */
export class CaseArchivedError extends CaseLifecycleError {
  constructor(readonly caseId: string) {
    super(`case ${caseId} is archived — restore the case first`, 409);
    this.name = "CaseArchivedError";
  }
}
