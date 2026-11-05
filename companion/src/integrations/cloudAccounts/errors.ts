// A cloud vault refusal. Every message is fixed text or names a path, an id or a field — never a
// secret value — so a route may send it to the analyst and a log line may carry it.
export type CloudVaultErrorCode = "invalid" | "not-found" | "locked" | "conflict";

export class CloudVaultError extends Error {
  constructor(
    readonly code: CloudVaultErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CloudVaultError";
  }
}

/** The text a cloud vault error may put in a log line or a response. */
export function cloudSafeError(err: unknown): string {
  if (err instanceof CloudVaultError) return err.message;
  // A JSON parse error quotes the file it failed on, and accounts.json holds sealed secrets.
  if (err instanceof SyntaxError) return err.name;
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return code ? `file error ${code}` : "unknown error";
}
