// The text a server set store error may put in a log. A JSON parse error quotes the start of the
// file it failed on, and sets.json holds sealed secrets and set names, so only its name is logged.
// The store's own errors (decrypt, not found, validation) name no secret and keep their message.
export function logSafeError(err: unknown): string {
  if (err instanceof SyntaxError) return err.name;
  return err instanceof Error ? err.message : "unknown error";
}
