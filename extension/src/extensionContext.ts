const INVALIDATED_CONTEXT = /extension context invalidated/i;

export function isExtensionContextInvalidated(error: unknown): boolean {
  if (error instanceof Error) return INVALIDATED_CONTEXT.test(error.message);
  return typeof error === "string" && INVALIDATED_CONTEXT.test(error);
}

// A content script survives in the page after an unpacked extension is reloaded, but its browser
// API calls become invalid. Chrome may throw synchronously here rather than return a rejected
// promise, so a trailing `.catch()` alone cannot contain the expected development/update failure.
export function runBestEffortExtensionCall(
  send: () => Promise<unknown>,
  onInvalidated: () => void,
): void {
  const handleFailure = (error: unknown): void => {
    if (isExtensionContextInvalidated(error)) onInvalidated();
  };
  try {
    void send().catch(handleFailure);
  } catch (error) {
    handleFailure(error);
  }
}
