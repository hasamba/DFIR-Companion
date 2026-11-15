// Is the configured AI provider on-box (so screenshots sent to it don't leave the machine)?
// Used to decide whether to warn that screenshots are NOT anonymized.
export function isLocalAiProvider(name: string | undefined, baseUrl: string | undefined): boolean {
  if ((name ?? "").toLowerCase() === "ollama") return true;
  const u = (baseUrl ?? "").toLowerCase();
  return /(?:\/\/|@)(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::|\/|$)/.test(u);
}
