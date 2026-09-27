// Compact progress-text formatters for the MCP agent and transfer jobs (routes/mcp.ts). Moved out of
// the route module (#1736) so it stays inside its file-size ledger; pure, no state.

/** `42s`, `3m 7s`, `1h 12m` — the elapsed and limit figures in an agent job's progress line. */
export function compactDuration(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return minutes < 60 ? `${minutes}m ${seconds % 60}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

/** `512 B`, `1.5 MiB`, `12 GiB` — the size figures in an evidence transfer's progress line. */
export function compactBytes(bytes: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}
