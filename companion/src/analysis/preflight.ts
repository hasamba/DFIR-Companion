// Startup pre-flight diagnostics (#179). PURE logic only — no I/O, no network.
// The route in server.ts runs the actual probes (AI provider, enrichment, Velociraptor)
// and feeds the results here to build the structured report and shareable text.

export interface PreflightItem {
  /** Short display name, e.g. "AI provider" or "Enrichment: MISP". */
  name: string;
  /** Whether this check passed. */
  ok: boolean;
  /**
   * True for checks whose failure means core analysis is unavailable (e.g. AI not configured).
   * False for optional/opt-in integrations (enrichment, Velociraptor) whose failure is a warning.
   */
  critical: boolean;
  /** Human-readable explanation — safe to log and display. Never contains API keys. */
  detail: string;
}

export interface PreflightReport {
  /** ISO-8601 timestamp of when the checks ran. */
  ranAt: string;
  /** Wall-clock duration of all checks in milliseconds. */
  durationMs: number;
  /** One entry per configured integration that was probed. */
  items: PreflightItem[];
  /** True if ANY check failed (critical or not). */
  anyFailed: boolean;
  /** True if a CRITICAL check (i.e. AI provider) failed. */
  anyCriticalFailed: boolean;
}

export function buildPreflightReport(
  items: PreflightItem[],
  ranAt: string,
  durationMs: number,
): PreflightReport {
  return {
    ranAt,
    durationMs,
    items,
    anyFailed: items.some((i) => !i.ok),
    anyCriticalFailed: items.some((i) => !i.ok && i.critical),
  };
}

/** Render a plain-text summary for the session log and clipboard. */
export function buildPreflightText(report: PreflightReport): string {
  const status = report.anyCriticalFailed ? "CRITICAL" : report.anyFailed ? "WARN" : "OK";
  const lines: string[] = [];
  lines.push("=== DFIR Companion — Pre-Flight ===");
  lines.push(`ran:    ${report.ranAt} (${report.durationMs}ms)`);
  lines.push(`status: ${status}`);
  lines.push("");
  for (const item of report.items) {
    const icon = item.ok ? "✓" : item.critical ? "✗ [CRITICAL]" : "⚠ [WARN]";
    lines.push(`  ${icon}  ${item.name}: ${item.detail}`);
  }
  return lines.join("\n");
}
