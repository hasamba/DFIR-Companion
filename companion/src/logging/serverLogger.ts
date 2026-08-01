import { createConsoleLogger, normalizeLogLevel, type Logger } from "./logger.js";

/**
 * The process-wide server logger, held in one mutable binding (#384).
 *
 * This lived in server.ts, which made it unreachable from anything server.ts itself imports. That
 * is the constraint that kept the environment factories stuck: `tlsFetchFor` has to warn when an
 * integration's TLS trust is misconfigured, so moving it out of server.ts would have created a
 * `server -> composition -> server` runtime import cycle — the exact hazard check:imports exists to
 * stop. Owning the binding here breaks the knot: both server.ts and src/composition/ import
 * downward into logging/, and neither imports the other.
 *
 * WHY A MUTABLE BINDING RATHER THAN A PARAMETER. startServer() swaps a file-backed logger in after
 * boot (a global session log plus per-case logs), and the dashboard's Logging toggle changes its
 * level live with no restart. Tests and the CLI keep the console-only default. Threading a logger
 * through every call site would be the tidier shape in the abstract, but it is not what this
 * codebase does, and rewiring ~70 call sites is a behaviour change wearing a refactor's clothes.
 *
 * server.ts re-exports setServerLogger/getServerLogger, so the eleven test files that reach for
 * them at `src/server.js` keep working against this same binding.
 */
let serverLogger: Logger = createConsoleLogger(normalizeLogLevel(process.env.DFIR_LOG_LEVEL));

export function setServerLogger(logger: Logger): void {
  serverLogger = logger;
}

export function getServerLogger(): Logger {
  return serverLogger;
}

export function logLine(msg: string): void {
  serverLogger.info(msg);
}

export function warnLine(msg: string): void {
  serverLogger.warn(msg);
}
