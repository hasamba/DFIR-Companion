import { join } from "node:path";
import { homedir } from "node:os";

/**
 * Expand a leading `~` (or `~/`, `~\`) to the user's home directory.
 *
 * `dotenv` does NOT perform tilde expansion, so an env var like
 * `DFIR_CASES_ROOT=~/Documents/cases` would otherwise be treated as a
 * relative path and create a literal `~/Documents` folder beside the
 * companion package instead of using `$HOME/Documents`.
 *
 * - `~`           → `homedir()`
 * - `~/foo`       → `join(homedir(), "foo")`
 * - `~\foo`       → `join(homedir(), "foo")`   (Windows-style)
 * - everything else (absolute paths, relative paths, `~user`) is returned unchanged.
 *
 * `~user` (another user's home) is intentionally NOT expanded — Node has no
 * portable API for it, and silently leaving it as-is matches the principle of
 * least surprise (the path won't resolve, the error surfaces honestly).
 */
export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  if (p.startsWith("~\\")) return join(homedir(), p.slice(2));
  return p;
}