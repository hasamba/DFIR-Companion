import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { relative, isAbsolute, sep } from "node:path";

/**
 * Refuse to run the browser suite against anything but a throwaway directory.
 *
 * #386 asked that E2E tests "never touch the real cases/ directory". That was written as a
 * convention a reviewer had to catch. Given the subject matter — a test run that writes into
 * somebody's real forensic case — a convention is not enough, so this is a hard precondition
 * instead: server-entry.ts calls it before it listens, and there is no other supported way to
 * start the server under test.
 *
 * realpath is applied to BOTH sides deliberately. macOS resolves /var to /private/var, so a naive
 * startsWith() comparison rejects a perfectly legitimate mkdtemp() directory there.
 *
 * @param candidate the intended cases root
 * @param repoRoot  the repository root, rejected even when it lives under tmp (worktrees do)
 * @returns the realpath-resolved candidate
 * @throws if the candidate does not exist, is not under the OS temp dir, or is inside the repo
 */
export function assertTempCasesRoot(candidate: string, repoRoot: string): string {
  let resolved: string;
  try {
    resolved = realpathSync(candidate);
  } catch {
    throw new Error(
      `[e2e] refusing to start: cases root does not exist: ${candidate}\n` +
        `[e2e] The suite creates its own temp root; it never reuses a configured one.`,
    );
  }

  const tmp = realpathSync(tmpdir());
  if (!contains(tmp, resolved)) {
    throw new Error(
      `[e2e] refusing to start: cases root is not under the OS temp dir.\n` +
        `[e2e]   cases root: ${resolved}\n` +
        `[e2e]   temp dir:   ${tmp}\n` +
        `[e2e] Running the browser suite against a real cases directory would write into live ` +
        `evidence. Fix the harness rather than relaxing this check.`,
    );
  }

  const repo = realpathSync(repoRoot);
  if (contains(repo, resolved)) {
    throw new Error(
      `[e2e] refusing to start: cases root is inside the repository: ${resolved}\n` +
        `[e2e] A worktree under /tmp still must not receive test cases.`,
    );
  }

  return resolved;
}

/**
 * True when `child` is `parent` or sits beneath it. Path-segment aware via relative(), so
 * /tmp/repo-extra is NOT treated as being inside /tmp/repo — which a startsWith() check would
 * get wrong, and which would make the repo rejection fire on unrelated sibling directories.
 */
function contains(parent: string, child: string): boolean {
  if (parent === child) return true;
  const rel = relative(parent, child);
  return rel.length > 0 && !rel.startsWith("..") && !isAbsolute(rel) && !rel.startsWith(`..${sep}`);
}
