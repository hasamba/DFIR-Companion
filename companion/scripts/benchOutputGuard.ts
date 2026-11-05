/**
 * Where the scale-baseline generator (cloud-scale-gen.ts) may write (#2300). Its output is up to
 * gigabytes of synthetic evidence, and none of it may ever land in a case: CLAUDE.md's "never touch
 * cases/" holds for scripts too. A string test on the argument is not enough — `--out=cases`,
 * `--out=.` run from inside a case folder, and a symlink whose own name says nothing all reach a
 * cases root — so the destination is judged by its REAL absolute path.
 */
import { existsSync, lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** companion/ — the anchor the server resolves a relative DFIR_CASES_ROOT against (server.ts). */
const COMPANION_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The real path of `p`, resolving symlinks through its nearest existing ancestor. */
export function realDestination(p: string): string {
  let existing = p;
  const rest: string[] = [];
  while (!existsSync(existing)) {
    const parent = dirname(existing);
    if (parent === existing) break;
    rest.unshift(basename(existing));
    existing = parent;
  }
  return join(realpathSync(existing), ...rest);
}

const expandHome = (p: string): string => (p === "~" || p.startsWith("~/") ? join(homedir(), p.slice(1)) : p);

/** Every cases root this checkout knows: the repo's own `cases/` and DFIR_CASES_ROOT, both real. */
export function knownCasesRoots(env: NodeJS.ProcessEnv = process.env): string[] {
  const roots = [resolve(COMPANION_DIR, "cases"), resolve(COMPANION_DIR, "..", "cases")];
  const configured = env.DFIR_CASES_ROOT && expandHome(env.DFIR_CASES_ROOT);
  if (configured) roots.push(isAbsolute(configured) ? configured : resolve(COMPANION_DIR, configured));
  return roots.map(realDestination);
}

const isWithin = (child: string, root: string): boolean => {
  const rel = relative(root, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
};

/**
 * The real absolute output directory, or a thrown refusal when it is, or is inside, a cases root —
 * a known one, or any folder named `cases` on the real path.
 */
export function safeOutputDir(out: string, cwd = process.cwd(), casesRoots = knownCasesRoots()): string {
  const real = realDestination(resolve(cwd, out));
  const namedCases = real.split(sep).some((seg) => seg.toLowerCase() === "cases");
  const root = casesRoots.find((r) => isWithin(real, r));
  if (namedCases || root)
    throw new Error(
      `refusing to write benchmark output into a cases folder: ${real}${root ? ` (cases root ${root})` : ""}`,
    );
  return real;
}

/** Refuse to write THROUGH a symlink: an output file that is a link (even a dangling one) could point anywhere. */
export function assertNotSymlink(file: string): void {
  let link = false;
  try {
    link = lstatSync(file).isSymbolicLink();
  } catch {
    return; // nothing there yet
  }
  if (link) throw new Error(`refusing to write through a symlink: ${file}`);
}
