import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

// Resolve the `public/` folder that ships the dashboard HTML + favicons.
//
// Three runtime modes the companion supports today, all served by one helper:
//   1. tsx dev      — `src/server.ts` is the entry; `../../public/` from there is repo-root `public/`.
//   2. tsc + Node   — `dist/server.js` is the entry (Docker image, `node dist/server.js`); same `../../public/`.
//   3. SEA EXE      — the bundled single-file binary; `public/` ships in the same folder as the .exe.
//
// In modes 1+2 the URL form keeps working because this file's relative depth to `public/`
// is identical to server.ts (sibling). In mode 3, `import.meta.url` points into the SEA blob,
// so we resolve next to `process.execPath` instead.
function detectSea(): boolean {
  // Try every avenue, because esbuild's CJS output stubs `import.meta.url` to empty,
  // which breaks `createRequire(import.meta.url)` inside the SEA blob — exactly the
  // place we most need this check to succeed.
  //
  // 1. `globalThis.require` exists inside SEA (it's the embedder's require) and resolves
  //    `node:sea` as a builtin. This is the fast path inside the EXE.
  // 2. `createRequire(process.execPath)` is the fallback for any environment where (1)
  //    isn't injected (e.g. some bundlers wipe the global require).
  // 3. Dev / Docker (tsx, tsc) goes through `createRequire(import.meta.url)`.
  const candidates: Array<() => NodeRequire | null> = [
    () => (typeof globalThis !== "undefined" && typeof (globalThis as { require?: NodeRequire }).require === "function"
      ? (globalThis as { require: NodeRequire }).require
      : null),
    () => { try { return createRequire(process.execPath); } catch { return null; } },
    () => { try { return import.meta.url ? createRequire(import.meta.url) : null; } catch { return null; } },
  ];
  for (const get of candidates) {
    try {
      const req = get();
      if (!req) continue;
      const sea = req("node:sea") as { isSea?: () => boolean };
      if (typeof sea.isSea === "function" && sea.isSea()) return true;
    } catch {
      // node:sea unavailable on this Node, or this candidate failed — try the next.
    }
  }
  return false;
}

const SEA_PUBLIC_ROOT: string | null = detectSea() ? join(dirname(process.execPath), "public") : null;

export function isSeaRuntime(): boolean {
  return SEA_PUBLIC_ROOT !== null;
}

function resolvePublicAsset(relative: string): URL | string {
  const clean = relative.startsWith("/") ? relative.slice(1) : relative;
  if (SEA_PUBLIC_ROOT) {
    return join(SEA_PUBLIC_ROOT, clean);
  }
  return new URL("../../public/" + clean, import.meta.url);
}

export function readPublicAsset(relative: string): Promise<Buffer>;
export function readPublicAsset(relative: string, encoding: "utf8"): Promise<string>;
export async function readPublicAsset(relative: string, encoding?: "utf8"): Promise<Buffer | string> {
  const target = resolvePublicAsset(relative);
  if (encoding === "utf8") {
    return readFile(target, "utf8");
  }
  return readFile(target);
}
