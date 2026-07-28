// The extension build, shared by both browser targets. build.mjs and build-firefox.mjs are thin
// callers; everything structural lives here so a new entry point or static asset is added once.
//
// Each target is built in 3 separate Vite invocations instead of one shared config.
//
// Content scripts, and the MAIN-world pageHook, are loaded as classic (non-module) scripts —
// neither file may contain `import`/`export` statements. Rollup only extracts a shared chunk
// (linked via `import`) when 2+ entries in the SAME build reference a common module, so content and
// pageHook each get their own single-entry build below: with nothing else in their build to share a
// module with, they're guaranteed fully self-contained regardless of what they import internally
// (e.g. content.ts pulling in adapters/override.ts, shared with popup.ts — that sharing only
// matters within a single build). serviceWorker/popup/options all run in contexts that support ES
// modules (the manifest declares the background `"type": "module"`, and popup/options.html load
// their scripts as `<script type="module">`), so they're free to share chunks together in one build.
//
// (A single vite.config.ts exporting an array of configs was tried first, but the installed Vite
// version's `vite build` CLI rejects an array — "config must export or return an object" — so this
// runs the Vite JS API directly instead, one build() call per group.)
import { build } from "vite";
import { resolve } from "node:path";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

/** Icon files copied into every target, referenced by manifest.icons / action.default_icon (#138). */
const ICONS = ["icon16.png", "icon32.png", "icon48.png", "icon128.png"];

/** The single source of truth for every manifest field that isn't browser-specific. */
export function readBaseManifest() {
  return JSON.parse(readFileSync(resolve(root, "manifest.json"), "utf8"));
}

// Guardrail: fail the build loudly (instead of shipping a script the browser silently refuses to
// run — "Cannot use import statement outside a module") if a future dependency change makes
// content.ts or pageHook.ts share a module with something outside their own single-entry build.
function assertNoEsmSyntax(dist, filename) {
  const code = readFileSync(resolve(dist, filename), "utf8");
  if (/^\s*(import|export)\b/m.test(code)) {
    throw new Error(
      `${filename} contains an import/export statement — the browser cannot load this as a classic ` +
      "script. Check whether it now shares a module with an entry outside its own build() call " +
      "in scripts/build-extension.mjs.",
    );
  }
}

function copyStaticPlugin(dist, manifest) {
  return {
    name: "copy-static",
    closeBundle() {
      mkdirSync(dist, { recursive: true });
      copyFileSync(resolve(root, "src/popup.html"), resolve(dist, "popup.html"));
      copyFileSync(resolve(root, "src/options.html"), resolve(dist, "options.html"));
      // An untransformed manifest is COPIED, not re-serialized, so the shipped file stays
      // byte-identical to the source. manifest.json is hand-formatted (compact arrays) and is what
      // the release version check reads — round-tripping it through JSON.stringify would reformat
      // the artifact for no reason. Only a derived manifest has to be written out.
      if (manifest === null) {
        copyFileSync(resolve(root, "manifest.json"), resolve(dist, "manifest.json"));
      } else {
        writeFileSync(resolve(dist, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
      }
      // The toolbar icon is still drawn at runtime (actionIcon.ts); these are the static assets the
      // browser shows before the background script runs, and that store listings require.
      mkdirSync(resolve(dist, "icons"), { recursive: true });
      for (const name of ICONS) {
        copyFileSync(resolve(root, "icons", name), resolve(dist, "icons", name));
      }
    },
  };
}

/**
 * Build the extension into `outDir`.
 *
 * @param {object} options
 * @param {string} options.outDir Directory under extension/ to emit into.
 * @param {(m: object) => object} [options.transformManifest]
 *        Derives the target's manifest from manifest.json. Omit for Chrome, which ships the file
 *        as-is — omitting is not the same as passing an identity function, which would reformat it.
 */
export async function buildExtension({ outDir, transformManifest }) {
  const dist = resolve(root, outDir);
  const manifest = transformManifest ? transformManifest(readBaseManifest()) : null;

  await build({
    root,
    build: {
      outDir,
      emptyOutDir: true,
      rollupOptions: {
        input: { content: resolve(root, "src/content.ts") },
        output: { entryFileNames: "[name].js" },
      },
    },
  });
  assertNoEsmSyntax(dist, "content.js");

  await build({
    root,
    build: {
      outDir,
      emptyOutDir: false,
      rollupOptions: {
        input: { pageHook: resolve(root, "src/pageHook.ts") },
        output: { entryFileNames: "[name].js" },
      },
    },
  });
  assertNoEsmSyntax(dist, "pageHook.js");

  await build({
    root,
    build: {
      outDir,
      emptyOutDir: false,
      rollupOptions: {
        input: {
          serviceWorker: resolve(root, "src/serviceWorker.ts"),
          popup: resolve(root, "src/popup.ts"),
          options: resolve(root, "src/options.ts"),
        },
        output: { entryFileNames: "[name].js" },
      },
    },
    plugins: [copyStaticPlugin(dist, manifest)],
  });

  return dist;
}
