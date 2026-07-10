// Builds the extension in 3 separate Vite invocations instead of one shared config.
//
// Chrome injects content_scripts, and loads a MAIN-world web-accessible resource (pageHook), as
// classic (non-module) scripts — neither file may contain `import`/`export` statements. Rollup
// only extracts a shared chunk (linked via `import`) when 2+ entries in the SAME build reference a
// common module, so content and pageHook each get their own single-entry build below: with
// nothing else in their build to share a module with, they're guaranteed fully self-contained
// regardless of what they import internally (e.g. content.ts pulling in adapters/override.ts,
// shared with popup.ts — that sharing only matters within a single build). serviceWorker/popup/
// options all run in contexts that support ES modules (the manifest declares the service worker
// `"type": "module"`, and popup/options.html load their scripts as `<script type="module">`), so
// they're free to share chunks together in one build.
//
// (A single vite.config.ts exporting an array of configs was tried first, but the installed Vite
// version's `vite build` CLI rejects an array — "config must export or return an object" — so this
// runs the Vite JS API directly instead, one build() call per group.)
import { build } from "vite";
import { resolve } from "node:path";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const dist = resolve(root, "dist");

// Guardrail: fail the build loudly (instead of shipping a script Chrome silently refuses to run —
// "Cannot use import statement outside a module") if a future dependency change makes content.ts
// or pageHook.ts share a module with something outside their own single-entry build again.
function assertNoEsmSyntax(filename) {
  const code = readFileSync(resolve(dist, filename), "utf8");
  if (/^\s*(import|export)\b/m.test(code)) {
    throw new Error(
      `${filename} contains an import/export statement — Chrome cannot load this as a classic ` +
      "script. Check whether it now shares a module with an entry outside its own build() call " +
      "in scripts/build.mjs.",
    );
  }
}

function copyStaticPlugin() {
  return {
    name: "copy-static",
    closeBundle() {
      mkdirSync(dist, { recursive: true });
      copyFileSync(resolve(root, "src/popup.html"), resolve(dist, "popup.html"));
      copyFileSync(resolve(root, "src/options.html"), resolve(dist, "options.html"));
      copyFileSync(resolve(root, "manifest.json"), resolve(dist, "manifest.json"));
      // Store icons referenced by manifest.icons / action.default_icon (#138). The toolbar
      // icon is still drawn at runtime (actionIcon.ts); these are the static assets Chrome
      // shows before the service worker runs and that the Web Store listing requires.
      mkdirSync(resolve(dist, "icons"), { recursive: true });
      for (const name of ["icon16.png", "icon32.png", "icon48.png", "icon128.png"]) {
        copyFileSync(resolve(root, "icons", name), resolve(dist, "icons", name));
      }
    },
  };
}

await build({
  root,
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: { content: resolve(root, "src/content.ts") },
      output: { entryFileNames: "[name].js" },
    },
  },
});
assertNoEsmSyntax("content.js");

await build({
  root,
  build: {
    outDir: "dist",
    emptyOutDir: false,
    rollupOptions: {
      input: { pageHook: resolve(root, "src/pageHook.ts") },
      output: { entryFileNames: "[name].js" },
    },
  },
});
assertNoEsmSyntax("pageHook.js");

await build({
  root,
  build: {
    outDir: "dist",
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
  plugins: [copyStaticPlugin()],
});
