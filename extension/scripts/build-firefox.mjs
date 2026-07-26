// Builds the extension for Firefox. Mirrors scripts/build.mjs but emits to dist-firefox and uses
// manifest-firefox.json. The only runtime difference is the background scripts entry and the
// executeScriptTarget shim that omits world:"MAIN" on Firefox.

import { build } from "vite";
import { resolve } from "node:path";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const dist = resolve(root, "dist-firefox");

function assertNoEsmSyntax(filename) {
  const code = readFileSync(resolve(dist, filename), "utf8");
  if (/^\s*(import|export)\b/m.test(code)) {
    throw new Error(
      `${filename} contains an import/export statement — content scripts must be classic scripts. ` +
      "Check whether it now shares a module with an entry outside its own build() call.",
    );
  }
}

function copyStaticPlugin() {
  return {
    name: "copy-static-firefox",
    closeBundle() {
      mkdirSync(dist, { recursive: true });
      copyFileSync(resolve(root, "src/popup.html"), resolve(dist, "popup.html"));
      copyFileSync(resolve(root, "src/options.html"), resolve(dist, "options.html"));
      copyFileSync(resolve(root, "manifest-firefox.json"), resolve(dist, "manifest.json"));
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
    outDir: "dist-firefox",
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
    outDir: "dist-firefox",
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
    outDir: "dist-firefox",
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

console.log(`Firefox extension built in ${dist}`);
