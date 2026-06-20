import { defineConfig } from "vite";
import { resolve } from "node:path";
import { copyFileSync, mkdirSync } from "node:fs";

export default defineConfig({
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        serviceWorker: resolve(__dirname, "src/serviceWorker.ts"),
        content: resolve(__dirname, "src/content.ts"),
        // pageHook is injected into the page (MAIN world) as a web-accessible resource, so it must
        // build to a single standalone file with no shared-chunk imports (see #102).
        pageHook: resolve(__dirname, "src/pageHook.ts"),
        popup: resolve(__dirname, "src/popup.ts"),
        options: resolve(__dirname, "src/options.ts"),
      },
      output: { entryFileNames: "[name].js" },
    },
  },
  plugins: [{
    name: "copy-static",
    closeBundle() {
      mkdirSync(resolve(__dirname, "dist"), { recursive: true });
      copyFileSync(resolve(__dirname, "src/popup.html"), resolve(__dirname, "dist/popup.html"));
      copyFileSync(resolve(__dirname, "src/options.html"), resolve(__dirname, "dist/options.html"));
      copyFileSync(resolve(__dirname, "manifest.json"), resolve(__dirname, "dist/manifest.json"));
      // Store icons referenced by manifest.icons / action.default_icon (#138). The toolbar
      // icon is still drawn at runtime (actionIcon.ts); these are the static assets Chrome
      // shows before the service worker runs and that the Web Store listing requires.
      mkdirSync(resolve(__dirname, "dist/icons"), { recursive: true });
      for (const name of ["icon16.png", "icon32.png", "icon48.png", "icon128.png"]) {
        copyFileSync(resolve(__dirname, "icons", name), resolve(__dirname, "dist/icons", name));
      }
    },
  }],
});
