// Chrome / Comet build → extension/dist. Ships manifest.json as-is; see build-extension.mjs for
// the pipeline (and why it runs three separate Vite invocations), and build-firefox.mjs for the
// Firefox target.
import { buildExtension } from "./build-extension.mjs";

const dist = await buildExtension({ outDir: "dist" });

console.log(`Chrome extension built in ${dist}`);
