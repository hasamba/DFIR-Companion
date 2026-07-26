// Firefox build → extension/dist-firefox. Same bundles as the Chrome target; the only difference is
// the manifest, derived from manifest.json by manifest-firefox.mjs rather than kept as a second file.
import { buildExtension } from "./build-extension.mjs";
import { toFirefoxManifest } from "./manifest-firefox.mjs";

const dist = await buildExtension({ outDir: "dist-firefox", transformManifest: toFirefoxManifest });

console.log(`Firefox extension built in ${dist}`);
