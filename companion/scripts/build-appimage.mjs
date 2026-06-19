// Build a Linux AppImage from the Node-SEA binary. Linux-only. Wraps companion/dist-sea/
// (binary + public/ + data/ + node_modules/sharp) in an AppDir; writable state (cases/, .env)
// is redirected by AppRun to the directory the user launches from (the squashfs is read-only).
//
// Run with:  npm run package:appimage   (on Linux; CI runs it on ubuntu-latest)
import { mkdir, rm, writeFile, copyFile, cp, chmod, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { platform, arch } from "node:os";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const COMPANION_DIR = resolve(SCRIPT_DIR, "..");
const REPO_DIR = resolve(COMPANION_DIR, "..");
const DIST_SEA = join(COMPANION_DIR, "dist-sea");
const BUILD_DIR = join(COMPANION_DIR, "build-appimage");
const APPDIR = join(BUILD_DIR, "DFIR-Companion.AppDir");
const OUT_DIR = join(COMPANION_DIR, "dist-appimage");
const OUT_FILE = join(OUT_DIR, "DFIR-Companion-x86_64.AppImage");
const APPIMAGETOOL = join(BUILD_DIR, "appimagetool-x86_64.AppImage");
// "continuous" is appimagetool's rolling latest — there is no stable release tag to pin to
// (this is what AppImage's own docs recommend for CI).
const APPIMAGETOOL_URL = "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage";

function run(cmd, args, opts = {}) {
  return new Promise((res, rej) => {
    const child = spawn(cmd, args, { stdio: "inherit", ...opts });
    child.on("error", rej);
    child.on("exit", (code) => (code === 0 ? res(undefined) : rej(new Error(`${cmd} ${args.join(" ")} exited with ${code}`))));
  });
}

async function main() {
  if (platform() !== "linux") {
    throw new Error(`AppImage builds run on Linux only (this is ${platform()}-${arch()}). Use CI or a Linux box.`);
  }
  // 1. Ensure the Linux SEA exists.
  if (!existsSync(join(DIST_SEA, "dfir-companion"))) {
    console.log("[appimage] dist-sea missing — running package:sea first");
    // shell:true so this works regardless of how `npm` is installed on the runner (script vs wrapper).
    await run("npm", ["run", "package:sea"], { cwd: COMPANION_DIR, shell: true });
  }
  // 2. Assemble the AppDir.
  await rm(BUILD_DIR, { recursive: true, force: true });
  await mkdir(join(APPDIR, "usr", "bin"), { recursive: true });
  await cp(DIST_SEA, join(APPDIR, "usr", "bin"), { recursive: true });
  await chmod(join(APPDIR, "usr", "bin", "dfir-companion"), 0o755);

  const icon = join(REPO_DIR, "public", "DFIR_Companion_favicon.png");
  await copyFile(icon, join(APPDIR, "dfir-companion.png"));
  await copyFile(icon, join(APPDIR, ".DirIcon"));

  await writeFile(join(APPDIR, "dfir-companion.desktop"),
    ["[Desktop Entry]", "Type=Application", "Name=DFIR Companion",
     "Exec=dfir-companion", "Icon=dfir-companion", "Categories=Utility;Security;",
     "Terminal=true", "Comment=Post-detection DFIR analysis companion", ""].join("\n"));

  const appRun = [
    "#!/bin/sh",
    'HERE="$(dirname "$(readlink -f "$0")")"',
    "# Writable state lives where the user launched the AppImage (the payload is read-only).",
    "# Both MUST be absolute — a relative DFIR_CASES_ROOT would anchor to the read-only mount.",
    'export DFIR_CASES_ROOT="${DFIR_CASES_ROOT:-$PWD/cases}"',
    'export DFIR_ENV_FILE="${DFIR_ENV_FILE:-$PWD/.env}"',
    'exec "$HERE/usr/bin/dfir-companion" "$@"',
    "",
  ].join("\n");
  await writeFile(join(APPDIR, "AppRun"), appRun);
  await chmod(join(APPDIR, "AppRun"), 0o755);

  // 3. Fetch appimagetool if absent.
  if (!existsSync(APPIMAGETOOL)) {
    console.log("[appimage] downloading appimagetool");
    const resp = await fetch(APPIMAGETOOL_URL);
    if (!resp.ok) throw new Error(`appimagetool download failed: ${resp.status}`);
    await writeFile(APPIMAGETOOL, Buffer.from(await resp.arrayBuffer()));
    await chmod(APPIMAGETOOL, 0o755);
  }

  // 4. Build the AppImage (extract-and-run avoids the FUSE requirement on CI runners).
  await mkdir(OUT_DIR, { recursive: true });
  await run(APPIMAGETOOL, ["--appimage-extract-and-run", APPDIR, OUT_FILE], { cwd: BUILD_DIR, env: { ...process.env, ARCH: "x86_64" } });

  const s = await stat(OUT_FILE);
  console.log(`[appimage] done → ${OUT_FILE} (${(s.size / (1024 * 1024)).toFixed(1)} MiB)`);
}

main().catch((err) => { console.error("[appimage] FAILED:", err.message ?? err); process.exit(1); });
