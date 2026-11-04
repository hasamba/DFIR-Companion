// The Velociraptor GUI URL a set stores is the GUI's base: deep links are built as
// `${guiUrl}/app/index.html?…`. A GUI served under a base path keeps that path
// (https://host/velociraptor). The address an analyst copies from the browser also works: everything
// from `/app/index.html` on (with any query or `#…` route) is dropped, then any trailing slash.
const SPA_PAGE = /\/app\/index\.html(?:[?#].*)?$/i;

export function normalizeVeloGuiUrl(raw: string): string {
  return raw.trim().replace(SPA_PAGE, "").replace(/\/+$/, "");
}
