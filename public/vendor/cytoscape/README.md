# Vendored graph libraries (offline — no CDN at runtime)

| File | Package | Version | License | Source |
|---|---|---|---|---|
| cytoscape.min.js | cytoscape | 3.30.4 | MIT | https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js |
| dagre.min.js | dagre | 0.8.5 | MIT | https://unpkg.com/dagre@0.8.5/dist/dagre.min.js |
| cytoscape-dagre.js | cytoscape-dagre | 2.5.0 | MIT | https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js |

Used by the dashboard's Login Graph section. Load order matters: dagre before cytoscape-dagre
(the plugin registers itself against the cytoscape global when both are present).
Same vendoring pattern as ../leaflet (see companion/src/server.ts `vendorFiles` whitelist).
