# Dashboard HTTP API

The web UI (served by `python3 -m netmap serve`) exposes a small JSON API
under `/api/`. All endpoints return `application/json` unless noted.

| Method | Path                       | Description                                            |
|--------|----------------------------|--------------------------------------------------------|
| GET    | `/`                        | HTML dashboard                                         |
| GET    | `/api/health`              | `{ok, version, snapshot, snapshot_id, allow_scan}`    |
| GET    | `/api/summary`             | KPI counts, severity histogram, topology metrics       |
| GET    | `/api/graph`               | `{width,height,nodes[],links[],bands[]}` for SVG       |
| GET    | `/api/findings`            | Array of all findings                                  |
| GET    | `/api/devices`             | Array of device summaries                              |
| GET    | `/api/device/<id>`         | Full device record (services, interfaces, neighbours)  |
| GET    | `/api/zones`               | Zone list with trust and criticality                   |
| GET    | `/api/links`               | All links (src/dst/kind/spof/protected/speed)          |
| GET    | `/api/errors`              | Scan errors                                            |
| GET    | `/api/rules`               | Rule catalogue metadata                                |
| GET    | `/api/jobs`                | Live-scan job statuses                                 |
| GET    | `/api/snapshot`            | Full snapshot JSON                                     |
| GET    | `/api/report.<fmt>`        | Download report: md, html, sarif, cef, dot, txt, json  |
| GET    | `/static/<path>`           | Static assets                                          |
| POST   | `/api/scan`                | Start a live scan (requires authorization & token)     |
| POST   | `/api/scan/<job>`          | Poll a scan job                                        |
| POST   | `/api/compare`             | Diff against another snapshot JSON file path           |

`web.auth_token` sets an `X-NetMap-Token` header requirement; without it the
API is read-only unless `--allow-scan` is set and the host is bound to
loopback.

### Graph nodes / links

Each node: `{id, label, ip, type, zone, risk, severity, findings, ports, x, y}`.
Each link: `{id, path, src_label, dst_label, kind, confidence, spof, protected, speed, risk}`.
Bands: `{name, y0, height}` for horizontal trust tiers.
