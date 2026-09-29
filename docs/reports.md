# Report Formats

NetMap writes reports via `netmap report` or as part of `lab`/`discover`. All
writers take a `ScanSnapshot`; every output is deterministic given the same
snapshot.

## `json`

Full snapshot: devices, services, interfaces, neighbours, arp/fdb/routes,
links, findings, zones, summary, risk, counters, timings. Use this for any
machine processing.

## `md`

Nine-section Markdown report (executive summary → highest-impact findings →
risk composition → topology/resilience → zones → devices at risk → everything
else → method → drift). Designed to paste directly into change tickets.

## `csv`

Five tables: `-devices.csv`, `-findings.csv`, `-links.csv`, `-services.csv`,
`-zones.csv`. Every CSV is UTF-8 with a header row.

## `html`

Standalone single-file dashboard; topology is rendered as inline SVG. No
external CSS/JS, so it renders in sandboxed iframe previews.

## `sarif` (2.1.0)

For GitHub/GitLab/VS Code / SARIF viewers:

- Every finding is a `result` with `ruleId`, `level` (info→note, low/medium→warning,
  high/critical→error), `message.text`, `locations[].physicalLocation.artifactLocation`
  set to the device id, and `partialFingerprints["netmap/1"]` for stable dedup.
- Accepted (`status != open`) findings are emitted with `suppressions[]`.
- Scan errors become `tool.notifications[]`.

## `cef`

Every finding is one line starting `CEF:0|NetMap|netmap|<ver>|<rule_id>|<title>|<1..10>|`.
Fields: `rt=`, `msg=`, `cs1Label=rule cs1=…`, `cs2Label=zone cs2=…`, `externalId=`.

## `dot`

Graphviz DOT source. Generate SVG/PDF/PNG with `dot -Tsvg out.dot -o out.svg`.
Node colour encodes severity; edge style marks SPOF links.

## `txt`

Plain-text console summary (same block printed after a run). Useful for email
pastes and terminals without Markdown rendering.
