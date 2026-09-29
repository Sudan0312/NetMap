# NetMap Documentation

NetMap ships with two kinds of documentation:

1. **README.md** (project root) — five-minute overview, quick start, CLI
   surface, architecture, and security model.
2. **Reference pages** (this folder) — deeper dives.

## Pages

- [Architecture](architecture.md) — pipeline stages, facts namespace, scoring.
- [Risk rule authoring](rules.md) — expression language, `applies_to`, `escalate`, foreach.
- [Authorization & rate-limiting](authorization.md) — what live scan will/won't do.
- [Report formats](reports.md) — field reference for each writer (JSON / SARIF / CEF / CSV / DOT / HTML / MD / TXT).
- [Dashboard HTTP API](api.md) — every endpoint under `/api/`.
- [FAQ](faq.md) — common problems and answers.
