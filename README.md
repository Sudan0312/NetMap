# NetMap — Enterprise Network Topology & Risk Mapper

> **Full-stack app:** this repo now ships a FastAPI backend (`backend/`) and a
> React frontend (`frontend/`) on top of the original stdlib discovery core
> (`netmap/`). The core is untouched and all tests still pass.
>
> The Discovery page is a **watch room**: start a scan and visibly follow the
> narrative event feed, devices appearing as they are identified, the topology
> assembling link-by-link, and risks surfacing — streamed live over SSE.

## Full-stack quick start (React + FastAPI)

Prerequisites: Python 3.10+, Node 18+.

Easiest (Windows): double-click **`start-netmap.bat`** — it opens both servers
and launches the browser at `http://127.0.0.1:5173` by itself.
First time only, install once: `python -m pip install -r backend/requirements.txt`
and `npm install` inside `frontend/`.

Manually, if you prefer two terminals:

```bash
# Terminal 1 — backend (FastAPI, :8000)
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8000

# Terminal 2 — frontend (React + Vite, :5173, proxies /api → :8000)
cd frontend
npm install
npm run dev
# open http://127.0.0.1:5173
```

Demo flow (no network needed, ~10 seconds):

1. Open the UI → sidebar shows **NO SCAN**.
2. Go to **Discovery**, keep Environment = **Demo network**, Size = Small.
3. Click **Start discovery** — watch the 8 real backend stages tick over
   (host discovery → … → risk analysis → persist).
4. On completion you land on the **Dashboard**: device/link/risk counts update.
5. Open **Topology**: zoom/pan/drag, filter by type/severity/zone, click a node
   for the device drawer (ports, services, findings, neighbours).
6. Open **Risks**: every finding shows evidence + remediation from the engine.
7. Open **History**: the scan is listed. Run a second scan (e.g. size Medium),
   then **History → Compare selected** or the Dashboard **Network changes**
   card shows `+10 devices, +13 risks` style diffs.
8. Open **Reports**: view/download JSON/Markdown/HTML/SARIF/CSV/DOT.

Live discovery (authorized networks only):

1. Discovery → Environment = **Live discovery**, Target = e.g. `192.168.1.0/24`
   (loopback such as `127.0.0.1/32` is allowed for safe local testing).
2. Tick the **authorized** checkbox (private/loopback ranges only; public ranges refused).
3. Optional: enter an **SNMP community** — sent once with the scan request,
   tried first, never stored, never logged, never echoed back (the UI even
   verifies the job response contains no trace of it).
4. Start discovery — progress streams over SSE (`/api/scan/{job}/events`) with
   polling fallback; the same staged pipeline runs `DiscoveryEngine`
   (ARP/TCP/UDP/DNS/TLS/SNMP). If `tcpdump` exists on the scanner host, a real
   8s CDP/LLDP capture window also runs; otherwise the job honestly reports
   `capture_status: skipped` and SNMP neighbour MIBs are still used.
5. Demo drift on demand: change **seed** or toggle **Include risk scenarios**
   (or switch size) — e.g. same small network with risks on vs off yields
   −7 devices / −36 findings of genuine drift in `/api/changes`.

API tests: `python backend/test_api.py` (needs backend on :8000).
Core tests: `pytest -q` (142 passed, 3 skipped — openssl not installed).
Frontend: `cd frontend && npm run build && npm test`.

Frontend structure (React is the product UI; it talks to FastAPI only):

```
frontend/src/
  main.jsx  App.jsx  styles.css
  pages/       Dashboard Topology Devices Discovery Risks Services/History/Reports/Settings
  components.jsx shared atoms (MetricCard, badges, drawers, ScanProgress, StageBanner, states)
  services/    api.js — single FastAPI gateway (health → scan jobs → snapshots → reports)
  hooks/       useFetch.js — fetch-with-state hook
  store/       ScanContext.jsx — GLOBAL state: snapshot/summary/job/running/environment/lastUpdated + refresh token every page reacts to
  topology/    icons.js layout.js TopoPreview.jsx — iconography, hierarchy layout, SVG preview
  utils/       format.js network.js — time/loopback helpers
```

Data flow: Python discovery engine → snapshot → FastAPI → `services/api.js`
→ React state → pages. The old stdlib HTML dashboard (`netmap/web/`) is not
served anywhere; `report.html` remains only as a downloadable report artifact.

Safety: read-only discovery. No exploits, brute-force, config changes, or DoS.
Live scans require explicit confirmation and private-range targets.

---

## Original core (stdlib CLI + engine)

NetMap is a **zero-dependency, end-to-end network discovery and risk-audit tool**
written in pure Python. It maps devices, links them into a topology graph,
scores them against a 53-rule risk catalogue (CIS / NIST / CWE / MITRE), and
emits reports in eight formats — including SARIF for CI pipelines and an
interactive HTML dashboard.

- **Stdlib-only core** — runs on any Python 3.10+ without pip installing anything.
- **Two discovery modes**: `lab` (deterministic simulator for demos/CI) and
  `discover` (live network, gated by an explicit written-authorization flag).
- **Risk rules are data** — `netmap/refs/rules.yaml` ships with 53 built-in
  checks; add your own with `--rules site.yaml`.
- **Safe expression engine** — rules evaluate in a JSONLogic-lite VM; no
  `eval`, no code execution from YAML.
- **Eight report formats** — JSON, Markdown, CSV (5 tables), HTML dashboard,
  SARIF 2.1.0, CEF, Graphviz DOT, plain text.
- **Authorization guardrails** — RFC1918/loopback/CGNAT/link-local by default,
  pps rate-limiter, explicit `--confirm-authorized` gate and a deny list.

---

## Quick start

```bash
# 1. Write a starter config
python3 -m netmap init -o configs/netmap.yaml

# 2. Generate a 50-device synthetic network + full report (no network needed)
python3 -m netmap lab --out out --formats json,md,html

# 3. Browse the dashboard
python3 -m netmap serve --snapshot out/lab-snapshot.json
# open http://127.0.0.1:8080

# 4. Run a risk-gated CI check
python3 -m netmap ci --from out/lab-snapshot.json --fail-on high
echo $?   # 0 = pass, 1 = threshold breached
```

Live scanning is opt-in:

```bash
python3 -m netmap discover 10.0.0.0/24 \
    --confirm-authorized \
    --statement "Ticket NETOPS-2042, change window 2026-09-23 02:00-04:00 UTC" \
    -o out --formats json,md,sarif
```

## CLI surface

| Command      | Purpose                                                       |
|--------------|---------------------------------------------------------------|
| `init`       | Emit a documented `netmap.yaml` starter                       |
| `lab`        | Synthetic discovery (deterministic, no sockets)               |
| `discover`   | Live ARP/TCP/UDP/TLS/SNMP sweep (authorization required)      |
| `analyze`    | (Re-)run topology + risk analysis on an existing snapshot     |
| `report`     | Render reports from a snapshot                                |
| `compare`    | Diff two snapshots for drift review                           |
| `serve`      | Start the web dashboard                                       |
| `rules`      | List / show / validate the rule catalogue                     |
| `ci`         | Non-zero exit when a severity threshold is exceeded           |

Common flags: `-c CONFIG`, `-o OUT`, `--formats …`, `--rules FILE…`,
`--top N`, `-q`, `-v`, `--set key=value`.

## How it works

```
host discovery ─► port scan ─► service fingerprint ─► TLS/cert inspection
       │                                                │
       └─► SNMP enumeration (interfaces, ARP, FDB, ────┘
           routes, neighbours, vlans, governance)
                    │
                    ▼
        passive CDP/LLDP frame capture (optional, needs pcap lib)
                    │
                    ▼
        topology graph (Tarjan bridges + articulation points)
                    │
                    ▼
         risk engine (data-driven rules, no code eval)
                    │
                    ▼
  scoring ─► findings ─► eight report formats + dashboard
```

Risk scoring blends weighted device risk, worst-device risk, exposure,
architecture (bridges / isolated nodes / coverage), and a saturation-capped
structural penalty. Bands: **Minimal < Low < Moderate < High < Critical**.

## Writing custom rules

Rules are YAML; the engine validates every operator before running. Example
(`examples/custom_rules.yaml`):

```yaml
rules:
  - id: ACME-EXPOSE-001
    title: Guest Wi-Fi able to reach internal subnets
    version: "1"
    family: segmentation
    severity: critical
    impact: 9
    likelihood: 7
    scope: link
    when: {"and": [
      {"==": [{"path": "link.zone_a"}, "guest"]},
      {"==": [{"path": "link.zone_b"}, "internal"]}
    ]}
    evidence: ["guest→internal reachability via {link.src_label}–{link.dst_label}"]
    description: Guest VLAN has L3 reachability into the internal zone.
    remediation: Block inter-zone traffic on the firewall; review ACLs.
    refs: {cis: "14.1", nist: "SC-7", cwe: "CWE-923"}
```

Validate with `netmap rules validate --files examples/custom_rules.yaml`.

## Installing extras (optional)

The core is stdlib-only, but two optional extras unlock more features:

```bash
pip install -e ".[config]"   # PyYAML: lets you use YAML configs directly
                              # (without it, NetMap falls back to JSON twins)
pip install -e ".[pcap]"      # scapy: passive CDP/LLDP frame capture
pip install -e ".[dev]"       # PyYAML + pytest + ruff
```

Run the tests:

```bash
pytest -q
```

## Project layout

```
netmap/
  cli.py                 entry point; argparse subcommands
  config.py              typed config + load/validate/merge
  util.py                IP/MAC/version/table helpers, colour/severity
  models.py              Device/Service/Interface/Finding/ScanSnapshot
  protocols/             BER, SNMP, CDP/LLDP frames, X.509 parser
  ports.py               well-known port registry + risk metadata
  reference.py           OS/banner/EOL catalogue (rules.yaml twin)
  discovery/             sweep, probes (TLS/HTTP/SNI), ARP, SNMP enum,
                         capture helpers, simulator, orchestration engine
  topology/              graph (bridges/articulation/components), layout,
                         cluster summaries
  risk/                  expr engine, facts enrichment, rule engine, scoring
  report/writer.py       8 output formats
  viz/                   topology SVG, static HTML report
  web/                   HTTP dashboard (stdlib http.server)
  refs/                  rules.yaml + reference.yaml (+ .json twins)
configs/netmap.example.yaml   annotated default config
data/inventory.example.csv    CMDB reconciliation example
examples/custom_rules.yaml    three worked example extension rules
tools/sync_data.py            regenerate .json twins after YAML edits
tests/                        pytest suite (145 tests, see below)
```

## Reports

Running `netmap lab --formats json,md,csv,html,sarif,cef,dot,txt` produces,
for example, `netmap-lab-20260923-153422.{json,md,html,sarif,cef,dot,txt}` plus
`-devices.csv`, `-links.csv`, `-findings.csv`, `-services.csv`, `-zones.csv`.

- **Markdown report** has nine sections: executive summary, highest-impact
  findings, risk composition, topology/resilience, zones, devices at risk,
  everything else open, method/coverage/caveats, drift (if present).
- **SARIF 2.1.0** uses `partialFingerprints["netmap/1"]` for stable rule ids,
  suppresses accepted findings, and surfaces scan errors as notifications.
- **CEF** prefixes every line with `CEF:0|NetMap|netmap|<ver>|…` and includes
  `rt=`, `msg=`, `cs1/2` labels, `externalId=`.
- **HTML dashboard** inlines the topology SVG; no external assets (works
  offline and in sandboxed iframe previews).
- **DOT** can be fed straight to `dot -Tsvg netmap-lab-*.dot > topology.svg`.

## Security & ethics

- Live scanning refuses non-private ranges by default and requires
  `--confirm-authorized`.
- Rate-limit defaults to 350 pps; no privileged raw sockets (uses `ping`
  binary when available, TCP connect fallback otherwise).
- The rule engine is a sandboxed expression VM; rules cannot call Python.
- Reports support a `--redact` flag that masks MAC OUI suffixes.

## License

MIT (see `LICENSE`). Contributions welcome.
