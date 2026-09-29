"""NetMap FastAPI backend — real discovery pipeline exposed as REST.

Wraps the existing stdlib engine (netmap.pipeline / netmap.discovery /
netmap.topology / netmap.risk) without duplicating network state:

    request -> Config -> pipeline.run -> ScanSnapshot (persisted as JSON)
        -> in-memory current snapshot + history index -> React UI

Demo mode uses netmap.discovery.simulator (clearly labelled synthetic).
Live mode uses netmap.discovery.engine.DiscoveryEngine with the same
authorization gate as the CLI.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

import asyncio
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netmap import __version__  # noqa: E402
from netmap.config import Config  # noqa: E402
from netmap.models import ScanSnapshot  # noqa: E402
from netmap.pipeline import analyze, compare_snapshots, discover, load_snapshot, save_snapshot  # noqa: E402
from netmap.util import SEVERITY_ORDER  # noqa: E402

CODE_VERSION = "20260927.6"
FEATURES = ["snapshot-graph", "sse", "watch-events", "live-topology", "snmp-per-scan", "snmp-session", "gateway-star", "link-source", "capture-status", "graph-roles"]

DATA_DIR = Path(__file__).resolve().parent / "data" / "scans"
DATA_DIR.mkdir(parents=True, exist_ok=True)
INDEX_FILE = DATA_DIR / "index.json"

STAGE_DEFS = [
    ("host_discovery", "Host discovery"),
    ("port_scan", "Port scanning"),
    ("service_fingerprint", "Service fingerprinting"),
    ("dns_resolution", "DNS resolution"),
    ("snmp_enumeration", "SNMP enumeration"),
    ("topology", "Topology construction"),
    ("risk_analysis", "Risk analysis"),
    ("persist", "Persisting results"),
]


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fresh_stages():
    return [{"id": sid, "label": label, "state": "pending"} for sid, label in STAGE_DEFS]


# ---------------------------------------------------------------- state
class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}
        self.current_id: str | None = None
        self.snapshots: dict[str, ScanSnapshot] = {}
        self.meta: dict[str, dict] = {}  # snapshot_id -> history row
        self._load_index()

    def _load_index(self) -> None:
        if INDEX_FILE.exists():
            try:
                rows = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
            except Exception:
                rows = []
        else:
            rows = []
        for row in rows:
            sid = row.get("snapshot_id")
            path = DATA_DIR / f"{sid}.json" if sid else None
            if sid and path and path.exists():
                try:
                    self.snapshots[sid] = load_snapshot(path)
                    self.meta[sid] = row
                except Exception:
                    continue
        if rows:
            latest = sorted(rows, key=lambda r: r.get("finished") or "", reverse=True)
            if latest and latest[0].get("snapshot_id") in self.snapshots:
                self.current_id = latest[0]["snapshot_id"]

    def _save_index(self) -> None:
        rows = sorted(self.meta.values(), key=lambda r: r.get("finished") or "", reverse=True)
        INDEX_FILE.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    def current(self) -> ScanSnapshot | None:
        if self.current_id and self.current_id in self.snapshots:
            return self.snapshots[self.current_id]
        return None


STATE = State()

# Session SNMP community (set via Settings, cleared on restart).
# Never persisted to disk, never logged, never returned by any endpoint.
SNMP_SESSION: dict[str, str | None] = {"community": None}


def snmp_is_configured() -> bool:
    if SNMP_SESSION.get("community"):
        return True
    return bool((__import__("os").environ.get("NETMAP_SNMP_RO") or "").strip())

app = FastAPI(title="NetMap API", version=__version__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------- models
class ScanRequest(BaseModel):
    target: str = Field(default="192.168.1.0/24")
    targets: list[str] | None = None
    environment: str = Field(default="demo")  # live | demo
    size: str = Field(default="medium")  # small | medium | large (demo)
    seed: int = Field(default=7, ge=0, le=999999)
    include_risks: bool = Field(default=True)  # demo: include misconfigurations
    mode: str = Field(default="normal")  # fast | normal | deep (live)
    methods: dict[str, bool] | None = None
    snmp_community: str | None = Field(default=None, max_length=128)  # live only; never stored or echoed
    confirmAuthorized: bool = Field(default=False)
    statement: str | None = None


# ---------------------------------------------------------------- helpers
def validate_targets(raw_targets: list[str]) -> list[str]:
    cleaned = [t.strip() for t in raw_targets if str(t).strip()]
    if not cleaned:
        raise HTTPException(status_code=400, detail="Target network is required (e.g. 192.168.1.0/24).")
    for t in cleaned:
        try:
            if "/" in t:
                net = ipaddress.ip_network(t, strict=False)
                if net.num_addresses > 4096:
                    raise HTTPException(status_code=400, detail=f"Target {t} is too large (>{4096} addresses). Narrow the range.")
            else:
                ipaddress.ip_address(t)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid target {t!r}: expected an IP address or CIDR (e.g. 192.168.1.0/24).")
    return cleaned


def is_private_target(t: str) -> bool:
    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            return net.is_private
        return ipaddress.ip_address(t).is_private
    except ValueError:
        return False


def snapshot_to_summary(snap: ScanSnapshot) -> dict:
    counts = {sev: sum(1 for f in snap.findings if f.severity == sev and f.status == "open") for sev in SEVERITY_ORDER}
    metrics = (snap.config or {}).get("topology_metrics") or {}
    devices = snap.devices
    return {
        "snapshot_id": snap.snapshot_id,
        "mode": snap.mode,
        "started": snap.started,
        "finished": snap.finished,
        "duration": snap.duration_seconds,
        "operator": snap.operator,
        "targets": snap.targets,
        "devices": len(devices),
        "online": sum(1 for d in devices if d.reachable),
        "links": len(snap.links),
        "zones": len(snap.zones),
        "findings": len(snap.findings),
        "severity_counts": counts,
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "risks": len([f for f in snap.findings if f.status == "open"]),
        "risk": snap.risk,
        "risk_band": (snap.summary or {}).get("risk_band"),
        "risk_score": (snap.risk or {}).get("score"),
        "summary": snap.summary,
        "topology": {k: v for k, v in metrics.items() if k not in ("derived_from", "notes")},
        "services": sum(len(d.open_ports) for d in devices),
        "open_ports": sum(len(d.open_ports) for d in devices),
        "scan_errors": len(snap.errors),
        "notes": snap.notes[:8],
    }


def device_list(snap: ScanSnapshot) -> list[dict]:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    counts: dict[str, int] = {}
    sev: dict[str, str] = {}
    for f in snap.findings:
        counts[f.target_id] = counts.get(f.target_id, 0) + 1
        cur = sev.get(f.target_id)
        if f.status == "open" and (cur is None or rank.get(f.severity, 9) < rank.get(cur, 9)):
            sev[f.target_id] = f.severity
    out = []
    for d in sorted(snap.devices, key=lambda x: (-(x.risk_score or 0), x.label)):
        services = [{"port": s.port, "protocol": s.protocol, "name": s.name, "product": s.product, "version": s.version} for s in d.services if s.is_open]
        out.append(
            {
                "id": d.id,
                "hostname": d.hostname,
                "name": d.hostname or d.ip or d.id,
                "label": d.label,
                "ip": d.ip,
                "mac": d.mac,
                "vendor": d.vendor,
                "model": d.model,
                "os": " ".join(str(x) for x in (d.os_family, d.os_version) if x),
                "os_family": d.os_family,
                "os_version": d.os_version,
                "type": d.device_type,
                "device_type": d.device_type,
                "role": d.role,
                "zone": d.zone,
                "trust": d.trust,
                "vlan": d.vlan,
                "criticality": d.criticality,
                "ports": d.open_ports,
                "open_ports": d.open_ports,
                "port_count": len(d.open_ports),
                "services": services,
                "service_count": len(services),
                "criticality_level": d.criticality,
                "risk": round(float(d.risk_score or 0), 1),
                "risk_score": round(float(d.risk_score or 0), 1),
                "severity": sev.get(d.id, "none"),
                "findings": counts.get(d.id, 0),
                "finding_count": counts.get(d.id, 0),
                "neighbours": len(d.neighbors),
                "neighbors": len(d.neighbors),
                "documented": d.documented,
                "reachable": d.reachable,
                "status": "online" if d.reachable else "offline",
                "last_seen": d.last_seen,
                "first_seen": d.last_seen,
                "exposed": d.exposed_to_wan,
            }
        )
    return out


def device_detail(snap: ScanSnapshot, ident: str) -> dict:
    from urllib.parse import unquote

    dev = snap.find_device(unquote(ident))
    if dev is None:
        raise HTTPException(status_code=404, detail=f"No device {ident}")
    services = []
    for s in dev.services:
        entry: dict[str, Any] = {
            "port": s.port,
            "protocol": s.protocol,
            "state": s.state,
            "name": s.name,
            "product": s.product,
            "version": s.version,
            "banner": (s.banner or "")[:400],
            "encryption": s.encryption,
        }
        if s.certificate:
            entry["certificate"] = {
                "subject_cn": s.certificate.subject_cn,
                "issuer_cn": s.certificate.issuer_cn,
                "self_signed": s.certificate.self_signed,
                "not_after": s.certificate.not_after,
                "days_left": s.certificate.days_left,
                "protocol": s.certificate.protocol,
                "expired": s.certificate.expired,
            }
        services.append(entry)
    findings = []
    for f in sorted(snap.findings, key=lambda x: x.sort_key):
        if f.target_id != dev.id:
            continue
        findings.append(
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.rule_title,
                "severity": f.severity,
                "score": round(f.score, 2),
                "evidence": [ev.get("text", "") for ev in f.evidence][:6],
                "description": f.description,
                "remediation": f.remediation,
                "recommendation": f.remediation,
                "refs": f.refs,
                "status": f.status,
                "first_seen": f.first_seen,
                "source": f.rule_id,
            }
        )
    links = []
    for ln in snap.links:
        if dev.id not in (ln.src_device, ln.dst_device):
            continue
        other = ln.dst_device if ln.src_device == dev.id else ln.src_device
        peer = snap.find_device(other)
        links.append(
            {
                "id": ln.id,
                "peer": peer.label if peer else other,
                "peer_id": other,
                "local_interface": ln.src_interface if ln.src_device == dev.id else ln.dst_interface,
                "peer_interface": ln.dst_interface if ln.src_device == dev.id else ln.src_interface,
                "kind": ln.kind,
                "spof": ln.is_spof,
                "protected": ln.protected,
            }
        )
    worst = "none"
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for f in findings:
        if rank.get(f["severity"], 9) < rank.get(worst, 9):
            worst = f["severity"]
    return {
        "id": dev.id,
        "label": dev.label,
        "name": dev.hostname or dev.ip or dev.id,
        "ip": dev.ip,
        "hostname": dev.hostname,
        "mac": dev.mac,
        "vendor": dev.vendor,
        "model": dev.model,
        "os": " ".join(str(x) for x in (dev.os_family, dev.os_version) if x),
        "os_family": dev.os_family,
        "os_version": dev.os_version,
        "os_eol": dev.os_eol,
        "type": dev.device_type,
        "device_type": dev.device_type,
        "role": dev.role,
        "zone": dev.zone,
        "trust": dev.trust,
        "vlan": dev.vlan,
        "criticality": dev.criticality,
        "documented": dev.documented,
        "exposed": dev.exposed_to_wan,
        "reachable": dev.reachable,
        "status": "online" if dev.reachable else "offline",
        "uptime": f"{int((dev.uptime_seconds or 0) / 3600)}h" if dev.uptime_seconds else None,
        "uptime_seconds": dev.uptime_seconds,
        "sources": dev.discovery_sources,
        "discovery_sources": dev.discovery_sources,
        "risk": round(float(dev.risk_score or 0), 1),
        "risk_score": round(float(dev.risk_score or 0), 1),
        "severity": worst,
        "open_ports": dev.open_ports,
        "ports": dev.open_ports,
        "interfaces": [i.to_dict() for i in dev.interfaces],
        "services": services,
        "service_count": len([s for s in services]),
        "findings": findings,
        "finding_count": len(findings),
        "links": links,
        "neighbours": [{"remote": n.remote_system or n.remote_key, "local_if": n.local_if, "via": n.via, "confidence": n.confidence} for n in dev.neighbors][:30],
        "neighbors": [{"remote": n.remote_system or n.remote_key, "local_if": n.local_if, "via": n.via, "confidence": n.confidence} for n in dev.neighbors][:30],
        "neighbor_count": len(dev.neighbors),
        "notes": dev.notes[:8],
        "last_seen": dev.last_seen,
        "lastSeen": dev.last_seen,
        "first_seen": dev.last_seen,
    }


def graph_payload(snap: ScanSnapshot) -> dict:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sev_by_dev: dict[str, str] = {}
    counts: dict[str, int] = {}
    for f in snap.findings:
        counts[f.target_id] = counts.get(f.target_id, 0) + 1
        if f.status != "open":
            continue
        cur = sev_by_dev.get(f.target_id)
        if cur is None or rank.get(f.severity, 9) < rank.get(cur, 9):
            sev_by_dev[f.target_id] = f.severity
    by_id = snap.device_map()
    nodes = []
    for d in snap.devices:
        nodes.append(
            {
                "id": d.id,
                "label": d.hostname or d.ip or d.id,
                "name": d.hostname or d.ip or d.id,
                "ip": d.ip,
                "type": d.device_type,
                "device_type": d.device_type,
                "role": d.role,
                "zone": d.zone,
                "trust": d.trust,
                "status": "online" if d.reachable else "offline",
                "exposed": d.exposed_to_wan,
                "risk": round(float(d.risk_score or 0), 1),
                "risk_score": round(float(d.risk_score or 0), 1),
                "severity": sev_by_dev.get(d.id) or ("none" if not d.risk_score else "info"),
                "findings": counts.get(d.id, 0),
                "ports": d.open_ports,
                "port_count": len(d.open_ports),
            }
        )
    edges = []
    for ln in snap.links:
        if ln.src_device not in by_id or ln.dst_device not in by_id:
            continue
        edges.append(
            {
                "id": ln.id,
                "source": ln.src_device,
                "target": ln.dst_device,
                "src": ln.src_device,
                "dst": ln.dst_device,
                "kind": ln.kind,
                "confidence": ln.confidence,
                "spof": ln.is_spof,
                "protected": ln.protected,
                "label": ln.kind,
            }
        )
    return {"nodes": nodes, "edges": edges, "links": edges}


def findings_list(snap: ScanSnapshot) -> list[dict]:
    out = []
    for f in sorted(snap.findings, key=lambda x: x.sort_key):
        dev = snap.find_device(f.target_id) if f.target_id else None
        out.append(
            {
                "id": f.id,
                "finding_id": f.id,
                "rule_id": f.rule_id,
                "title": f.rule_title,
                "severity": f.severity,
                "score": round(f.score, 2),
                "scope": f.scope,
                "target": f.target_label,
                "target_label": f.target_label,
                "target_id": f.target_id,
                "device": (dev.hostname or dev.ip) if dev else f.target_label,
                "ip": dev.ip if dev else None,
                "device_type": f.device_type,
                "zone": f.zone,
                "evidence": [ev.get("text", "") for ev in f.evidence][:6],
                "description": f.description,
                "remediation": f.remediation,
                "recommendation": f.remediation,
                "refs": f.refs,
                "status": f.status,
                "first_seen": f.first_seen,
                "first_detected": f.first_seen,
                "last_detected": snap.finished,
                "source": f.rule_id,
                "detection_source": f.rule_id,
            }
        )
    return out


# ---------------------------------------------------------------- jobs
def set_stage(job: dict, stage_id: str, state: str) -> None:
    for st in job["stages"]:
        if st["id"] == stage_id:
            st["state"] = state
    job["stage"] = stage_id


def update_job(job_id: str, **kw) -> None:
    with STATE.lock:
        job = STATE.jobs.get(job_id)
        if job:
            job.update(kw)


def job_event(job_id: str, stage: str, msg: str) -> None:
    """Append a human-readable narrative line to the job's watch feed (capped)."""
    with STATE.lock:
        job = STATE.jobs.get(job_id)
        if not job:
            return
        feed = job.setdefault("events", [])
        feed.append({"t": utcnow(), "stage": stage, "msg": msg[:300]})
        if len(feed) > 200:
            del feed[: len(feed) - 200]


def compact_devices(snap, limit: int = 80) -> list[dict]:
    from netmap.util import SEVERITY_ORDER as _SEV

    rank = {s: i for i, s in enumerate(_SEV)}
    sev: dict[str, str] = {}
    for f in snap.findings:
        cur = sev.get(f.target_id)
        if f.status == "open" and (cur is None or rank.get(f.severity, 9) < rank.get(cur, 9)):
            sev[f.target_id] = f.severity
    rows = sorted(snap.devices, key=lambda d: (-(d.risk_score or 0), d.label))[:limit]
    return [
        {
            "id": d.id,
            "label": d.hostname or d.ip or d.id,
            "ip": d.ip,
            "type": d.device_type,
            "device_type": d.device_type,
            "role": d.role,
            "zone": d.zone,
            "status": "online" if d.reachable else "offline",
            "risk": round(float(d.risk_score or 0), 1),
            "severity": sev.get(d.id, "none"),
            "ports": d.open_ports,
        }
        for d in rows
    ]


def compact_links(snap, limit: int = 200) -> list[dict]:
    return [
        {"source": ln.src_device, "target": ln.dst_device, "kind": ln.kind, "spof": ln.is_spof, "protected": ln.protected}
        for ln in snap.links[:limit]
    ]


def compact_findings(snap, limit: int = 12) -> list[dict]:
    out = []
    for f in sorted(snap.findings, key=lambda x: x.sort_key)[:limit]:
        dev = snap.find_device(f.target_id) if f.target_id else None
        out.append(
            {
                "severity": f.severity,
                "title": f.rule_title,
                "device": (dev.hostname or dev.ip) if dev else (f.target_label or ""),
                "rule_id": f.rule_id,
            }
        )
    return out


def run_demo_job(job_id: str, size: str, seed: int, include_risks: bool = True) -> None:
    """Real staged demo pipeline: simulator -> classify -> topology -> risk -> persist."""
    from netmap.discovery.engine import classify_devices, snapshot_from_devices
    from netmap.discovery.simulator import build_devices, build_specs, to_devices
    from netmap.topology.builder import build_topology
    from netmap.risk.engine import RiskEngine, band_for

    def mark(sid: str, state: str, pct: int, msg: str = ""):
        with STATE.lock:
            job = STATE.jobs.get(job_id)
            if not job:
                return
            set_stage(job, sid, state)
            job["progress"] = pct
            if msg:
                job["message"] = msg

    try:
        update_job(job_id, status="running", started_at=utcnow())
        t0 = time.time()
        mark("host_discovery", "running", 5, "Building simulated hosts")
        job_event(job_id, "host_discovery", f"probing demo campus ({size}, seed {seed})…")
        specs = build_specs(size, seed=seed, include_risks=include_risks)
        with STATE.lock:
            STATE.jobs[job_id]["counts"] = {"hosts": len(specs)}
            STATE.jobs[job_id]["live_devices"] = [
                {"id": f"sim:{s.ip}", "label": s.hostname or s.ip, "ip": s.ip, "type": s.device_type, "device_type": s.device_type, "role": s.role, "zone": s.zone, "status": "online", "risk": 0, "severity": "none", "ports": []}
                for s in specs[:80]
            ]
        job_event(job_id, "host_discovery", f"{len(specs)} hosts responding — identifying device roles…")
        time.sleep(0.35)
        mark("host_discovery", "done", 18, f"{len(specs)} simulated hosts")

        mark("port_scan", "running", 22, "Probing simulated ports")
        import random as _random

        devices, zones = to_devices(specs, rng=_random.Random(seed))
        open_ports = sum(len(d.open_ports) for d in devices)
        busiest = sorted(devices, key=lambda d: -len(d.open_ports))[:3]
        with STATE.lock:
            STATE.jobs[job_id]["counts"] = {"hosts": len(specs), "devices": len(devices), "services": open_ports}
        job_event(job_id, "port_scan", f"{open_ports} open ports across {len(devices)} devices — e.g. " + ", ".join(f"{d.label} ({len(d.open_ports)} ports)" for d in busiest))
        time.sleep(0.35)
        mark("port_scan", "done", 38, f"{open_ports} open ports")

        mark("service_fingerprint", "running", 42, "Fingerprinting services")
        classify_devices(devices)
        tls_n = sum(1 for d in devices for s in d.services if s.is_open and s.certificate is not None)
        types = {}
        for d in devices:
            types[d.device_type] = types.get(d.device_type, 0) + 1
        top_types = ", ".join(f"{v}× {k}" for k, v in sorted(types.items(), key=lambda kv: -kv[1])[:5])
        job_event(job_id, "service_fingerprint", f"banners classified: {top_types}… · {tls_n} TLS endpoints fingerprinted")
        time.sleep(0.3)
        mark("service_fingerprint", "done", 55, f"{len(devices)} devices classified")

        mark("dns_resolution", "running", 58, "Resolving names")
        resolved = sum(1 for d in devices if d.hostname)
        job_event(job_id, "dns_resolution", f"{resolved} of {len(devices)} devices resolved to hostnames")
        time.sleep(0.25)
        mark("dns_resolution", "done", 63, f"{resolved} hostnames")

        mark("snmp_enumeration", "running", 65, "Reading simulated SNMP facts")
        snmp_ok = sum(1 for d in devices if (d.snmp or {}).get("readable"))
        snmp_default = sum(1 for d in devices if (d.snmp or {}).get("default_community"))
        job_event(job_id, "snmp_enumeration", f"{snmp_ok} devices answered SNMP" + (f" — {snmp_default} still use a default community" if snmp_default else ""))
        time.sleep(0.3)
        mark("snmp_enumeration", "done", 72, f"{snmp_ok} SNMP-readable (simulated)")

        mark("topology", "running", 75, "Building topology graph")
        cfg = Config()
        cfg.set("scan.mode", "lab")
        snap = snapshot_from_devices(devices, cfg, mode="lab", zones=zones)
        snap.snapshot_id = f"snap-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:4]}"
        snap.operator = "web-demo"
        snap.targets = [f"demo:{size}:seed-{seed}"]
        snap.notes.append("demo mode: devices are synthetic, generated by netmap.discovery.simulator")
        metrics = build_topology(snap, cfg.get)
        snap.config["topology_metrics"] = metrics
        spofs = sum(1 for ln in snap.links if ln.is_spof)
        with STATE.lock:
            STATE.jobs[job_id]["live_links"] = compact_links(snap)
        job_event(job_id, "topology", f"assembled {len(snap.links)} links from LLDP/SNMP evidence" + (f" — {spofs} single points of failure" if spofs else ""))
        time.sleep(0.3)
        mark("topology", "done", 85, f"{len(snap.links)} links")

        mark("risk_analysis", "running", 87, "Evaluating 53 risk rules")
        engine = RiskEngine()
        engine.analyze(snap)
        from netmap.risk.engine import band_for as _band

        snap.summary = {**(snap.summary or {}), "risk_band": _band(float((snap.risk or {}).get("score") or 0)), "mode": "lab"}
        sev_counts = {}
        for f in snap.findings:
            if f.status == "open":
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        first = None
        for f in sorted(snap.findings, key=lambda x: x.sort_key):
            if f.status == "open":
                first = f
                break
        with STATE.lock:
            STATE.jobs[job_id]["live_devices"] = compact_devices(snap)
            STATE.jobs[job_id]["live_findings"] = compact_findings(snap)
        job_event(job_id, "risk_analysis", f"53 rules evaluated → {len(snap.findings)} findings ({sev_counts.get('critical', 0)} critical)" + (f" — worst first: [{first.severity}] {first.rule_title} on {first.target_label}" if first else ""))
        time.sleep(0.3)
        mark("risk_analysis", "done", 94, f"{len(snap.findings)} findings")

        mark("persist", "running", 96, "Saving snapshot")
        snap.finished = utcnow()
        snap.duration_seconds = round(time.time() - t0, 2)
        save_snapshot(snap, DATA_DIR / f"{snap.snapshot_id}.json")
        job_event(job_id, "persist", f"snapshot {snap.snapshot_id} saved ({len(snap.devices)} devices, {len(snap.links)} links, {len(snap.findings)} findings)")
        row = {
            "snapshot_id": snap.snapshot_id,
            "scan_id": snap.snapshot_id,
            "target": f"demo:{size}",
            "targets": snap.targets,
            "environment": "demo",
            "mode": "lab",
            "scan_mode": "normal",
            "started": snap.started,
            "finished": snap.finished,
            "duration": snap.duration_seconds,
            "devices": len(snap.devices),
            "links": len(snap.links),
            "services": sum(len(d.open_ports) for d in snap.devices),
            "findings": len(snap.findings),
            "status": "completed",
            "job_id": job_id,
        }
        with STATE.lock:
            STATE.snapshots[snap.snapshot_id] = snap
            STATE.meta[snap.snapshot_id] = row
            STATE.current_id = snap.snapshot_id
            STATE._save_index()
        mark("persist", "done", 100, "Done")
        update_job(
            job_id,
            status="completed",
            finished_at=utcnow(),
            snapshot_id=snap.snapshot_id,
            scan_id=snap.snapshot_id,
            duration=round(time.time() - t0, 2),
            counts={"devices": len(snap.devices), "services": sum(len(d.open_ports) for d in snap.devices), "links": len(snap.links), "risks": len(snap.findings)},
            message=f"{len(snap.devices)} devices, {len(snap.links)} links, {len(snap.findings)} findings",
        )
    except Exception as exc:  # noqa: BLE001
        with STATE.lock:
            job = STATE.jobs.get(job_id)
            if job:
                for st in job["stages"]:
                    if st["state"] == "running":
                        st["state"] = "error"
                job.update({"status": "failed", "finished_at": utcnow(), "error": f"{type(exc).__name__}: {exc}", "message": str(exc)[:500]})


def run_live_job(job_id: str, targets: list[str], mode: str, methods: dict, statement: str | None, snmp_community: str | None = None) -> None:
    """Real live pipeline via DiscoveryEngine + analyze, with stage mapping."""
    t0 = time.time()
    with STATE.lock:
        job = STATE.jobs.get(job_id)
        if not job:
            return
        set_stage(job, "host_discovery", "running")
        job["progress"] = 5

    ENGINE_TO_STAGE = {
        "host-discovery": "host_discovery",
        "port-scan": "port_scan",
        "service-fingerprint": "service_fingerprint",
        "name-resolution": "dns_resolution",
        "snmp-enumeration": "snmp_enumeration",
        "passive-neighbours": "snmp_enumeration",
        "classification": "topology",
    }

    def progress(stage: str, frac: float, message: str):
        sid = ENGINE_TO_STAGE.get(stage, "port_scan")
        with STATE.lock:
            job = STATE.jobs.get(job_id)
            if not job:
                return
            for st in job["stages"]:
                if st["id"] == sid and st["state"] == "pending":
                    st["state"] = "running"
            job["progress"] = max(5, min(80, int(round(frac * 80))))
            job["message"] = f"{stage}: {message}"[:300]
        job_event(job_id, sid, f"{stage}: {message}"[:300])

    try:
        update_job(job_id, status="running", started_at=utcnow())
        cfg = Config()
        cfg.set("scan.mode", "live")
        cfg.set("scan.targets", targets)
        cfg.set("operator", "web-operator")
        # scan depth presets
        if mode == "fast":
            cfg.set("scan.tcp_ports", [22, 23, 80, 443, 445, 3389, 8080])
            cfg.set("scan.udp_ports", [53, 161])
            cfg.set("scan.tls_probe", False)
        elif mode == "deep":
            cfg.set("scan.tcp_ports", "full" if len(targets) <= 4 else "top")
            cfg.set("scan.banner_grab", True)
            cfg.set("scan.tls_probe", True)
        # methods toggles
        m = methods or {}
        if m.get("arp") is False:
            cfg.set("scan.arp.enabled", False)
        if m.get("dns") is False:
            cfg.set("scan.resolve_names", False)
        if m.get("tls") is False:
            cfg.set("scan.tls_probe", False)
        if m.get("snmp") is False:
            cfg.set("scan.snmp.enabled", False)
        elif snmp_community and snmp_community.strip():
            # Per-scan credential: tried first, never persisted, never echoed.
            extra = snmp_community.strip()
            comms = [extra] + [c for c in (cfg.get("scan.snmp.communities") or []) if c != extra]
            cfg.set("scan.snmp.communities", comms)
        elif SNMP_SESSION.get("community"):
            # Session credential from Settings: tried first, never echoed.
            extra = SNMP_SESSION["community"]
            comms = [extra] + [c for c in (cfg.get("scan.snmp.communities") or []) if c != extra]
            cfg.set("scan.snmp.communities", comms)
        # Home/small networks expose no LLDP/CDP, SNMP agents or MAC tables,
        # so link evidence is absent. Allow the topology builder's labelled
        # gateway-star inference (same-subnet, low confidence) for live scans.
        cfg.set("topology.treat_same_subnet_as_adjacency", True)
        # CDP/LLDP passive capture: genuinely attempted when the operator asked
        # for it AND a capture tool exists; otherwise honestly reported as skipped.
        capture_status = "disabled by operator"
        if m.get("cdp_lldp") is not False:
            if shutil.which("tcpdump"):
                cfg.set("scan.capture.enabled", True)
                cfg.set("scan.capture.seconds", 8)
                capture_status = "active: tcpdump 8s window"
            else:
                capture_status = "skipped: no capture tool (tcpdump not found); SNMP neighbour MIBs still used"
        update_job(job_id, capture_status=capture_status)
        if m.get("tcp") is False:
            cfg.set("scan.tcp_ports", [])
        if m.get("udp") is False:
            cfg.set("scan.udp_ports", [])
        # authorization gate (same rule as CLI)
        cfg.set("authorization.confirmed", True)
        cfg.set("authorization.signed_by", "web operator")
        cfg.set("authorization.statement", statement or "confirmed in the web UI at scan start")
        cfg.set("authorization.scope", targets)
        problems = cfg.authorization_problems()
        if problems:
            raise PermissionError("authorization incomplete: " + "; ".join(problems))
        non_private = [t for t in targets if not is_private_target(t)]
        if non_private:
            raise PermissionError(f"Live scan refused: {', '.join(non_private)} is outside private/loopback ranges (demo mode has no restriction).")

        snap = discover(cfg, progress=progress)
        alive = [d for d in snap.devices if d.reachable]
        job_event(job_id, "host_discovery", f"{len(alive)} of {len(snap.devices)} probed hosts alive: " + ", ".join(d.ip or d.id for d in alive[:8]) + (f" (+{len(alive) - 8} more)" if len(alive) > 8 else ""))
        with STATE.lock:
            STATE.jobs[job_id]["counts"] = {"devices": len(alive), "services": sum(len(d.open_ports) for d in alive)}
            STATE.jobs[job_id]["live_devices"] = [
                {"id": d.id, "label": d.hostname or d.ip or d.id, "ip": d.ip, "type": d.device_type, "device_type": d.device_type, "role": d.role, "zone": d.zone, "status": "online" if d.reachable else "offline", "risk": 0, "severity": "none", "ports": d.open_ports}
                for d in alive[:80]
            ]
        with STATE.lock:
            job = STATE.jobs.get(job_id)
            if job:
                for sid in ("host_discovery", "port_scan", "service_fingerprint", "dns_resolution", "snmp_enumeration"):
                    for st in job["stages"]:
                        if st["id"] == sid and st["state"] == "pending":
                            st["state"] = "done"
                set_stage(job, "topology", "running")
                job["progress"] = 84
                job["message"] = "Building topology + risk"
        analyze(cfg, snap)
        job_event(job_id, "topology", f"assembled {len(snap.links)} links" + (f" ({sum(1 for ln in snap.links if ln.is_spof)} SPOF)" if snap.links else ""))
        with STATE.lock:
            STATE.jobs[job_id]["live_links"] = compact_links(snap)
            STATE.jobs[job_id]["live_devices"] = compact_devices(snap)
            STATE.jobs[job_id]["live_findings"] = compact_findings(snap)
        crit = sum(1 for f in snap.findings if f.severity == "critical" and f.status == "open")
        job_event(job_id, "risk_analysis", f"53 rules evaluated → {len(snap.findings)} findings ({crit} critical)")
        with STATE.lock:
            job = STATE.jobs.get(job_id)
            if job:
                for sid in ("topology", "risk_analysis"):
                    set_stage(job, sid, "done")
                set_stage(job, "persist", "running")
                job["progress"] = 96
        snap.finished = utcnow()
        snap.duration_seconds = round(time.time() - t0, 2)
        if not snap.snapshot_id:
            snap.snapshot_id = f"snap-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:4]}"
        save_snapshot(snap, DATA_DIR / f"{snap.snapshot_id}.json")
        row = {
            "snapshot_id": snap.snapshot_id,
            "scan_id": snap.snapshot_id,
            "target": ", ".join(targets),
            "targets": targets,
            "environment": "live",
            "mode": "live",
            "scan_mode": mode,
            "started": snap.started,
            "finished": snap.finished,
            "duration": snap.duration_seconds,
            "devices": len(snap.devices),
            "links": len(snap.links),
            "services": sum(len(d.open_ports) for d in snap.devices),
            "findings": len(snap.findings),
            "status": "completed",
            "job_id": job_id,
        }
        with STATE.lock:
            STATE.snapshots[snap.snapshot_id] = snap
            STATE.meta[snap.snapshot_id] = row
            STATE.current_id = snap.snapshot_id
            STATE._save_index()
            job = STATE.jobs.get(job_id)
            if job:
                for st in job["stages"]:
                    if st["state"] in ("pending", "running"):
                        st["state"] = "done"
                job.update(
                    {
                        "status": "completed",
                        "finished_at": utcnow(),
                        "snapshot_id": snap.snapshot_id,
                        "scan_id": snap.snapshot_id,
                        "duration": round(time.time() - t0, 2),
                        "counts": {"devices": len(snap.devices), "services": sum(len(d.open_ports) for d in snap.devices), "links": len(snap.links), "risks": len(snap.findings)},
                        "progress": 100,
                        "message": f"{len(snap.devices)} devices, {len(snap.links)} links, {len(snap.findings)} findings",
                    }
                )
    except PermissionError as exc:
        update_job(job_id, status="failed", finished_at=utcnow(), error=str(exc), message=str(exc)[:500])
        with STATE.lock:
            job = STATE.jobs.get(job_id)
            if job:
                for st in job["stages"]:
                    if st["state"] == "running":
                        st["state"] = "error"
    except Exception as exc:  # noqa: BLE001
        update_job(job_id, status="failed", finished_at=utcnow(), error=f"{type(exc).__name__}: {exc}", message=str(exc)[:500])
        with STATE.lock:
            job = STATE.jobs.get(job_id)
            if job:
                for st in job["stages"]:
                    if st["state"] == "running":
                        st["state"] = "error"


# ---------------------------------------------------------------- routes
@app.get("/api/health")
def health():
    snap = STATE.current()
    return {"ok": True, "version": __version__, "code_version": CODE_VERSION, "features": FEATURES, "snapshot": bool(snap), "snapshot_id": snap.snapshot_id if snap else None, "mode": snap.mode if snap else None, "jobs": len(STATE.jobs), "scans": len(STATE.meta)}


@app.get("/api/capabilities")
def capabilities():
    snap = STATE.current()
    snmp_configured = snmp_is_configured()
    tcpdump = shutil.which("tcpdump") or None
    return {
        "methods": {
            "arp": {"available": True, "label": "ARP"},
            "tcp": {"available": True, "label": "TCP connect"},
            "udp": {"available": True, "label": "UDP"},
            "dns": {"available": True, "label": "DNS"},
            "tls": {"available": True, "label": "TLS fingerprinting"},
            "snmp": {"available": True, "configured": snmp_configured, "label": "SNMP", "note": None if snmp_configured else "No NETMAP_SNMP_RO set — enter a community per scan, or only 'public' will be tried"},
            "cdp_lldp": {
                "available": bool(tcpdump),
                "label": "CDP/LLDP passive capture",
                "tool": tcpdump,
                "note": "Live capture active (8s window) when tcpdump is present" if tcpdump else "tcpdump not found on this host — neighbour rows from SNMP MIBs are still used",
            },
        },
        "live_allowed": True,
        "loopback_allowed": True,
        "snapshot": snap.snapshot_id if snap else None,
    }


class SnmpBody(BaseModel):
    community: str | None = Field(default=None, max_length=128)


@app.get("/api/settings/snmp")
def snmp_settings():
    """Whether a session SNMP community is set. The secret itself is never returned."""
    return {"configured": snmp_is_configured(), "source": "session" if SNMP_SESSION.get("community") else ("environment" if (__import__("os").environ.get("NETMAP_SNMP_RO") or "").strip() else "none")}


@app.post("/api/settings/snmp")
def snmp_save(body: SnmpBody):
    """Store an SNMP community for this backend session only (lost on restart)."""
    comm = (body.community or "").strip()
    SNMP_SESSION["community"] = comm or None
    return {"configured": snmp_is_configured()}


@app.delete("/api/settings/snmp")
def snmp_clear():
    SNMP_SESSION["community"] = None
    return {"configured": snmp_is_configured()}


@app.post("/api/scan", status_code=202)
def start_scan(body: ScanRequest):
    env = (body.environment or "demo").lower()
    if env not in ("live", "demo"):
        raise HTTPException(status_code=400, detail="environment must be 'live' or 'demo'")
    targets = body.targets or ([body.target] if body.target else [])
    targets = [t.strip() for t in targets if str(t).strip()]
    if env == "demo":
        if body.size not in ("small", "medium", "large"):
            raise HTTPException(status_code=400, detail="size must be small|medium|large")
        targets = [f"demo:{body.size}:seed-{body.seed}"]
    else:
        targets = validate_targets(targets)
        if not body.confirmAuthorized:
            raise HTTPException(status_code=400, detail="Live discovery requires confirmAuthorized: true (authorized scanning only).")
    job_id = uuid.uuid4().hex[:12]
    job = {
        "job_id": job_id,
        "job": job_id,
        "status": "queued",
        "state": "queued",
        "stage": "queued",
        "stages": fresh_stages(),
        "progress": 0,
        "done": 0,
        "total": 100,
        "target": ", ".join(targets),
        "targets": targets,
        "environment": env,
        "size": body.size,
        "seed": body.seed,
        "include_risks": bool(body.include_risks),
        "scan_mode": body.mode,
        "mode": body.mode,
        "methods": body.methods or {"arp": True, "tcp": True, "udp": True, "dns": True, "tls": True, "snmp": True, "cdp_lldp": True},
        "created_at": utcnow(),
        "started_at": None,
        "finished_at": None,
        "message": "Queued",
        "counts": {"devices": 0, "services": 0, "links": 0, "risks": 0},
    }
    with STATE.lock:
        STATE.jobs[job_id] = job
    if env == "demo":
        th = threading.Thread(target=run_demo_job, args=(job_id, body.size, int(body.seed), bool(body.include_risks)), daemon=True)
    else:
        # NOTE: snmp_community travels only as a thread arg — it is never
        # written into the job dict, logs, snapshots, or API responses.
        th = threading.Thread(
            target=run_live_job,
            args=(job_id, targets, body.mode, job["methods"], body.statement, body.snmp_community),
            daemon=True,
        )
    th.start()
    return job


@app.get("/api/scan/{job_id}")
def get_scan(job_id: str):
    with STATE.lock:
        job = STATE.jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="unknown job")
    return job


@app.get("/api/scan/{job_id}/events")
async def scan_events(job_id: str):
    """Server-Sent Events stream of live job progress (polling fallback: GET /api/scan/{job})."""
    with STATE.lock:
        if job_id not in STATE.jobs:
            raise HTTPException(status_code=404, detail="unknown job")

    async def gen():
        import json as _json

        idle = 0
        while True:
            with STATE.lock:
                job = dict(STATE.jobs.get(job_id) or {})
            if not job:
                yield "event: gone\ndata: {}\n\n"
                return
            # Strip anything sensitive (defence in depth — secrets are never stored, but belt and braces).
            safe = {k: v for k, v in job.items() if "community" not in k.lower() and "password" not in k.lower()}
            yield f"data: {_json.dumps(safe, default=str)}\n\n"
            if safe.get("status") in ("completed", "failed"):
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(0.5)
            idle += 1
            if idle > 1200:  # ~10 min safety cap
                yield "event: timeout\ndata: {}\n\n"
                return

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/jobs")
def list_jobs():
    with STATE.lock:
        jobs = list(STATE.jobs.values())
    jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
    return jobs


def require_snapshot() -> ScanSnapshot:
    snap = STATE.current()
    if snap is None:
        raise HTTPException(status_code=404, detail="No scan yet. Run a discovery scan first (demo mode needs no network).")
    return snap


@app.get("/api/summary")
def summary():
    return snapshot_to_summary(require_snapshot())


@app.get("/api/devices")
def devices(type: str | None = None, zone: str | None = None, risk: str | None = None, search: str | None = None, status: str | None = None):
    rows = device_list(require_snapshot())
    if type and type != "all":
        rows = [r for r in rows if (r.get("device_type") or "") == type]
    if zone and zone != "all":
        rows = [r for r in rows if (r.get("zone") or "") == zone]
    if risk and risk != "all":
        rows = [r for r in rows if (r.get("severity") or "") == risk]
    if status and status != "all":
        rows = [r for r in rows if (r.get("status") or "") == status]
    if search:
        q = search.lower()
        rows = [r for r in rows if q in str(r.get("name") or "").lower() or q in str(r.get("ip") or "").lower() or q in str(r.get("vendor") or "").lower()]
    return rows


@app.get("/api/devices/{device_id:path}")
def device_one(device_id: str):
    return device_detail(require_snapshot(), device_id)


@app.get("/api/graph")
def graph(snapshot_id: str | None = None):
    if snapshot_id:
        with STATE.lock:
            snap = STATE.snapshots.get(snapshot_id)
        if snap is None:
            raise HTTPException(status_code=404, detail="unknown snapshot")
        return graph_payload(snap)
    return graph_payload(require_snapshot())


@app.get("/api/links")
def links():
    snap = require_snapshot()
    by_id = snap.device_map()
    out = []
    for ln in snap.links:
        src, dst = by_id.get(ln.src_device), by_id.get(ln.dst_device)
        out.append(
            {
                "id": ln.id,
                "source": ln.src_device,
                "target": ln.dst_device,
                "src": src.label if src else ln.src_device,
                "dst": dst.label if dst else ln.dst_device,
                "src_label": src.label if src else ln.src_device,
                "dst_label": dst.label if dst else ln.dst_device,
                "kind": ln.kind,
                "confidence": ln.confidence,
                "derived_from": ln.derived_from,
                "spof": ln.is_spof,
                "protected": ln.protected,
                "risk": round(float(ln.risk_score or 0), 1),
            }
        )
    return out


@app.get("/api/zones")
def zones():
    snap = require_snapshot()
    return [
        {
            "name": z.name,
            "trust": z.trust,
            "devices": z.device_count or len(snap.devices_by(zone=z.name)),
            "device_count": z.device_count or len(snap.devices_by(zone=z.name)),
            "cidrs": z.cidrs,
            "vlans": z.vlans,
            "enforced": z.segmentation_enforced,
            "gateway": z.default_gateway,
            "description": z.description,
        }
        for z in snap.zones
    ]


@app.get("/api/findings")
def findings(severity: str | None = None, search: str | None = None):
    rows = findings_list(require_snapshot())
    if severity and severity != "all":
        rows = [r for r in rows if r.get("severity") == severity]
    if search:
        q = search.lower()
        rows = [r for r in rows if q in str(r.get("title") or "").lower() or q in str(r.get("device") or "").lower() or q in str(r.get("rule_id") or "").lower()]
    return rows


@app.get("/api/findings/{finding_id}")
def finding_one(finding_id: str):
    for f in findings_list(require_snapshot()):
        if f["id"] == finding_id or f["rule_id"] == finding_id:
            return f
    raise HTTPException(status_code=404, detail="unknown finding")


@app.get("/api/services")
def services():
    snap = require_snapshot()
    agg: dict[tuple, dict] = {}
    for d in snap.devices:
        for s in d.services:
            if not s.is_open:
                continue
            key = (s.port, s.protocol, s.name or "")
            row = agg.setdefault(key, {"port": s.port, "protocol": s.protocol, "name": s.name, "product": s.product or "", "count": 0, "devices": []})
            row["count"] += 1
            if len(row["devices"]) < 8:
                row["devices"].append(d.hostname or d.ip or d.id)
    return sorted(agg.values(), key=lambda r: (-r["count"], r["port"]))


@app.get("/api/reports")
def reports():
    return [
        {"format": "json", "label": "JSON snapshot", "url": "/api/report.json"},
        {"format": "md", "label": "Markdown report", "url": "/api/report.md"},
        {"format": "html", "label": "HTML dashboard", "url": "/api/report.html"},
        {"format": "sarif", "label": "SARIF (CI)", "url": "/api/report.sarif"},
        {"format": "csv", "label": "CSV tables", "url": "/api/report.csv"},
        {"format": "dot", "label": "Graphviz DOT", "url": "/api/report.dot"},
        {"format": "cef", "label": "CEF (SIEM)", "url": "/api/report.cef"},
        {"format": "txt", "label": "Plain text", "url": "/api/report.txt"},
    ]


@app.get("/api/report.{fmt}")
def report(fmt: str):
    from netmap.report.writer import to_cef, to_csv, to_dot, to_markdown, to_sarif, to_txt
    from netmap.viz.static_html import render_html
    from netmap.viz.topology_svg import render_svg

    snap = require_snapshot()
    fmt = fmt.lower()
    if fmt == "json":
        return JSONResponse(content=json.loads(json.dumps(snap.to_dict(), default=str)))
    if fmt in ("md", "markdown"):
        return PlainTextResponse(to_markdown(snap), media_type="text/markdown")
    if fmt == "html":
        return Response(render_html(snap, svg=render_svg(snap)), media_type="text/html")
    if fmt == "sarif":
        return JSONResponse(content=json.loads(to_sarif(snap)))
    if fmt == "csv":
        rows = to_csv(snap)
        body = "### findings\n" + rows.get("findings", "") + "\n### devices\n" + rows.get("devices", "")
        return PlainTextResponse(body, media_type="text/csv")
    if fmt == "dot":
        return PlainTextResponse(to_dot(snap), media_type="text/vnd.graphviz")
    if fmt == "svg":
        return Response(render_svg(snap), media_type="image/svg+xml")
    if fmt == "cef":
        return PlainTextResponse(to_cef(snap), media_type="text/plain")
    if fmt == "txt":
        return PlainTextResponse(to_txt(snap), media_type="text/plain")
    raise HTTPException(status_code=404, detail=f"unsupported format {fmt}")


@app.get("/api/history")
def history():
    with STATE.lock:
        rows = list(STATE.meta.values())
        snaps = dict(STATE.snapshots)
    rows.sort(key=lambda r: r.get("finished") or "", reverse=True)
    out = []
    for r in rows:
        snap = snaps.get(r.get("snapshot_id"))
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        if snap is not None:
            for sev in SEVERITY_ORDER:
                counts[sev] = sum(1 for f in snap.findings if f.severity == sev and f.status == "open")
        out.append({**r, "severity_counts": counts, "critical": counts.get("critical", 0)})
    return out


@app.get("/api/history/{scan_id}")
def history_one(scan_id: str):
    with STATE.lock:
        snap = STATE.snapshots.get(scan_id)
        meta = STATE.meta.get(scan_id)
    if snap is None:
        raise HTTPException(status_code=404, detail="unknown scan")
    counts = {sev: sum(1 for f in snap.findings if f.severity == sev and f.status == "open") for sev in SEVERITY_ORDER}
    top = [
        {"rule_id": f["rule_id"], "title": f["title"], "severity": f["severity"], "score": f["score"], "device": f["device"]}
        for f in findings_list(snap)[:5]
    ]
    return {"meta": meta, "summary": snapshot_to_summary(snap), "devices": len(snap.devices), "links": len(snap.links), "findings": len(snap.findings), "severity_counts": counts, "top_findings": top}


class CompareBody(BaseModel):
    old_id: str | None = None
    new_id: str | None = None


@app.get("/api/changes")
def changes():
    with STATE.lock:
        rows = sorted(STATE.meta.values(), key=lambda r: r.get("finished") or "")
    if len(rows) < 2:
        return {"available": False, "reason": "Run at least two scans to compare changes.", "changes": None}
    old_id, new_id = rows[-2]["snapshot_id"], rows[-1]["snapshot_id"]
    old, new = STATE.snapshots[old_id], STATE.snapshots[new_id]
    diff = compare_snapshots(old, new)
    return {"available": True, "old_id": old_id, "new_id": new_id, "changes": diff, "summary": summarize_diff(diff)}


@app.post("/api/compare")
def compare(body: CompareBody):
    with STATE.lock:
        ids = sorted(STATE.meta.keys(), key=lambda k: STATE.meta[k].get("finished") or "")
    old_id = body.old_id or (ids[-2] if len(ids) >= 2 else None)
    new_id = body.new_id or (ids[-1] if ids else None)
    if not old_id or not new_id or old_id not in STATE.snapshots or new_id not in STATE.snapshots:
        raise HTTPException(status_code=400, detail="Need two completed scans to compare.")
    diff = compare_snapshots(STATE.snapshots[old_id], STATE.snapshots[new_id])
    return {"old_id": old_id, "new_id": new_id, "changes": diff, "summary": summarize_diff(diff)}


def summarize_diff(diff: dict) -> dict:
    return {
        "devices_added": len(diff.get("devices_added") or []),
        "devices_removed": len(diff.get("devices_removed") or []),
        "device_changes": len(diff.get("device_changes") or []),
        "findings_appeared": len(diff.get("findings_appeared") or []),
        "findings_resolved": len(diff.get("findings_resolved") or []),
        "new_critical": diff.get("new_critical", 0),
        "risk_delta": (diff.get("risk_score") or {}).get("delta"),
    }


@app.get("/")
def root():
    return {"service": "NetMap API", "version": __version__, "docs": "/docs", "health": "/api/health"}
