"""Stdlib HTTP API + dashboard for NetMap (`netmap serve`).

Deliberately `http.server`, not a framework: the tool has to run on a jump host
where installing uvicorn is a change request. The API is small and read-mostly;
the only mutating endpoint is the scan runner, which is behind the same
authorization gate as the CLI.
"""

from __future__ import annotations

import json
import mimetypes
import threading
import traceback
import uuid
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .. import __version__
from ..config import Config
from ..models import ScanSnapshot
from ..pipeline import analyze, discover, load_snapshot, save_snapshot
from ..report.writer import to_csv, to_dot, to_markdown, to_sarif, write_report
from ..topology.layout import edges_with_layout, layout
from ..util import SEVERITY_ORDER
from ..viz.topology_svg import render_svg
from .page import render_app


class Workspace:
    """The current snapshot plus background scan jobs."""

    def __init__(self, cfg: Config | None = None, snapshot: ScanSnapshot | None = None, *, allow_scan: bool = True):
        self.cfg = cfg or Config()
        self.snapshot = snapshot
        self.allow_scan = allow_scan
        self.jobs: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.out_dir = Path(str(self.cfg.get("report.output_dir") or "out"))
        self.out_dir.mkdir(parents=True, exist_ok=True)

    # -- helpers ------------------------------------------------------------
    def require(self) -> ScanSnapshot:
        if self.snapshot is None:
            raise LookupError("no snapshot loaded")
        return self.snapshot

    def progress(self, job_id: str | None):
        def _cb(stage: str, frac: float, message: str) -> None:
            if not job_id:
                return
            with self.lock:
                job = self.jobs.get(job_id)
                if job:
                    job.update({"stage": stage, "done": int(round(frac * 100)), "total": 100, "message": message})

        return _cb

    def start_scan(self, payload: dict) -> dict:
        job_id = uuid.uuid4().hex[:12]
        job = {"job": job_id, "state": "running", "stage": "queued", "done": 0, "total": 100, "message": "", "payload": payload}
        with self.lock:
            self.jobs[job_id] = job
        if not self.allow_scan:
            job.update({"state": "error", "error": "this server was started with a fixed snapshot and cannot scan"})
            return job
        mode = str(payload.get("mode") or "lab").lower()
        cfg_data = self.cfg.copy()
        try:
            cfg_data.set("scan.mode", mode)
            if mode == "lab":
                cfg_data.set("lab.size", str(payload.get("size") or cfg_data.get("lab.size") or "medium"))
                cfg_data.set("lab.seed", int(payload.get("seed") or cfg_data.get("lab.seed") or 7))
            else:
                targets = [str(t) for t in (payload.get("targets") or []) if str(t).strip()]
                if not targets:
                    raise ValueError("live scans need at least one target")
                cfg_data.set("scan.targets", targets)
                if payload.get("confirm"):
                    cfg_data.set("authorization.confirmed", True)
                    cfg_data.set("authorization.signed_by", cfg_data.get("authorization.signed_by") or cfg_data.get("operator") or "web operator")
                    cfg_data.set("authorization.statement", "confirmed in the web UI at scan start")
                problems = cfg_data.authorization_problems()
                if problems:
                    raise PermissionError("authorization incomplete: " + "; ".join(problems))
        except Exception as exc:  # noqa: BLE001 - report the reason to the UI
            job.update({"state": "error", "error": str(exc)})
            return job

        thread = threading.Thread(target=self._scan_thread, args=(job_id, cfg_data), daemon=True)
        thread.start()
        return job

    def _scan_thread(self, job_id: str, cfg: Any) -> None:
        try:
            self._job(job_id, stage="discover", message="discovering")
            snap = discover(cfg, progress=self.progress(job_id))
            self._job(job_id, stage="analyze", message="topology + risk")
            analyze(cfg, snap)
            snap.notes.append("scan started from the web dashboard")
            stamp = snap.finished or ""
            path = self.out_dir / f"served-{snap.mode}-{uuid.uuid4().hex[:6]}.json"
            save_snapshot(snap, path)
            with self.lock:
                self.snapshot = snap
                self.jobs[job_id].update({"state": "done", "stage": "done", "done": 100, "snapshot_file": str(path), "finished": stamp})
        except Exception as exc:  # noqa: BLE001 - the UI must show the failure
            with self.lock:
                self.jobs[job_id].update({"state": "error", "error": f"{type(exc).__name__}: {exc}", "trace": traceback.format_exc()[-2000:]})

    def _job(self, job_id: str, **kw: Any) -> None:
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(kw)

    # -- API payloads --------------------------------------------------------
    def summary(self) -> dict:
        snap = self.require()
        counts = {sev: sum(1 for f in snap.findings if f.severity == sev and f.status == "open") for sev in SEVERITY_ORDER}
        metrics = (snap.config or {}).get("topology_metrics") or {}
        return {
            "snapshot_id": snap.snapshot_id,
            "mode": snap.mode,
            "started": snap.started,
            "finished": snap.finished,
            "operator": snap.operator,
            "devices": len(snap.devices),
            "links": len(snap.links),
            "zones": len(snap.zones),
            "findings": len(snap.findings),
            "severity_counts": counts,
            "risk": snap.risk,
            "summary": snap.summary,
            "topology": {k: v for k, v in metrics.items() if k not in ("derived_from", "notes")},
            "devices_detail": (snap.summary or {}).get("devices") or {},
            "services": sum(len(d.open_ports) for d in snap.devices),
            "ports": len({p for d in snap.devices for p in d.open_ports}),
            "scan_errors": len(snap.errors),
            "authorization": snap.authorization,
            "notes": snap.notes[:8],
        }

    def graph(self) -> dict:
        snap = self.require()
        devices = sorted(snap.devices, key=lambda d: (-(d.risk_score or 0), d.label))[:220]
        view = ScanSnapshot(devices=devices, links=snap.links, zones=snap.zones, findings=snap.findings)
        placed = layout(view, width=1500, node_gap=112.0, tier_gap=210.0)
        pos = placed["nodes"]
        sev_by_dev: dict[str, str] = {}
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        for f in snap.findings:
            if f.status != "open":
                continue
            cur = sev_by_dev.get(f.target_id)
            if cur is None or rank.get(f.severity, 9) < rank.get(cur, 9):
                sev_by_dev[f.target_id] = f.severity
        counts: dict[str, int] = {}
        for f in snap.findings:
            counts[f.target_id] = counts.get(f.target_id, 0) + 1
        nodes = []
        for d in devices:
            p = pos.get(d.id) or {"x": 0, "y": 0}
            sev = sev_by_dev.get(d.id) or ("none" if d.risk_score == 0 else "info")
            nodes.append(
                {
                    "id": d.id,
                    "label": d.hostname or d.ip or d.id,
                    "ip": d.ip,
                    "type": d.device_type,
                    "zone": d.zone,
                    "risk": round(float(d.risk_score or 0), 1),
                    "severity": sev,
                    "findings": counts.get(d.id, 0),
                    "ports": len(d.open_ports),
                    "x": p["x"],
                    "y": p["y"],
                }
            )
        edges = []
        by_id = snap.device_map()
        for edge in edges_with_layout(view, pos):
            src, dst = by_id.get(edge["src"]), by_id.get(edge["dst"])
            if src is None or dst is None or src.id not in pos or dst.id not in pos:
                continue
            edges.append(
                {
                    **{k: edge[k] for k in ("id", "path", "kind", "confidence", "spof", "protected", "speed")},
                    "src_label": src.label,
                    "dst_label": dst.label,
                }
            )
        bands = [
            {"name": meta.get("name") or f"tier {t}", "y0": meta.get("y0"), "height": meta.get("band_height"), "devices": meta.get("devices")}
            for t, meta in sorted((placed["bounds"].get("tiers") or {}).items(), key=lambda kv: int(kv[0]))
        ]
        return {"width": placed["bounds"]["width"], "height": placed["bounds"]["height"], "nodes": nodes, "links": edges, "bands": bands}

    def findings(self) -> list[dict]:
        snap = self.require()
        out = []
        for f in sorted(snap.findings, key=lambda x: x.sort_key):
            out.append(
                {
                    "rule_id": f.rule_id,
                    "title": f.rule_title,
                    "severity": f.severity,
                    "status": f.status,
                    "score": round(f.score, 2),
                    "scope": f.scope,
                    "target": f.target_label,
                    "target_id": f.target_id,
                    "zone": f.zone,
                    "evidence": [ev.get("text", "") for ev in f.evidence][:6],
                    "remediation": f.remediation,
                    "refs": " ".join(f"{k}:{v}" for k, v in (f.refs or {}).items()),
                }
            )
        return out

    def devices(self) -> list[dict]:
        snap = self.require()
        counts: dict[str, int] = {}
        sev: dict[str, str] = {}
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        for f in snap.findings:
            counts[f.target_id] = counts.get(f.target_id, 0) + 1
            cur = sev.get(f.target_id)
            if f.status == "open" and (cur is None or rank.get(f.severity, 9) < rank.get(cur, 9)):
                sev[f.target_id] = f.severity
        return [
            {
                "id": d.id,
                "hostname": d.hostname,
                "ip": d.ip,
                "type": d.device_type,
                "os": " ".join(str(x) for x in (d.os_family, d.os_version) if x),
                "zone": d.zone,
                "ports": len(d.open_ports),
                "criticality": d.criticality,
                "risk": round(float(d.risk_score or 0), 1),
                "severity": sev.get(d.id, "none"),
                "findings": counts.get(d.id, 0),
                "documented": d.documented,
            }
            for d in sorted(snap.devices, key=lambda x: (-(x.risk_score or 0), x.label))
        ]

    def device(self, ident: str) -> dict:
        snap = self.require()
        dev = snap.find_device(unquote(ident))
        if dev is None:
            raise LookupError(f"no device {ident}")
        services = []
        for s in dev.services:
            entry = {
                "port": s.port,
                "protocol": s.protocol,
                "state": s.state,
                "name": s.name,
                "product": s.product,
                "version": s.version,
                "encryption": s.encryption,
                "banner": (s.banner or "")[:400],
            }
            if s.certificate:
                entry["cert"] = (
                    f"cn={s.certificate.subject_cn} issuer={s.certificate.issuer_cn} "
                    f"{s.certificate.protocol} valid_until={s.certificate.not_after} self_signed={s.certificate.self_signed}"
                )
            services.append(entry)
        findings = [
            {
                "rule_id": f.rule_id,
                "title": f.rule_title,
                "severity": f.severity,
                "score": round(f.score, 2),
                "evidence": [ev.get("text", "") for ev in f.evidence][:5],
                "remediation": f.remediation,
                "refs": " ".join(f"{k}:{v}" for k, v in (f.refs or {}).items()),
                "status": f.status,
            }
            for f in sorted(snap.findings, key=lambda x: x.sort_key)
            if f.target_id == dev.id
        ]
        links = []
        for l in snap.links:
            if dev.id not in (l.src_device, l.dst_device):
                continue
            other = l.dst_device if l.src_device == dev.id else l.src_device
            peer = snap.find_device(other)
            links.append(
                {
                    "peer": peer.label if peer else other,
                    "local_interface": l.src_interface if l.src_device == dev.id else l.dst_interface,
                    "peer_interface": l.dst_interface if l.src_device == dev.id else l.src_interface,
                    "kind": l.kind,
                    "spof": l.is_spof,
                    "protected": l.protected,
                }
            )
        return {
            "id": dev.id,
            "label": dev.label,
            "ip": dev.ip,
            "hostname": dev.hostname,
            "mac": dev.mac,
            "type": dev.device_type,
            "role": dev.role,
            "vendor": dev.vendor,
            "model": dev.model,
            "os": " ".join(str(x) for x in (dev.os_family, dev.os_version) if x),
            "os_eol": dev.os_eol,
            "zone": dev.zone,
            "trust": dev.trust,
            "criticality": dev.criticality,
            "documented": dev.documented,
            "exposed": dev.exposed_to_wan,
            "snmp_readable": bool((dev.snmp or {}).get("readable")),
            "uptime": (f"{int((dev.uptime_seconds or 0) / 3600)}h" if dev.uptime_seconds else None),
            "sources": dev.discovery_sources,
            "risk": round(float(dev.risk_score or 0), 1),
            "services": services,
            "findings": findings,
            "links": links,
            "notes": dev.notes[:8],
            "neighbors": [
                {"remote": n.remote_system or n.remote_key, "local_if": n.local_if, "via": n.via, "confidence": n.confidence}
                for n in dev.neighbors
            ][:30],
        }

    def zones(self) -> list[dict]:
        snap = self.require()
        return [
            {
                "name": z.name,
                "trust": z.trust,
                "devices": z.device_count or len(snap.devices_by(zone=z.name)),
                "cidrs": z.cidrs,
                "vlans": z.vlans,
                "enforced": z.segmentation_enforced,
                "note": z.segmentation_note,
                "gateway": z.default_gateway,
            }
            for z in snap.zones
        ]

    def links(self) -> list[dict]:
        snap = self.require()
        by_id = snap.device_map()
        out = []
        for l in snap.links:
            src, dst = by_id.get(l.src_device), by_id.get(l.dst_device)
            notes = []
            if l.is_spof:
                notes.append("SPOF")
            if l.protected:
                notes.append("redundant")
            if l.redundant_group:
                notes.append(f"group {l.redundant_group}")
            out.append(
                {
                    "id": l.id,
                    "src": src.label if src else l.src_device,
                    "dst": dst.label if dst else l.dst_device,
                    "src_interface": l.src_interface,
                    "dst_interface": l.dst_interface,
                    "kind": l.kind,
                    "speed": l.speed_mbps,
                    "source": ", ".join(l.derived_from),
                    "confidence": l.confidence,
                    "risk": round(float(l.risk_score or 0), 1),
                    "notes": " ".join(notes),
                }
            )
        return out

    def report(self, fmt: str) -> tuple[bytes, str, str]:
        """Return (body, media_type, filename) for an on-demand export."""
        snap = self.require()
        fmt = fmt.lower()
        if fmt == "html":
            body = render_html_report(snap)
            return body.encode("utf-8"), "text/html; charset=utf-8", "netmap-report.html"
        if fmt in ("md", "markdown"):
            return to_markdown(snap).encode("utf-8"), "text/markdown; charset=utf-8", "netmap-report.md"
        if fmt == "sarif":
            return to_sarif(snap).encode("utf-8"), "application/json", "netmap.sarif"
        if fmt == "csv":
            rows = to_csv(snap)
            body = "### findings\n" + rows.get("findings", "") + "\n### devices\n" + rows.get("devices", "")
            return body.encode("utf-8"), "text/csv; charset=utf-8", "netmap.csv"
        if fmt == "dot":
            return to_dot(snap).encode("utf-8"), "text/vnd.graphviz", "netmap.dot"
        if fmt == "svg":
            return render_svg(snap).encode("utf-8"), "image/svg+xml; charset=utf-8", "netmap-topology.svg"
        if fmt == "json":
            return json.dumps(snap.to_dict(), indent=2, default=str).encode("utf-8"), "application/json", "netmap-snapshot.json"
        if fmt == "files":
            written = write_report(snap, self.out_dir, formats=["json", "md", "csv", "html", "sarif", "cef", "dot"])
            return (
                json.dumps({k: str(v) for k, v in written.items()}, indent=2).encode("utf-8"),
                "application/json",
                "netmap-files.json",
            )
        raise LookupError(f"unsupported format {fmt}")


def render_html_report(snap: ScanSnapshot) -> str:
    from ..viz.static_html import render_html

    return render_html(snap, svg=render_svg(snap))


class Handler(BaseHTTPRequestHandler):
    workspace: Workspace = None  # type: ignore[assignment]
    token: str | None = None

    server_version = f"NetMap/{__version__}"

    # -- plumbing ------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # quieter default log
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _authorized(self, path: str) -> bool:
        if not self.token:
            return True
        supplied = self.headers.get("X-NetMap-Token") or ""
        if not supplied:
            supplied = (parse_qs(urlparse(path).query).get("token") or [""])[0]
        return supplied == self.token

    def _send(self, code: int, body: bytes, media: str = "application/json", extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: Any, code: int = 200) -> None:
        self._send(code, (json.dumps(payload, indent=2, default=str) + "\n").encode("utf-8"))

    def _html(self, markup: str, code: int = 200) -> None:
        self._send(code, markup.encode("utf-8"), "text/html; charset=utf-8")

    def _error(self, code: int, message: str) -> None:
        self._json({"error": message, "status": code}, code)

    # -- routes --------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch_post()

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if not self._authorized(self.path):
            self._error(401, "missing or invalid X-NetMap-Token")
            return
        try:
            ws = self.workspace
            if path == "/":
                self._html(render_app(live=ws.allow_scan))
            elif path == "/api/health":
                self._json(
                    {
                        "ok": True,
                        "version": __version__,
                        "snapshot": bool(ws.snapshot),
                        "snapshot_id": ws.snapshot.snapshot_id if ws.snapshot else None,
                        "allow_scan": ws.allow_scan,
                    }
                )
            elif path == "/api/summary":
                self._json(ws.summary())
            elif path == "/api/graph":
                self._json(ws.graph())
            elif path == "/api/findings":
                self._json(ws.findings())
            elif path == "/api/devices":
                self._json(ws.devices())
            elif path == "/api/zones":
                self._json(ws.zones())
            elif path == "/api/links":
                self._json(ws.links())
            elif path.startswith("/api/device/"):
                self._json(ws.device(path[len("/api/device/") :]))
            elif path == "/api/errors":
                self._json([asdict(e) for e in ws.require().errors])
            elif path == "/api/rules":
                self._json(_rule_index())
            elif path.startswith("/api/report."):
                body, media, filename = ws.report(path.split("/api/report.", 1)[1])
                self._send(200, body, media, {"Content-Disposition": f'attachment; filename="{filename}"'})
            elif path == "/api/snapshot":
                self._send(200, (json.dumps(ws.require().to_dict(), indent=2, default=str) + "\n").encode("utf-8"), "application/json")
            elif path == "/api/jobs":
                self._json(list(ws.jobs.values()))
            elif path.startswith("/api/scan/"):
                job_id = path[len("/api/scan/") :]
                with ws.lock:
                    job = ws.jobs.get(job_id)
                if job is None:
                    self._error(404, "unknown job")
                else:
                    self._json({k: v for k, v in job.items() if k != "payload"})
            elif path.startswith("/static/"):
                self._static(path)
            else:
                self._error(404, f"no route {path}")
        except LookupError as exc:
            self._error(404, str(exc))
        except PermissionError as exc:
            self._error(403, str(exc))
        except Exception as exc:  # noqa: BLE001 - never leak a stack trace as a 500 page
            self._error(500, f"{type(exc).__name__}: {exc}")

    def _static(self, path: str) -> None:
        root = Path(__file__).parent / "static"
        candidate = (root / path[len("/static/") :]).resolve()
        if root.resolve() not in candidate.parents or not candidate.is_file():
            self._error(404, "not found")
            return
        media = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        self._send(200, candidate.read_bytes(), media)

    def _dispatch_post(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if not self._authorized(self.path):
            self._error(401, "missing or invalid X-NetMap-Token")
            return
        ws = self.workspace
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("body must be a JSON object")
            except json.JSONDecodeError as exc:
                self._error(400, f"invalid JSON body: {exc}")
                return
            if path == "/api/scan":
                job = ws.start_scan(payload)
                self._json(job, 202)
            elif path == "/api/compare":
                other = payload.get("snapshot")
                if not other:
                    raise ValueError("body needs {snapshot: path}")
                base = load_snapshot(Path(other))
                from ..pipeline import compare_snapshots

                self._json(compare_snapshots(base, ws.require()))
            else:
                self._error(404, f"no POST route {path}")
        except (LookupError, PermissionError, ValueError) as exc:
            code = 403 if isinstance(exc, PermissionError) else 404 if isinstance(exc, LookupError) else 400
            self._error(code, str(exc))
        except Exception as exc:  # noqa: BLE001
            self._error(500, f"{type(exc).__name__}: {exc}")

def _rule_index() -> list[dict]:
    from ..risk.engine import RiskEngine

    engine = RiskEngine()
    out = []
    for rule in engine.rules:
        out.append(
            {
                "id": rule.raw.get("id"),
                "title": rule.raw.get("title"),
                "severity": rule.raw.get("severity"),
                "family": rule.raw.get("family"),
                "scope": rule.raw.get("scope"),
                "version": rule.raw.get("version"),
                "tags": rule.raw.get("tags") or [],
                "refs": {k: v for k, v in (rule.raw.get("refs") or {}).items()},
                "description": rule.raw.get("description"),
                "remediation": rule.raw.get("remediation"),
                "active": bool(getattr(rule, "active", True)),
            }
        )
    return out


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: Any, verbose: bool = False, **kw: Any):
        super().__init__(*args, **kw)
        self.verbose = verbose


def serve(
    cfg: Config,
    *,
    snapshot_path: str | Path | None = None,
    host: str | None = None,
    port: int | None = None,
    allow_scan: bool = True,
    verbose: bool = False,
) -> tuple[Server, Workspace]:
    """Build the server (does not block). Returns (server, workspace)."""
    workspace = Workspace(cfg, allow_scan=allow_scan)
    path = snapshot_path or cfg.get("web.snapshot")
    if path:
        workspace.snapshot = load_snapshot(Path(str(path)))
    httpd = Server(
        (str(host or cfg.get("web.host") or "0.0.0.0"), int(port or cfg.get("web.port") or 8080)),
        _bind_handler(workspace, cfg),
        verbose=verbose,
    )
    return httpd, workspace


def _bind_handler(workspace: Workspace, cfg: Config):
    token = cfg.get("web.auth_token") or None

    class Bound(Handler):
        pass

    Bound.workspace = workspace
    Bound.token = str(token) if token else None
    return Bound


def serve_forever(cfg: Config, **kw: Any) -> None:
    httpd, workspace = serve(cfg, **kw)
    host, port = httpd.server_address[0], httpd.server_address[1]
    print(f"NetMap {__version__} listening on http://{host}:{port}  (workspace: {len(workspace.jobs)} jobs)")
    if not workspace.snapshot:
        print("  no snapshot attached - use 'run scan' in the UI or --snapshot PATH")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        print("shutting down")
        httpd.shutdown()


__all__ = ["Handler", "Server", "Workspace", "render_app", "serve", "serve_forever"]
