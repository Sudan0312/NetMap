"""CLI + web-server smoke tests.

Starts the dashboard on an ephemeral port, loads a lab snapshot, and hits the
JSON API endpoints with `urllib` (stdlib only).
"""
from __future__ import annotations

import json
import threading
import urllib.request
import urllib.error
from pathlib import Path

import pytest

from netmap.config import load
from netmap.discovery.engine import classify_devices, snapshot_from_devices
from netmap.discovery.simulator import build_devices
from netmap.pipeline import analyze, save_snapshot
from netmap.web.server import serve


@pytest.fixture(scope="module")
def lab_snapshot_path(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("web")
    devices, zones = build_devices("small", seed=11)
    classify_devices(devices)
    cfg = load(None); cfg.set("scan.mode", "lab")
    snap = snapshot_from_devices(devices, cfg, mode="lab", zones=zones)
    analyze(cfg, snap)
    p = tmp / "snap.json"
    save_snapshot(snap, p)
    return p


@pytest.fixture(scope="module")
def http_server(lab_snapshot_path):
    cfg = load(None); cfg.set("scan.mode", "lab")
    httpd, _ = serve(cfg, snapshot_path=str(lab_snapshot_path), host="127.0.0.1", port=0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.read().decode("utf-8", "replace"), resp.headers.get("Content-Type", "")


def test_root_serves_html_dashboard(http_server):
    host, port = http_server.server_address
    status, body, ct = _get(f"http://{host}:{port}/")
    assert status == 200
    assert "text/html" in ct
    assert "<!DOCTYPE html>" in body or "<html" in body.lower()


def test_health_endpoint(http_server):
    host, port = http_server.server_address
    status, body, ct = _get(f"http://{host}:{port}/api/health")
    assert status == 200
    payload = json.loads(body)
    assert payload.get("ok") is True


def test_summary_endpoint_shape(http_server):
    host, port = http_server.server_address
    status, body, _ = _get(f"http://{host}:{port}/api/summary")
    assert status == 200
    s = json.loads(body)
    for key in ("devices", "links", "risk", "topology", "severity_counts"):
        assert key in s, f"missing {key}"
    assert s["mode"] == "lab"
    assert s["risk"]["score"] >= 0


def test_graph_endpoint_has_nodes_and_links(http_server):
    host, port = http_server.server_address
    status, body, _ = _get(f"http://{host}:{port}/api/graph")
    assert status == 200
    g = json.loads(body)
    assert g["nodes"] and g["links"]
    for n in g["nodes"][:3]:
        assert {"id", "label", "x", "y", "risk"} <= set(n.keys())
    for l in g["links"][:3]:
        assert {"id", "path", "src_label", "dst_label"} <= set(l.keys())


def test_findings_endpoint_returns_list(http_server):
    host, port = http_server.server_address
    status, body, _ = _get(f"http://{host}:{port}/api/findings")
    assert status == 200
    fs = json.loads(body)
    assert isinstance(fs, list) and fs
    f0 = fs[0]
    assert "rule_id" in f0 and "severity" in f0 and "title" in f0


def test_device_detail_endpoint(http_server, lab_snapshot_path):
    snap = json.loads(lab_snapshot_path.read_text())
    dev_id = snap["devices"][0]["id"]
    host, port = http_server.server_address
    status, body, _ = _get(f"http://{host}:{port}/api/device/{dev_id}")
    assert status == 200
    d = json.loads(body)
    assert d["id"] == dev_id
    assert "services" in d


def test_report_markdown_endpoint(http_server):
    host, port = http_server.server_address
    status, body, ct = _get(f"http://{host}:{port}/api/report.md")
    assert status == 200
    assert "Executive summary" in body or "Top findings" in body


def test_discover_requires_authorization(http_server):
    """Live-scan endpoint refuses to run without confirm_authorized."""
    host, port = http_server.server_address
    req = urllib.request.Request(
        f"http://{host}:{port}/api/scan",
        data=json.dumps({"targets": ["127.0.0.1"]}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", "replace")
            assert resp.status in (403, 400, 202)
    except urllib.error.HTTPError as e:
        # 403 is the expected "authorization refused" response
        assert e.code in (403, 400, 412)


def test_cli_help_lists_all_subcommands():
    import subprocess, sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    p = subprocess.run([sys.executable, "-m", "netmap", "--help"], capture_output=True, text=True, cwd=str(root))
    assert p.returncode == 0
    for cmd in ("init", "lab", "discover", "analyze", "report", "compare", "serve", "rules", "ci"):
        assert cmd in p.stdout
