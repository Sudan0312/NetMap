"""End-to-end pipeline + drift comparison + snapshot persistence."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from netmap.config import load
from netmap.discovery.engine import classify_devices, snapshot_from_devices
from netmap.discovery.simulator import build_devices
from netmap.pipeline import (
    analyze,
    compare_snapshots,
    load_snapshot,
    save_snapshot,
)


ROOT = Path(__file__).resolve().parent.parent


def _run(size="small", seed=11, **overrides):
    devices, zones = build_devices(size, seed=seed, **overrides)
    classify_devices(devices)
    cfg = load(None); cfg.set("scan.mode", "lab")
    snap = snapshot_from_devices(devices, cfg, mode="lab", zones=zones)
    analyze(cfg, snap)
    return cfg, snap


def test_save_and_load_round_trip(tmp_path):
    cfg, snap = _run("small")
    p = tmp_path / "snap.json"
    save_snapshot(snap, p)
    assert p.exists()
    data = json.loads(p.read_text())
    assert data["schema_version"] == "1.0"
    assert data["mode"] == "lab"
    snap2 = load_snapshot(p)
    assert len(snap2.devices) == len(snap.devices)
    assert len(snap2.findings) == len(snap.findings)
    problems = snap2.validate()
    # Dangling-neighbour notes are allowed; anything else is a real error.
    hard_errors = [x for x in problems if "duplicate" in x or "ip is not" in x or "unknown device" in x]
    assert hard_errors == [], problems


def test_compare_snapshots_detects_drift(tmp_path):
    _, clean = _run("small", seed=11, include_risks=False)
    _, risky = _run("small", seed=11, include_risks=True)
    drift = compare_snapshots(clean, risky)
    assert "findings_appeared" in drift
    assert "devices_added" in drift
    assert drift["findings_appeared"], "risky sim must produce findings vs clean"


def test_analyze_populates_summary_and_counters(tmp_path):
    _, snap = _run("small")
    assert "risk" in snap.summary
    assert "topology" in snap.summary
    assert snap.summary["open_findings"] == len([f for f in snap.findings if f.status == "open"])
    assert snap.risk["score"] > 0
    assert snap.config["timings"]["topology_seconds"] >= 0
    assert snap.config["timings"]["risk_seconds"] >= 0
    # network score band must be one of the five known bands
    assert snap.risk["band"] in {"Minimal", "Low", "Moderate", "High", "Critical"}


def test_lab_cli_produces_all_outputs(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    p = subprocess.run(
        [sys.executable, "-m", "netmap", "lab", "--size", "small", "--seed", "11",
         "--out", str(out), "--formats", "json,md,sarif,cef,csv,dot,html,txt", "--quiet"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=60)
    assert p.returncode == 0, p.stderr
    files = list(out.iterdir())
    names = {f.name for f in files}
    assert any(n.endswith(".json") for n in names)
    assert any(n.endswith(".md") for n in names)
    assert any(n.endswith(".sarif") for n in names)
    assert any(n.endswith(".cef") for n in names)
    assert any(n.endswith(".dot") for n in names)
    assert any(n.endswith(".html") for n in names)
    assert any(n.endswith(".txt") for n in names)
    assert any(n.endswith("-findings.csv") for n in names)
    assert any(n.endswith("-devices.csv") for n in names)
    assert any(n.endswith("-links.csv") for n in names)
    snap_json = [f for f in files if f.name.endswith(".json") and "lab-snapshot" not in f.name][0]
    snap = load_snapshot(snap_json)
    assert len(snap.devices) > 0


def test_ci_subcommand_exit_code_threshold(tmp_path):
    out = tmp_path / "out"; out.mkdir()
    subprocess.run(
        [sys.executable, "-m", "netmap", "lab", "--size", "small", "--seed", "11",
         "--out", str(out), "--formats", "json", "--quiet", "--snapshot-out", str(out/"s.json")],
        capture_output=True, text=True, cwd=str(ROOT), timeout=60, check=True)
    # with a critical-cap, must exit 1 because the lab has critical findings
    p = subprocess.run(
        [sys.executable, "-m", "netmap", "ci", "--from", str(out/"s.json"), "--fail-on", "info"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=30)
    assert p.returncode == 1
    # --fail-on never -> always 0
    p2 = subprocess.run(
        [sys.executable, "-m", "netmap", "ci", "--from", str(out/"s.json"), "--fail-on", "never"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=30)
    assert p2.returncode == 0


def test_init_writes_default_config(tmp_path):
    cfg_path = tmp_path / "netmap.yaml"
    p = subprocess.run(
        [sys.executable, "-m", "netmap", "init", "-o", str(cfg_path)],
        capture_output=True, text=True, cwd=str(ROOT), timeout=15)
    assert p.returncode == 0, p.stderr
    assert cfg_path.exists()
    text = cfg_path.read_text(encoding="utf-8")
    assert "scan:" in text and "authorization:" in text
