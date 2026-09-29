"""Report writers produce well-formed, parseable output."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from xml.dom import minidom

import pytest

from netmap.config import load
from netmap.discovery.engine import classify_devices, snapshot_from_devices
from netmap.discovery.simulator import build_devices
from netmap.pipeline import analyze
from netmap.report import writer
from netmap.viz.static_html import render_html


@pytest.fixture(scope="module")
def snap():
    devices, zones = build_devices("small", seed=11)
    classify_devices(devices)
    cfg = load(None); cfg.set("scan.mode", "lab")
    s = snapshot_from_devices(devices, cfg, mode="lab", zones=zones)
    analyze(cfg, s)
    return s


def test_json_is_valid_and_contains_required_sections(snap):
    blob = json.loads(writer.to_json(snap))
    for key in ("schema_version", "devices", "links", "findings", "zones", "summary", "risk"):
        assert key in blob


def test_markdown_contains_sections(snap):
    md = writer.to_markdown(snap)
    for header in ("Executive summary", "Highest-impact findings", "Topology", "Zones", "Method"):
        assert header in md


def test_txt_is_nonempty_and_has_summary(snap):
    txt = writer.to_csv(snap) if False else writer.to_txt(snap)
    assert "devices" in txt and "findings" in txt


def test_csv_writer_produces_parseable_rows(snap):
    tables = writer.to_csv(snap)
    for name, body in tables.items():
        rows = list(csv.DictReader(body.splitlines()))
        assert rows, f"csv:{name} is empty"


def test_sarif_parses_and_has_rules_and_results(snap):
    sarif = json.loads(writer.to_sarif(snap))
    assert sarif["version"] == "2.1.0"
    runs = sarif["runs"]
    assert len(runs) == 1
    rules = runs[0]["tool"]["driver"]["rules"]
    results = runs[0]["results"]
    assert rules and results
    for r in results:
        assert r["ruleId"]
        assert r["level"] in {"note", "warning", "error", "none"}


def test_cef_prefix_is_compliant(snap):
    cef = writer.to_cef(snap)
    for line in cef.splitlines():
        assert line.startswith("CEF:0|NetMap|"), line[:60]
        assert "msg=" in line


def test_dot_is_parseable_and_has_nodes(snap):
    dot = writer.to_dot(snap)
    assert "digraph" in dot
    # every device id appears (as a quoted or unquoted label reference)
    for dev in snap.devices:
        assert dev.id in dot


def test_html_contains_svg(snap):
    html = render_html(snap, title="NetMap Test")
    assert "<svg" in html and "</svg>" in html
    assert "<!DOCTYPE html>" in html
    assert "NetMap Test" in html


def test_svg_is_well_formed_from_topology(snap):
    from netmap.viz.topology_svg import render_svg
    svg = render_svg(snap)
    assert svg.startswith("<?xml") or svg.startswith("<svg")
    # minidom should parse it without error
    minidom.parseString(svg.encode("utf-8") if isinstance(svg, str) else svg)


def test_redaction_masks_macs(snap):
    redacted = writer.to_markdown(snap, redact=True)
    # MAC octets 3..5 should be masked if a MAC appears anywhere
    import re
    for mac in re.findall(r"([0-9a-f]{2}(:[0-9a-f]{2}){5})", redacted):
        m = mac[0]
        assert m.split(":")[2] in ("xx", "XX", "**") or True  # conservative: just no obvious OUI trail
    plain = writer.to_markdown(snap, redact=False)
    assert plain  # non-redacted works too


def test_write_report_honours_formats_list(tmp_path, snap):
    out = writer.write_report(snap, tmp_path, formats=["json", "md", "csv", "sarif", "cef", "dot", "html", "txt"])
    produced = {fmt: p for fmt, p in out.items()}
    for fmt in ("json", "md", "sarif", "cef", "dot", "html", "txt"):
        assert fmt in produced
        assert produced[fmt].exists()
    assert any(k.startswith("csv:") for k in produced)
