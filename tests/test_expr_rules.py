"""Expression engine + risk-catalogue sanity checks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from netmap.config import load
from netmap.pipeline import analyze
from netmap.risk.engine import RiskEngine, Rule, DEFAULT_RULES


ROOT = Path(__file__).resolve().parent.parent
RULES_YAML = ROOT / "netmap" / "refs" / "rules.yaml"
RULES_JSON = ROOT / "netmap" / "refs" / "rules.json"
REFS_YAML = ROOT / "netmap" / "refs" / "reference.yaml"
REFS_JSON = ROOT / "netmap" / "refs" / "reference.json"


def _rules():
    return RiskEngine().load([str(RULES_JSON)])


# ---------------------------------------------------------------------------
# catalogue integrity
# ---------------------------------------------------------------------------
def test_json_twins_match_yaml_after_sync():
    """tools/sync_data.py must have been run."""
    import yaml
    from_yaml = yaml.safe_load(RULES_YAML.read_text())
    from_json = json.loads(RULES_JSON.read_text())
    assert from_yaml == from_json, "run tools/sync_data.py to refresh rules.json"
    from_yaml_r = yaml.safe_load(REFS_YAML.read_text())
    from_json_r = json.loads(REFS_JSON.read_text())
    assert from_yaml_r == from_json_r, "run tools/sync_data.py to refresh reference.json"


def test_catalogue_loads_and_ids_are_unique():
    rules = _rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 50


def test_every_rule_validates_cleanly():
    for r in _rules():
        problems = r.validate()
        assert problems == [], f"{r.id}: {problems}"


def test_references_are_well_formed():
    from netmap.util import SEVERITY_ORDER
    known_families = {"architecture", "asset", "coverage", "crypto", "exposure",
                      "hardening", "lifecycle", "segmentation", "threat", "general"}
    for r in _rules():
        assert r.severity in SEVERITY_ORDER, r.id
        assert r.family in known_families, (r.id, r.family)
        impact = r.raw.get("impact", 5)
        likelihood = r.raw.get("likelihood", 5)
        assert 0 <= float(impact) <= 10
        assert 0 <= float(likelihood) <= 10
        refs = r.raw.get("refs") or {}
        for label in ("cwe", "nist", "cis", "mitre"):
            if label in refs:
                assert isinstance(refs[label], (str, list)), (r.id, label)


# ---------------------------------------------------------------------------
# expression-language semantics
# ---------------------------------------------------------------------------
from netmap.risk import expr  # noqa: E402


def test_expr_literals_and_paths():
    ctx = {"device": {"hostname": "fw1", "risk": 3}}
    assert expr.evaluate({"literal": 42}, ctx) == 42
    assert expr.evaluate({"literal": "hello"}, ctx) == "hello"
    assert expr.evaluate({"path": "device.hostname"}, ctx) == "fw1"


def test_expr_comparisons_and_logic():
    ctx = {"x": 5, "flag": True, "s": "ssh"}
    assert expr.evaluate({"==": [{"path": "x"}, 5]}, ctx) is True
    assert expr.evaluate({"!=": [{"path": "x"}, 6]}, ctx) is True
    assert expr.evaluate({">=": [{"path": "x"}, 5]}, ctx) is True
    assert expr.evaluate({"<": [{"path": "x"}, 9]}, ctx) is True
    assert expr.evaluate({"and": [{"path": "flag"}, {"==": [{"path": "x"}, 5]}]}, ctx) is True
    assert expr.evaluate({"or": [False, False, True]}, ctx) is True
    assert expr.evaluate({"not": False}, ctx) is True
    assert expr.evaluate({"in": [{"path": "s"}, {"literal": ["ssh", "http"]}]}, ctx) is True
    assert expr.evaluate({"not_in": [{"path": "s"}, {"literal": ["ftp", "telnet"]}]}, ctx) is True


def test_expr_aggregates_and_strings():
    ctx = {"xs": [1, 4, 9]}
    assert expr.evaluate({"count": {"literal": [1, 4, 9]}}, ctx) == 3
    assert expr.evaluate({"sum": {"literal": [1, 4, 9]}}, ctx) == 14
    assert expr.evaluate({"max_of": {"literal": [1, 4, 9]}}, ctx) == 9
    assert expr.evaluate({"contains": [{"literal": "hello world"}, {"literal": "world"}]}, ctx) is True
    assert expr.evaluate({"lower": {"literal": "SSH"}}, ctx) == "ssh"
    assert expr.evaluate({"coalesce": [{"path": "missing"}, {"literal": "fallback"}]}, {}) == "fallback"
    assert expr.evaluate({"join": [{"literal": ["a", "b", "c"]}, {"literal": ", "}]}, {}) == "a, b, c"


def test_expr_if_and_any_in():
    assert expr.evaluate({"if": [True, {"literal": "yes"}, {"literal": "no"}]}, {}) == "yes"
    assert expr.evaluate({"any_in": [{"literal": [22, 80, 443]}, {"literal": [80, 8080]}]}, {}) is True
    assert expr.evaluate({"any_in": [{"literal": [22, 80]}, {"literal": [21, 23]}]}, {}) is False


def test_expr_regex():
    assert expr.evaluate({"regex": [{"literal": "OpenSSH_8.9"}, {"literal": "OpenSSH_[0-9]+"}]}, {}) is True
    assert expr.evaluate({"regex": [{"literal": "apache"}, {"literal": "nginx"}]}, {}) is False


def test_expr_now_iso_is_iso8601():
    import re
    out = expr.evaluate({"now_iso": True}, {})
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", out), out


# ---------------------------------------------------------------------------
# rule engine integration
# ---------------------------------------------------------------------------
def test_engine_fires_expected_rules_on_lab(lab_snapshot):
    fired = {f.id for f in lab_snapshot.findings if f.status == "open"}
    # Findings are keyed "RULEID@target" when they apply to a device/service.
    fired_rule_stems = {fid.split("@", 1)[0] for fid in fired}
    expected = {"NM-LC-001", "NM-SNMP-001", "NM-TLS-001", "NM-WEB-001", "NM-ARCH-002"}
    missing = expected - fired_rule_stems
    assert not missing, f"expected rules missing from lab findings: {missing}; have {len(fired)} fired"


def test_engine_produces_valid_scores(lab_snapshot):
    snap = lab_snapshot
    assert 0 <= snap.risk["score"] <= 10
    assert snap.risk["band"] in {"Minimal", "Low", "Moderate", "High", "Critical"}
    counts = snap.risk["counts"]
    assert sum(counts.values()) == sum(1 for f in snap.findings if f.status == "open")
    assert snap.summary["risk_band"] == snap.risk["band"]


def test_disabling_a_rule_silences_it(fresh_snapshot, cfg):
    cfg.set("risk.disabled", ["NM-LC-001"])
    analyze(cfg, fresh_snapshot)
    fired = {f.id for f in fresh_snapshot.findings}
    assert "NM-LC-001" not in fired


def test_custom_rules_file_extends_the_catalogue(fresh_snapshot, cfg, tmp_path):
    import yaml
    extra = tmp_path / "extra.yaml"
    extra.write_text(yaml.safe_dump({
        "rules": [
            {"id": "NM-CUST-001", "title": "SSH seen", "version": "1", "family": "asset",
             "severity": "info", "impact": 1, "likelihood": 1, "scope": "device",
             "when": {"port_open": 22}, "evidence": ["ssh on {device.ip}"],
             "description": "test", "remediation": "none"}
        ]
    }), encoding="utf-8")
    analyze(cfg, fresh_snapshot, rules=[str(extra)])
    assert any(f.id.startswith("NM-CUST-001") for f in fresh_snapshot.findings), "custom rule did not fire"


def test_cli_rules_validate_exits_clean():
    import subprocess, sys
    p = subprocess.run(
        [sys.executable, "-m", "netmap", "rules", "validate", "--files", "examples/custom_rules.yaml"],
        capture_output=True, text=True, cwd=str(ROOT))
    assert p.returncode == 0, p.stderr
    assert "no problems" in p.stdout
