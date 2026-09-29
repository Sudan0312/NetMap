"""Risk evaluation: run the rule catalogue against an enriched snapshot.

    snapshot -> Enricher (derived facts) -> rules -> findings -> scores
                                            ^
                    exceptions / overrides / disables (from config)

Scoring model
-------------
Every finding gets ``score = impact * likelihood / 10`` (0..10), optionally
escalated by context. A device's risk is the *probabilistic union* of its
finding weights -- ``10 * (1 - prod(1 - w/10))`` -- which is monotonic, bounded,
and does not let 40 low findings out-score one critical.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..models import Device, Finding, Link, ScanSnapshot
from ..util import SEVERITY_ORDER, SEVERITY_WEIGHT, clamp, iso, now_utc
from .expr import RuleError, evaluate, ops, resolve_path, validate
from .facts import Enricher

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "refs", "rules.yaml")
BANDS = ((9.0, "Critical"), (7.0, "High"), (4.5, "Moderate"), (2.0, "Low"), (0.0, "Minimal"))


def _load_yaml_or_json(path: str) -> dict:
    """Read a catalogue file, preferring the YAML source but not requiring PyYAML.

    `make data` regenerates a compact JSON twin next to every YAML catalogue, so
    a host with no third-party packages still loads the same rules.
    """
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError:
            twin = Path(path).with_suffix(".json")
            if twin.exists():
                return json.loads(twin.read_text(encoding="utf-8")) or {}
            raise RuntimeError(f"{path}: PyYAML is missing and {twin.name} was not generated (run `make data`)")
        return yaml.safe_load(text) or {}
    return json.loads(text) or {}


def _load_rules_file(path: str) -> dict:
    return _load_yaml_or_json(path)


@dataclass
class Rule:
    raw: dict
    active: bool = True
    compile_problems: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return str(self.raw["id"])

    @property
    def title(self) -> str:
        return str(self.raw.get("title") or self.id)

    @property
    def scope(self) -> str:
        return str(self.raw.get("scope") or "device")

    @property
    def family(self) -> str:
        return str(self.raw.get("family") or "general")

    @property
    def severity(self) -> str:
        return str(self.raw.get("severity") or "medium")

    def evaluate(self, facts: dict) -> Any:
        return evaluate(self.raw.get("when", {"literal": True}), facts)

    def unless_hit(self, facts: dict) -> bool:
        unless = self.raw.get("unless")
        return bool(unless) and bool(evaluate(unless, facts))

    def matches_filter(self, facts: dict) -> bool:
        """`applies_to` shorthand: {device_type: [...], trust: [...], role: ...}."""
        spec = self.raw.get("applies_to")
        if not spec:
            return True
        for key, want in spec.items():
            actual = resolve_path(facts, f"device.{key}" if self.scope == "device" else f"{self.scope}.{key}")
            wanted = want if isinstance(want, (list, tuple, set)) else [want]
            if actual not in wanted and str(actual) not in {str(w) for w in wanted}:
                return False
        return True

    def validate(self) -> list[str]:
        problems: list[str] = []
        for key in ("when", "unless", "applies_to"):
            value = self.raw.get(key)
            if isinstance(value, dict):
                problems.extend(f"{self.id}: {p}" for p in validate(value, _path=key))
        foreach = self.raw.get("foreach")
        if isinstance(foreach, dict):
            if foreach.get("where"):
                problems.extend(f"{self.id}: {p}" for p in validate(foreach["where"], _path="foreach.where"))
            if not str(foreach.get("over", "")).startswith(("device.", "network.", "link.")):
                problems.append(f"{self.id}: foreach.over must be a dotted path")
        for escalate in self.raw.get("escalate") or []:
            if isinstance(escalate, dict) and escalate.get("when"):
                problems.extend(f"{self.id}: {p}" for p in validate(escalate["when"], _path="escalate.when"))
        if self.severity not in SEVERITY_ORDER:
            problems.append(f"{self.id}: unknown severity {self.severity!r}")
        for numeric in ("impact", "likelihood"):
            value = self.raw.get(numeric)
            if value is not None and not (0 <= float(value) <= 10):
                problems.append(f"{self.id}: {numeric} must be 0..10")
        return problems


class RiskEngine:
    def __init__(
        self,
        *,
        rules: list[Rule] | None = None,
        rules_files: list[str] | None = None,
        config: dict | None = None,
        thresholds: dict | None = None,
        exceptions: list[dict] | None = None,
        graph=None,
        policy: dict | None = None,
    ):
        self.config = config or {}
        self.thresholds = {
            "expiring_cert_days": 30,
            "unknown_device_max_ports": 12,
            "high_criticality": 4,
            "stale_firmware_days": 730,
            "recent_reboot_minutes": 10,
            **(thresholds or {}),
        }
        self.exceptions = exceptions or []
        self.graph = graph
        self.policy = policy or {}
        self.rules: list[Rule] = rules if rules is not None else self.load(rules_files or [DEFAULT_RULES])
        self.audit: dict[str, Any] = {"rules_total": len(self.rules), "skipped": {}, "errors": []}
        self._apply_config_filters()

    # -- loading ------------------------------------------------------------
    def load(self, paths: list[str]) -> list[Rule]:
        rules: list[Rule] = []
        seen: set[str] = set()
        for path in paths:
            if not path:
                continue
            data = _load_rules_file(path)
            for entry in data.get("rules") or []:
                if not isinstance(entry, dict) or "id" not in entry:
                    self.audit["errors"].append(f"{path}: rule entry without id skipped")
                    continue
                rid = str(entry["id"])
                if rid in seen:  # later files override earlier ones
                    rules = [r for r in rules if r.id != rid]
                rules.append(Rule(raw={**entry, "_source": path}))
                seen.add(rid)
        return rules

    def _apply_config_filters(self) -> None:
        disabled = {str(x) for x in self.config.get("disabled") or []}
        only = {str(x) for x in self.config.get("only") or []}
        overrides = self.config.get("severity_overrides") or {}
        min_sev = str(self.config.get("min_severity") or "info")
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        keep: list[Rule] = []
        for rule in self.rules:
            if rule.id in disabled:
                self.audit["skipped"][rule.id] = "disabled by config"
                continue
            if only and rule.id not in only and rule.family not in only:
                self.audit["skipped"][rule.id] = "not in risk.only"
                continue
            if order.get(rule.severity, 4) > order.get(min_sev, 4):
                self.audit["skipped"][rule.id] = f"below min_severity={min_sev}"
                continue
            if rule.id in overrides:
                rule.raw = {**rule.raw, "severity": overrides[rule.id], "_overridden": True}
            problems = rule.validate()
            if problems:
                rule.active = False
                self.audit["errors"].extend(problems)
            keep.append(rule)
        self.rules = keep

    # -- helpers -----------------------------------------------------------
    def _facts(self, dev: Device, enricher: Enricher) -> dict:
        return {
            "device": enricher.device_facts(dev),
            "zone": (enricher.zones.get(dev.zone or "") or Zone_stub()).to_dict(),
            "scan": {
                "mode": self.config.get("mode", "live"),
                "started": self.config.get("started"),
                "targets": self.config.get("targets", []),
                "thresholds": self.thresholds,
                "now": iso(now_utc()),
            },
            "service": None,
            "network": None,
            "link": None,
            "thresholds": self.thresholds,
        }

    def _exception_for(self, rule_id: str, target: str | None, dev: Device | None) -> dict | None:
        for exc in self.exceptions:
            if str(exc.get("rule_id")) not in (rule_id, "*", ""):
                continue
            scope = exc.get("target")
            if scope in (None, "", "*"):
                return exc
            scope = str(scope)
            candidates = {target, dev.id if dev else None, dev.ip if dev else None, dev.hostname if dev else None, dev.zone if dev else None, dev.device_type if dev else None}
            candidates |= set(dev.tags) if dev else set()
            if scope.lower().strip() in {str(c).lower() for c in candidates if c}:
                return exc
            if any(_glob(str(c), scope) for c in candidates if c):
                return exc
        return None

    # -- main --------------------------------------------------------------
    def analyze(self, snapshot: ScanSnapshot, *, graph=None) -> ScanSnapshot:
        enricher = Enricher(snapshot, graph=graph or self.graph, thresholds=self.thresholds, policy=self.policy)
        findings: list[Finding] = []
        hit_count: dict[str, int] = {}
        errors: list[str] = list(self.audit["errors"])
        network_facts_cache: dict | None = None

        for rule in self.rules:
            try:
                if rule.scope == "network":
                    if network_facts_cache is None:
                        network_facts_cache = {"network": enricher.network_facts(), "scan": {"thresholds": self.thresholds, "mode": snapshot.mode}, "device": {}, "zone": {}, "link": {}}
                    findings.extend(self._run_rule(rule, network_facts_cache, target_id="network", target_label="network-wide", snapshot=snapshot, enricher=enricher))
                elif rule.scope == "link":
                    for link in snapshot.links:
                        facts = enricher.link_facts(link)
                        facts["scan"] = {"thresholds": self.thresholds, "mode": snapshot.mode}
                        facts["device"] = {}
                        facts["zone"] = {}
                        findings.extend(self._run_rule(rule, facts, target_id=link.id, target_label=f"{facts['link']['src_label']} <-> {facts['link']['dst_label']}", snapshot=snapshot, enricher=enricher))
                else:
                    for dev in snapshot.devices:
                        facts = self._facts(dev, enricher)
                        findings.extend(self._run_rule(rule, facts, target_id=dev.id, target_label=dev.display, snapshot=snapshot, enricher=enricher, device=dev))
            except RuleError as exc:
                errors.append(f"{rule.id}: {exc}")
            except Exception as exc:  # noqa: BLE001 - one bad rule must not abort the run
                errors.append(f"{rule.id}: evaluation failed: {type(exc).__name__}: {exc}")
        hit_count = {}
        for f in findings:
            hit_count[f.rule_id] = hit_count.get(f.rule_id, 0) + 1

        findings = self._dedupe(findings)
        cap = int(self.config.get("max_findings_per_rule") or 0)
        if cap > 0:
            per: dict[str, int] = {}
            capped: list[Finding] = []
            for f in findings:
                used = per.get(f.rule_id, 0)
                if used >= cap:
                    self.audit["capped"] = {**self.audit.get("capped", {}), f.rule_id: self.audit.get("capped", {}).get(f.rule_id, 0) + 1}
                    continue
                per[f.rule_id] = used + 1
                capped.append(f)
            findings = capped
        findings = self._apply_exceptions(findings, snapshot)
        snapshot.findings = findings
        score_devices(snapshot, findings)
        snapshot.risk = score_network(snapshot, findings, thresholds=self.thresholds)
        self.audit["hit_count"] = dict(sorted(hit_count.items(), key=lambda kv: -kv[1]))
        self.audit["findings"] = len(findings)
        self.audit["rules_active"] = len(self.rules)
        self.audit["errors"] = errors
        snapshot.summary = summarize(snapshot)
        snapshot.config = {**(snapshot.config or {}), "risk_audit": {k: v for k, v in self.audit.items() if k != "errors"}}
        if errors:
            snapshot.notes.extend(f"risk engine: {e}" for e in errors[:10])
        return snapshot

    def _run_rule(self, rule: Rule, facts: dict, *, target_id: str, target_label: str, snapshot: ScanSnapshot, enricher: Enricher, device: Device | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not rule.matches_filter(facts):
            return findings
        foreach = rule.raw.get("foreach")
        try:
            if rule.unless_hit(facts):
                return findings
        except RuleError as exc:
            facts.setdefault("_errors", []).append(str(exc))
            return findings
        items: list[Any] = [None]
        if isinstance(foreach, dict) and foreach.get("over"):
            raw_list = resolve_path(facts, str(foreach["over"]))
            where = foreach.get("where")
            candidates = list(raw_list or [])
            items = []
            for item in candidates:
                local = dict(facts)
                local["service"] = item if isinstance(item, dict) else None
                if where is None or evaluate(where, local):
                    items.append(item)
            if not items:
                return findings
        for item in items:
            local = dict(facts)
            if item is not None:
                local["service"] = item if isinstance(item, dict) else {str(k): v for k, v in vars(item).items()} if hasattr(item, "__dict__") else item
            try:
                if not evaluate(rule.raw.get("when", {"literal": True}), local):
                    continue
            except RuleError as exc:
                facts.setdefault("_errors", []).append(f"{rule.id}: {exc}")
                return findings
            finding = self._build_finding(rule, local, target_id=target_id, target_label=target_label, device=device)
            if finding is not None:
                findings.append(finding)
            if rule.raw.get("first_match_only"):
                break
        return findings

    def _build_finding(self, rule: Rule, facts: dict, *, target_id: str, target_label: str, device: Device | None) -> Finding | None:
        severity = rule.severity
        impact = float(rule.raw.get("impact") or SEVERITY_WEIGHT.get(severity, 4.5))
        likelihood = float(rule.raw.get("likelihood") or 6.0)
        reasons: list[str] = []
        for esc in rule.raw.get("escalate") or []:
            if not isinstance(esc, dict):
                continue
            cond = esc.get("when")
            try:
                hit = bool(evaluate(cond, facts)) if cond else True
            except RuleError:
                hit = False
            if not hit:
                continue
            if esc.get("severity") and SEVERITY_ORDER.index(esc["severity"]) < SEVERITY_ORDER.index(severity):
                severity = str(esc["severity"])
            if esc.get("impact"):
                impact = max(impact, float(esc["impact"]))
            if esc.get("likelihood"):
                likelihood = max(likelihood, float(esc["likelihood"]))
            if esc.get("reason"):
                reasons.append(str(esc["reason"]))
        score = round(clamp(impact * likelihood / 10.0, 0.0, 10.0), 2)
        evidence = self._render_evidence(rule.raw.get("evidence") or [], facts)
        fingerprint = hashlib.sha1(
            "|".join([rule.id, str(target_id), str(rule.raw.get("version", 1)), *sorted(str(e) for e in evidence)[:6]]).encode()
        ).hexdigest()[:16]
        dev = facts.get("device") or {}
        finding = Finding(
            id=f"{rule.id}@{target_id}"[:120],
            rule_id=rule.id,
            rule_title=rule.title,
            rule_version=str(rule.raw.get("version", "1")),
            severity=severity,
            score=score,
            scope=rule.scope,
            target_id=target_id,
            target_label=target_label,
            description=_render(str(rule.raw.get("description") or "").strip(), facts),
            impact=_render(str(rule.raw.get("impact_note") or ""), facts) or None,
            likelihood=str(likelihood),
            remediation=_render(str(rule.raw.get("remediation") or "").strip(), facts) or None,
            evidence=evidence + [{"escalated": r} for r in reasons],
            refs=dict(rule.raw.get("refs") or {}),
            status="open",
            first_seen=iso(now_utc()),
            device_type=dev.get("device_type"),
            zone=dev.get("zone"),
            criticality=int(dev.get("criticality") or 2),
            exposed=bool(dev.get("exposed_to_wan")),
            confidence=float(rule.raw.get("confidence") or 1.0),
            fingerprint=fingerprint,
        )
        return finding

    def _render_evidence(self, templates: list, facts: dict) -> list[dict]:
        out: list[dict] = []
        for tpl in templates or []:
            if isinstance(tpl, dict):
                # {label: "...", value: "{device.ip}"} or free text key
                label = tpl.get("label")
                value = _render(str(tpl.get("value", "")), facts)
                out.append({"label": label, "value": value} if label else {"text": value})
            else:
                out.append({"text": _render(str(tpl), facts)})
        return out

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        best: dict[str, Finding] = {}
        for f in findings:
            key = f.fingerprint or f.id
            current = best.get(key)
            if current is None or f.sort_key < current.sort_key:
                best[key] = f
        return sorted(best.values(), key=lambda f: f.sort_key)

    def _apply_exceptions(self, findings: list[Finding], snapshot: ScanSnapshot) -> list[Finding]:
        by_id = snapshot.device_map()
        out: list[Finding] = []
        for f in findings:
            dev = by_id.get(f.target_id or "")
            exc = self._exception_for(f.rule_id, f.target_id, dev)
            if exc:
                f.status = "accepted" if str(exc.get("type", "accepted")) == "accepted" else "suppressed"
                f.status_note = f"{exc.get('reason', 'accepted risk')} ({exc.get('approved_by', 'n/a')}" + (f", expires {exc['expires']})" if exc.get("expires") else ")")
            out.append(f)
        return out


class Zone_stub:
    """Empty zone for devices whose zone is not declared in config."""

    name = None
    trust = "unknown"
    segmentation_enforced = False
    cidrs: list[str] = []
    vlans: list[int] = []
    description = None
    default_gateway = None
    device_count = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "trust": self.trust,
            "segmentation_enforced": self.segmentation_enforced,
            "cidrs": list(self.cidrs),
            "vlans": list(self.vlans),
            "description": self.description,
            "default_gateway": self.default_gateway,
            "device_count": self.device_count,
        }


def _render(template: str, facts: dict) -> str:
    """Substitute {a.b.c} paths from the facts namespace, leaving unknowns as-is."""

    def repl(m):
        path = m.group(1).strip()
        value = resolve_path(facts, path)
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            items = list(value)
            return ", ".join(str(i) for i in items) if items else "none"
        if isinstance(value, dict):
            return json.dumps(value, default=str)[:300]
        if isinstance(value, float):
            return f"{value:g}"
        return str(value)

    return re.sub(r"\{([a-zA-Z0-9_.\[\]']+)\}", repl, template)


def _glob(candidate: str, pattern: str) -> bool:
    if "*" not in pattern and "?" not in pattern:
        return False
    return re.fullmatch(re.escape(pattern).replace("\\*", ".*").replace("\\?", "."), candidate, re.I) is not None


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def score_devices(snapshot: ScanSnapshot, findings: list[Finding]) -> None:
    """Probabilistic union of finding weights, per device."""
    by_target: dict[str, list[Finding]] = {}
    for f in findings:
        by_target.setdefault(f.target_id or "", []).append(f)
    for dev in snapshot.devices:
        mine = by_target.get(dev.id, [])
        active = [f for f in mine if f.status == "open"]
        product = 1.0
        for f in active:
            weight = f.score or SEVERITY_WEIGHT.get(f.severity, 2.0)
            product *= 1.0 - clamp(weight, 0.0, 9.9) / 10.0
        base = round(10.0 * (1.0 - product), 2)
        # criticality tilts the operational priority, not the probability
        criticality_bias = 1.0 + (max(0, int(dev.criticality) - 3)) * 0.05
        exposure_bias = 1.08 if dev.exposed_to_wan else 1.0
        dev.risk_score = round(clamp(base * criticality_bias * exposure_bias, 0.0, 10.0), 2)
        dev.finding_ids = [f.id for f in sorted(mine, key=lambda f: f.sort_key)]
    for dev in snapshot.devices:
        dev.raw["findings_by_severity"] = {
            sev: sum(1 for f in findings if f.target_id == dev.id and f.severity == sev and f.status == "open") for sev in SEVERITY_ORDER
        }
        dev.raw["accepted_findings"] = sum(1 for f in findings if f.target_id == dev.id and f.status != "open")


def band_for(score: float) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "Minimal"


def score_network(snapshot: ScanSnapshot, findings: list[Finding], *, thresholds: dict | None = None) -> dict:
    devices = snapshot.devices
    open_findings = [f for f in findings if f.status == "open"]
    weights = [d.risk_score for d in devices]
    criticality = [max(1, int(d.criticality)) for d in devices]
    weighted = sum(w * c for w, c in zip(weights, criticality)) / max(1, sum(criticality))
    max_dev = max(weights or [0.0])
    exposure = _exposure_index(snapshot)
    architecture = _architecture_index(snapshot)
    # Structural penalties are rates, not raw counts: six single points of failure
    # across a 200-link core is a different problem from six across 40 links.
    metrics = snapshot.config.get("topology_metrics") or {}
    n_links = max(1, int(metrics.get("links") or len(snapshot.links) or 1))
    n_nodes = max(1, int(metrics.get("nodes") or len(devices) or 1))
    bridges = int(metrics.get("bridges") or 0)
    isolated = int(metrics.get("isolated_nodes") or 0)
    bridge_rate = bridges / n_links
    isolation_rate = isolated / n_nodes
    penalty = min(2.5, 2.5 * bridge_rate) + min(1.5, 3.0 * isolation_rate)
    coverage = max(0.0, (100.0 - float(metrics.get("link_coverage_pct", 100.0))) / 100.0)
    score = clamp(
        0.55 * weighted + 0.25 * max_dev + 0.20 * exposure + 0.25 * architecture + 0.45 * penalty + 1.2 * coverage,
        0.0,
        10.0,
    )
    counts = {sev: sum(1 for f in open_findings if f.severity == sev) for sev in SEVERITY_ORDER}
    families: dict[str, dict[str, float]] = {}
    for f in open_findings:
        # a rule's own `family` label beats an id-derived guess
        parts = f.rule_id.split("-")
        fam = str((f.refs or {}).get("family") or (parts[1] if len(parts) > 2 else "general"))
        entry = families.setdefault(str(fam), {"count": 0, "score": 0.0, "worst": "info"})
        entry["count"] += 1
        entry["score"] += f.score
        if SEVERITY_ORDER.index(f.severity) < SEVERITY_ORDER.index(entry["worst"]):
            entry["worst"] = f.severity
    return {
        "score": round(score, 2),
        "band": band_for(score),
        "components": {
            "weighted_device_risk": round(weighted, 2),
            "worst_device_risk": round(max_dev, 2),
            "exposure_index": round(exposure, 2),
            "structural_penalty": round(penalty, 2),
            "architecture_index": round(architecture, 2),
            "coverage_penalty": round(coverage * 1.2, 2),
        },
        "counts": counts,
        "total_findings": len(findings),
        "open_findings": len(open_findings),
        "accepted_findings": len(findings) - len(open_findings),
        "families": {
            k: {
                "count": int(v["count"]),
                "score": round(v["score"], 2),
                "worst": v["worst"],
                "share_pct": round(100.0 * v["score"] / max(1e-9, sum(x["score"] for x in families.values())), 1),
            }
            for k, v in sorted(families.items(), key=lambda kv: -kv[1]["score"])
        },
        "structure": {
            "links": n_links,
            "nodes": n_nodes,
            "bridges": bridges,
            "isolated_nodes": isolated,
            "bridge_rate": round(bridge_rate, 3),
            "link_coverage_pct": metrics.get("link_coverage_pct"),
        },
        "band_scale": [{"min": t, "label": l} for t, l in BANDS],
    }


def _exposure_index(snapshot: ScanSnapshot) -> float:
    """0..10 measure of reachable attack surface."""
    devices = [d for d in snapshot.devices if d.reachable]
    if not devices:
        return 0.0
    total = 0.0
    for dev in devices:
        surface = 0.0
        for svc in dev.services:
            if not svc.is_open:
                continue
            from ..ports import port_risk

            risk = port_risk(svc.port, svc.protocol)
            factor = 1.0 if svc.encryption in ("none", "unknown") else 0.35
            surface += risk * factor
        if dev.exposed_to_wan:
            surface *= 1.5
        if dev.criticality >= 4:
            surface *= 1.2
        total += min(surface, 40.0)
    return clamp(total / max(1, len(devices)) / 4.0, 0.0, 10.0)


def _architecture_index(snapshot: ScanSnapshot) -> float:
    metrics = snapshot.config.get("topology_metrics") or {}
    nodes = max(1, int(metrics.get("nodes", 1)))
    missing_redundancy = max(0.0, 1.0 - float(metrics.get("redundant_pairs", 0)) / max(1, nodes / 3))
    bridges = float(metrics.get("bridges", 0)) / nodes
    articulation = float(metrics.get("articulation_points", 0)) / nodes
    return clamp(10.0 * (0.4 * missing_redundancy + 0.3 * bridges + 0.3 * articulation), 0.0, 10.0)


def _count_by(items, attr: str) -> dict:
    out: dict[str, int] = {}
    for item in items:
        key = str(getattr(item, attr, None) or "unspecified")
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def summarize(snapshot: ScanSnapshot) -> dict:
    from ..models import summarize_devices

    findings = snapshot.findings
    counts = {sev: sum(1 for f in findings if f.severity == sev and f.status == "open") for sev in SEVERITY_ORDER}
    top = sorted([f for f in findings if f.status == "open"], key=lambda f: f.sort_key)[:10]
    return {
        "devices": summarize_devices(snapshot.devices),
        "links": len(snapshot.links),
        "zones": len(snapshot.zones),
        "findings": {"total": len(findings), **counts},
        "risk": snapshot.risk,
        "top_findings": [
            {"rule": f.rule_id, "severity": f.severity, "target": f.target_label, "score": f.score, "title": f.rule_title} for f in top
        ],
        "services": _service_rollup(snapshot),
        "device_types": _count_by(snapshot.devices, "device_type"),
        "zones_by_trust": _count_by(snapshot.zones, "trust"),
        "generated_at": iso(now_utc()),
    }


def _service_rollup(snapshot: ScanSnapshot) -> list[dict]:
    tally: dict[str, dict[str, Any]] = {}
    for dev in snapshot.devices:
        for svc in dev.services:
            if not svc.is_open:
                continue
            key = str(svc.name or f"{svc.port}/{svc.protocol}")
            row = tally.setdefault(key, {"name": key, "ports": set(), "devices": 0, "cleartext": 0, "products": set()})
            row["ports"].add(svc.port)
            row["devices"] += 1
            if svc.encryption in ("none", "unknown"):
                row["cleartext"] += 1
            if svc.product:
                row["products"].add(str(svc.product))
    return sorted(
        [{"name": r["name"], "ports": sorted(r["ports"]), "devices": r["devices"], "cleartext": r["cleartext"], "products": sorted(r["products"])[:4]} for r in tally.values()],
        key=lambda r: -r["devices"],
    )


__all__ = ["RiskEngine", "Rule", "score_devices", "score_network", "summarize", "band_for", "DEFAULT_RULES"]
