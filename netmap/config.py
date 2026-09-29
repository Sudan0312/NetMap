"""Configuration loading, validation and governance gates.

Config may be YAML or JSON. Values in strings support ``${ENV_VAR}``
interpolation so secrets (SNMP communities, v3 passwords) never need to be
committed to a repo.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import MAX_HOSTS, cidr_contains, expand_cidr, is_ip, parse_iso

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")

DEFAULT_TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 79, 80, 81, 88, 110, 111, 123, 135, 137, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 512, 513, 514, 515, 548, 554, 587, 623,
    631, 636, 700, 990, 993, 995, 1080, 1433, 1521, 1720, 1883, 1900, 2049, 2181,
    2375, 2379, 3000, 3128, 3306, 3389, 3690, 4000, 4369, 4444, 5000, 5060, 5432,
    5555, 5601, 5666, 5900, 5985, 5986, 6379, 6443, 7000, 8000, 8080, 8081, 8443,
    8883, 9000, 9090, 9093, 9100, 9200, 9300, 9999, 10000, 11211, 15672, 27017, 50000,
]

DEFAULT_UDP_PORTS = [53, 67, 68, 69, 111, 123, 137, 161, 162, 500, 514, 1701, 1900, 3283, 4500, 5353, 11954, 1900]


def _default_config() -> dict:
    return {
        "profile": "default",
        "operator": None,
        "authorization": {
            "confirmed": False,
            "ticket": None,
            "signed_by": None,
            "scope": [],
            "valid_until": None,
        },
        "scan": {
            "mode": "live",
            "targets": [],
            "exclude": [],
            "allow_external": False,
            "max_hosts": MAX_HOSTS,
            "ping": {"enabled": True, "strategy": "auto", "timeout": 1.0, "count": 1, "tcp_probe_ports": [22, 80, 443, 445, 3389]},
            "tcp_ports": "top",
            "udp_ports": [53, 67, 68, 123, 161, 162, 514, 1900],
            "concurrency": 180,
            "rate_pps": 350,
            "retries": 1,
            "timeouts": {"connect": 0.75, "read": 1.25, "write": 1.0, "snmp": 1.2, "dns": 1.0},
            "banner_grab": True,
            "banner_bytes": 1024,
            "service_probe_timeout": 2.0,
            "tls_probe": True,
            "dns_ptr": True,
            "dns_forward": False,
            "arp": {"enabled": True, "source": "auto", "file": None},
            "snmp": {
                "enabled": True,
                "version": "auto",
                "communities": ["public", "${NETMAP_SNMP_RO}"],
                "v3": {"enabled": False, "user": None, "auth_proto": "SHA", "auth_pass": "${NETMAP_SNMP_V3_AUTH}", "priv_proto": "AES128", "priv_pass": "${NETMAP_SNMP_V3_PRIV}", "context": ""},
                "port": 161,
                "walk_max_repetitions": 40,
                "walk_max_rows": 600,
                "enumerate": ["system", "interfaces", "neighbors", "arp", "fdb", "routes", "vlans", "governance"],
            },
            "resolve_names": True,
            "import_path": None,
            "nmap_xml": None,
        },
        "lab": {"size": "medium", "seed": 7, "include_risks": True, "device_count_hint": 50},
        "zones": [
            {"name": "wan-edge", "cidrs": [], "vlans": [10], "trust": "untrusted", "description": "Internet-facing / perimeter segment"},
            {"name": "dmz", "cidrs": [], "vlans": [20], "trust": "dmz", "description": "Public services"},
            {"name": "core", "cidrs": [], "vlans": [100], "trust": "internal", "description": "Core/distribution switching and routing"},
            {"name": "server-farm", "cidrs": [], "vlans": [110, 120], "trust": "restricted", "description": "Application + database tiers"},
            {"name": "storage", "cidrs": [], "vlans": [130], "trust": "restricted", "description": "SAN/NAS and backup"},
            {"name": "management", "cidrs": [], "vlans": [999], "trust": "out_of_band", "description": "OOB device management"},
            {"name": "access", "cidrs": [], "vlans": [200, 210], "trust": "internal", "description": "User access layer and wireless"},
            {"name": "iot", "cidrs": [], "vlans": [300], "trust": "internal", "description": "Cameras, badges, AV"},
            {"name": "guest", "cidrs": [], "vlans": [400], "trust": "untrusted", "description": "BYOD / guest"},
        ],
        "inventory": {"file": None, "key": "ip", "strict": False, "required_tags": []},
        "risk": {
            "rules_file": None,
            "disabled": [],
            "only": [],
            "severity_overrides": {},
            "exceptions": [],
            "thresholds": {
                "expiring_cert_days": 30,
                "unknown_device_max_ports": 12,
                "high_criticality": 4,
                "stale_firmware_days": 730,
                "recent_reboot_minutes": 10,
                "min_subnet_redundancy": 2,
                "max_undocumented_pct": 5.0,
            },
            "min_severity": "info",
            "rules_files": [],
            "max_findings_per_rule": 0,
            "baseline": None,
            "fail_on": "critical",
        },
        "topology": {
            "infer_l3_via_routing": True,
            "min_confidence": 0.4,
            "treat_same_subnet_as_adjacency": False,
            "collapse_access_layers": True,
        },
        "report": {
            "formats": ["json", "md", "csv", "html"],
            "output_dir": "out",
            "title": "Enterprise Network Topology & Risk Report",
            "redact": True,
            "language": "en",
            "max_findings_per_device": 40,
            "baseline": None,
            "svg": True,
            "static_html": True,
            "top_n": 25,
        },
        "web": {"host": "0.0.0.0", "port": 8080, "snapshot": None, "auth_token": None},
        "integrations": {
            "siem": {"format": "cef", "endpoint": None, "dry_run": True},
            "ticket": {"system": None, "project": None, "min_severity": "high"},
        },
    }


@dataclass
class Config:
    """Dict-backed config with attribute access + defaults deep-merged."""

    data: dict = field(default_factory=_default_config)
    path: str | None = None
    sources: list[str] = field(default_factory=list)

    # -- access -------------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = self.data
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def copy(self) -> "Config":
        """Independent deep copy (used by concurrent web scans / CLI overrides)."""
        return Config(json.loads(json.dumps(self.data)), path=self.path, sources=list(self.sources))

    # -- targets ------------------------------------------------------------
    def resolved_targets(self) -> tuple[list[str], list[str]]:
        """Expand CIDRs/ranges/hostnames to probeable hosts (deduped)."""
        raw = [str(t).strip() for t in self.get("scan.targets") or [] if str(t).strip()]
        exclude = [str(e).strip() for e in self.get("scan.exclude") or [] if str(e).strip()]
        max_hosts = int(self.get("scan.max_hosts", MAX_HOSTS))
        hosts: list[str] = []
        names: list[str] = []
        for item in raw:
            if "/" in item or "-" in item or is_ip(item):
                hosts.extend(expand_cidr(item, exclude=exclude))
            else:
                names.append(item)
        ordered: list[str] = []
        seen = set()
        for h in hosts:
            if h not in seen:
                seen.add(h)
                ordered.append(h)
        capped = ordered[:max_hosts]
        return capped + [n for n in names if n not in seen], exclude

    def is_allowed(self, ip: str) -> bool:
        """Safety filter: private space unless explicitly allowed, minus exclusions."""
        from .util import ip_in_private_ranges

        if not ip:
            return False
        if cidr_contains(self.get("scan.exclude") or [], ip):
            return False
        if not ip_in_private_ranges(ip):
            return bool(self.get("scan.allow_external"))
        return True

    def tcp_port_list(self) -> list[int]:
        ports = self.get("scan.tcp_ports")
        if isinstance(ports, str):
            key = ports.strip().lower()
            if key in ("top", "common"):
                return list(DEFAULT_TOP_PORTS)
            if key == "full":
                return list(range(1, 1025))
            if key == "none":
                return []
            return [int(p) for p in re.findall(r"\d+", key)]
        return sorted({int(p) for p in ports or [] if str(p).strip().isdigit()})

    def udp_port_list(self) -> list[int]:
        ports = self.get("scan.udp_ports")
        if isinstance(ports, str):
            key = ports.strip().lower()
            if key == "none":
                return []
            if key == "common":
                return list(DEFAULT_UDP_PORTS)
            return [int(p) for p in re.findall(r"\d+", key)]
        return sorted({int(p) for p in ports or [] if str(p).strip().isdigit()})

    # -- governance ---------------------------------------------------------
    def authorization_problems(self) -> list[str]:
        """Live discovery must be explicitly authorized. Returns blockers."""
        problems: list[str] = []
        auth = self.get("authorization") or {}
        if str(self.get("scan.mode", "live")).lower() not in ("live",):
            return problems
        if not auth.get("confirmed"):
            problems.append(
                "scan.mode=live requires authorization.confirmed: true "
                "(written permission to probe these hosts)"
            )
        if not (auth.get("signed_by") or self.get("operator")):
            problems.append("authorization.signed_by (or operator) must name the accountable owner")
        if not auth.get("scope"):
            problems.append("authorization.scope must list the approved target ranges")
        until = auth.get("valid_until")
        if until:
            d = days_left(until)
            if d is not None and d < 0:
                problems.append(f"authorization expired on {until}")
        return problems

    def active_exceptions(self, *, at=None) -> list[dict]:
        out = []
        for ex in self.get("risk.exceptions") or []:
            expires = ex.get("expires")
            if expires:
                d = days_left(expires, at=at)
                if d is not None and d < 0:
                    continue
            out.append(ex)
        return out

    def summary(self) -> dict:
        targets, exclude = self.resolved_targets()
        return {
            "profile": self.get("profile"),
            "mode": self.get("scan.mode"),
            "operator": self.get("operator"),
            "targets_expanded": len(targets),
            "excluded": len(exclude),
            "tcp_ports": len(self.tcp_port_list()),
            "udp_ports": len(self.udp_port_list()),
            "snmp": bool(self.get("scan.snmp.enabled")),
            "concurrency": self.get("scan.concurrency"),
            "rate_pps": self.get("scan.rate_pps"),
            "sources": self.sources,
        }


def days_left(value: str | None, *, at=None) -> float | None:
    from .util import days_until

    return days_until(value, at=at)


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        def sub(m):
            return os.environ.get(m.group(1), m.group(2) or "")

        return ENV_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for key, val in (over or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = copy.deepcopy(val)
    return out


def _read_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError:
            # A JSON twin of the same file is generated by `make data`.
            twin = Path(path).with_suffix(".json")
            if not twin.exists():
                raise RuntimeError(f"{path}: PyYAML is missing and no {twin.name} twin exists; use a JSON config")
            loaded = json.loads(twin.read_text(encoding="utf-8"))
        else:
            loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: top level must be a mapping, got {type(loaded).__name__}")
    return loaded


def load(path: str | None = None, *, overrides: dict | None = None, extra_args: list[str] | None = None) -> Config:
    """Build a Config from defaults + file + override dict + `key=value` CLI pairs."""
    data = _default_config()
    sources: list[str] = ["defaults"]
    env_file = os.environ.get("NETMAP_CONFIG")
    if path:
        data = deep_merge(data, _read_file(path))
        sources.append(str(path))
    elif env_file and os.path.exists(env_file):
        data = deep_merge(data, _read_file(env_file))
        sources.append(env_file)
    for more in extra_args or []:
        if "=" not in more:
            raise ValueError(f"--set expects key=value, got {more!r}")
        key, raw = more.split("=", 1)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = raw
        _set_path(data, key.strip(), value)
        sources.append(f"--set {key}")
    data = deep_merge(data, overrides or {})
    data = _interpolate(data)
    # drop empty strings produced by unset ${ENV} references in default lists
    data["scan"]["snmp"]["communities"] = [c for c in data["scan"]["snmp"]["communities"] if c] or ["public"]
    return Config(data=data, path=path, sources=sources)


def _set_path(root: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = root
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
        if not isinstance(cur, dict):
            raise ValueError(f"cannot descend into {part!r}")
    cur[parts[-1]] = value


def validate(cfg: Config) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors block a live scan; warnings do not."""
    errors: list[str] = []
    warnings: list[str] = []
    mode = str(cfg.get("scan.mode", "live")).lower()
    if mode not in ("live", "lab", "import", "offline"):
        errors.append(f"scan.mode must be live|lab|import, got {mode!r}")
    targets, _excl = cfg.resolved_targets()
    if mode == "live" and not targets:
        errors.append("scan.targets is empty for a live scan")
    if int(cfg.get("scan.concurrency", 1)) < 1 or int(cfg.get("scan.concurrency", 1)) > 2000:
        errors.append("scan.concurrency must be between 1 and 2000")
    if int(cfg.get("scan.rate_pps", 1)) < 1:
        errors.append("scan.rate_pps must be >= 1")
    if float(cfg.get("scan.timeouts.connect", 0.1)) < 0.05:
        warnings.append("scan.timeouts.connect below 50ms will produce false negatives")
    if not cfg.get("scan.tcp_ports") and not cfg.get("scan.udp_ports"):
        warnings.append("no TCP or UDP ports selected; discovery will be ping-only")
    if int(cfg.get("scan.max_hosts", 0)) and len(targets) > int(cfg.get("scan.max_hosts", 0)):
        warnings.append(f"target list truncated to scan.max_hosts={cfg.get('scan.max_hosts')}")
    for zone in cfg.get("zones") or []:
        if not zone.get("name"):
            errors.append("zone entry missing 'name'")
        if zone.get("trust") not in ("untrusted", "dmz", "internal", "restricted", "out_of_band"):
            warnings.append(f"zone {zone.get('name')}: unusual trust level {zone.get('trust')!r}")
    if mode == "live":
        errors.extend(cfg.authorization_problems())
    for rule_id in cfg.get("risk.disabled") or []:
        if not re.fullmatch(r"[A-Z0-9_.:-]+", str(rule_id)):
            warnings.append(f"suspicious rule id in risk.disabled: {rule_id!r}")
    ports = cfg.tcp_port_list()
    if len(ports) > 200:
        warnings.append(f"{len(ports)} TCP ports selected; expect long scan times")
    if int(cfg.get("scan.snmp.port", 161)) not in (161, 0):
        warnings.append("non-standard SNMP port configured")
    return errors, warnings


def dump_default() -> str:
    try:
        import yaml  # type: ignore

        return yaml.safe_dump(_default_config(), sort_keys=False, width=120)
    except ImportError:  # pragma: no cover
        return json.dumps(_default_config(), indent=2)


def load_inventory(cfg: Config, base_dir: str = ".") -> dict[str, dict]:
    """Read the CMDB/asset export (CSV) and index it by the configured key."""
    rel = cfg.get("inventory.file")
    if not rel:
        return {}
    path = rel if os.path.isabs(rel) else os.path.join(base_dir, rel)
    if not os.path.exists(path):
        return {}
    import csv

    key = str(cfg.get("inventory.key", "ip")).lower()
    index: dict[str, dict] = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            row = {(k or "").strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
            value = row.get(key) or row.get("address") or row.get("ipv4") or row.get("mgmt_ip")
            if not value:
                continue
            index[str(value).strip().lower()] = row
    return index


__all__ = ["Config", "load", "dump_default", "validate", "load_inventory", "deep_merge", "DEFAULT_TOP_PORTS", "DEFAULT_UDP_PORTS"]
