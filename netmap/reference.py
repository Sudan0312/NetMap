"""Reference data access: OS/vendor fingerprints, banner signatures, HTTP
surface probes and product lifecycle (EOL) windows.

Data lives in ``netmap/refs/reference.yaml`` so a network-security team can
tune detection without patching Python. If PyYAML is unavailable the tables come
back empty and everything degrades to port-based classification, which keeps the
core package usable on locked-down hosts.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from .util import parse_version, version_lt

REFS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "refs")
REF_FILE = os.path.join(REFS_DIR, "reference.yaml")


def _load_yaml(path: str) -> dict:
    """Load a reference catalogue: YAML when PyYAML exists, else the JSON twin.

    Silently returning {} here used to disable every fingerprint, which turns a
    scan into a port list - so the fallback is an explicit twin file, never an
    empty catalogue.
    """
    if not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
    except ImportError:
        twin = os.path.splitext(path)[0] + ".json"
        if not os.path.exists(twin):
            raise RuntimeError(f"{path}: PyYAML is missing and {twin} was not generated (run `make data`)")
        with open(twin, "r", encoding="utf-8") as fh:
            data = json.load(fh) or {}
        return data if isinstance(data, dict) else {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data if isinstance(data, dict) else {}


@dataclass
class BannerRule:
    id: str
    ports: tuple[int, ...]
    regex: re.Pattern
    sets: dict = field(default_factory=dict)

    def applies(self, port: int) -> bool:
        return not self.ports or port in self.ports


@dataclass
class OsRule:
    id: str
    regex: re.Pattern
    vendor: str | None = None
    family: str | None = None
    device_type: str | None = None
    product: str | None = None
    version_regex: re.Pattern | None = None


@dataclass
class LifecycleEntry:
    product: str
    match: str | None = None
    version_lt: str | None = None
    end_of_support: str | None = None
    data: str | None = None
    regex: re.Pattern | None = None


class References:
    """Compiled view of reference.yaml."""

    def __init__(self, path: str | None = None):
        self.path = path or REF_FILE
        self.source = self.path if os.path.exists(self.path) else None
        raw = _load_yaml(self.path)
        self.os_rules = [self._compile_os(r) for r in raw.get("os_patterns") or [] if isinstance(r, dict)]
        self.banner_rules = [self._compile_banner(r) for r in raw.get("banner_services") or [] if isinstance(r, dict)]
        self.http_probes = [r for r in raw.get("http_probes") or [] if isinstance(r, dict) and r.get("path")]
        self.credential_markers = raw.get("default_credential_markers") or {}
        self.lifecycle = [self._compile_lifecycle(r) for r in raw.get("lifecycle") or [] if isinstance(r, dict)]
        self.available = bool(raw)

    # -- compilation --------------------------------------------------------
    @staticmethod
    def _compile_os(rule: dict) -> OsRule:
        return OsRule(
            id=str(rule.get("id") or rule.get("product") or "os"),
            regex=re.compile(str(rule.get("regex", "")), re.I | re.S),
            vendor=rule.get("vendor"),
            family=rule.get("family"),
            device_type=rule.get("device_type"),
            product=rule.get("product"),
            version_regex=re.compile(str(rule["version_regex"])) if rule.get("version_regex") else None,
        )

    @staticmethod
    def _compile_banner(rule: dict) -> BannerRule:
        ports = rule.get("ports") or ([int(rule["port"])] if rule.get("port") is not None else [])
        return BannerRule(
            id=str(rule.get("id") or "banner"),
            ports=tuple(int(p) for p in ports),
            regex=re.compile(str(rule.get("regex", ".")), re.S | re.I),
            sets={k: v for k, v in (rule.get("sets") or {}).items() if v is not None},
        )

    @staticmethod
    def _compile_lifecycle(rule: dict) -> LifecycleEntry:
        return LifecycleEntry(
            product=str(rule.get("product") or ""),
            match=rule.get("match"),
            version_lt=rule.get("version_lt"),
            end_of_support=rule.get("end_of_support"),
            data=rule.get("data"),
            regex=re.compile(str(rule["match"]), re.I) if rule.get("match") else None,
        )

    # -- lookups ------------------------------------------------------------
    def guess_os(self, text: str | None) -> dict[str, Any]:
        """Map sysDescr/banner text to vendor, family, device type and version."""
        if not text:
            return {}
        for rule in self.os_rules:
            m = rule.regex.search(text)
            if not m:
                continue
            out: dict[str, Any] = {
                "rule": rule.id,
                "vendor": rule.vendor,
                "os_family": rule.family,
                "device_type": rule.device_type,
                "product": rule.product,
            }
            if rule.version_regex:
                vm = rule.version_regex.search(text)
                if vm:
                    groups = [g for g in vm.groups() if g] if vm.groups() else []
                    out["version"] = (groups or [vm.group(1) if vm.lastindex else vm.group(0)])[0].strip("()., -")
            return {k: v for k, v in out.items() if v}
        return {}

    def apply_banners(self, port: int, banner: str | None, protocol: str = "tcp") -> dict[str, Any]:
        """Merge every banner rule that matches, in file order.

        Pass 1 only considers rules registered for this port. If nothing
        matched, pass 2 lets a *self-identifying* banner (e.g. ``HTTP/1.1`` on
        an ephemeral port) override the port-based guess. Catch-all rules
        (regex ``.``) never participate in pass 2 -- they only make sense with
        the port they are bound to.
        """
        merged: dict[str, Any] = {}
        if not banner:
            return merged
        generic = [r for r in self.banner_rules if r.regex.pattern not in (".", "^.", ".*")]
        for first_pass in (True, False):
            if merged:
                break
            for rule in self.banner_rules if first_pass else generic:
                if not rule.applies(port) and first_pass:
                    continue
                if not rule.applies(port) and not first_pass and rule.ports:
                    rule = BannerRule(rule.id, (), rule.regex, rule.sets)
                m = rule.regex.search(banner)
                if not m:
                    continue
                # First writer wins per field. Multiple rules legitimately
                # describe one banner (`http` gives the status code, `server-nginx`
                # the product), so every match is merged - but the table is ordered
                # specific-first and a later generic rule must not clobber what an
                # earlier precise one already identified.
                for key, value in rule.sets.items():
                    merged.setdefault(key, value)
                try:
                    groups = m.groupdict()
                except Exception:  # pragma: no cover
                    groups = {}
                for name, value in groups.items():
                    if value:
                        merged.setdefault(name, value.strip() if isinstance(value, str) else value)
                merged["_rules"] = sorted(set(merged.get("_rules", [])) | {rule.id})
            if merged and not first_pass:
                merged["_unported"] = True
        return merged

    def eol_for(self, product: str | None, version: str | None = None, description: str | None = None) -> dict | None:
        """Return the worst-matching (earliest) lifecycle entry for a product."""
        if not product:
            return None
        blob = " ".join(x for x in (product, version, description) if x)
        best: LifecycleEntry | None = None
        for entry in self.lifecycle:
            if entry.product.lower() != str(product).lower():
                continue
            if entry.regex and not entry.regex.search(blob):
                continue
            if entry.version_lt and version:
                if not version_lt(version, entry.version_lt):
                    continue
            if entry.version_lt and not version:
                continue  # cannot decide without a version
            if best is None or (entry.end_of_support or "") < (best.end_of_support or "9999"):
                best = entry
        if best is None:
            return None
        return {
            "product": best.product,
            "end_of_support": best.end_of_support,
            "basis": best.data,
            "matched_rule": {"match": best.match, "version_lt": best.version_lt},
        }

    def risky_http_paths(self) -> list[dict]:
        return [p for p in self.http_probes if p.get("risky")]

    def stats(self) -> dict:
        return {
            "source": self.source,
            "loaded": self.available,
            "os_rules": len(self.os_rules),
            "banner_rules": len(self.banner_rules),
            "http_probes": len(self.http_probes),
            "lifecycle_entries": len(self.lifecycle),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<References {self.stats()}>"


@lru_cache(maxsize=4)
def get_references(path: str | None = None) -> References:
    return References(path)


__all__ = ["References", "get_references", "REF_FILE", "REFS_DIR", "parse_version"]
