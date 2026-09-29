"""Discovery orchestration.

Pipeline (each stage independent, timed, and failure-tolerant):

    targets + ARP seeds -> host sweep -> port sweep -> service fingerprinting
      -> reverse DNS -> SNMP enumeration -> passive neighbour merge
      -> inventory reconciliation -> zone assignment -> snapshot
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from .. import __version__
from ..config import Config, load_inventory
from ..models import (
    ArpEntry,
    Device,
    Neighbor,
    ScanError,
    ScanSnapshot,
    Service,
    Zone,
    device_id_for,
)
from ..reference import References, get_references
from ..util import is_ip, iso, norm_ip, now_utc, parse_mac, slug
from . import arp as arpmod
from . import sweep
from .probes import classify_service, fingerprint_service
from .snmp_enum import enumerate_device

log = logging.getLogger("netmap.engine")

SNMP_PORTS = {161, 162}


@dataclass
class Stage:
    name: str
    seconds: float = 0.0
    notes: list[str] = field(default_factory=list)
    counters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"name": self.name, "seconds": round(self.seconds, 3), "notes": self.notes, "counters": self.counters}


class DiscoveryEngine:
    def __init__(
        self,
        cfg: Config,
        *,
        refs: References | None = None,
        inventory: dict[str, dict] | None = None,
        progress: Callable[[str, dict], None] | None = None,
        base_dir: str | None = None,
    ):
        self.cfg = cfg
        self.refs = refs or get_references(cfg.get("refs.file") or None)
        self.base_dir = base_dir or os.getcwd()
        self.inventory = inventory if inventory is not None else load_inventory(cfg, self.base_dir)
        self.progress = progress or (lambda stage, info: None)
        self.stages: list[Stage] = []
        self.errors: list[ScanError] = []
        self.counters: dict[str, Any] = {
            "hosts_targeted": 0,
            "hosts_alive": 0,
            "ports_probed": 0,
            "services_found": 0,
            "snmp_readable": 0,
            "snmp_default_community": 0,
            "devices_documented": 0,
            "tls_endpoints": 0,
            "http_endpoints": 0,
        }
        self._t0 = 0.0
        # only used to turn stage completions into a 0..1 progress fraction
        self.expected_stages = 9

    # ------------------------------------------------------------------ util
    def _stage(self, name: str):
        engine = self

        class _Ctx:
            def __init__(self) -> None:
                self.stage = Stage(name=name)

            def __enter__(self) -> Stage:
                self.stage.started = time.monotonic()  # type: ignore[attr-defined]
                return self.stage

            def __exit__(self, *exc) -> None:
                self.stage.seconds = time.monotonic() - getattr(self.stage, "started", time.monotonic())
                engine.stages.append(self.stage)
                # progress contract shared with the CLI/web: (stage, fraction, message)
                frac = min(0.95, len(engine.stages) / float(getattr(engine, "expected_stages", 9) or 9))
                bits = ", ".join(f"{k}={v}" for k, v in list(self.stage.counters.items())[:6] if not isinstance(v, (dict, list)))
                engine.progress(name, frac, f"done in {self.stage.seconds:.1f}s" + (f" ({bits})" if bits else ""))

        return _Ctx()

    def _error(self, stage: str, message: str, target: str | None = None) -> None:
        self.errors.append(ScanError(stage=stage, target=target, message=str(message)[:400]))
        log.debug("%s: %s (%s)", stage, message, target)

    # ------------------------------------------------------------- entrypoint
    def run(self) -> ScanSnapshot:
        return asyncio.run(self.run_async())

    async def run_async(self) -> ScanSnapshot:
        self._t0 = time.monotonic()
        snapshot = ScanSnapshot(
            snapshot_id=now_utc().strftime("snap-%Y%m%dT%H%M%SZ"),
            scanner_version=__version__,
            mode=str(self.cfg.get("scan.mode", "live")),
            operator=self.cfg.get("operator"),
            started=iso(self._t0),
            targets=[str(t) for t in (self.cfg.get("scan.targets") or [])],
            authorization=dict(self.cfg.get("authorization") or {}),
            config=self.cfg.summary(),
        )
        targets, _excluded = self._seed_targets()
        snapshot.targets = targets or snapshot.targets
        if not targets and snapshot.mode == "live":
            raise RuntimeError("no probeable targets after exclusions/safety filter")

        with self._stage("host-discovery") as st:
            hosts, alive = await self._discover_hosts(targets)
            st.counters = {"targeted": len(hosts), "alive": len(alive)}
            self.counters["hosts_targeted"] = len(hosts)
            self.counters["hosts_alive"] = len(alive)

        devices: dict[str, Device] = {ip: Device(id=device_id_for(ip), ip=ip) for ip in alive}
        for dev in devices.values():
            dev.reachable = True
            dev.discovery_sources = ["sweep"]
            dev.last_seen = iso(now_utc())

        with self._stage("port-scan") as st:
            port_results = await self._scan_ports(alive)
            st.counters = {"hosts": len(port_results), "open_ports": sum(1 for r in port_results.values() for x in r if x.state.startswith("open"))}

        with self._stage("service-fingerprint") as st:
            await self._fingerprint(devices, port_results)
            st.counters = {"services": self.counters["services_found"]}

        with self._stage("name-resolution") as st:
            if self.cfg.get("scan.resolve_names", True):
                await self._resolve_names(devices)

        with self._stage("snmp-enumeration") as st:
            await self._snmp_pass(devices)
            st.counters = {"readable": self.counters["snmp_readable"], "default_community": self.counters["snmp_default_community"]}

        with self._stage("passive-neighbours") as st:
            if self.cfg.get("scan.capture.enabled"):
                await self._capture_neighbours(devices)
            else:
                st.notes.append("disabled (set scan.capture.enabled to ingest CDP/LLDP frames)")

        with self._stage("classification") as st:
            self._classify(devices)
            self._reconcile_inventory(devices)

        snapshot.zones = self._build_zones(devices)
        snapshot.devices = list(devices.values())
        snapshot.errors = self.errors
        snapshot.counters = self.counters
        snapshot.finished = iso(time.time())
        snapshot.duration_seconds = round(time.monotonic() - self._t0, 3)
        snapshot.config = {**self.cfg.summary(), "stages": [s.to_dict() for s in self.stages], "reference": self.refs.stats()}
        snapshot.notes.append(
            "Discovery is read-only: no SNMP SET, no login attempts, no exploit payloads."
        )
        return snapshot

    # ------------------------------------------------------------- stages
    def _seed_targets(self) -> tuple[list[str], list[str]]:
        """Configured targets, plus ARP-learned hosts inside the target space."""
        hosts = [h for h in (self.cfg.resolved_targets()[0] if self.cfg.get("scan.targets") else [])]
        arp_rows: list[ArpEntry] = []
        if self.cfg.get("scan.arp.enabled", True):
            path = self.cfg.get("scan.arp.file")
            if path and os.path.exists(path):
                arp_rows = parse_arp_file(path)
                self.counters["arp_source"] = path
            else:
                arp_rows = arpmod.read_arp_table()
                self.counters["arp_source"] = "system"
        self._arp_alive = {r.ip for r in arp_rows if r.ip}
        self._arp_rows = arp_rows
        self.counters["arp_entries"] = len(arp_rows)
        if self.cfg.get("scan.arp.include_in_targets") and arp_rows:
            for row in arp_rows:
                if row.ip and row.ip not in hosts and self.cfg.is_allowed(row.ip):
                    hosts.append(row.ip)
        hosts = [h for h in hosts if self.cfg.is_allowed(h) or not is_ip(h)]
        if not hosts and arp_rows and self.cfg.get("scan.mode") != "live":
            hosts = sorted({r.ip for r in arp_rows if r.ip})[:256]
        self.counters["hosts_seeded_by_arp"] = len(set(hosts) & self._arp_alive)
        return list(dict.fromkeys(hosts)), []

    async def _discover_hosts(self, targets: Sequence[str]) -> tuple[list[str], list[str]]:
        names = [t for t in targets if not is_ip(t)]
        ips = [t for t in targets if is_ip(t)]
        resolved = set(ips)
        for name in names:
            for ip in arpmod.forward_dns(name):
                if self.cfg.is_allowed(ip):
                    resolved.add(ip)
                else:
                    self._error("host-discovery", f"target {name} resolves to {ip}, which is outside the authorized scope")
        ips = sorted(resolved, key=lambda a: ipaddress.ip_address(a))
        if not ips:
            return [], []
        strategy = str(self.cfg.get("scan.ping.strategy", "auto"))
        results = await sweep.discover(
            ips,
            strategy=strategy,
            icmp_timeout=float(self.cfg.get("scan.ping.timeout", 1.0)),
            icmp_count=int(self.cfg.get("scan.ping.count", 1)),
            concurrency=int(self.cfg.get("scan.concurrency", 180)),
            rate_pps=float(self.cfg.get("scan.rate_pps", 350)),
            tcp_ping_ports=[int(p) for p in self.cfg.get("scan.ping.tcp_probe_ports") or []],
            known_alive=self._arp_alive if self.cfg.get("scan.arp.enabled", True) else set(),
        )
        alive, dead = sweep.partition_alive(results)
        for ip, res in results.items():
            if res.evidence:
                self.counters.setdefault("discovery_evidence", {})[ip] = res.evidence
            if res.rtt_ms:
                self.counters.setdefault("rtt_ms", {})[ip] = res.rtt_ms
        self.counters["hosts_unresponsive"] = len(dead)
        if not alive and ips:
            note = "no responsive hosts; check scan.ping.strategy (ICMP needs CAP_NET_RAW) or scan.targets"
            self._error("host-discovery", note)
            if str(self.cfg.get("scan.ping.strategy")) == "auto":
                alive = ips  # keep the pipeline useful: fall through to port sweep
                self._error("host-discovery", "promoting all targets to port sweep so the scan still yields data")
        self._host_results = results
        return ips, alive

    async def _scan_ports(self, hosts: Sequence[str]) -> dict[str, list[sweep.PortResult]]:
        tcp_ports = self.cfg.tcp_port_list()
        udp_ports = self.cfg.udp_port_list()
        if not tcp_ports and not udp_ports:
            self._error("port-scan", "no ports configured; skipping port sweep")
            return {}
        limiter = sweep.RateLimiter(float(self.cfg.get("scan.rate_pps", 350)))
        sem = asyncio.Semaphore(max(1, int(self.cfg.get("scan.concurrency", 180)) // 12 or 1))
        per_host_concurrency = max(8, int(self.cfg.get("scan.concurrency", 180)))
        results: dict[str, list[sweep.PortResult]] = {}

        async def _one(host: str) -> tuple[str, list[sweep.PortResult]]:
            async with sem:
                started = time.monotonic()
                ports = await sweep.scan_host(
                    host,
                    tcp_ports=tcp_ports,
                    udp_ports=udp_ports,
                    concurrency=per_host_concurrency,
                    connect_timeout=float(self.cfg.get("scan.timeouts.connect", 0.75)),
                    read_timeout=float(self.cfg.get("scan.timeouts.read", 1.25)),
                    banner_grab=bool(self.cfg.get("scan.banner_grab", True)),
                    banner_bytes=int(self.cfg.get("scan.banner_bytes", 1024)),
                    limiter=limiter,
                )
                self.counters["ports_probed"] += len(ports)
                open_count = sum(1 for p in ports if p.state.startswith("open"))
                log.debug("port sweep %s: %d ports, %d open, %.2fs", host, len(ports), open_count, time.monotonic() - started)
                return host, ports

        pairs = await asyncio.gather(*[_one(h) for h in hosts], return_exceptions=True)
        for item in pairs:
            if isinstance(item, BaseException):
                self._error("port-scan", f"{type(item).__name__}: {item}")
                continue
            host, ports = item
            results[host] = ports
        return results

    async def _fingerprint(self, devices: dict[str, Device], port_results: dict[str, list[sweep.PortResult]]) -> None:
        if not self.cfg.get("scan.banner_grab", True) and not self.cfg.get("scan.tls_probe", True):
            for host, ports in port_results.items():
                dev = devices.get(host)
                if not dev:
                    continue
                for res in ports:
                    if res.state.startswith("open"):
                        dev.services.append(classify_service(res.port, res.protocol, res.state, banner=res.banner, refs=self.refs))
            self.counters["services_found"] = sum(len(d.services) for d in devices.values())
            return
        sem = asyncio.Semaphore(max(4, int(self.cfg.get("scan.concurrency", 180)) // 4))
        timeout = float(self.cfg.get("scan.service_probe_timeout", 2.0))
        tasks: list[asyncio.Task] = []
        loop = asyncio.get_running_loop()

        async def _one(host: str, res: sweep.PortResult) -> tuple[str, Service, dict]:
            async with sem:
                payload = {
                    "port": res.port,
                    "protocol": res.protocol,
                    "state": res.state,
                    "banner": res.banner,
                }
                svc, detail = await fingerprint_service(
                    host,
                    payload,
                    refs=self.refs,
                    do_tls=bool(self.cfg.get("scan.tls_probe", True)),
                    do_http=True,
                    timeout=timeout,
                )
                return host, svc, detail

        for host, ports in port_results.items():
            for res in ports:
                if not res.state.startswith("open"):
                    continue
                tasks.append(loop.create_task(_one(host, res)))
        if not tasks:
            return
        done = await asyncio.gather(*tasks, return_exceptions=True)
        for item in done:
            if isinstance(item, BaseException):
                self._error("service-fingerprint", f"{type(item).__name__}: {item}")
                continue
            host, svc, detail = item
            dev = devices.get(host)
            if dev is None:
                continue
            dev.services.append(svc)
            self.counters["services_found"] += 1
            if detail.get("tls"):
                self.counters["tls_endpoints"] += 1
            if detail.get("http"):
                self.counters["http_endpoints"] += 1
            if detail:
                svc.config.setdefault("_probe_detail", {k: v for k, v in detail.items() if k != "http"})
                if detail.get("http"):
                    http = detail["http"]
                    svc.http = {
                        "status": http.get("status"),
                        "headers": http.get("headers"),
                        "paths": http.get("paths"),
                        "security_headers": http.get("security_headers"),
                        "exposed_admin_paths": http.get("exposed_admin_paths"),
                        "leaks": http.get("leaks"),
                    }
        # keep service ordering stable for diffing
        for dev in devices.values():
            dev.services.sort(key=lambda s: (s.protocol, s.port))

    async def _resolve_names(self, devices: dict[str, Device]) -> None:
        loop = asyncio.get_running_loop()
        timeout = float(self.cfg.get("scan.timeouts.dns", 1.0))

        async def _one(dev: Device) -> None:
            if not dev.ip:
                return
            name = await loop.run_in_executor(None, lambda: arpmod.reverse_dns(dev.ip, timeout=timeout))
            if not name:
                return
            dev.hostname = name
            if self.cfg.get("scan.dns_forward", False):
                addrs = await loop.run_in_executor(None, lambda: arpmod.forward_dns(name))
                dev.raw["ptr_forward"] = addrs
                if dev.ip not in addrs:
                    dev.notes.append("reverse/forward DNS mismatch")

        await asyncio.gather(*[_one(d) for d in devices.values()], return_exceptions=True)

    async def _snmp_pass(self, devices: dict[str, Device]) -> None:
        snmp_cfg = self.cfg.get("scan.snmp") or {}
        if not snmp_cfg.get("enabled", True):
            self.stages and self.stages[-1].notes.append("SNMP disabled")
            return
        communities = [str(c) for c in snmp_cfg.get("communities") or ["public"] if c]
        versions = snmp_cfg.get("version") or "auto"
        version_list = ["v2c", "v1"] if versions == "auto" else [str(versions)]
        port = int(snmp_cfg.get("port", 161))
        want = set(snmp_cfg.get("enumerate") or ["system", "interfaces", "neighbors", "arp", "fdb", "routes", "vlans", "governance"])
        max_rows = int(snmp_cfg.get("walk_max_rows", 600))
        timeout = float(self.cfg.get("scan.timeouts.snmp", 1.2))
        retries = int(self.cfg.get("scan.retries", 1))
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(max(2, int(self.cfg.get("scan.concurrency", 180)) // 12))
        targets = [
            dev
            for dev in devices.values()
            if dev.ip and (dev.has_port(SNMP_PORTS, "udp") or dev.has_port(SNMP_PORTS, "tcp") or bool(snmp_cfg.get("probe_all")))
        ]
        if not targets:
            self.stages and self.stages[-1].notes.append("no host advertised udp/161; SNMP enumeration skipped")
            return

        async def _one(dev: Device) -> None:
            async with sem:
                creds, facts = await loop.run_in_executor(
                    None,
                    lambda: _try_creds(dev.ip, communities, version_list, port, timeout, retries, snmp_cfg.get("v3") or {}),
                )
                if creds is None:
                    dev.snmp = {
                        "readable": False,
                        "default_community": False,
                        "communities_tested": [_mask_snmp(c) for c in communities],
                    }
                    return
                data = await loop.run_in_executor(
                    None,
                    lambda: enumerate_device(
                        dev.ip,
                        creds,
                        port=port,
                        timeout=timeout,
                        retries=retries,
                        max_rows=max_rows,
                        want=want,
                    ),
                )
                apply_snmp_facts(dev, data)
                from .snmp_enum import is_default_community

                dev.snmp["default_community"] = is_default_community(creds.community)
                if dev.snmp["default_community"]:
                    self.counters["snmp_default_community"] += 1
                self.counters["snmp_readable"] += 1

        done = await asyncio.gather(*[_one(d) for d in targets], return_exceptions=True)
        for item in done:
            if isinstance(item, BaseException):
                self._error("snmp-enumeration", f"{type(item).__name__}: {item}")

    async def _capture_neighbours(self, devices: dict[str, Device]) -> None:
        from .capture import capture_neighbour_frames  # local import: optional tooling

        iface = self.cfg.get("scan.capture.interface")
        seconds = float(self.cfg.get("scan.capture.seconds", 25))
        try:
            frames = await capture_neighbour_frames(iface=iface, seconds=seconds)
        except Exception as exc:  # noqa: BLE001 - capture is best effort
            self._error("passive-neighbours", str(exc))
            return
        applied = 0
        for frame in frames:
            key = frame.get("source_ip") or frame.get("remote_system")
            dev = devices.get(key) or next((d for d in devices.values() if d.hostname == frame.get("remote_system")), None)
            if dev is None:
                continue
            dev.neighbors.append(frame["neighbor"])
            applied += 1
        self.stages[-1].counters = {"frames": len(frames), "applied": applied}

    # ------------------------------------------------------- post-processing
    def _classify(self, devices: dict[str, Device]) -> None:
        classify_devices(list(devices.values()), self.refs)

    @staticmethod
    def _type_from_services(dev: Device) -> str:
        return type_from_services(dev)

    def _reconcile_inventory(self, devices: dict[str, Device]) -> None:
        if not self.inventory:
            return
        key_field = str(self.cfg.get("inventory.key", "ip")).lower()
        for dev in devices.values():
            rec = self.inventory.get((dev.ip or "").lower()) or self.inventory.get((dev.hostname or "").lower())
            if not rec:
                continue
            dev.documented = True
            dev.inventory = rec
            self.counters["devices_documented"] += 1
            dev.role = rec.get("role") or rec.get("function") or dev.role
            dev.asset_tag = rec.get("asset_tag") or rec.get("asset") or dev.asset_tag
            dev.serial = rec.get("serial") or dev.serial
            dev.model = rec.get("model") or dev.model
            dev.vendor = dev.vendor or rec.get("vendor") or rec.get("manufacturer")
            if str(rec.get("criticality", "")).strip().isdigit():
                dev.criticality = max(1, min(5, int(rec["criticality"])))
            elif str(rec.get("tier", "")).strip().lower() in ("0", "1"):
                dev.criticality = 5
            tags = rec.get("tags") or rec.get("labels") or ""
            dev.tags = sorted({t.strip() for t in str(tags).replace(";", ",").split(",") if t.strip()})
            if rec.get("hostname") and not dev.hostname:
                dev.hostname = rec["hostname"]
            if rec.get("os"):
                dev.os_family = dev.os_family or slug(rec["os"])
                dev.raw["inventory_os"] = rec["os"]
            for required in self.cfg.get("inventory.required_tags") or []:
                if required not in dev.tags:
                    dev.notes.append(f"inventory record missing required tag {required!r}")
            if key_field == "ip" and rec.get("ip") and dev.ip and norm_ip(rec["ip"]) != dev.ip:
                dev.notes.append(f"inventory IP mismatch: record says {rec['ip']}")
        required = self.cfg.get("inventory.required_tags") or []
        if required:
            missing = [d.label for d in devices.values() if d.documented and not set(required) <= set(d.tags)]
            if missing:
                self.counters["inventory_tag_gaps"] = len(missing)

    def _build_zones(self, devices: dict[str, Device]) -> list[Zone]:
        cfg_zones = self.cfg.get("zones") or []
        zones: dict[str, Zone] = {}
        for z in cfg_zones:
            zone = Zone(
                name=str(z.get("name")),
                cidrs=[str(c) for c in (z.get("cidrs") or [])],
                vlans=[int(v) for v in (z.get("vlans") or []) if str(v).isdigit()],
                trust=str(z.get("trust") or "internal"),
                description=z.get("description"),
                default_gateway=z.get("default_gateway"),
                segmentation_enforced=bool(z.get("segmentation_enforced", True)),
            )
            zones[zone.name] = zone
        # auto-create a zone per /24 for devices the operator never mapped
        for dev in devices.values():
            if not dev.ip:
                continue
            assigned = None
            for zone in zones.values():
                if dev.vlan and zone.vlans and dev.vlan in zone.vlans:
                    assigned = zone
                    break
                if zone.owns_ip(dev.ip):
                    assigned = zone
                    break
            if assigned is None:
                net = subnet_label(dev.ip)
                assigned = zones.get(net) or Zone(
                    name=net,
                    cidrs=[subnet_cidr(dev.ip)],
                    trust="internal",
                    description="auto-derived from discovered address space (not in config.zones)",
                    segmentation_enforced=False,
                )
                zones[net] = assigned
            dev.zone = assigned.name
            dev.trust = assigned.trust
            if dev.ip not in assigned.cidrs:
                pass  # cidrs keep their configured (aggregate) form
        for zone in zones.values():
            members = [d for d in devices.values() if d.zone == zone.name]
            observed = {subnet_cidr(d.ip) for d in members if d.ip}
            if not zone.cidrs:
                zone.cidrs = sorted(observed)
            zone.vlans = sorted({m.vlan for m in members if m.vlan} | set(zone.vlans))
            zone.device_count = len(members)
        return list(zones.values())


def subnet_cidr(ip: str, prefix: int = 24) -> str:
    """The /24 (or /64) network that contains `ip`, as text."""
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def subnet_label(ip: str) -> str:
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return "unknown"
    return f"subnet-{str(net).replace('.', '-').replace('/', '_')}"


def apply_snmp_facts(dev: Device, data: dict) -> None:
    """Merge enumeration output into the device record."""
    snmp = data.get("snmp") or {}
    dev.snmp = {**dev.snmp, **snmp}
    if snmp.get("sys_descr"):
        dev.sys_descr = snmp["sys_descr"]
    if data.get("hostname") and not dev.hostname:
        dev.hostname = data["hostname"]
    elif data.get("hostname") and dev.hostname and data["hostname"] != dev.hostname:
        dev.notes.append(f"SNMP name {data['hostname']!r} differs from DNS {dev.hostname!r}")
        dev.raw["snmp_name"] = data["hostname"]
    if data.get("location"):
        dev.raw["location"] = data["location"]
    if data.get("uptime_seconds"):
        dev.uptime_seconds = float(data["uptime_seconds"])
        dev.last_boot = iso(time.time() - float(data["uptime_seconds"]))
    for key, attr in (("interfaces", "interfaces"), ("neighbors", "neighbors"), ("arp", "arp"), ("fdb", "fdb"), ("routes", "routes")):
        rows = data.get(key) or []
        if rows:
            current = getattr(dev, attr)
            existing = {getattr(r, "if_index", None) or getattr(r, "ip", None) or getattr(r, "mac", None) for r in current}
            for row in rows:
                marker = getattr(row, "if_index", None) or getattr(row, "ip", None) or getattr(row, "mac", None)
                if marker in existing and marker is not None:
                    continue
                current.append(row)
                existing.add(marker)
    if data.get("vlans"):
        dev.raw["vlans"] = {str(k): v for k, v in data["vlans"].items()}
    if data.get("config"):
        dev.config = {**dev.config, **data["config"]}
    dev.discovery_sources = sorted(set(dev.discovery_sources) | {"snmp"})
    # SNMP identity can improve classification
    from ..protocols.mibs import ENTERPRISE_VENDORS

    ent = snmp.get("enterprise")
    if ent and not dev.vendor:
        dev.vendor = ENTERPRISE_VENDORS.get(str(ent), dev.vendor)
    if dev.sys_descr:
        guess = get_references().guess_os(dev.sys_descr)
        if guess:
            dev.vendor = guess.get("vendor") or dev.vendor
            dev.os_family = guess.get("os_family") or dev.os_family
            dev.os_version = dev.os_version or guess.get("version")
            dev.device_type = guess.get("device_type") or dev.device_type
            dev.raw["product"] = guess.get("product")
            if guess.get("rule") == "cisco-ios" and (dev.device_type in (None, "unknown") or "Router" in dev.sys_descr):
                dev.device_type = "router" if "Router" in dev.sys_descr else "switch"
            dev.raw["os_rule"] = guess.get("rule")


def _try_creds(host: str, communities: list[str], versions: list[str], port: int, timeout: float, retries: int, v3: dict):
    from ..protocols.snmp import try_credentials

    return try_credentials(
        host,
        port=port,
        versions=versions,
        communities=communities,
        v3=v3,
        timeout=timeout,
        retries=retries,
    )


def _mask_snmp(community: str) -> str:
    if not community or len(community) <= 2:
        return "*" * len(community or "")
    return community[0] + "*" * (len(community) - 2) + community[-1]


def parse_arp_file(path: str) -> list[ArpEntry]:
    """Parse an exported ARP table (`arp -a` or `ip neigh` or CSV-ish text)."""
    entries: list[ArpEntry] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "," in line and line.lower().startswith("ip"):
                header = [h.strip().lower() for h in line.split(",")]
                continue
            m = re_arp(line)
            if m:
                entries.append(m)
    return entries


def re_arp(line: str) -> ArpEntry | None:
    m = arpmod.ARP_LINE.search(line)
    if not m:
        return None
    iface = None
    im = re.search(r"on (\S+)|interface[: ]+(\S+)", line)
    if im:
        iface = im.group(1) or im.group(2)
    return ArpEntry(ip=m.group("ip"), mac=parse_mac(m.group("mac")), interface=iface, entry_type="dynamic")


def type_from_services(dev: Device) -> str:
    """Fallback role inference for hosts that never identified themselves."""
    names = {str(s.name or "") for s in dev.services if s.is_open}
    ports = set(dev.open_ports)
    if {"printer", "jetdirect", "jetdirect-printer"} & names or {9100, 9101, 9102} & ports:
        return "printer"
    if names & {"ipmi", "asf-mgmt", "asf-remap", "net-assistant", "avocent"} or {623, 4011, 8500, 16992} & ports:
        return "out_of_band"
    if names & {"microsoft-ds"} and {445, 3389} <= ports:
        return "server"
    if ports & {5060, 5061, 2000} and not ports & {443, 80}:
        return "voip"
    if ports & {80, 443, 8080, 8443} and dev.hostname and any(tok in dev.hostname.lower() for tok in ("cam", "ipc", "video")):
        return "camera"
    if {67, 68} & ports:
        return "dhcp"
    if 53 in ports and len(ports) <= 3:
        return "dns"
    if ports & {161} and len(ports) <= 4:
        return "switch"
    if ports & {80, 443} and len(ports) <= 6:
        return "web"
    return "unknown"


def classify_devices(devices: Iterable[Device], refs: References | None = None) -> None:
    """Identity, lifecycle and type inference from banners/sysDescr.

    Shared by the live pipeline and lab/import modes so a simulated or imported
    snapshot is classified exactly like a discovered one.
    """
    refs = refs or get_references()
    for dev in devices:
        if not dev.os_family and not dev.vendor:
            blob = dev.text_blob()
            guess = refs.guess_os(blob) if blob else {}
            if guess:
                dev.vendor = guess.get("vendor") or dev.vendor
                dev.os_family = guess.get("os_family") or dev.os_family
                dev.os_version = dev.os_version or guess.get("version")
                dev.device_type = guess.get("device_type") or dev.device_type
                dev.raw["os_rule"] = guess.get("rule")
                dev.raw.setdefault("product", guess.get("product"))
        if dev.device_type in (None, "unknown"):
            dev.device_type = type_from_services(dev)
        if dev.os_eol is None:
            entry = refs.eol_for(dev.raw.get("product"), dev.os_version or dev.firmware, dev.sys_descr)
            if entry:
                dev.os_eol = entry.get("end_of_support")
                dev.os_eol_basis = entry.get("basis")
                dev.raw["lifecycle"] = entry
        for intf in dev.interfaces:
            if intf.oper_status == "up" and intf.role in ("uplink", "routed") and dev.device_type in ("router", "firewall"):
                if (intf.name or f"if{intf.if_index}") not in dev.wan_interfaces:
                    dev.wan_interfaces.append(intf.name or f"if{intf.if_index}")


def snapshot_from_devices(devices: Iterable[Device], cfg: Config, *, mode: str = "lab", zones: Sequence[Zone] | None = None) -> ScanSnapshot:
    """Wrap a pre-built device set (lab mode / imported data) in a snapshot."""
    devices = list(devices)
    snap = ScanSnapshot(
        snapshot_id=now_utc().strftime("snap-%Y%m%dT%H%M%SZ"),
        scanner_version=__version__,
        mode=mode,
        operator=cfg.get("operator"),
        started=iso(time.time()),
        finished=iso(time.time()),
        targets=sorted({d.ip for d in devices if d.ip}),
        authorization=dict(cfg.get("authorization") or {}),
        config=cfg.summary(),
        devices=devices,
        zones=list(zones) if zones else [],
    )
    if not snap.zones:
        by_zone: dict[str, list[Device]] = {}
        for d in devices:
            by_zone.setdefault(d.zone or "unassigned", []).append(d)
        for name, members in by_zone.items():
            zone = Zone(name=name, trust=members[0].trust or "internal")
            zone.cidrs = sorted({c for c in (subnet_cidr(m.ip) for m in members if m.ip) if c})
            zone.vlans = sorted({m.vlan for m in members if m.vlan})
            snap.zones.append(zone)
    snap.counters = {
        "hosts_alive": len([d for d in devices if d.reachable]),
        "services_found": sum(len(d.services) for d in devices),
        "snmp_readable": len([d for d in devices if d.snmp.get("readable")]),
    }
    return snap


__all__ = ["DiscoveryEngine", "Stage", "apply_snmp_facts", "classify_devices", "snapshot_from_devices", "subnet_label"]
