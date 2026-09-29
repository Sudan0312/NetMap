"""Core data model for NetMap.

Plain dataclasses with tolerant ``from_dict``/``to_dict`` so a snapshot can be
persisted as JSON, reloaded for offline analysis, and round-tripped without a
schema library. Field names are the public contract of the report format.
"""

from __future__ import annotations

import dataclasses
import fnmatch
from dataclasses import dataclass, field
from typing import Any, Iterable

from .util import dataclass_to_dict, days_until, is_ip, norm_ip, parse_mac, sorted_ips

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# enumerations (kept as strings on the wire for forward compatibility)
# ---------------------------------------------------------------------------

DEVICE_TYPES = (
    "firewall",
    "router",
    "switch",
    "wireless_controller",
    "access_point",
    "load_balancer",
    "ips_ids",
    "proxy",
    "server",
    "hypervisor",
    "storage",
    "out_of_band",
    "printer",
    "camera",
    "iot",
    "voip",
    "workstation",
    "directory",
    "database",
    "web",
    "mail",
    "file",
    "dns",
    "dhcp",
    "monitoring",
    "unknown",
)

TRUST_LEVELS = ("untrusted", "dmz", "internal", "restricted", "out_of_band")

SEVERITIES = ("critical", "high", "medium", "low", "info")

LINK_KINDS = ("ethernet", "port-channel", "point-to-point-ip", "tunnel", "wireless", "virtual", "inferred-l3")


def _filter_fields(cls, data: dict) -> dict:
    known = {f.name for f in dataclasses.fields(cls)}
    return {k: v for k, v in data.items() if k in known}


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------


@dataclass
class Certificate:
    """Result of a TLS handshake against a service."""

    subject_cn: str | None = None
    subject: dict = field(default_factory=dict)
    issuer_cn: str | None = None
    self_signed: bool = False
    not_before: str | None = None
    not_after: str | None = None
    days_left: float | None = None
    san: list[str] = field(default_factory=list)
    san_source: str | None = None  # extension | common_name | none
    hostname_match: bool | None = None
    protocol: str | None = None  # TLSv1 / TLSv1.1 / TLSv1.2 / TLSv1.3
    cipher: str | None = None
    bits: int | None = None
    key_type: str | None = None
    key_bits: int | None = None
    weak_cipher: bool = False
    error: str | None = None
    pinned_hosts: list[str] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        """Names a client may match against: the SAN, else the subject CN."""
        if self.san:
            return list(self.san)
        return [self.subject_cn] if self.subject_cn else []

    @property
    def days_remaining(self) -> float | None:
        """Days until expiry: the probed value if present, else `not_after`."""
        if self.days_left is not None:
            try:
                return float(self.days_left)
            except (TypeError, ValueError):
                return None
        return days_until(self.not_after)

    @property
    def expired(self) -> bool:
        d = self.days_remaining
        return d is not None and d < 0

    @property
    def expiring_soon(self) -> bool:
        d = self.days_remaining
        return d is not None and 0 <= d <= 30

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Certificate":
        return cls(**_filter_fields(cls, data))


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"  # open | closed | filtered | refused | udp-open | udp-open|filtered
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    banner: str | None = None
    cpe: str | None = None
    encryption: str = "unknown"  # none | tls | ssh | ipsec | unknown
    certificate: Certificate | None = None
    config: dict = field(default_factory=dict)  # probe-derived config facts (e.g. recursion=on)
    confidence: float = 1.0
    probe: str | None = None
    http: dict = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        return self.state.startswith("open") or "open" in self.state

    @property
    def is_encrypted(self) -> bool:
        return self.encryption in ("tls", "ssh", "ipsec", "wpa3")

    @property
    def is_plaintext(self) -> bool:
        """Advertised cleartext, or a known-plaintext port with no crypto wrapper.

        Probes set `encryption` when they can see the wrapper; when a service was
        only learned from a port list we fall back to the port table so that
        "tcp/23 with nothing else known" still reads as telnet-shaped exposure.
        """
        if self.is_encrypted:
            return False
        if self.encryption in ("none", "unknown"):
            return True
        if self.encryption in (None, ""):
            from .ports import is_plaintext as _table_plaintext

            try:
                return bool(_table_plaintext(int(self.port), self.protocol))
            except (TypeError, ValueError):
                return False
        return False

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}{'' if not self.name else f' ({self.name})'}"

    def to_dict(self) -> dict:
        d = dataclass_to_dict(self)
        if self.certificate is not None:
            d["certificate"] = self.certificate.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Service":
        cert = data.get("certificate")
        obj = cls(**_filter_fields(cls, {k: v for k, v in data.items() if k != "certificate"}))
        obj.certificate = Certificate.from_dict(cert) if isinstance(cert, dict) else None
        return obj


# ---------------------------------------------------------------------------
# layer 2 / 3 detail
# ---------------------------------------------------------------------------


@dataclass
class Interface:
    if_index: int | None = None
    name: str | None = None
    description: str | None = None
    mac: str | None = None
    type: str | None = None  # ethernetCsmacd, loopback, vlan ...
    speed_mbps: int | None = None
    admin_status: str = "up"
    oper_status: str = "unknown"  # up | down | testing | unknown
    vlan: int | None = None
    ips: list[str] = field(default_factory=list)
    mtu: int | None = None
    counters: dict = field(default_factory=dict)
    aggregation: str | None = None  # LAG member-of marker
    role: str | None = None  # access | trunk | uplink | loopback | management | member

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Interface":
        return cls(**_filter_fields(cls, data))

    @property
    def is_virtual(self) -> bool:
        return (self.type or "") in ("loopback", "vlan", "portchannel", "tunnel", "softwareLoopback")


@dataclass
class Neighbor:
    """A layer-1/2 adjacency reported by CDP/LLDP/MAC table/static config."""

    via: str = "lldp"  # lldp | cdp | mac_table | static | config | manual
    local_if: str | None = None
    local_if_index: int | None = None
    remote_key: str | None = None  # best identity: chassis mgmt IP or hostname
    remote_system: str | None = None
    remote_port: str | None = None
    remote_mac: str | None = None
    remote_chassis_id: str | None = None
    remote_description: str | None = None
    remote_ip: str | None = None
    ttl_seconds: int | None = None
    capabilities: list[str] = field(default_factory=list)
    confidence: float = 0.9

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Neighbor":
        return cls(**_filter_fields(cls, data))


@dataclass
class ArpEntry:
    ip: str | None = None
    mac: str | None = None
    if_index: int | None = None
    interface: str | None = None
    entry_type: str = "dynamic"  # dynamic | static | local

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ArpEntry":
        return cls(**_filter_fields(cls, data))


@dataclass
class FdbEntry:
    mac: str | None = None
    vlan: int | None = None
    if_index: int | None = None
    port: str | None = None
    entry_type: str = "dynamic"

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "FdbEntry":
        return cls(**_filter_fields(cls, data))


@dataclass
class Route:
    dest: str | None = None
    next_hop: str | None = None
    if_index: int | None = None
    protocol: str = "unknown"
    metric: int | None = None
    type: str = "unicast"

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Route":
        return cls(**_filter_fields(cls, data))


# ---------------------------------------------------------------------------
# devices
# ---------------------------------------------------------------------------


@dataclass
class Device:
    id: str
    ip: str | None = None
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial: str | None = None
    asset_tag: str | None = None
    device_type: str = "unknown"
    role: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    firmware: str | None = None
    sys_descr: str | None = None
    zone: str | None = None
    trust: str = "unknown"
    vlan: int | None = None
    criticality: int = 2  # 1 irrelevant .. 5 crown jewel
    tags: list[str] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    fdb: list[FdbEntry] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    snmp: dict = field(default_factory=dict)  # sysDescr/... + community + snmp version used
    config: dict = field(default_factory=dict)  # governance facts: syslog/ntp/tacacs/...
    exposed_to_wan: bool = False
    wan_interfaces: list[str] = field(default_factory=list)
    reachable: bool = True
    last_seen: str | None = None
    uptime_seconds: float | None = None
    last_boot: str | None = None
    discovery_sources: list[str] = field(default_factory=list)
    documented: bool = False
    inventory: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    os_eol: str | None = None
    os_eol_basis: str | None = None
    risk_score: float = 0.0
    finding_ids: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    # -- convenience accessors used by the rule engine and renderers --------
    @property
    def label(self) -> str:
        return self.hostname or (self.ip or self.id)

    @property
    def display(self) -> str:
        if self.ip and self.hostname and self.ip != self.hostname:
            return f"{self.hostname} ({self.ip})"
        return self.ip or self.hostname or self.id

    def service(self, port: int, protocol: str = "tcp") -> Service | None:
        for svc in self.services:
            if svc.port == int(port) and svc.protocol == protocol and svc.is_open:
                return svc
        return None

    def has_port(self, port: int | Iterable[int], protocol: str | None = None) -> bool:
        ports = {int(p) for p in (port if isinstance(port, (list, tuple, set)) else [port])}
        for svc in self.services:
            if not svc.is_open or svc.port not in ports:
                continue
            if protocol and svc.protocol != protocol:
                continue
            return True
        return False

    @property
    def open_ports(self) -> list[int]:
        return sorted({s.port for s in self.services if s.is_open})

    @property
    def port_service_names(self) -> dict[int, str]:
        return {s.port: (s.name or "") for s in self.services if s.is_open}

    def matches_port_service(self, ports: Iterable[int], names: Iterable[str] = ()) -> bool:
        wanted = {int(p) for p in ports}
        named = {str(n).lower() for n in names}
        for svc in self.services:
            if not svc.is_open:
                continue
            if svc.port in wanted:
                return True
            if named and str(svc.name or "").lower() in named:
                return True
        return False

    def text_blob(self) -> str:
        """Concatenated fingerprint text for regex-driven rules."""
        bits = [self.sys_descr or "", self.os_version or "", self.firmware or "", self.model or "", self.vendor or ""]
        for svc in self.services:
            # service *names* belong in the blob: a host that only revealed
            # "tcp/445 open" still has to match the smb/windows fingerprints
            bits += [svc.name or "", svc.product or "", svc.version or "", svc.banner or ""]
        return "\n".join(b for b in bits if b)

    def interface(self, name: str | int | None) -> Interface | None:
        """Find an interface by name or by ifIndex.

        Both spellings are needed: LLDP/CDP and CLI output name ports
        (`Gi1/0/5`), while SNMP's ifIndex is the only stable key across
        renumbering, so neighbour rows carry either one.
        """
        if name in (None, ""):
            return None
        if isinstance(name, int) or (isinstance(name, str) and name.isdigit()):
            index = int(name)
            for intf in self.interfaces:
                if intf.if_index == index:
                    return intf
        text = str(name).lower()
        for intf in self.interfaces:
            if intf.name and (intf.name == name or intf.name.lower() == text):
                return intf
        return None

    @property
    def management_protocols(self) -> list[str]:
        out = []
        for svc in self.services:
            if svc.is_open and svc.port in (22, 23, 80, 443, 161, 389, 636, 3389, 5985, 5986):
                out.append(svc.name or str(svc.port))
        return sorted(set(out))

    @property
    def uplink_count(self) -> int:
        """Adjacencies known for this device (neighbour rows, else uplink interfaces).

        Devices that do not run LLDP/CDP still report their configured uplinks,
        so the "single uplink on a critical device" rule does not fire purely
        because a neighbour protocol is disabled.
        """
        if self.neighbors:
            return len({n.local_if or n.local_if_index for n in self.neighbors})
        return len([i for i in self.interfaces if (i.role or "") in ("uplink", "lag")])

    @property
    def is_network_infrastructure(self) -> bool:
        return self.device_type in ("router", "switch", "firewall", "wireless_controller", "load_balancer", "access_point", "proxy", "ips_ids")

    def to_dict(self) -> dict:
        d = dataclass_to_dict(self)
        for key, cls_ in (
            ("interfaces", Interface),
            ("services", Service),
            ("neighbors", Neighbor),
            ("arp", ArpEntry),
            ("fdb", FdbEntry),
            ("routes", Route),
        ):
            d[key] = [x.to_dict() if isinstance(x, cls_) else x for x in d.get(key) or []]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Device":
        payload = {k: v for k, v in data.items() if k in {"interfaces", "services", "neighbors", "arp", "fdb", "routes"}}
        obj = cls(**_filter_fields(cls, {k: v for k, v in data.items() if k not in payload}))
        obj.interfaces = [Interface.from_dict(x) if isinstance(x, dict) else x for x in payload.get("interfaces") or []]
        obj.services = [Service.from_dict(x) if isinstance(x, dict) else x for x in payload.get("services") or []]
        obj.neighbors = [Neighbor.from_dict(x) if isinstance(x, dict) else x for x in payload.get("neighbors") or []]
        obj.arp = [ArpEntry.from_dict(x) if isinstance(x, dict) else x for x in payload.get("arp") or []]
        obj.fdb = [FdbEntry.from_dict(x) if isinstance(x, dict) else x for x in payload.get("fdb") or []]
        obj.routes = [Route.from_dict(x) if isinstance(x, dict) else x for x in payload.get("routes") or []]
        return obj


@dataclass
class Link:
    id: str
    src_device: str
    dst_device: str
    src_interface: str | None = None
    dst_interface: str | None = None
    kind: str = "ethernet"
    speed_mbps: int | None = None
    confidence: float = 0.9
    derived_from: str = "lldp"
    redundant_group: str | None = None  # shared LAG / parallel-path grouping key
    protected: bool = False
    carries: list[str] = field(default_factory=list)  # VLANs / traffic classes
    risk_score: float = 0.0
    is_spof: bool = False

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Link":
        return cls(**_filter_fields(cls, data))

    def endpoints(self) -> tuple[str, str]:
        return self.src_device, self.dst_device


@dataclass
class Zone:
    name: str
    cidrs: list[str] = field(default_factory=list)
    vlans: list[int] = field(default_factory=list)
    trust: str = "internal"
    description: str | None = None
    default_gateway: str | None = None
    segmentation_enforced: bool = True
    segmentation_note: str | None = None
    device_count: int = 0

    def owns_ip(self, ip: str | None) -> bool:
        from .util import cidr_contains

        if not ip:
            return False
        return cidr_contains(self.cidrs, ip)

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Zone":
        return cls(**_filter_fields(cls, data))


@dataclass
class Finding:
    id: str
    rule_id: str
    rule_title: str
    severity: str = "medium"
    score: float = 0.0
    scope: str = "device"  # device | link | zone | network
    target_id: str | None = None
    target_label: str | None = None
    description: str = ""
    impact: str | None = None
    likelihood: str | None = None
    remediation: str | None = None
    evidence: list[dict] = field(default_factory=list)
    refs: dict = field(default_factory=dict)  # {cis, nist, cwe, attack, cvss}
    status: str = "open"  # open | accepted | suppressed
    status_note: str | None = None
    first_seen: str | None = None
    device_type: str | None = None
    zone: str | None = None
    criticality: int = 2
    exposed: bool = False
    confidence: float = 1.0
    rule_version: str = "1"
    fingerprint: str | None = None  # stable dedupe key across scans

    @property
    def sort_key(self) -> tuple:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return (-self.score, order.get(self.severity, 9), self.target_label or "", self.rule_id)

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(**_filter_fields(cls, data))


@dataclass
class ScanError:
    stage: str
    target: str | None = None
    message: str = ""

    def to_dict(self) -> dict:
        return dataclass_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanError":
        return cls(**_filter_fields(cls, data))


@dataclass
class ScanSnapshot:
    """A complete, self-describing result of one discovery + analysis pass."""

    snapshot_id: str = ""
    scanner_version: str = ""
    schema_version: str = SCHEMA_VERSION
    mode: str = "live"  # live | lab | import
    operator: str | None = None
    started: str | None = None
    finished: str | None = None
    duration_seconds: float | None = None
    targets: list[str] = field(default_factory=list)
    authorization: dict = field(default_factory=dict)
    config: dict = field(default_factory=dict)
    devices: list[Device] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    zones: list[Zone] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    counters: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    risk: dict = field(default_factory=dict)
    drift: dict | None = None
    notes: list[str] = field(default_factory=list)

    # -- indexes ------------------------------------------------------------
    def device_map(self) -> dict[str, Device]:
        return {d.id: d for d in self.devices}

    def find_device(self, key: str | None) -> Device | None:
        if not key:
            return None
        key = key.strip()
        for dev in self.devices:
            if key in (dev.id, dev.ip, dev.hostname, dev.mac):
                return dev
        for dev in self.devices:
            if dev.hostname and fnmatch.fnmatch(dev.hostname.lower(), key.lower()):
                return dev
            if key.lower() in (dev.id or "").lower():
                return dev
        return None

    def devices_by(self, **kw: Any) -> list[Device]:
        out = []
        for dev in self.devices:
            ok = True
            for k, v in kw.items():
                actual = getattr(dev, k, None)
                if isinstance(v, (list, tuple, set)):
                    ok = ok and actual in v
                else:
                    ok = ok and actual == v
            if ok:
                out.append(dev)
        return out

    @property
    def open_devices(self) -> list[Device]:
        return [d for d in self.devices if d.reachable]

    # -- serialisation ------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "scanner_version": self.scanner_version,
            "schema_version": self.schema_version,
            "mode": self.mode,
            "operator": self.operator,
            "started": self.started,
            "finished": self.finished,
            "duration_seconds": self.duration_seconds,
            "targets": self.targets,
            "authorization": self.authorization,
            "config": self.config,
            "zones": [z.to_dict() for z in self.zones],
            "devices": [d.to_dict() for d in self.devices],
            "links": [l.to_dict() for l in self.links],
            "findings": [f.to_dict() for f in self.findings],
            "errors": [e.to_dict() for e in self.errors],
            "counters": self.counters,
            "summary": self.summary,
            "risk": self.risk,
            "drift": self.drift,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanSnapshot":
        nested = {"devices", "links", "zones", "findings", "errors"}
        snap = cls(**_filter_fields(cls, {k: v for k, v in data.items() if k not in nested}))
        snap.zones = [Zone.from_dict(x) for x in data.get("zones") or [] if isinstance(x, dict)]
        snap.devices = [Device.from_dict(x) for x in data.get("devices") or [] if isinstance(x, dict)]
        snap.links = [Link.from_dict(x) for x in data.get("links") or [] if isinstance(x, dict)]
        snap.findings = [Finding.from_dict(x) for x in data.get("findings") or [] if isinstance(x, dict)]
        snap.errors = [ScanError.from_dict(x) for x in data.get("errors") or [] if isinstance(x, dict)]
        return snap

    def validate(self) -> list[str]:
        """Cheap consistency checks; surfaces corruption early."""
        problems: list[str] = []
        ids = [d.id for d in self.devices]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            problems.append(f"duplicate device ids: {sorted(dupes)}")
        for d in self.devices:
            if d.ip and not is_ip(d.ip):
                problems.append(f"{d.id}: ip is not an IP address ({d.ip})")
            for n in d.neighbors:
                if n.remote_key and n.remote_key not in ids and self.find_device(n.remote_key) is None:
                    problems.append(f"{d.id}: neighbor {n.remote_key} has no matching device")
        known = set(ids)
        for l in self.links:
            for side in (l.src_device, l.dst_device):
                if side not in known:
                    problems.append(f"link {l.id} references unknown device {side}")
        return problems


def device_id_for(ip: str | None, hostname: str | None = None) -> str:
    """Deterministic device key: prefer IP, else hostname slug."""
    ip = norm_ip(ip)
    if ip and is_ip(ip):
        return f"ip:{ip}"
    if hostname:
        return f"host:{str(hostname).lower().strip()}"
    return "unknown"


def merge_devices(target: Device, other: Device) -> Device:
    """Fold two views of the same host (e.g. ARP row + SNMP result) together."""
    for f in dataclasses.fields(Device):
        if f.name in {"id", "ip", "hostname"}:
            continue
        cur = getattr(target, f.name)
        new = getattr(other, f.name)
        if new in (None, "", [], {}, 0) or cur == new:
            continue
        if isinstance(f.type, str) and f.type.startswith("list"):
            if isinstance(cur, list) and isinstance(new, list):
                target_keys = {getattr(x, "port", None) or getattr(x, "name", None) or getattr(x, "mac", None) for x in cur}
                for item in new:
                    key = getattr(item, "port", None) or getattr(item, "name", None) or getattr(item, "mac", None)
                    if key not in target_keys:
                        cur.append(item)
                        target_keys.add(key)
                continue
        if cur in (None, "", [], {}):
            setattr(target, f.name, new)
    target.reachable = target.reachable or other.reachable
    if other.discovery_sources:
        target.discovery_sources = sorted(set(target.discovery_sources) | set(other.discovery_sources))
    return target


def summarize_devices(devices: Iterable[Device]) -> dict:
    devices = list(devices)
    types: dict[str, int] = {}
    for d in devices:
        types[d.device_type] = types.get(d.device_type, 0) + 1
    return {
        "total": len(devices),
        "reachable": sum(1 for d in devices if d.reachable),
        "documented": sum(1 for d in devices if d.documented),
        "undocumented": sum(1 for d in devices if not d.documented),
        "undocumented_pct": round(100.0 * sum(1 for d in devices if not d.documented) / max(1, len(devices)), 1),
        "exposed_to_wan": sum(1 for d in devices if d.exposed_to_wan),
        "with_eol": sum(1 for d in devices if d.os_eol),
        "by_type": dict(sorted(types.items(), key=lambda kv: (-kv[1], kv[0]))),
        "ports_open": sorted({p for d in devices for p in d.open_ports}),
        "ips": sorted_ips([d.ip for d in devices if d.ip]),
    }


def is_blank(value: Any) -> bool:
    return value in (None, "", [], {}, set())


__all__ = [
    "ArpEntry",
    "Certificate",
    "Device",
    "Finding",
    "FdbEntry",
    "Interface",
    "Link",
    "Neighbor",
    "Route",
    "ScanError",
    "ScanSnapshot",
    "Service",
    "Zone",
    "device_id_for",
    "merge_devices",
    "parse_mac",
    "summarize_devices",
    "SCHEMA_VERSION",
    "DEVICE_TYPES",
    "SEVERITIES",
    "TRUST_LEVELS",
]
