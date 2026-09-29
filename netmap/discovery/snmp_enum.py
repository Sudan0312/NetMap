"""SNMP-driven device enumeration: system, interfaces, neighbours, ARP, FDB,
routes, VLANs and governance facts.

Every walk is individually guarded: a device that answers sysDescr but aborts
on a private MIB must still produce a usable record.
"""

from __future__ import annotations

import logging
from typing import Any

from ..models import ArpEntry, Device, FdbEntry, Interface, Neighbor, Route
from ..protocols import mibs
from ..protocols.snmp import Credentials, SNMPClient, SNMPError, SNMPTimeout
from ..util import parse_mac

log = logging.getLogger("netmap.snmp_enum")

STATUS = mibs.STATUS_TEXT
IF_TYPE = mibs.IF_TYPES


def _safe(client: SNMPClient, oids: list[str]) -> dict[str, Any]:
    try:
        return client.get(oids)
    except (SNMPError, SNMPTimeout, OSError) as exc:
        log.debug("get %s failed: %s", oids, exc)
        return {}


def _walk(client: SNMPClient, base: str, max_rows: int) -> list[tuple[str, Any]]:
    try:
        return client.bulk_walk(base, max_rows=max_rows) or client.walk(base, max_rows=max_rows)
    except (SNMPError, SNMPTimeout, OSError) as exc:
        log.debug("walk %s failed: %s", base, exc)
        return []


def _s(value: Any) -> str | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace").strip() or None
    if isinstance(value, (int, float)):
        return str(int(value))
    return str(value).strip() if value not in (None, "") else None


def _ip_from_octets(value: Any) -> str | None:
    if isinstance(value, (bytes, bytearray)) and len(value) == 4:
        return ".".join(str(b) for b in value)
    if isinstance(value, str) and value.count(".") == 3:
        return value
    return None


def read_system(client: SNMPClient) -> dict[str, Any]:
    oids = [
        mibs.SYS_DESCR,
        mibs.SYS_OBJECT_ID,
        mibs.SYS_UPTIME,
        mibs.SYS_CONTACT,
        mibs.SYS_NAME,
        mibs.SYS_LOCATION,
        mibs.SYS_SERVICES,
    ]
    raw = _safe(client, oids)
    ent = ""
    obj = _s(raw.get(mibs.SYS_OBJECT_ID)) or ""
    if obj.startswith("1.3.6.1.4.1."):
        ent = obj.split(".")[4]
    return {
        "sys_descr": _s(raw.get(mibs.SYS_DESCR)),
        "sys_object_id": obj or None,
        "enterprise": ent or None,
        "uptime_ticks": raw.get(mibs.SYS_UPTIME) if isinstance(raw.get(mibs.SYS_UPTIME), int) else None,
        "sys_contact": _s(raw.get(mibs.SYS_CONTACT)),
        "sys_name": _s(raw.get(mibs.SYS_NAME)),
        "sys_location": _s(raw.get(mibs.SYS_LOCATION)),
        "sys_services": raw.get(mibs.SYS_SERVICES),
    }


def read_interfaces(client: SNMPClient, *, max_rows: int = 600) -> list[Interface]:
    """IF-MIB ifTable + ifXTable + ipAdEntTable, keyed by ifIndex."""
    rows: dict[int, Interface] = {}

    def row(index: int) -> Interface:
        return rows.setdefault(index, Interface(if_index=index))

    simple = (
        (mibs.IF_TYPE, "type", lambda v: IF_TYPE.get(int(v or 0), str(v))),
        (mibs.IF_MTU, "mtu", lambda v: int(v) if str(v).isdigit() else None),
        (mibs.IF_SPEED, "speed_mbps", _speed_mbps),
        (mibs.IF_PHYS_ADDRESS, "mac", parse_mac),
        (mibs.IF_ADMIN_STATUS, "admin_status", lambda v: STATUS.get(int(v or 0), "unknown")),
        (mibs.IF_OPER_STATUS, "oper_status", lambda v: STATUS.get(int(v or 0), "unknown")),
    )
    for base, attr, conv in simple:
        for oid, value in _walk(client, base, max_rows):
            idx = mibs.oid_index(oid, base)
            if not idx or not idx.isdigit():
                continue
            try:
                setattr(row(int(idx)), attr, conv(value))
            except (TypeError, ValueError) as exc:
                log.debug("ifTable %s row %s: %s", base, idx, exc)
    for base in (mibs.IF_DESCR, mibs.IF_NAME, mibs.IF_ALIAS, mibs.IF_HIGH_SPEED):
        for oid, value in _walk(client, base, max_rows):
            idx = mibs.oid_index(oid, base)
            if not idx or not idx.isdigit():
                continue
            try:
                index = int(idx)
            except ValueError:
                continue
            intf = row(index)
            text = _s(value)
            if base == mibs.IF_DESCR:
                intf.name = intf.name or text
            elif base == mibs.IF_NAME and text:
                intf.name = text  # ifXTable name wins over ifDescr
            elif base == mibs.IF_ALIAS:
                intf.description = text
            elif base == mibs.IF_HIGH_SPEED and str(value).isdigit():
                intf.speed_mbps = max(intf.speed_mbps or 0, int(value) // 1_000_000)
    # ipAdEntIfIndex: addr -> ifIndex, so we learn which interface owns which IP
    for oid, value in _walk(client, mibs.IP_ADENT_IF, max_rows):
        tail = oid[len(mibs.IP_ADENT_IF) + 1 :] if oid.startswith(mibs.IP_ADENT_IF + ".") else ""
        if tail.count(".") == 3 and str(value).isdigit():
            intf = row(int(value))
            if tail not in intf.ips:
                intf.ips.append(tail)
    for base in (mibs.IF_OPER_STATUS, mibs.IF_ADMIN_STATUS):
        pass  # already applied above
    out: list[Interface] = []
    for index in sorted(rows):
        intf = rows[index]
        if not intf.name:
            intf.name = f"if{index}"
        if intf.type in ("softwareLoopback", "loopback"):
            intf.role = "loopback"
        elif intf.type in ("l3ipvlan", "l2vlan"):
            intf.role = "vlan"
            digits = "".join(ch for ch in (intf.name or "") if ch.isdigit())
            intf.vlan = int(digits) if digits else None
        elif "portchannel" in (intf.name or "").lower() or "po" == (intf.name or "").split("-")[0].lower():
            intf.role = "lag"
        elif intf.speed_mbps and intf.speed_mbps >= 1000:
            intf.role = "uplink"
        elif intf.ips:
            intf.role = "routed"
        else:
            intf.role = "access"
        out.append(intf)
    return out


def _speed_mbps(value: Any) -> int | None:
    """ifSpeed/ifHighSpeed are bits per second; return whole Mbps."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    if v <= 0 or v > 4294967295:
        return None
    return (v // 1_000_000) or None


def read_arp(client: SNMPClient, *, max_rows: int = 600) -> list[ArpEntry]:
    phys: dict[str, Any] = {}
    ips: dict[str, Any] = {}
    ifaces: dict[str, Any] = {}
    types: dict[str, Any] = {}
    for base, dest in ((mibs.IP_NET_TO_MEDIA_PHYS, phys), (mibs.IP_NET_TO_MEDIA_IP, ips), (mibs.IP_NET_TO_MEDIA_IF, ifaces), (mibs.IP_NET_TO_MEDIA_TYPE, types)):
        for oid, value in _walk(client, base, max_rows):
            idx = mibs.oid_index(oid, base)
            if idx:
                dest[idx] = value
    entries: list[ArpEntry] = []
    for idx in sorted(ips):
        entry = ArpEntry(
            ip=_ip_from_octets(ips[idx]) or (ips[idx] if isinstance(ips[idx], str) else None),
            mac=parse_mac(phys.get(idx)),
            if_index=int(ifaces[idx]) if str(ifaces.get(idx, "")).isdigit() else None,
            entry_type={1: "other", 2: "invalid", 3: "dynamic", 4: "static", 5: "dynamic"}.get(int(types[idx]), "dynamic") if str(types.get(idx, "")).isdigit() else "dynamic",
        )
        if entry.ip:
            entries.append(entry)
    return entries


def read_fdb(client: SNMPClient, *, max_rows: int = 1500) -> list[FdbEntry]:
    """dot1dTpFdb: MAC -> bridge port; base port table maps bridge port -> ifIndex."""
    macs: dict[str, Any] = {}
    ports: dict[str, Any] = {}
    for oid, value in _walk(client, mibs.DOT1D_TP_FDB_ADDRESS, max_rows):
        idx = mibs.oid_index(oid, mibs.DOT1D_TP_FDB_ADDRESS)
        if idx and len(idx.split(".")) == 6:
            try:
                macs[idx] = ":".join(f"{int(p):02x}" for p in idx.split("."))
            except ValueError:
                continue
    for oid, value in _walk(client, mibs.DOT1D_TP_FDB_PORT, max_rows):
        idx = mibs.oid_index(oid, mibs.DOT1D_TP_FDB_PORT)
        if idx:
            ports[idx] = value
    port_if: dict[str, Any] = {}
    for oid, value in _walk(client, mibs.DOT1D_BASE_PORT_IF, max_rows // 2):
        idx = mibs.oid_index(oid, mibs.DOT1D_BASE_PORT_IF)
        if idx:
            port_if[idx] = value
    out: list[FdbEntry] = []
    for idx, mac in macs.items():
        bridge_port = ports.get(idx)
        if not str(bridge_port).isdigit():
            continue
        if_index = port_if.get(str(bridge_port))
        out.append(
            FdbEntry(
                mac=mac,
                if_index=int(if_index) if str(if_index).isdigit() else None,
                port=str(bridge_port),
                entry_type="dynamic",
            )
        )
    return out


def read_routes(client: SNMPClient, *, max_rows: int = 400) -> list[Route]:
    dests: dict[str, Any] = {}
    nexts: dict[str, Any] = {}
    ifs: dict[str, Any] = {}
    types: dict[str, Any] = {}
    protos: dict[str, Any] = {}
    for base, dest in (
        (mibs.IP_ROUTE_DEST, dests),
        (mibs.IP_ROUTE_NEXT_HOP, nexts),
        (mibs.IP_ROUTE_IF, ifs),
        (mibs.IP_ROUTE_TYPE, types),
        (mibs.IP_ROUTE_PROTO, protos),
    ):
        for oid, value in _walk(client, base, max_rows):
            idx = mibs.oid_index(oid, base)
            if idx:
                dest[idx] = value
    out: list[Route] = []
    for idx in sorted(dests):
        dest = dests[idx]
        entry = Route(
            dest=_ip_from_octets(dest) or (dest if isinstance(dest, str) else None),
            next_hop=_ip_from_octets(nexts.get(idx)) or (nexts.get(idx) if isinstance(nexts.get(idx), str) else None),
            if_index=int(ifs[idx]) if str(ifs.get(idx, "")).isdigit() else None,
            type={1: "other", 2: "invalid", 3: "direct", 4: "indirect", 5: "address", 6: "cached"}.get(int(types[idx]), "other") if str(types.get(idx, "")).isdigit() else "other",
            protocol={1: "other", 2: "local", 3: "netmgmt", 4: "icmp", 5: "egp", 6: "iso10747", 7: "ospf", 8: "isis", 9: "esi", 10: "nlsp", 11: "bgp", 12: "static"}.get(int(protos[idx]), "unknown") if str(protos.get(idx, "")).isdigit() else "unknown",
        )
        if entry.dest or entry.next_hop:
            out.append(entry)
    return out


def read_vlans(client: SNMPClient, *, max_rows: int = 200) -> dict[int, str]:
    out: dict[int, str] = {}
    for oid, value in _walk(client, mibs.DOT1Q_VLAN_NAME, max_rows):
        idx = mibs.oid_index(oid, mibs.DOT1Q_VLAN_NAME)
        if idx and idx.isdigit():
            out[int(idx)] = _s(value) or f"vlan{idx}"
    return out


def read_neighbors(client: SNMPClient, *, max_rows: int = 400) -> list[Neighbor]:
    """Prefer LLDP-MIB; fall back to CISCO-CDP-MIB."""
    neighbors = _read_lldp(client, max_rows=max_rows)
    if not neighbors:
        neighbors = _read_cdp(client, max_rows=max_rows)
    return neighbors


def _read_lldp(client: SNMPClient, *, max_rows: int) -> list[Neighbor]:
    cols: dict[str, dict[str, Any]] = {"chassis": {}, "port": {}, "desc": {}, "name": {}, "descr": {}}
    mapping = {
        "chassis": mibs.LLDP_REM_CHASSIS_ID,
        "port": mibs.LLDP_REM_PORT_ID,
        "name": mibs.LLDP_REM_SYS_NAME,
        "desc": mibs.LLDP_REM_PORT_DESC,
        "descr": mibs.LLDP_REM_SYS_DESC,
    }
    local_ports: dict[str, str] = {}
    for oid, value in _walk(client, mibs.LLDP_LOC_PORT_ID, max_rows):
        idx = mibs.oid_index(oid, mibs.LLDP_LOC_PORT_ID)
        if idx:
            local_ports[idx] = _s(value) or ""
    for key, base in mapping.items():
        for oid, value in _walk(client, base, max_rows):
            idx = mibs.oid_index(oid, base)
            if idx:
                cols[key][idx] = value
    out: list[Neighbor] = []
    for idx in sorted(cols["name"]):
        parts = idx.split(".")
        local_port_num = parts[1] if len(parts) > 2 else parts[0]
        chassis = cols["chassis"].get(idx)
        remote_mac = parse_mac(chassis) if isinstance(chassis, (bytes, bytearray)) else None
        name = _s(cols["name"].get(idx))
        port = _s(cols["port"].get(idx))
        if isinstance(cols["port"].get(idx), (bytes, bytearray)):
            port = port or parse_mac(cols["port"].get(idx))
        remote_ip = None
        raw_ip = cols["chassis"].get(idx)
        if isinstance(raw_ip, str) and raw_ip.count(".") == 3:
            remote_ip = raw_ip
        out.append(
            Neighbor(
                via="lldp",
                local_if=local_ports.get(local_port_num) or local_port_num,
                local_if_index=int(local_port_num) if local_port_num.isdigit() else None,
                remote_key=remote_ip or name,
                remote_system=name,
                remote_port=port if isinstance(port, str) else None,
                remote_chassis_id=remote_mac or (_s(raw_ip) if raw_ip is not None else None),
                remote_mac=remote_mac,
                remote_ip=remote_ip,
                remote_description=_s(cols["descr"].get(idx)),
                confidence=0.9,
            )
        )
    return out


def _read_cdp(client: SNMPClient, *, max_rows: int) -> list[Neighbor]:
    fields = {
        "addr": mibs.CDP_CACHE_ADDR,
        "dev": mibs.CDP_CACHE_DEV_ID,
        "port": mibs.CDP_CACHE_DEV_PORT,
        "caps": mibs.CDP_CACHE_CAP,
        "platform": mibs.CDP_CACHE_PLATFORM,
        "version": mibs.CDP_CACHE_VERSION,
    }
    rows: dict[str, dict[str, Any]] = {}
    for key, base in fields.items():
        for oid, value in _walk(client, base, max_rows):
            idx = mibs.oid_index(oid, base)
            if idx:
                rows.setdefault(idx, {})[key] = value
    out: list[Neighbor] = []
    for idx, row in sorted(rows.items()):
        parts = idx.split(".")
        local_if_index = int(parts[0]) if parts and parts[0].isdigit() else None
        caps_bits = row.get("caps") if isinstance(row.get("caps"), int) else 0
        caps = [name for bit, name in ((0x01, "router"), (0x02, "switch"), (0x04, "bridge"), (0x08, "wlan"), (0x40, "server")) if caps_bits & bit]
        remote_ip = _ip_from_octets(row.get("addr"))
        dev = _s(row.get("dev"))
        out.append(
            Neighbor(
                via="cdp",
                local_if=f"if{local_if_index}" if local_if_index else None,
                local_if_index=local_if_index,
                remote_key=remote_ip or dev,
                remote_system=dev,
                remote_port=_s(row.get("port")),
                remote_ip=remote_ip,
                remote_description=_s(row.get("version")) or _s(row.get("platform")),
                capabilities=caps,
                confidence=0.9,
            )
        )
    return out


def read_governance(client: SNMPClient, *, max_rows: int = 300) -> dict[str, Any]:
    """Config hygiene facts a read-only community can still reveal."""
    facts: dict[str, Any] = {}
    sw: dict[str, str] = {}
    for oid, value in _walk(client, mibs.HR_SW_NAME, max_rows):
        idx = mibs.oid_index(oid, mibs.HR_SW_NAME)
        if idx:
            sw[idx] = (_s(value) or "").lower()
    names = " ".join(sw.values())
    if sw:
        facts["running_processes"] = sorted({n for n in sw.values() if n})[:40]
        for token, key in (
            ("ntpd", "ntp"),
            ("chronyd", "ntp"),
            ("systemd-timesyncd", "ntp"),
            ("rsyslog", "syslog"),
            ("syslog-ng", "syslog"),
            ("snmptrap", "snmp_traps"),
            ("auditd", "audit"),
            ("sssd", "central_auth"),
            ("winrm", "winrm"),
            ("rpcbind", "rpcbind"),
            ("xinetd", "xinetd"),
            ("telnetd", "telnetd"),
            ("ftpd", "ftpd"),
            ("docker", "container_runtime"),
        ):
            if token in names:
                facts[key] = True
    disk: dict[str, int] = {}
    for oid, value in _walk(client, NETSNMP_DSK, 200):
        idx = mibs.oid_index(oid, NETSNMP_DSK)
        if idx and str(value).isdigit():
            disk[idx] = int(value)
    if disk:
        worst = max(disk.values())
        facts["max_disk_used_pct"] = worst
        facts["disk_full"] = worst >= 90
    for base, key, limit in ((NETSNMP_CPU, "cpu_5m", None),):
        rows = _walk(client, base, 6)
        vals = [v for _, v in rows if str(v).replace(".", "").isdigit()]
        if vals:
            try:
                facts[key] = round(float(vals[0]) / 100, 1)
            except (TypeError, ValueError):
                pass
    return facts


NETSNMP_DSK = "1.3.6.1.4.1.2021.9.1.10"
NETSNMP_CPU = "1.3.6.1.4.1.2021.10.1.3.1"
NETSNMP_OS_RELEASE = "1.3.6.1.4.1.2021.4.6.0"
NETSNMP_OS_VERSION = "1.3.6.1.4.1.2021.4.5.0"


def enumerate_device(
    host: str,
    creds: Credentials,
    *,
    port: int = 161,
    timeout: float = 1.2,
    retries: int = 1,
    max_rows: int = 600,
    want: set[str] | None = None,
) -> dict[str, Any]:
    """Read everything the configured `enumerate` list asks for."""
    want = want or {"system", "interfaces", "neighbors", "arp", "fdb", "routes", "vlans", "governance"}
    result: dict[str, Any] = {
        "snmp": {
            "version": creds.version,
            "community_used": _mask(creds.community),
            "readable": True,
            "default_community": is_default_community(creds.community),
        }
    }
    problems: list[str] = []
    with SNMPClient(host, creds=creds, port=port, timeout=timeout, retries=retries) as client:
        if "system" in want:
            sysinfo = read_system(client)
            result["snmp"].update(sysinfo)
            if sysinfo.get("sys_descr"):
                result["sys_descr"] = sysinfo["sys_descr"]
            if sysinfo.get("sys_name"):
                result["hostname"] = sysinfo["sys_name"]
            if sysinfo.get("sys_location"):
                result["location"] = sysinfo["sys_location"]
            if sysinfo.get("sys_contact"):
                result["snmp"]["sys_contact"] = sysinfo["sys_contact"]
            ticks = sysinfo.get("uptime_ticks")
            if ticks:
                result["uptime_seconds"] = ticks / 100.0
        if "interfaces" in want:
            result["interfaces"] = read_interfaces(client, max_rows=max_rows)
        if "arp" in want:
            result["arp"] = read_arp(client, max_rows=max_rows)
        if "fdb" in want:
            result["fdb"] = read_fdb(client, max_rows=max_rows)
        if "routes" in want:
            result["routes"] = read_routes(client, max_rows=max_rows)
        if "vlans" in want:
            try:
                result["vlans"] = read_vlans(client)
            except (SNMPError, SNMPTimeout) as exc:
                problems.append(f"vlans: {exc}")
        if "neighbors" in want:
            result["neighbors"] = read_neighbors(client, max_rows=max_rows)
        if "governance" in want:
            result["config"] = read_governance(client, max_rows=300)
        result["snmp"]["last_rtt_ms"] = client.last_rtt_ms
        result["snmp"]["requests"] = client.requests
        result["snmp"]["timeouts"] = client.timeouts
    if problems:
        result["snmp"]["problems"] = problems
    return result


# Communities that ship enabled on real gear. Kept here (not in the rules) so the
# engine can record a boolean and the report can stay masked.
DEFAULT_COMMUNITIES = (
    "public",
    "private",
    "manager",
    "cisco",
    "community",
    "read-only",
    "readwrite",
    "admin",
    "monitor",
)


def is_default_community(community: str | None) -> bool:
    """True when the accepted string is a factory/guessable community name."""
    if not community:
        return False
    value = str(community).strip().lower()
    # a <=4 character community is guessable by definition, even if not a vendor default
    return value in DEFAULT_COMMUNITIES or len(value) <= 4


def _mask(community: str | None) -> str:
    """Never persist a community string in plaintext in reports."""
    if not community:
        return ""
    if len(community) <= 2:
        return "*" * len(community)
    return community[0] + "*" * (len(community) - 2) + community[-1]


def enumerate_with_credentials(
    host: str,
    creds: Credentials,
    *,
    communities_tested: list[str] | None = None,
    **kw: Any,
) -> dict[str, Any]:
    data = enumerate_device(host, creds, **kw)
    data["snmp"]["communities_tested"] = [_mask(c) for c in communities_tested or []]
    return data


__all__ = [
    "enumerate_device",
    "enumerate_with_credentials",
    "read_system",
    "read_interfaces",
    "read_arp",
    "read_fdb",
    "read_routes",
    "read_vlans",
    "read_neighbors",
    "read_governance",
]
