"""Synthetic enterprise network (lab mode).

Real discovery needs real gear, so the same pipeline must also be provable
offline. `build_devices()` produces a defensible mid-size campus: dual firewalls,
VPC core, distribution/access layers, a server farm, storage, an OT/IoT
population, plus the mistakes that audits actually find (telnet on switches,
`public` SNMP, EOL NX-OS, an unauthenticated Docker socket, a rogue DHCP
server, a duplicate-IP pair, expired certs, a single uplink on a floor switch).

Deterministic: same seed -> same snapshot, which is what makes the report and
rule tests meaningful.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from ..models import (
    ArpEntry,
    Certificate,
    Device,
    FdbEntry,
    Interface,
    Neighbor,
    Route,
    Service,
    Zone,
    device_id_for,
)
from ..util import iso, now_utc, parse_mac


@dataclass
class Spec:
    ip: str
    hostname: str
    device_type: str = "unknown"
    vendor: str | None = None
    model: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    sys_descr: str | None = None
    zone: str = "core"
    criticality: int = 2
    role: str | None = None
    tags: list[str] = field(default_factory=list)
    documented: bool = True
    snmp: dict | None = None
    sys_uptime: float | None = None
    services: list[dict] = field(default_factory=list)
    neighbours: list[dict] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)
    vlan: int | None = None
    exposed_to_wan: bool = False
    config: dict = field(default_factory=dict)
    mac: str | None = None
    arp: list[dict] = field(default_factory=list)
    fdb: list[dict] = field(default_factory=list)
    inventory: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _svc(port: int, *, proto: str = "tcp", state: str = "open", product: str | None = None, version: str | None = None, banner: str | None = None, encryption: str | None = None, http: dict | None = None, config: dict | None = None, cert: dict | None = None, name: str | None = None) -> dict:
    out = {"port": port, "protocol": proto, "state": state, "product": product, "version": version, "banner": banner, "encryption": encryption, "http": http, "config": config or {}, "certificate": cert, "name": name}
    return out


def _cert(*, cn: str, issuer: str = "Contoso Internal CA", self_signed: bool = False, days_left: float = 400.0, protocol: str = "TLSv1.2", cipher: str = "ECDHE-RSA-AES256-GCM-SHA384", bits: int = 256, key_bits: int = 2048, san: list[str] | None = None, match: bool = True) -> dict:
    from datetime import timedelta

    stamp = (now_utc() + timedelta(days=days_left)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "subject_cn": cn,
        "issuer_cn": issuer,
        "self_signed": self_signed,
        "not_after": stamp,
        "days_left": round(days_left, 1),
        "san": san or [cn],
        "hostname_match": match,
        "protocol": protocol,
        "cipher": cipher,
        "bits": bits,
        "key_bits": key_bits,
    }


def _http(*, server: str = "nginx", status: int = 200, admin: list[str] | None = None, leaks: list[str] | None = None, headers: dict | None = None, hsts: bool = False) -> dict:
    headers = {"server": server}
    if hsts:
        headers["strict-transport-security"] = "max-age=31536000"
    return {
        "status": status,
        "headers": headers,
        "security_headers": {"hsts": hsts, "frame_options": False, "csp": False, "nosniff": False},
        "exposed_admin_paths": admin or [],
        "leaks": leaks or [],
        "paths": {},
    }


def _nbr(remote: str, local_if: str, remote_if: str, *, via: str = "lldp", remote_ip: str | None = None, system: str | None = None, confidence: float = 0.95) -> dict:
    return {"via": via, "local_if": local_if, "remote_key": remote_ip or remote, "remote_system": system or remote, "remote_port": remote_if, "remote_ip": remote_ip, "confidence": confidence}


def build_specs(size: str = "medium", *, seed: int = 7, include_risks: bool = True) -> list[Spec]:
    rng = random.Random(seed)
    specs: list[Spec] = []

    # ---------------------------------------------------------------- perimeter
    panos_bad = Spec(
        ip="10.0.0.1",
        hostname="fw-edge-01",
        device_type="firewall",
        vendor="palo-alto",
        model="PA-3220",
        os_family="panos",
        os_version="9.1.3",
        sys_descr="Palo Alto Networks PA-3220 serial 01550001234, PAN-OS 9.1.3",
        zone="wan-edge",
        criticality=5,
        role="perimeter",
        exposed_to_wan=True,
        tags=["perimeter", "nw", "change-window-required"],
        snmp={"readable": True, "version": "v2c", "community_used": "p****c", "default_community": True, "sys_descr": "Palo Alto Networks PA-3220, PAN-OS 9.1.3"},
        sys_uptime=86400 * 240,
        interfaces=[
            {"name": "ethernet1/1", "if_index": 1, "description": "ISP-A transit", "speed_mbps": 1000, "oper_status": "up", "role": "wan", "ips": ["198.51.100.6"]},
            {"name": "ethernet1/2", "if_index": 2, "description": "core peerlink", "speed_mbps": 10000, "oper_status": "up", "role": "uplink"},
            {"name": "management", "if_index": 3, "description": "OOB", "speed_mbps": 1000, "oper_status": "up", "role": "management", "ips": ["10.0.0.1"]},
        ],
        services=[
            _svc(443, product="PAN-OS WebUI", encryption="tls", cert=_cert(cn="fw-edge-01.contoso.example", self_signed=True, days_left=-14, protocol="TLSv1.2", match=False, san=["pan-3220.local"])),
            _svc(22, product="OpenSSH", version="8.2", encryption="ssh", banner="SSH-2.0-OpenSSH_8.2"),
            _svc(500, proto="udp", product="IKE"),
            _svc(4500, proto="udp", product="IPsec NAT-T"),
        ],
        routes=[{"dest": "0.0.0.0/0", "next_hop": "198.51.100.1", "protocol": "static", "if_index": 1}],
        neighbours=[_nbr("core-sw-01", "ethernet1/2", "Ethernet1/1", remote_ip="10.0.1.1"), _nbr("isp-router", "ethernet1/1", "Gi0/0/1", remote_ip="198.51.100.1", system="edge-rtr-isp", confidence=0.5)],
        config={"syslog": False, "ntp": True, "central_auth": False, "antiphish": False},
    )
    panos_good = Spec(
        ip="10.0.0.2",
        hostname="fw-edge-02",
        device_type="firewall",
        vendor="palo-alto",
        model="PA-3220",
        os_family="panos",
        os_version="10.2.3",
        sys_descr="Palo Alto Networks PA-3220 serial 01550009999, PAN-OS 10.2.3",
        zone="wan-edge",
        criticality=5,
        exposed_to_wan=True,
        role="perimeter",
        snmp={"readable": True, "version": "v3", "community_used": "", "default_community": False},
        sys_uptime=86400 * 30,
        interfaces=[
            {"name": "ethernet1/1", "if_index": 1, "description": "ISP-B transit", "speed_mbps": 1000, "oper_status": "up", "role": "wan", "ips": ["198.51.101.6"]},
            {"name": "ethernet1/2", "if_index": 2, "description": "core peerlink", "speed_mbps": 10000, "oper_status": "up", "role": "uplink"},
        ],
        services=[
            _svc(443, product="PAN-OS WebUI", encryption="tls", cert=_cert(cn="fw-edge-02.contoso.example", days_left=210, protocol="TLSv1.3")),
            _svc(22, product="OpenSSH", version="8.8", encryption="ssh", banner="SSH-2.0-OpenSSH_8.8"),
        ],
        routes=[{"dest": "0.0.0.0/0", "next_hop": "198.51.101.1", "protocol": "static", "if_index": 1}],
        neighbours=[_nbr("core-sw-02", "ethernet1/2", "Ethernet1/1", remote_ip="10.0.1.2")],
        config={"syslog": True, "ntp": True, "central_auth": True},
    )
    specs += [panos_bad, panos_good]

    # ---------------------------------------------------------------- core
    for idx, (ip, host) in enumerate((("10.0.1.1", "core-sw-01"), ("10.0.1.2", "core-sw-02"))):
        specs.append(
            Spec(
                ip=ip,
                hostname=host,
                device_type="switch",
                vendor="cisco",
                model="Nexus 9336C",
                os_family="nxos",
                os_version="9.3(8)",
                sys_descr=f"Cisco Nexus Operating System (NX-OS) software, Version 9.3(8), TMS support, {host}",
                zone="core",
                criticality=5,
                role="core",
                snmp={"readable": True, "version": "v2c", "community_used": "c***s", "default_community": False},
                sys_uptime=86400 * (410 - idx * 5),
                interfaces=[
                    {"name": "port-channel1", "if_index": 101, "description": "peerlink vPC", "speed_mbps": 32000, "oper_status": "up", "role": "lag"},
                    {"name": "Ethernet1/1", "if_index": 1, "description": "to fw-edge-0%s e1/2" % (idx + 1), "speed_mbps": 1000, "oper_status": "up", "role": "uplink"},
                    {"name": "Ethernet1/2", "if_index": 2, "description": "dist-sw-01", "speed_mbps": 40000, "oper_status": "up", "role": "uplink"},
                    {"name": "Ethernet1/3", "if_index": 3, "description": "dist-sw-02", "speed_mbps": 40000, "oper_status": "up", "role": "uplink"},
                    {"name": "Vlan110", "if_index": 110, "description": "server farm gateway", "speed_mbps": None, "oper_status": "up", "role": "routed", "ips": ["10.20.110.1"], "type": "l3ipvlan", "vlan": 110},
                ],
                services=[
                    _svc(22, product="OpenSSH", version="7.4", encryption="ssh", banner="SSH-2.0-OpenSSH_7.4"),
                    _svc(161, proto="udp", product="Cisco NX-OS snmpd", banner=""),
                    _svc(443, product="NX-API", encryption="tls", cert=_cert(cn=host + ".contoso.example", self_signed=True, days_left=95)),
                ],
                neighbours=[
                    _nbr("dist-sw-01", "Ethernet1/2", "Ethernet1/51", remote_ip="10.0.2.1"),
                    _nbr("dist-sw-02", "Ethernet1/3", "Ethernet1/51", remote_ip="10.0.2.2"),
                    _nbr("fw-edge-0%s" % (idx + 1), "Ethernet1/1", "ethernet1/2", remote_ip="10.0.0.%s" % (idx + 1)),
                ],
                routes=[{"dest": "0.0.0.0/0", "next_hop": "10.0.0.%s" % (idx + 1), "protocol": "static", "if_index": 1}],
                config={"syslog": True, "ntp": True, "central_auth": True},
                arp=[{"ip": f"10.20.110.{i}", "mac": f"00:50:56:aa:bb:{i:02x}"} for i in range(1, 9)],
            )
        )

    # ---------------------------------------------------------------- distribution
    for idx, (ip, host) in enumerate((("10.0.2.1", "dist-sw-01"), ("10.0.2.2", "dist-sw-02"))):
        risky = include_risks and idx == 0
        specs.append(
            Spec(
                ip=ip,
                hostname=host,
                device_type="switch",
                vendor="cisco",
                model="Catalyst 9300",
                os_family="ios",
                os_version="15.2(4)E7" if idx else "16.6.7",
                sys_descr=f"Cisco IOS Software, Catalyst 9300 Software (C9300-UNIVERSALK9-M), Version 16.6.7, RELEASE SOFTWARE, {host}" if idx else "Cisco IOS Software, C3750E Software (C3750E-UNIVERSAL9-M), Version 15.2(4)E7, RELEASE SOFTWARE, " + host,
                zone="core",
                criticality=4,
                role="distribution",
                snmp={"readable": True, "version": "v2c", "community_used": "p****c", "default_community": risky},
                sys_uptime=86400 * (60 if idx else 44),
                interfaces=[
                    {"name": "Port-channel1", "if_index": 1, "description": "core", "speed_mbps": 40000, "oper_status": "up", "role": "lag"},
                    {"name": "GigabitEthernet1/0/1", "if_index": 101, "description": "floor-1 uplink", "speed_mbps": 1000, "oper_status": "up", "role": "uplink"},
                ],
                services=[
                    _svc(22, product="OpenSSH", version="7.4", encryption="ssh", banner="SSH-2.0-Cisco-1.25"),
                    _svc(161, proto="udp", product="Cisco IOS snmpd"),
                    *([_svc(23, product="Cisco Telnet", banner="User Access Verification\r\n", encryption="none", name="telnet"),
                       _svc(69, proto="udp", product="IOS TFTP", name="tftp", encryption="none"),
                       _svc(80, product="Cisco Web UI", banner="HTTP/1.1 200 OK\r\nServer: Cisco-HTTPD/1.0\r\n\r\n", encryption="none", name="http", http=_http(server="Cisco-HTTPD/1.0", admin=["/login"]), config={"weak": True})] if risky else []),
                ],
                neighbours=[_nbr("core-sw-0%s" % (idx + 1), "Port-channel1", "Ethernet1/2", remote_ip="10.0.1.%s" % (idx + 1)), _nbr("acc-sw-f1-01" if idx == 0 else "acc-sw-f2-01", "GigabitEthernet1/0/1", "GigabitEthernet0/1", remote_ip="10.0.3.1" if idx == 0 else "10.0.3.2")],
                config={"syslog": not risky, "ntp": True, "central_auth": not risky, "snmp_write_community_rw": risky},
                routes=[{"dest": "0.0.0.0/0", "next_hop": "10.0.1.1", "protocol": "ospf", "if_index": 1}],
                arp=[{"ip": "10.0.3.1" if idx == 0 else "10.0.3.2", "mac": "00:1c:b3:aa:0b:01" if idx == 0 else "00:1c:b3:aa:0b:02"}],
            )
        )

    # ---------------------------------------------------------------- access layer
    floors = 2 if size == "small" else (4 if size == "medium" else 7)
    host_rows: list[dict[str, Any]] = []
    for floor in range(1, floors + 1):
        ip = f"10.0.3.{floor}"
        host = f"acc-sw-f{floor}-01"
        single_uplink = include_risks and floor % 2 == 1
        specs.append(
            Spec(
                ip=ip,
                hostname=host,
                device_type="switch",
                vendor="cisco",
                model="Catalyst 2960X" if floor % 2 else "Catalyst 9200",
                os_family="ios",
                os_version="12.2(55)SE12" if floor % 2 else "15.2(7)E3",
                sys_descr="Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE12, RELEASE SOFTWARE (fc2)" if floor % 2 else "Cisco IOS Software, Catalyst 9200 Software, Version 15.2(7)E3",
                zone="access",
                criticality=3,
                role="access",
                vlan=200 + floor,
                snmp={"readable": floor % 2 == 0, "version": "v2c", "community_used": "p****c", "default_community": floor % 2 == 0},
                sys_uptime=86400 * (900 + floor) if floor % 2 else 86400 * 120,
                interfaces=[
                    {"name": "GigabitEthernet0/1", "if_index": 1, "description": f"dist-sw-0{1 if single_uplink else (1 if floor % 2 else 2)}", "speed_mbps": 1000, "oper_status": "up", "role": "uplink"},
                    *[
                        {"name": f"GigabitEthernet0/{10 + p}", "if_index": 10 + p, "description": f"patch panel {floor}.{p}", "speed_mbps": 1000, "oper_status": "up", "role": "access", "vlan": 200 + floor}
                        for p in range(1, 5)
                    ],
                ],
                services=[
                    _svc(22, product="OpenSSH", version="7.4", encryption="ssh", banner="SSH-2.0-Cisco-1.25"),
                    _svc(161, proto="udp", product="Cisco IOS snmpd"),
                    *([_svc(23, product="Cisco Telnet", banner="User Access Verification\r\n", encryption="none", name="telnet")] if include_risks and floor == 1 else []),
                ],
                neighbours=[_nbr("dist-sw-01" if single_uplink else f"dist-sw-0{2 if floor % 2 == 0 else 1}", "GigabitEthernet0/1", "GigabitEthernet1/0/1", remote_ip="10.0.2.1" if single_uplink else "10.0.2.2")],
                config={"syslog": False, "ntp": True, "central_auth": False},
                fdb=[{"mac": f"00:1c:b3:aa:{floor:02x}:{p:02x}", "if_index": 10 + p, "port": str(10 + p), "vlan": 200 + floor} for p in range(1, 5)],
                arp=[{"ip": f"10.30.{floor}.1{p}", "mac": f"00:1c:b3:aa:{floor:02x}:{p:02x}"} for p in range(1, 5)],
            )
        )
        for p in range(1, 5):
            host_rows.append({"ip": f"10.30.{floor}.1{p}", "mac": f"00:1c:b3:aa:{floor:02x}:{p:02x}", "switch": host, "port": f"GigabitEthernet0/{10 + p}", "vlan": 200 + floor, "floor": floor})

    # user workstations (some undocumented)
    for i, row in enumerate(host_rows[: len(host_rows)]):
        undocumented = include_risks and i % 7 == 3
        specs.append(
            Spec(
                ip=row["ip"],
                hostname=None if undocumented else f"ws-{row['floor']}-{i:02d}.contoso.example",
                device_type="workstation",
                vendor="dell" if not undocumented else None,
                model="OptiPlex 7090" if not undocumented else None,
                os_family="windows",
                os_version="10.0.19045" if not undocumented else None,
                zone="access",
                vlan=row["vlan"],
                criticality=1,
                role="endpoint",
                documented=not undocumented,
                mac=row["mac"],
                snmp={"readable": False, "version": None, "community_used": None},
                services=[
                    _svc(135, product="rpc epmap", encryption="none", name="msrpc"),
                    _svc(139, product="netbios-ssn", encryption="none", banner="\x83\x00\x00\x00", name="netbios-ssn"),
                    _svc(445, product="SMB", banner="\x83\x00\x00\x00", encryption="none", name="microsoft-ds"),
                    *([_svc(3389, product="Microsoft Terminal Services", banner="\x03\x00\x00\x13\x0e\xd0", encryption="none", name="ms-wbt-server")] if i % 3 == 0 else []),
                ],
                interfaces=[{"name": "Ethernet0", "if_index": 1, "mac": row["mac"], "speed_mbps": 1000, "oper_status": "up", "role": "access", "ips": [row["ip"]], "vlan": row["vlan"]}],
                tags=[] if undocumented else ["managed", "crowdstrike"],
                notes=[f"learned on {row['switch']} port {row['port']}"] if undocumented else [],
            )
        )

    # ---------------------------------------------------------------- server farm
    specs += [
        Spec(
            ip="10.20.110.11",
            hostname="web-01.contoso.example",
            device_type="web",
            vendor="canonical",
            os_family="linux",
            os_version="5.4.0-150-generic",
            sys_descr="Linux web-01 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux",
            zone="dmz",
            criticality=5,
            role="public web tier",
            exposed_to_wan=True,
            tags=["tier1", "internet-facing", "nginx"],
            snmp={"readable": True, "version": "v2c", "community_used": "n***r", "default_community": False},
            sys_uptime=86400 * 260,
            config={"syslog": True, "ntp": True, "central_auth": False},
            services=[
                _svc(80, product="nginx", version="1.18.0", banner="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", encryption="none", name="http", http=_http(server="nginx/1.18.0", admin=["/admin/", "/phpmyadmin/"], leaks=["/.env"])),
                _svc(443, product="nginx", version="1.18.0", encryption="tls", name="https", cert=_cert(cn="www.contoso.example", days_left=21, protocol="TLSv1.1", cipher="ECDHE-RSA-AES128-SHA", san=["www.contoso.example"], match=True), http=_http(server="nginx/1.18.0", hsts=False)),
                _svc(22, product="OpenSSH", version="8.2p1", encryption="ssh", banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
            ],
            interfaces=[{"name": "ens192", "if_index": 2, "speed_mbps": 10000, "oper_status": "up", "ips": ["10.20.110.11"], "role": "routed", "mac": "00:50:56:aa:bb:0b"}],
            neighbours=[_nbr("core-sw-01", "ens192", "Ethernet1/24", remote_ip="10.0.1.1")],
            routes=[{"dest": "0.0.0.0/0", "next_hop": "10.20.110.1", "protocol": "static", "if_index": 2}],
        ),
        Spec(
            ip="10.20.110.12",
            hostname="app-01.contoso.example",
            device_type="server",
            vendor="canonical",
            os_family="linux",
            os_version="20.04",
            sys_descr="Linux app-01 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux",
            zone="server-farm",
            criticality=4,
            role="application",
            tags=["tier1", "container-host"],
            snmp={"readable": True, "version": "v2c", "community_used": "n***r", "default_community": False},
            sys_uptime=86400 * 95,
            config={"syslog": True, "ntp": True, "container_runtime": True, "running_processes": ["dockerd", "containerd", "rsyslogd", "chronyd"]},
            services=[
                _svc(22, product="OpenSSH", version="8.2p1", encryption="ssh", banner="SSH-2.0-OpenSSH_8.2p1"),
                _svc(2375, product="Docker Engine API", banner='{"ApiVersion":"1.40","Arch":"amd64","KernelVersion":"5.4.0-150-generic","Os":"linux"}\r\n', encryption="none", name="docker-api"),
                _svc(8080, product="Apache Tomcat", version="9.0.37", banner="HTTP/1.1 401 Unauthorized\r\nServer: Apache-Coyote/1.1\r\n\r\n", encryption="none", name="http-proxy", http=_http(server="Apache-Coyote/1.1", admin=["/manager/html"])),
                _svc(6379, product="Redis", banner="-NOAUTH Authentication required.\r\n", encryption="none", name="redis"),
            ],
            interfaces=[{"name": "ens192", "if_index": 2, "speed_mbps": 10000, "oper_status": "up", "ips": ["10.20.110.12"], "role": "routed", "mac": "00:50:56:aa:bb:0c"}],
            neighbours=[_nbr("core-sw-02", "ens192", "Ethernet1/24", remote_ip="10.0.1.2")],
        ),
        Spec(
            ip="10.20.120.21",
            hostname="db-01.contoso.example",
            device_type="database",
            vendor="redhat",
            os_family="linux",
            os_version="8.6",
            sys_descr="Linux db-01 4.18.0-372.9.1.el8.x86_64 x86_64",
            zone="server-farm",
            criticality=5,
            role="database",
            tags=["tier0", "pci"],
            snmp={"readable": False, "version": None, "community_used": None},
            sys_uptime=86400 * 33,
            config={"syslog": True, "ntp": True},
            services=[
                _svc(22, product="OpenSSH", version="8.0", encryption="ssh", banner="SSH-2.0-OpenSSH_8.0"),
                _svc(5432, product="PostgreSQL", banner="E#FATAL 28000 invalid catalog\r\n", encryption="none", name="postgresql"),
                _svc(9021, name="unknown", encryption="none"),
            ],
            interfaces=[{"name": "ens192", "if_index": 2, "speed_mbps": 25000, "oper_status": "up", "ips": ["10.20.120.21"], "role": "routed", "mac": "00:50:56:aa:bb:15"}],
            neighbours=[_nbr("core-sw-01", "ens192", "Ethernet1/25", remote_ip="10.0.1.1")],
        ),
        Spec(
            ip="10.20.110.31",
            hostname="dc-01.contoso.example",
            device_type="directory",
            vendor="microsoft",
            os_family="windows",
            os_version="10.0.17763.4377",
            sys_descr="Microsoft Windows [Version 10.0.17763.4377]",
            zone="server-farm",
            criticality=5,
            role="domain controller",
            tags=["tier0", "identity"],
            snmp={"readable": True, "version": "v2c", "community_used": "p****c", "default_community": True},
            sys_uptime=86400 * 118,
            config={"syslog": False, "ntp": True, "central_auth": False},
            services=[
                _svc(53, product="Microsoft DNS", proto="udp", name="dns", encryption="none"),
                _svc(88, product="Kerberos", name="kerberos-sec", encryption="other"),
                _svc(135, name="msrpc", encryption="none"),
                _svc(389, product="Microsoft Active Directory LDAP", banner="\x30\x81\x84\x02\x01\x63", encryption="none", name="ldap"),
                _svc(445, product="SMB", encryption="none", name="microsoft-ds"),
                _svc(464, name="kpasswd5", encryption="other"),
                _svc(636, product="LDAPS", encryption="tls", name="ldaps", cert=_cert(cn="dc-01.contoso.example", days_left=64, protocol="TLSv1.2")),
                _svc(3268, name="microsoft-gc", encryption="none"),
                _svc(5985, product="WinRM", banner="HTTP/1.1 405\r\nServer: Microsoft-HTTPAPI/2.0\r\nWWW-Authenticate: Negotiate\r\n\r\n", encryption="none", name="wsman", http=_http(server="Microsoft-HTTPAPI/2.0")),
            ],
            interfaces=[{"name": "Ethernet", "if_index": 10, "speed_mbps": 10000, "oper_status": "up", "ips": ["10.20.110.31"], "role": "routed", "mac": "00:50:56:aa:bb:1e"}],
            neighbours=[_nbr("core-sw-01", "Ethernet", "Ethernet1/26", remote_ip="10.0.1.1")],
        ),
        Spec(
            ip="10.20.110.32",
            hostname="dc-02.contoso.example",
            device_type="directory",
            vendor="microsoft",
            os_family="windows",
            os_version="6.3.9600.20999",
            sys_descr="Microsoft Windows [Version 6.3.9600.20999]",
            zone="server-farm",
            criticality=5,
            role="domain controller (legacy)",
            tags=["tier0", "identity", "pending-upgrade"],
            documented=True,
            snmp={"readable": False, "version": None, "community_used": None},
            sys_uptime=86400 * 800,
            config={"syslog": False, "ntp": True},
            services=[
                _svc(53, proto="udp", name="dns", encryption="none"),
                _svc(135, name="msrpc", encryption="none"),
                _svc(139, name="netbios-ssn", encryption="none"),
                _svc(389, name="ldap", encryption="none"),
                _svc(445, name="microsoft-ds", encryption="none"),
                _svc(3389, product="Microsoft Terminal Services", banner="\x03\x00\x00\x13\x0e\xd0\x00", encryption="none", name="ms-wbt-server"),
            ],
            interfaces=[{"name": "Ethernet", "if_index": 10, "speed_mbps": 1000, "oper_status": "up", "ips": ["10.20.110.32"], "role": "routed", "mac": "00:50:56:aa:bb:1f"}],
            neighbours=[_nbr("core-sw-02", "Ethernet", "Ethernet1/26", remote_ip="10.0.1.2")],
        ),
    ]

    # ---------------------------------------------------------------- storage / backup / hypervisor / oob
    specs += [
        Spec(
            ip="10.20.130.5",
            hostname="nas-01.contoso.example",
            device_type="storage",
            vendor="netapp",
            os_family="ontap",
            os_version="9.7P20",
            sys_descr="NetApp Release 9.7P20: Wed May 18 2022",
            zone="storage",
            criticality=5,
            role="primary storage",
            snmp={"readable": True, "version": "v2c", "community_used": "r**-d", "default_community": False},
            sys_uptime=86400 * 415,
            config={"syslog": True, "ntp": True, "central_auth": True},
            services=[
                _svc(111, proto="udp", name="rpcbind", encryption="none"),
                _svc(2049, name="nfs", encryption="none"),
                _svc(445, name="microsoft-ds", encryption="none"),
                _svc(10000, product="NetApp SnapManager", encryption="none", name="networker"),
                _svc(3260, name="iscsi-target", encryption="none"),
            ],
            interfaces=[{"name": "e0a", "if_index": 1, "speed_mbps": 25000, "oper_status": "up", "ips": ["10.20.130.5"], "role": "uplink", "mac": "00:a0:98:aa:bb:05"}],
            neighbours=[_nbr("core-sw-01", "e0a", "Ethernet1/30", remote_ip="10.0.1.1"), _nbr("core-sw-02", "e0b", "Ethernet1/30", remote_ip="10.0.1.2")],
        ),
        Spec(
            ip="10.20.130.9",
            hostname="bkp-01.contoso.example",
            device_type="storage",
            vendor="dell",
            os_family="linux",
            os_version="8.4",
            sys_descr="Linux bkp-01 4.18.0-305.el8.x86_64",
            zone="storage",
            criticality=5,
            role="backup appliance",
            documented=True,
            tags=["tier0", "backup", "immutable-target"],
            snmp={"readable": True, "version": "v2c", "community_used": "p****c", "default_community": True},
            sys_uptime=86400 * 12,
            config={"syslog": True, "ntp": True},
            services=[
                _svc(22, product="OpenSSH", version="7.4", encryption="ssh", banner="SSH-2.0-OpenSSH_7.4"),
                _svc(514, proto="udp", name="syslog", encryption="none"),
                _svc(563, name="snews", encryption="tls"),
                _svc(990, name="ftps", encryption="none", banner="220 (vsFTPd 3.0.3)\r\n", product="vsFTPd", config={"ftp_anonymous": True}),
                _svc(10000, product="Networker", encryption="none", name="networker"),
                _svc(8080, product="App Interface", banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.6\r\n\r\n", encryption="none", name="http-proxy", http=_http(server="Apache/2.4.6", admin=["/admin/", "/debug"])),
            ],
            interfaces=[{"name": "bond0", "if_index": 2, "speed_mbps": 10000, "oper_status": "up", "ips": ["10.20.130.9"], "role": "lag", "mac": "00:14:5e:aa:bb:09"}],
            neighbours=[_nbr("core-sw-02", "bond0", "Ethernet1/31", remote_ip="10.0.1.2")],
        ),
        Spec(
            ip="10.20.110.41",
            hostname="esx-01.contoso.example",
            device_type="hypervisor",
            vendor="vmware",
            os_family="esxi",
            os_version="6.7.0",
            sys_descr="VMkernel esx-01 6.7.0 releasebuild-19969346",
            zone="server-farm",
            criticality=5,
            role="compute host",
            tags=["tier0", "compute"],
            snmp={"readable": False, "version": None, "community_used": None},
            sys_uptime=86400 * 512,
            config={"syslog": False, "ntp": True, "central_auth": False},
            services=[
                _svc(443, product="ESXi Host Client", encryption="tls", name="https", cert=_cert(cn="esx-01.local", self_signed=True, days_left=11, protocol="TLSv1.0", cipher="DES-CBC3-SHA", san=["esx-01.local"], match=False), http=_http(server="ESXi", admin=["/hostui"])),
                _svc(902, name="vixdisklib", encryption="none"),
                _svc(22, product="OpenSSH", version="7.4p1", encryption="ssh", banner="SSH-2.0-OpenSSH_7.4p1"),
            ],
            interfaces=[
                {"name": "vmnic0", "if_index": 1, "speed_mbps": 25000, "oper_status": "up", "role": "uplink"},
                {"name": "vmnic1", "if_index": 2, "speed_mbps": 25000, "oper_status": "up", "role": "uplink"},
                {"name": "vmk0", "if_index": 800, "speed_mbps": None, "oper_status": "up", "ips": ["10.20.110.41"], "role": "management", "type": "propVirtual"},
            ],
            neighbours=[_nbr("core-sw-01", "vmnic0", "Ethernet1/40", remote_ip="10.0.1.1"), _nbr("core-sw-02", "vmnic1", "Ethernet1/40", remote_ip="10.0.1.2")],
            inventory={"owner": "Virtualisation", "os": "VMware ESXi 6.7", "last_patch_date": "2022-11-04"},
        ),
        Spec(
            ip="10.99.0.21",
            hostname="bmc-esx-01",
            device_type="out_of_band",
            vendor="dell",
            model="iDRAC9",
            os_family="embedded",
            os_version="6.10.80.00",
            sys_descr="Dell iDRAC9 6.10.80.00",
            zone="management",
            criticality=4,
            role="server management",
            tags=["oob"],
            snmp={"readable": True, "version": "v1", "community_used": "p****c", "default_community": True},
            services=[
                _svc(623, proto="udp", product="IPMI RMCP+", banner="\x06\x00\xff\x07\x00\x00\x00\x00\x00", encryption="none", name="ipmi", config={"ipmi_cipher_level": 0}),
                _svc(443, product="iDRAC Web UI", encryption="tls", name="https", cert=_cert(cn="iDRAC-esx-01", self_signed=True, days_left=1200, protocol="TLSv1.1")),
                _svc(5900, product="iDRAC Virtual Console", banner="RFB 003.008\r\n", encryption="none", name="vnc"),
                _svc(5986, name="wsmans", encryption="tls"),
            ],
            interfaces=[{"name": "iDRAC", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "ips": ["10.99.0.21"], "role": "management"}],
            neighbours=[],
            config={"syslog": False, "ntp": False, "snmp_write_community_rw": True},
            documented=True,
        ),
    ]

    # ---------------------------------------------------------------- printers / cameras / IoT / OT
    specs += [
        Spec(
            ip="10.30.2.201",
            hostname="prn-hr-01",
            device_type="printer",
            vendor="hp",
            model="LaserJet Enterprise M630",
            os_family="embedded",
            os_version="7.8.10",
            sys_descr="HP SmartStream [version V7.8.10.202401] LaserJet Enterprise M630",
            zone="access",
            criticality=2,
            role="printer",
            documented=True,
            snmp={"readable": True, "version": "v1", "community_used": "p****c", "default_community": True, "sys_descr": "HP SmartStream LaserJet"},
            services=[
                _svc(80, product="HP JetDirect EWS", banner="HTTP/1.1 200 OK\r\nServer: HP-HTTPD/1.0\r\n\r\n", encryption="none", name="http", http=_http(server="HP-HTTPD/1.0", admin=["/admin", "/setup"])),
                _svc(443, product="HP JetDirect EWS", encryption="tls", name="https", cert=_cert(cn="HP Print Server Certificate", self_signed=True, issuer="HP Self-Signed CA", days_left=900, protocol="TLSv1.0", cipher="RC4-MD5")),
                _svc(515, name="printer", encryption="none"),
                _svc(631, name="ipp", encryption="none"),
                _svc(9100, name="jetdirect-printer", product="HP JetDirect", encryption="none"),
                _svc(23, product="Telnet", banner="Escape character is '^]'.\r\n", encryption="none", name="telnet"),
            ],
            interfaces=[{"name": "eth0", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "ips": ["10.30.2.201"], "role": "access", "mac": "3c:52:82:aa:bb:01"}],
            config={"syslog": False, "ntp": False, "central_auth": False},
            tags=["print"],
        ),
        Spec(
            ip="10.40.1.51",
            hostname="cam-l4-north",
            device_type="camera",
            vendor="hikvision",
            model="DS-2CD2T47G2",
            os_family="embedded",
            os_version="V5.7.10",
            sys_descr="HIKVISION DS-2CD2T47G2-LU V5.7.10 build 220413",
            zone="iot",
            criticality=2,
            role="surveillance",
            tags=["physical-security"],
            documented=True,
            snmp={"readable": False, "version": None, "community_used": None},
            services=[
                _svc(80, product="Hikvision Web UI", banner="HTTP/1.1 200 OK\r\nServer: webserver\r\n\r\n", encryption="none", name="http", http=_http(server="Hikvision webserver", admin=["/SDK/webLanguage", "/GponForm/diag_Form"])),
                _svc(554, product="RTSP", name="rtsp", encryption="none"),
                _svc(8000, product="Hikvision ISAPI", name="http-alt", encryption="none"),
            ],
            interfaces=[{"name": "eth0", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "ips": ["10.40.1.51"], "role": "access", "mac": "18:fe:15:aa:bb:51"}],
            config={"syslog": False, "ntp": False, "central_auth": False},
        ),
        Spec(
            ip="10.40.1.52",
            hostname="cam-l4-south",
            device_type="camera",
            vendor="axis",
            model="P1447-LE",
            os_family="axis-os",
            os_version="11.6.3",
            sys_descr="AXIS P1447-LE-3MP Network Camera 11.6.3",
            zone="iot",
            criticality=2,
            role="surveillance",
            documented=True,
            services=[
                _svc(80, product="AXIS Camera Web Server", banner="HTTP/1.1 401 Unauthorized\r\nServer: AXIS Camera Web Server\r\n\r\n", encryption="none", name="http", http=_http(server="AXIS Camera Web Server", admin=["/axis-cgi/"])),
                _svc(443, product="AXIS Camera Web Server", encryption="tls", name="https", cert=_cert(cn="AXIS-OS", self_signed=True, days_left=3000, protocol="TLSv1.2")),
                _svc(554, name="rtsp", encryption="none"),
            ],
            interfaces=[{"name": "eth0", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "ips": ["10.40.1.52"], "role": "access", "mac": "00:40:8c:aa:bb:52"}],
            config={"syslog": False, "ntp": True},
        ),
        Spec(
            ip="10.40.9.10",
            hostname="bms-meu-01",
            device_type="iot",
            vendor="schneider",
            model="Modicon M340",
            os_family="rtos",
            os_version="V3.20",
            sys_descr="Schneider Electric Modicon M340 PLC - V3.20",
            zone="iot",
            criticality=4,
            role="building management",
            tags=["ot", "no-patch-window"],
            documented=True,
            services=[
                _svc(502, product="Modbus/TCP", banner="\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00", encryption="none", name="modbus"),
                _svc(44818, product="EtherNet/IP", encryption="none", name="unknown/44818"),
            ],
            interfaces=[{"name": "eth0", "if_index": 1, "speed_mbps": 100, "oper_status": "up", "ips": ["10.40.9.10"], "role": "access", "mac": "00:80:f4:aa:bb:10"}],
            config={"syslog": False, "ntp": False},
        ),
        Spec(
            ip="10.20.110.61",
            hostname="ap-01-l1.contoso.example",
            device_type="access_point",
            vendor="aruba",
            model="AP-515",
            os_family="aos",
            os_version="8.6.0.13",
            sys_descr="ArubaOS (Model: AP515), 8.6.0.13_37688",
            zone="access",
            criticality=3,
            role="wireless",
            documented=True,
            services=[_svc(22, product="OpenSSH", version="8.2", encryption="ssh", banner="SSH-2.0-OpenSSH_8.2"), _svc(161, proto="udp", name="snmp", encryption="none")],
            interfaces=[{"name": "eth0", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "ips": ["10.20.110.61"], "role": "uplink", "mac": "40:46:da:aa:bb:61"}],
            neighbours=[_nbr("acc-sw-f1-01", "eth0", "GigabitEthernet0/12", remote_ip="10.0.3.1", confidence=0.7)],
            config={"syslog": True, "ntp": True, "central_auth": True},
        ),
    ]

    # ---------------------------------------------------------------- infra services with risky config
    specs += [
        Spec(
            ip="10.20.110.71",
            hostname="dns-01.contoso.example",
            device_type="dns",
            vendor="linux",
            os_family="linux",
            os_version="5.15.0",
            sys_descr="Linux dns-01 5.15.0-79-generic #86-Ubuntu SMP",
            zone="server-farm",
            criticality=4,
            role="recursive + authoritative DNS",
            documented=True,
            snmp={"readable": False, "version": None, "community_used": None},
            config={"syslog": True, "ntp": True},
            services=[
                _svc(53, proto="udp", product="BIND 9.18", name="dns", encryption="none", config={"recursion": True, "version": "9.18.24"}),
                _svc(53, product="BIND 9.18", name="dns", encryption="none", config={"recursion": True}),
            ],
            interfaces=[{"name": "ens3", "if_index": 2, "speed_mbps": 10000, "oper_status": "up", "ips": ["10.20.110.71"], "role": "routed", "mac": "00:50:56:aa:bb:71"}],
            neighbours=[_nbr("core-sw-01", "ens3", "Ethernet1/28", remote_ip="10.0.1.1")],
        ),
        Spec(
            ip="10.20.110.72",
            hostname="ntp-01.contoso.example",
            device_type="infra",
            vendor="linux",
            os_family="linux",
            os_version="4.18.0",
            sys_descr="Linux ntp-01 4.18.0-348.el8.x86_64",
            zone="server-farm",
            criticality=3,
            role="time source",
            documented=True,
            config={"ntp": True, "syslog": True, "running_processes": ["ntpd", "rsyslogd"]},
            services=[
                _svc(123, proto="udp", product="ntpd", version="4.2.8p10", name="ntp", encryption="none", config={"ntp_monlist": True, "ntp_monlist_count": 621}),
            ],
            interfaces=[{"name": "ens3", "if_index": 2, "speed_mbps": 10000, "oper_status": "up", "ips": ["10.20.110.72"], "role": "routed", "mac": "00:50:56:aa:bb:72"}],
        ),
        Spec(
            ip="10.20.110.73",
            hostname="radius-01.contoso.example",
            device_type="directory",
            vendor="freeradius",
            os_family="linux",
            os_version="3.0.21",
            sys_descr="Linux radius-01 4.18.0-425.10.1.el8.x86_64",
            zone="management",
            criticality=5,
            role="network access authentication",
            documented=True,
            config={"syslog": True, "ntp": True, "central_auth": True},
            services=[
                _svc(1812, proto="udp", product="FreeRADIUS", name="radius", encryption="other"),
                _svc(1813, proto="udp", product="FreeRADIUS accounting", name="radius-acct", encryption="other"),
            ],
            interfaces=[{"name": "ens3", "if_index": 2, "speed_mbps": 10000, "oper_status": "up", "ips": ["10.20.110.73"], "role": "routed", "mac": "00:50:56:aa:bb:73"}],
        ),
    ]

    # ---------------------------------------------------------------- risk set pieces
    if include_risks:
        specs += [
            Spec(
                ip="10.30.2.77",
                hostname=None,
                device_type="unknown",
                zone="access",
                criticality=2,
                documented=False,
                vlan=202,
                mac="a4:83:e7:11:22:33",
                notes=["device never registered; learned on acc-sw-f1-01 Gi0/3"],
                services=[
                    _svc(p, name="unknown", encryption="none") for p in (22, 80, 135, 139, 445, 3389, 5040, 5357, 54321, 49664)
                ]
                + [_svc(5357, product="WS-Discovery", banner="HTTP/1.1 200 OK\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n", http=_http(server="Microsoft-HTTPAPI/2.0"))],
                interfaces=[{"name": "wlan0", "if_index": 1, "mac": "a4:83:e7:11:22:33", "oper_status": "up", "ips": ["10.30.2.77"], "role": "access", "vlan": 202}],
            ),
            Spec(
                ip="10.20.110.88",
                hostname="kiosk-l1-01",
                device_type="workstation",
                vendor="unknown",
                zone="server-farm",
                criticality=3,
                documented=False,
                mac="b0:4e:26:aa:bb:88",
                services=[_svc(80, product="Kiosk Server", banner="HTTP/1.1 200 OK\r\nServer: Lighttpd/1.4.35\r\n\r\n", encryption="none", name="http", http=_http(server="lighttpd/1.4.35", admin=["/setup"]))],
                interfaces=[{"name": "eth0", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "ips": ["10.20.110.88"], "role": "access", "mac": "b0:4e:26:aa:bb:88"}],
                neighbours=[_nbr("core-sw-01", "eth0", "Ethernet1/33", remote_ip="10.0.1.1")],
                notes=["address also claimed from a second switchport"],
            ),
            Spec(
                ip="10.20.110.88",
                hostname=None,
                device_type="unknown",
                zone="server-farm",
                criticality=1,
                documented=False,
                mac="b0:4e:26:aa:bb:99",
                services=[],
                interfaces=[{"name": "eth0", "if_index": 1, "mac": "b0:4e:26:aa:bb:99", "oper_status": "up", "ips": ["10.20.110.88"], "role": "access"}],
                notes=["duplicate address event"],
            ),
            Spec(
                ip="10.30.2.90",
                hostname=None,
                device_type="dhcp",
                vendor="unknown",
                zone="access",
                criticality=2,
                documented=False,
                services=[_svc(67, proto="udp", product="dnsmasq", name="dhcp-server", encryption="none", banner="")],
                interfaces=[{"name": "br0", "if_index": 1, "mac": "02:42:aa:bb:cc:dd", "oper_status": "up", "ips": ["10.30.2.90"], "role": "access"}],
                notes=["DHCP service present in a user VLAN (only 10.20.110.1 is approved)"],
                config={"ntp": False, "syslog": False},
            ),
            Spec(
                ip="10.0.9.31",
                hostname="vpn-lb-01",
                device_type="load_balancer",
                vendor="f5",
                model="BIG-IP i2800",
                os_family="bigip",
                os_version="13.1.3.6",
                sys_descr="BIG-IP v13.1.3.6 Build 0.0.6 - Locale en",
                zone="dmz",
                criticality=5,
                role="external LB / VPN",
                exposed_to_wan=True,
                documented=True,
                snmp={"readable": True, "version": "v2c", "community_used": "p****c", "default_community": True},
                config={"syslog": True, "ntp": True, "central_auth": False},
                services=[
                    _svc(443, product="F5 TMM UI", encryption="tls", name="https", cert=_cert(cn="vpn.contoso.example", days_left=240, protocol="TLSv1.2", cipher="ECDHE-RSA-AES256-GCM-SHA399")),
                    _svc(80, product="F5 ConfigSync http", banner="HTTP/1.1 404 Not Found\r\nServer: BigIP\r\n\r\n", encryption="none", name="http", http=_http(server="BigIP")),
                    _svc(161, proto="udp", name="snmp", encryption="none"),
                    _svc(8443, product="F5 iControl REST", banner="HTTP/1.1 401 Unauthorized\r\nServer: BigIP\r\n\r\n", encryption="tls", name="https-alt"),
                ],
                neighbours=[_nbr("core-sw-01", "1.2", "Ethernet1/12", remote_ip="10.0.1.1"), _nbr("core-sw-02", "1.3", "Ethernet1/12", remote_ip="10.0.1.2")],
                interfaces=[{"name": "1.1", "if_index": 1, "speed_mbps": 10000, "oper_status": "up", "role": "wan", "ips": ["198.51.100.20"]}, {"name": "1.2", "if_index": 2, "speed_mbps": 10000, "oper_status": "up", "role": "uplink", "ips": ["10.0.9.31"]}],
            ),
            Spec(
                ip="10.0.0.14",
                hostname="printer-l3",
                device_type="printer",
                vendor="samsung",
                os_family="embedded",
                os_version="1.0",
                sys_descr="Samsung SEC-Print 1.0",
                zone="wan-edge",
                criticality=2,
                documented=False,
                exposed_to_wan=True,
                services=[
                    _svc(23, product="Telnet", banner="Escape character is '^]'.\r\n", encryption="none", name="telnet"),
                    _svc(80, product="Samsung EWS", banner="HTTP/1.1 200 OK\r\nServer: Sec/1.0\r\n\r\n", encryption="none", name="http", http=_http(server="SEC Web Server", admin=["/admin", "/setup"], leaks=["/.git/config"])),
                    _svc(9100, name="jetdirect-printer", encryption="none"),
                    _svc(623, proto="udp", name="ipmi", encryption="none"),
                ],
                interfaces=[{"name": "eth0", "if_index": 1, "speed_mbps": 100, "oper_status": "up", "ips": ["10.0.0.14"], "role": "access", "mac": "c4:4e:1f:aa:bb:14"}],
                config={"syslog": False, "ntp": False, "central_auth": False},
                notes=["address in the perimeter subnet"],
            ),
            Spec(
                ip="10.20.110.95",
                hostname="flr1-mgmt-sw",
                device_type="switch",
                vendor="hpe",
                model="Aruba 2530",
                os_family="comware",
                os_version="16.02.0007",
                sys_descr="ProCurve J9779A 2530-24G, revision 16.02.0007",
                zone="management",
                criticality=3,
                role="OOB switch",
                documented=True,
                snmp={"readable": True, "version": "v1", "community_used": "p****c", "default_community": True},
                sys_uptime=180,  # rebooted moments ago
                config={"syslog": False, "ntp": False, "central_auth": False},
                services=[
                    _svc(23, product="Telnet", banner="User Access Verification\r\nPassword:", encryption="none", name="telnet"),
                    _svc(22, product="OpenSSH", version="6.6", encryption="ssh", banner="SSH-2.0-libssh_0.6.3"),
                    _svc(161, proto="udp", name="snmp", encryption="none"),
                ],
                interfaces=[{"name": "1", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "role": "uplink", "ips": ["10.20.110.95"]}],
                neighbours=[_nbr("core-sw-02", "1", "Ethernet1/45", remote_ip="10.0.1.2", confidence=0.85)],
            ),
        ]

    if size == "large":
        # extra floors of access switches + more endpoints, cheap procedurals
        for block in range(5, 10):
            ip = f"10.0.3.{block}"
            specs.append(
                Spec(
                    ip=ip,
                    hostname=f"acc-sw-f{block}-01",
                    device_type="switch",
                    vendor="cisco",
                    model="Catalyst 2960",
                    os_family="ios",
                    os_version="12.2(55)SE12",
                    sys_descr="Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE12",
                    zone="access",
                    criticality=2,
                    role="access",
                    documented=True,
                    snmp={"readable": block % 3 == 0, "version": "v2c", "community_used": "p****c", "default_community": block % 2 == 0},
                    services=[
                        _svc(22, product="OpenSSH", version="6.6", encryption="ssh", banner="SSH-2.0-Cisco-1.25"),
                        _svc(161, proto="udp", name="snmp", encryption="none"),
                        *([_svc(23, product="Cisco Telnet", banner="User Access Verification", encryption="none", name="telnet")] if block % 2 else []),
                    ],
                    interfaces=[{"name": "Gi0/1", "if_index": 1, "speed_mbps": 1000, "oper_status": "up", "role": "uplink"}],
                    neighbours=[_nbr("dist-sw-01", "Gi0/1", "Gi1/0/%s" % (block - 3), remote_ip="10.0.2.1")],
                    config={"syslog": False, "ntp": True},
                )
            )
    return specs


def to_devices(specs: list[Spec], *, rng: random.Random | None = None) -> tuple[list[Device], list[Zone]]:
    """Materialise specs into model objects, wiring ARP/FDB cross-references."""
    devices: list[Device] = []
    by_host: dict[str, Device] = {}
    used_ids: set[str] = set()
    for spec in specs:
        ident = device_id_for(spec.ip, spec.hostname)
        if ident in used_ids and spec.mac:
            ident = f"{ident}+{spec.mac.replace(':', '')[-6:]}"
        used_ids.add(ident)
        dev = Device(
            id=ident,
            ip=spec.ip,
            hostname=spec.hostname,
            mac=spec.mac,
            vendor=spec.vendor,
            model=spec.model,
            os_family=spec.os_family,
            os_version=spec.os_version,
            sys_descr=spec.sys_descr,
            device_type=spec.device_type,
            role=spec.role,
            zone=spec.zone,
            vlan=spec.vlan,
            criticality=spec.criticality,
            tags=list(spec.tags),
            documented=spec.documented,
            inventory=dict(spec.inventory),
            notes=list(spec.notes),
            exposed_to_wan=spec.exposed_to_wan,
            uptime_seconds=spec.sys_uptime,
            last_boot=iso((now_utc().timestamp() - spec.sys_uptime)) if spec.sys_uptime else None,
            config=dict(spec.config),
            discovery_sources=["sim"],
            last_seen=iso(now_utc()),
            snmp=dict(spec.snmp or {"readable": False, "version": None, "community_used": None}),
            reachable=True,
        )
        if dev.snmp.get("readable") and spec.sys_descr:
            dev.snmp.setdefault("sys_descr", spec.sys_descr)
            dev.snmp.setdefault("sys_name", spec.hostname or dev.id)
            dev.snmp.setdefault("sys_location", f"{spec.zone} rack {(rng or random.Random(len(devices))).randint(1, 24):02d}")
        for intf in spec.interfaces:
            dev.interfaces.append(Interface(**intf))
        for route in spec.routes:
            dev.routes.append(Route(**route))
        for nbr in spec.neighbours:
            dev.neighbors.append(Neighbor(**nbr))
        for entry in spec.arp:
            dev.arp.append(ArpEntry(**entry))
        for entry in spec.fdb:
            dev.fdb.append(FdbEntry(**entry))
        for svc in spec.services:
            data = dict(svc)
            cert = data.pop("certificate", None)
            service = Service(**data)
            service.confidence = 0.95 if service.banner else 0.8
            service.name = service.name or None
            if cert:
                service.certificate = Certificate(**cert)
                service.encryption = "tls"
                service.config.update(
                    {
                        "tls_version": cert.get("protocol"),
                        "tls_cipher": cert.get("cipher"),
                        "self_signed": cert.get("self_signed"),
                        "not_after": cert.get("not_after"),
                        "key_bits": cert.get("key_bits"),
                        "weak_protocol": str(cert.get("protocol") or "") in ("TLSv1", "TLSv1.1", "SSLv3"),
                        "weak_cipher": any(tok in str(cert.get("cipher") or "").upper() for tok in ("RC4", "DES", "3DES", "NULL", "EXPORT")),
                    }
                )
            if service.name is None:
                from ..ports import port_name

                service.name = port_name(service.port, service.protocol)
            dev.services.append(service)
        dev.services.sort(key=lambda s: (s.protocol, s.port))
        if dev.os_family == "windows" and dev.os_version:
            dev.raw["product"] = "Microsoft Windows"
        elif dev.os_family in ("ios", "nxos", "asa") and dev.vendor == "cisco":
            dev.raw["product"] = {"ios": "Cisco IOS", "nxos": "Cisco NX-OS", "asa": "Cisco ASA"}[dev.os_family]
        elif dev.os_family == "panos":
            dev.raw["product"] = "Palo Alto PAN-OS"
        elif dev.os_family == "esxi":
            dev.raw["product"] = "VMware ESXi"
        elif dev.os_family == "linux":
            dev.raw["product"] = "Red Hat Enterprise Linux" if "el8" in (dev.sys_descr or "") or "el7" in (dev.sys_descr or "") else "Ubuntu Server"
        elif dev.os_family == "bigip":
            dev.raw["product"] = "F5 BIG-IP"
        elif dev.os_family == "junos":
            dev.raw["product"] = "Juniper JUNOS"
        elif dev.os_family == "ontap":
            dev.raw["product"] = "NetApp ONTAP"
        devices.append(dev)
        by_host[ident] = dev
        if spec.hostname:
            by_host[spec.hostname] = dev

    # resolve neighbour identities that were expressed by hostname
    for dev in devices:
        for nbr in dev.neighbors:
            target = by_host.get(str(nbr.remote_system))
            if target is not None and not nbr.remote_ip:
                nbr.remote_key = target.ip or target.id
                nbr.remote_ip = target.ip

    # give every switch the ARP+FDB rows for hosts that name it as their peer,
    # so mac-table correlation has real work to do
    for host in devices:
        if host.device_type in ("switch", "router", "firewall"):
            continue
        for intf in host.interfaces:
            if not (intf.mac and intf.ips):
                continue
            for nbr in host.neighbors:
                peer = by_host.get(str(nbr.remote_system)) or next((d for d in devices if d.id == f"ip:{nbr.remote_key}"), None)
                if peer is None or peer.device_type != "switch":
                    continue
                peer.arp.append(ArpEntry(ip=intf.ips[0], mac=intf.mac, entry_type="dynamic", interface=nbr.local_if))
                match = peer.interface(nbr.local_if) or (peer.interfaces[0] if peer.interfaces else None)
                if match is not None:
                    peer.fdb.append(FdbEntry(mac=intf.mac, if_index=match.if_index, port=str(match.if_index), vlan=host.vlan or (match.vlan if match else None)))
    zones = _zones_from_specs(specs)
    return devices, zones


_ZONE_DEFS = [
    ("wan-edge", "untrusted", ["10.0.0.0/24"], [10], "Internet-facing / perimeter segment"),
    ("dmz", "dmz", ["10.0.9.0/24", "10.20.110.64/26"], [20], "Public services behind the LB"),
    ("core", "internal", ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"], [100], "Core, distribution and access switching"),
    ("server-farm", "restricted", ["10.20.110.0/24", "10.20.120.0/24"], [110, 120], "Application, database and identity tiers"),
    ("storage", "restricted", ["10.20.130.0/24"], [130], "Primary storage and backup targets"),
    ("management", "out_of_band", ["10.99.0.0/24"], [999], "BMC / OOB device management"),
    ("access", "internal", ["10.30.0.0/16"], [200, 201, 202], "User access layer and wireless"),
    ("iot", "internal", ["10.40.0.0/16"], [300], "Cameras, badge readers, AV and building management"),
    ("guest", "untrusted", ["10.50.0.0/16"], [400], "BYOD / guest wireless"),
]


def _zones_from_specs(specs: list[Spec]) -> list[Zone]:
    used = {s.zone for s in specs}
    out: list[Zone] = []
    for name, trust, cidrs, vlans, desc in _ZONE_DEFS:
        if name not in used:
            continue
        zone = Zone(name=name, trust=trust, cidrs=list(cidrs), vlans=list(vlans), description=desc)
        zone.device_count = sum(1 for s in specs if s.zone == name)
        if name == "access":
            zone.segmentation_enforced = False
            zone.segmentation_note = "user VLANs bridge to the server farm without an inter-VLAN policy"
        if name == "iot":
            zone.segmentation_enforced = False
            zone.segmentation_note = "no NAC/802.1X enforcement recorded for the device VLAN"
        if name in ("server-farm", "storage"):
            zone.default_gateway = "10.20.110.1"
        if name == "access":
            zone.default_gateway = "10.30.0.1"
        out.append(zone)
    return out


def build_devices(size: str = "medium", *, seed: int = 7, include_risks: bool = True) -> tuple[list[Device], list[Zone]]:
    rng = random.Random(seed)
    specs = build_specs(size, seed=seed, include_risks=include_risks)
    return to_devices(specs, rng=rng)


__all__ = ["build_devices", "build_specs", "to_devices", "Spec"]
