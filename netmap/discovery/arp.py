"""Local network context: neighbour (ARP) tables and our own addresses.

ARP is the cheapest authoritative liveness signal available: a host with a
dynamic entry on a router or switch is up. It is also the raw material for
duplicate-IP / ARP-spoofing and rogue-MAC detection.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass

from ..models import ArpEntry
from ..util import is_ip, parse_mac


@dataclass
class LocalAddress:
    iface: str
    ip: str
    prefix: int
    broadcast: str | None = None
    mac: str | None = None

    @property
    def network(self) -> str:
        try:
            return str(ipaddress.ip_network(f"{self.ip}/{self.prefix}", strict=False))
        except ValueError:
            return ""


ARP_LINE = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?:.*?\s)?(?P<mac>(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})")


def run(cmd: list[str], timeout: float = 4.0) -> str:
    """Run a helper binary, returning stdout ('' on any failure)."""
    if not shutil.which(cmd[0]):
        return ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        return ""
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def read_arp_table(include_system: bool = True) -> list[ArpEntry]:
    """Collect ARP/NDP rows from /proc/net/arp, `ip neigh` and `arp -a`."""
    entries: list[ArpEntry] = []
    seen: set[tuple[str | None, str | None]] = set()

    def add(entry: ArpEntry) -> None:
        key = (entry.ip, entry.mac)
        if key not in seen and (entry.ip or entry.mac):
            seen.add(key)
            entries.append(entry)

    path = "/proc/net/arp"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4 and is_ip(parts[0]):
                add(
                    ArpEntry(
                        ip=parts[0],
                        mac=parse_mac(parts[3]) if parts[3] != "00:00:00:00:00:00" else None,
                        interface=parts[5] if len(parts) > 5 else None,
                        entry_type={"0x2": "dynamic", "0x6": "complete", "0x0": "incomplete"}.get(parts[2], "dynamic"),
                    )
                )
    out = run(["ip", "-o", "neigh", "show"]) if include_system else ""
    for line in out.splitlines():
        m = re.match(r"\d+\.\s+(\S+)\s+(?:dev\s+(\S+)\s+)?(?:lladdr\s+(\S+)\s+)?.*?\b(REACHABLE|PERMANENT|STALE|DELAY|PROBE|FAILED|INCOMPLETE|NOARP)\b", line)
        if not m:
            continue
        ip_part, dev, lladdr, state = m.group(1), m.group(2), m.group(3), m.group(4)
        if not is_ip(ip_part):
            continue
        add(
            ArpEntry(
                ip=ip_part,
                mac=parse_mac(lladdr) if lladdr else None,
                interface=dev,
                entry_type="static" if state == "PERMANENT" else "dynamic",
            )
        )
    if include_system and not entries:
        for line in run(["arp", "-a"]).splitlines():
            m = ARP_LINE.search(line)
            if not m:
                continue
            iface = None
            ifm = re.search(r"on (\S+)", line)
            if ifm:
                iface = ifm.group(1)
            add(ArpEntry(ip=m.group("ip"), mac=parse_mac(m.group("mac")), interface=iface))
    return entries


def local_addresses() -> list[LocalAddress]:
    """This host's addresses/prefixes; tells the engine what it can reach."""
    out: list[LocalAddress] = []
    text = run(["ip", "-o", "addr", "show"])
    for line in text.splitlines():
        m = re.search(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            m6 = re.search(r"\d+:\s+(\S+)\s+inet6\s+(\S+)/(\d+)", line)
            if m6:
                out.append(LocalAddress(iface=m6.group(1), ip=m6.group(2).split("%")[0], prefix=int(m6.group(3))))
            continue
        mac = None
        mmac = re.search(r"link/\S+\s+(\S+)", line)
        if mmac:
            mac = parse_mac(mmac.group(1))
        out.append(LocalAddress(iface=m.group(1), ip=m.group(2), prefix=int(m.group(3)), mac=mac))
    if not out:  # fallback: the primary address the kernel would use outbound
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 53))
                ip = s.getsockname()[0]
            out.append(LocalAddress(iface="default", ip=ip, prefix=24))
        except OSError:
            pass
    return out


def local_subnets() -> list[str]:
    return sorted({a.network for a in local_addresses() if a.network})


def interface_for_ip(ip: str) -> str | None:
    for addr in local_addresses():
        if addr.network and is_ip(ip):
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(addr.network):
                    return addr.iface
            except ValueError:
                continue
    return None


def reverse_dns(ip: str, *, timeout: float = 1.0) -> str | None:
    """PTR lookup, tolerant of broken resolvers."""
    if not is_ip(ip):
        return None
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    finally:
        socket.setdefaulttimeout(old)
    return name or None


def forward_dns(name: str, *, timeout: float = 1.0) -> list[str]:
    if not name or is_ip(name):
        return [name] if name and is_ip(name) else []
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None)})
    except (OSError, UnicodeError):
        return []
    finally:
        socket.setdefaulttimeout(old)


__all__ = ["read_arp_table", "local_addresses", "local_subnets", "interface_for_ip", "reverse_dns", "forward_dns", "LocalAddress", "run"]
