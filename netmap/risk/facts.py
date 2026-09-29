"""Evidence enrichment: derived facts the rule catalogue reads.

Rules stay declarative; anything that needs graph traversal, cross-device
correlation or a time computation happens here once and is exposed as a plain
field on the device/zone/link/network facts namespace.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..models import Device, Finding, Link, ScanSnapshot, Zone
from ..util import days_until, is_ip, iso, now_utc, parse_version, version_lt

POLICY_DEVICE_TYPES = {"firewall", "proxy", "ips_ids", "load_balancer"}
DHCP_PORTS = {67, 68}
AUTH_PORTS = {1812, 1813, 49, 2001, 3799}


def _trust_rank(trust: str) -> int:
    return {"untrusted": 0, "unknown": 1, "dmz": 2, "internal": 3, "restricted": 4, "out_of_band": 5}.get(trust, 1)


class Enricher:
    """Computes derived facts for one snapshot."""

    def __init__(self, snapshot: ScanSnapshot, *, graph=None, thresholds: dict | None = None, policy: dict | None = None):
        self.snap = snapshot
        self.graph = graph
        self.thresholds = thresholds or {}
        self.policy = policy or {}
        self.devices = snapshot.devices
        self.by_id = snapshot.device_map()
        self.adjacency: dict[str, set[str]] = defaultdict(set)
        self.links_by_node: dict[str, list[Link]] = defaultdict(list)
        for link in snapshot.links:
            self.adjacency[link.src_device].add(link.dst_device)
            self.adjacency[link.dst_device].add(link.src_device)
            self.links_by_node[link.src_device].append(link)
            self.links_by_node[link.dst_device].append(link)
        self.zones = {z.name: z for z in snapshot.zones}
        self._dup_macs: dict[str, list[dict]] | None = None
        self._isolation: dict[str, dict[str, Any]] | None = None
        self._reach: dict[str, dict[str, Any]] | None = None
        self._dhcp_rogues: set[str] | None = None

    # -- duplicate IP correlation -------------------------------------------
    def duplicate_ips(self) -> dict[str, list[dict]]:
        if self._dup_macs is not None:
            return self._dup_macs
        claims: dict[str, dict[str, dict]] = defaultdict(dict)
        for dev in self.devices:
            for entry in dev.arp:
                if entry.ip and entry.mac:
                    claims[entry.ip].setdefault(entry.mac, {"mac": entry.mac, "source": dev.label, "type": entry.entry_type})
            if dev.ip and dev.mac:
                claims[dev.ip].setdefault(dev.mac, {"mac": dev.mac, "source": dev.label, "type": "address"})
        dupes = {ip: list(mac_map.values()) for ip, mac_map in claims.items() if len(mac_map) > 1}
        self._dup_macs = dupes
        return dupes

    # -- reachability --------------------------------------------------------
    def reachability(self) -> dict[str, dict[str, Any]]:
        """For each device: can devices of trust X reach it without crossing policy?"""
        if self._reach is not None:
            return self._reach
        out: dict[str, dict[str, Any]] = defaultdict(dict)
        sources: dict[str, list[str]] = defaultdict(list)
        for dev in self.devices:
            sources[dev.trust or "unknown"].append(dev.id)
        for trust, start_nodes in sources.items():
            blocked = {d.id for d in self.devices if d.device_type in POLICY_DEVICE_TYPES}
            # BFS with policy devices removed (they are the enforcement points)
            free = self._multi_source_bfs(start_nodes, exclude=blocked - set(start_nodes))
            # BFS with everything allowed, remembering the first policy hop
            full = self._multi_source_bfs(start_nodes, exclude=set())
            for dev in self.devices:
                reachable = dev.id in full
                unfiltered = dev.id in free and (dev.device_type not in POLICY_DEVICE_TYPES or dev.id in start_nodes)
                out[dev.id][trust] = {
                    "reachable": reachable,
                    "hops": full.get(dev.id, {}).get("hops"),
                    "path": full.get(dev.id, {}).get("path", []),
                    "filtered": reachable and not unfiltered,
                    "unfiltered": unfiltered,
                }
        self._reach = dict(out)
        return self._reach

    def _multi_source_bfs(self, start: Iterable[str], *, exclude: set[str]) -> dict[str, dict[str, Any]]:
        from collections import deque

        seen: dict[str, dict[str, Any]] = {}
        queue = deque()
        for node in start:
            if node in exclude:
                continue
            seen[node] = {"hops": 0, "path": [node]}
            queue.append(node)
        while queue:
            node = queue.popleft()
            hops = seen[node]["hops"]
            for nb in sorted(self.adjacency.get(node, ())):
                if nb in seen or nb in exclude:
                    continue
                seen[nb] = {"hops": hops + 1, "path": seen[node]["path"] + [nb]}
                queue.append(nb)
        return seen

    def rogue_dhcp(self) -> set[str]:
        """Devices answering DHCP that are not the zone's approved server."""
        if self._dhcp_rogues is not None:
            return self._dhcp_rogues
        approved = {str(a) for a in (self.policy.get("dhcp_servers") or [])}
        for zone in self.zones.values():
            if zone.default_gateway:
                approved.add(zone.default_gateway)
        by_zone: dict[str, list[Device]] = defaultdict(list)
        for dev in self.devices:
            if dev.has_port(list(DHCP_PORTS)) or dev.device_type == "dhcp":
                by_zone[dev.zone or "unassigned"].append(dev)
        rogues: set[str] = set()
        for zone, members in by_zone.items():
            keep = [d for d in members if (d.ip in approved) or (d.hostname in approved) or d.documented and (d.role or "").lower() in ("dhcp", "ipam")]
            others = [d for d in members if d not in keep]
            if not keep and len(members) < 2:
                continue  # nothing known-good to compare against
            for dev in others:
                if keep:
                    rogues.add(dev.id)
        self._dhcp_rogues = rogues
        return rogues

    # -- per-device ----------------------------------------------------------
    def lifecycle(self, dev: Device) -> dict[str, Any]:
        eol = dev.os_eol
        if not eol:
            return {"status": "unknown", "eol": None, "days_left": None, "basis": None}
        days = days_until(eol)
        if days is None:
            return {"status": "unknown", "eol": eol, "days_left": None, "basis": dev.os_eol_basis}
        if days < 0:
            status = "eol"
        elif days <= 180:
            status = "eol-soon"
        else:
            status = "supported"
        return {"status": status, "eol": eol, "days_left": round(days, 1), "basis": dev.os_eol_basis}

    def components(self) -> list[list[str]]:
        seen: set[str] = set()
        out: list[list[str]] = []
        nodes = sorted(self.adjacency) + sorted({d.id for d in self.devices if d.id not in self.adjacency})
        for start in nodes:
            if start in seen:
                continue
            seen.add(start)
            comp = [start]
            stack = [start]
            while stack:
                cur = stack.pop()
                for nb in sorted(self.adjacency.get(cur, ())):
                    if nb not in seen:
                        seen.add(nb)
                        comp.append(nb)
                        stack.append(nb)
            out.append(sorted(comp))
        return out

    def isolation_impact(self) -> dict[str, dict[str, Any]]:
        """Per device: how many neighbours are stranded if it disappears.

        "Splits the segment into N parts" is not a useful number on its own - a
        floor switch that orphans four printers and one that orphans nothing both
        produce N=2 - so the enricher walks the graph with the node removed and
        counts the devices that lose *every* path, weighted by criticality.
        """
        if self._isolation is not None:
            return self._isolation
        comps = self.components()
        comp_of = {node: i for i, comp in enumerate(comps) for node in comp}
        out: dict[str, dict[str, Any]] = {}
        for dev in self.devices:
            if not dev.raw.get("is_articulation_point"):
                continue
            comp = comps[comp_of.get(dev.id, 0)] if dev.id in comp_of else [dev.id]
            if len(comp) > 900:  # too large to brute force; the builder flag still stands
                out[dev.id] = {"devices": None, "groups": None, "note": "component too large to evaluate", "max_criticality": dev.criticality, "sample": []}
                continue
            rest = set(comp) - {dev.id}
            pieces: list[list[str]] = []
            seen: set[str] = set()
            for start in sorted(rest):
                if start in seen:
                    continue
                seen.add(start)
                piece = [start]
                stack = [start]
                while stack:
                    cur = stack.pop()
                    for nb in sorted(self.adjacency.get(cur, ())):
                        if nb in rest and nb not in seen:
                            seen.add(nb)
                            piece.append(nb)
                            stack.append(nb)
                pieces.append(piece)
            pieces.sort(key=len, reverse=True)
            stranded = [node for piece in pieces[1:] for node in piece]
            ranked = sorted(
                (self.by_id.get(x) or x for x in stranded),
                key=lambda d: (-int(getattr(d, "criticality", 0) or 0), str(getattr(d, "label", d))),
            )
            out[dev.id] = {
                "devices": len(stranded),
                "groups": max(0, len(pieces) - 1),
                "largest_group_kept": len(pieces[0]) if pieces else 0,
                "max_criticality": max([int(getattr(d, "criticality", 0) or 0) for d in ranked] or [0]),
                "types": sorted({str(getattr(d, "device_type", "unknown")) for d in ranked})[:6],
                "sample": [str(getattr(d, "label", d)) for d in ranked[:5]],
                "component_size": len(comp),
            }
        self._isolation = out
        return out

    def device_facts(self, dev: Device) -> dict[str, Any]:
        d = dev.to_dict()
        links = self.links_by_node.get(dev.id, [])
        peers = []
        uplink_bundles = 0
        for link in links:
            other = link.dst_device if link.src_device == dev.id else link.src_device
            peer = self.by_id.get(other)
            if link.kind == "port-channel":
                uplink_bundles += 1
            peers.append(
                {
                    "id": other,
                    "label": peer.label if peer else other,
                    "type": peer.device_type if peer else "unknown",
                    "interface": link.src_interface if link.src_device == dev.id else link.dst_interface,
                    "peer_interface": link.dst_interface if link.src_device == dev.id else link.src_interface,
                    "kind": link.kind,
                    "link_id": link.id,
                    "protected": link.protected,
                    "spof": link.is_spof,
                    "trust": peer.trust if peer else None,
                }
            )
        farthest = 0
        far_zone = None
        for peer in peers:
            peer_trust = peer.get("trust") or (self.by_id.get(peer["id"]).trust if self.by_id.get(peer["id"]) else None)
            if peer_trust:
                distance = abs(_trust_rank(dev.trust) - _trust_rank(peer_trust))
                if distance > farthest:
                    farthest = distance
                    far_zone = f"{self.by_id.get(peer['id']).label} ({peer_trust})" if self.by_id.get(peer["id"]) else peer["label"]
        zone = self.zones.get(dev.zone or "")
        dupes = self.duplicate_ips().get(dev.ip or "", [])
        other_macs = [x for x in dupes if x.get("mac") != dev.mac]
        reach = self.reachability().get(dev.id, {})
        firmware_age = None
        last_patch = dev.inventory.get("last_patch_date") or dev.inventory.get("firmware_date") or (dev.config or {}).get("last_patch_date")
        if last_patch:
            left = days_until(last_patch if isinstance(last_patch, str) else None)
            firmware_age = None if left is None else round(-left, 1)
        d.update(
            {
                "label": dev.label,
                "display": dev.display,
                "is_open": dev.reachable,
                "open_ports": sorted({int(s.port) for s in dev.services if s.is_open}),
                "open_port_count": len([s for s in dev.services if s.is_open]),
                "open_services": [s.to_dict() for s in dev.services if s.is_open],
                "service_names": sorted({str(s.name or "") for s in dev.services if s.is_open}),
                "plaintext_services": sorted(s.label for s in dev.services if s.is_open and s.is_plaintext),
                "management_services": sorted({str(s.port) for s in dev.services if s.is_open and s.port in (22, 23, 80, 443, 161, 623, 3389, 5985, 830, 10255, 3000)}),
                "has_web_management": any(s.is_open and s.port in (80, 443, 8080, 8443, 3000, 8443, 5000, 8443, 9443, 20000) for s in dev.services),
                "is_network_infrastructure": dev.is_network_infrastructure,
                "uplinks": [p["label"] for p in peers],
                "uplink_detail": peers,
                "uplink_count": len(peers),
                "uplink_is_bundle": uplink_bundles > 0 or any("bundle" in str(p.get("interface") or "").lower() or "po" in str(p.get("interface") or "").lower()[:3] for p in peers),
                "max_trust_distance": farthest,
                "nearest_far_zone": far_zone or "n/a",
                "segmentation_enforced": bool(zone.segmentation_enforced) if zone else False,
                "zone_trust": dev.trust,
                "degree": len(peers),
                "isolated": bool(dev.raw.get("isolated")),
                "component_count": int(dev.raw.get("component_size") or (1 if not peers else 0)),
                "is_articulation_point": bool(dev.raw.get("is_articulation_point")),
                "isolation": self.isolation_impact().get(dev.id) or {"devices": 0, "groups": 0, "max_criticality": 0, "sample": []},
                "duplicate_ip_macs": [x.get("mac") for x in other_macs],
                "duplicate_ip_sources": sorted({str(x.get("source")) for x in other_macs}),
                "is_rogue_dhcp": dev.id in self.rogue_dhcp(),
                "reachability": reach,
                "lifecycle": self.lifecycle(dev),
                "firmware_age_days": firmware_age,
                "clock_skew_seconds": dev.config.get("clock_skew_seconds"),
                "uptime_minutes": round((dev.uptime_seconds or 0) / 60.0, 1) if dev.uptime_seconds else None,
                "dangling_neighbors": [
                    {"remote": n.remote_key or n.remote_system, "local_if": n.local_if, "via": n.via}
                    for n in dev.neighbors
                    if not (n.remote_key and self.snap.find_device(n.remote_key))
                ],
                "inventory": dev.inventory or {},
                "snmp": dev.snmp or {},
                "config": dev.config or {},
                "raw": dev.raw or {},
                "certificate_summary": self._cert_summary(dev),
                "tls": self._tls_summary(dev),
                "last_seen": dev.last_seen,
            }
        )
        return d

    @staticmethod
    def _cert_summary(dev: Device) -> dict[str, Any]:
        days = None
        worst: dict[str, Any] = {}
        for svc in dev.services:
            cert = svc.certificate
            if not cert:
                continue
            item = {
                "port": svc.port,
                "protocol": cert.protocol,
                "not_after": cert.not_after,
                "days_left": cert.days_left,
                "self_signed": cert.self_signed,
                "subject_cn": cert.subject_cn,
                "cipher": cert.cipher,
                "key_bits": cert.key_bits,
                "hostname_match": cert.hostname_match,
            }
            if days is None or (cert.days_left is not None and cert.days_left < days):
                days = cert.days_left
                worst = item
        worst["min_days_left"] = days
        return worst

    @staticmethod
    def _tls_summary(dev: Device) -> dict[str, Any]:
        best_version = None
        order = {"SSLv3": 0, "TLSv1": 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4}
        weak = []
        for svc in dev.services:
            ver = str((svc.config or {}).get("tls_version") or (svc.certificate.protocol if svc.certificate else "") or "")
            if ver and (best_version is None or order.get(ver, 9) > order.get(best_version, 9)):
                best_version = ver
            if (svc.config or {}).get("weak_protocol") or (svc.config or {}).get("weak_cipher"):
                weak.append(svc.port)
        return {"best_version": best_version, "weakest_version": None, "weak_ports": sorted(weak)}

    # -- network scope -------------------------------------------------------
    def network_facts(self) -> dict[str, Any]:
        devices = self.devices
        zones = self.zones
        documented = sum(1 for d in devices if d.documented)
        snmp_readable = sum(1 for d in devices if d.snmp.get("readable"))
        auth_servers = [d for d in devices if d.has_port(list(AUTH_PORTS))]
        per_zone: dict[str, list[Device]] = defaultdict(list)
        for dev in devices:
            per_zone[dev.zone or "unassigned"].append(dev)
        unbounded = [z for z in zones.values() if not z.segmentation_enforced or not z.cidrs]
        zone_sizes_unbounded = [len(per_zone.get(z.name, [])) for z in unbounded] or [0]
        single_gateway: list[str] = []
        for zone in zones.values():
            members = per_zone.get(zone.name, [])
            gateways = [d for d in members if d.device_type in ("router", "firewall")]
            redundant = [d for d in gateways if any(getattr(p, "protected", False) for p in self.links_by_node.get(d.id, []))]
            if len(members) >= 3 and len(gateways) >= 1 and not redundant:
                single_gateway.append(f"{zone.name} ({len(gateways)} gateway device(s), none redundant)")
        guest_paths = 0
        guest_details: list[str] = []
        reach = self.reachability()
        for dev in devices:
            r = reach.get(dev.id, {}).get("untrusted") or {}
            if r.get("unfiltered") and dev.trust not in ("untrusted", "dmz") and dev.device_type not in POLICY_DEVICE_TYPES:
                guest_paths += 1
                guest_details.append(f"{dev.label} via {' -> '.join(str(x) for x in (r.get('path') or [])[:4])}")
        return {
            "device_count": len(devices),
            "reachable_count": sum(1 for d in devices if d.reachable),
            "documented": documented,
            "undocumented": len(devices) - documented,
            "undocumented_pct": round(100.0 * (len(devices) - documented) / max(1, len(devices)), 1),
            "snmp_readable": snmp_readable,
            "snmp_coverage_pct": round(100.0 * snmp_readable / max(1, len(devices)), 1),
            "devices_without_snmp": sorted({d.label for d in devices if not d.snmp.get("readable")})[:20],
            "infrastructure_count": sum(1 for d in devices if d.is_network_infrastructure),
            "auth_server_count": len(auth_servers),
            "auth_servers": sorted({d.label for d in auth_servers}),
            "zone_count": len(zones),
            "zones": [
                {
                    "name": z.name,
                    "trust": z.trust,
                    "devices": len(per_zone.get(z.name, [])),
                    "segmentation_enforced": z.segmentation_enforced,
                    "cidrs": z.cidrs,
                    "vlans": z.vlans,
                }
                for z in zones.values()
            ],
            "zone_sizes_unbounded": zone_sizes_unbounded,
            "max_zone_size_unbounded": max(zone_sizes_unbounded),
            "max_zone_unbounded": max(unbounded, key=lambda z: len(per_zone.get(z.name, []))).name if unbounded else "n/a",
            "zones_with_single_gateway": single_gateway,
            "guest_to_internal_paths": guest_paths,
            "guest_paths": guest_details[:12],
            "links": len(self.snap.links),
            "redundant_links": sum(1 for l in self.snap.links if l.protected),
            "spof_links": sum(1 for l in self.snap.links if l.is_spof),
            "duplicate_ip_count": len(self.duplicate_ips()),
            "rogue_dhcp_count": len(self.rogue_dhcp()),
            "mode": self.snap.mode,
            "scan_started": self.snap.started,
            "scan_finished": self.snap.finished,
        }

    def link_facts(self, link: Link) -> dict[str, Any]:
        src = self.by_id.get(link.src_device)
        dst = self.by_id.get(link.dst_device)
        d = link.to_dict()
        d.update(
            {
                "src_label": src.label if src else link.src_device,
                "dst_label": dst.label if dst else link.dst_device,
                "src_criticality": src.criticality if src else 0,
                "dst_criticality": dst.criticality if dst else 0,
                "src_trust": src.trust if src else "unknown",
                "dst_trust": dst.trust if dst else "unknown",
                "src_type": src.device_type if src else "unknown",
                "dst_type": dst.device_type if dst else "unknown",
                "src_zone": src.zone if src else None,
                "dst_zone": dst.zone if dst else None,
            }
        )
        return {"link": d, "src": _device_view(src), "dst": _device_view(dst), "scan": {}}


def _device_view(dev: Device | None) -> dict[str, Any]:
    if dev is None:
        return {}
    return {
        "id": dev.id,
        "label": dev.label,
        "ip": dev.ip,
        "hostname": dev.hostname,
        "device_type": dev.device_type,
        "trust": dev.trust,
        "zone": dev.zone,
        "criticality": dev.criticality,
        "documented": dev.documented,
        "os_family": dev.os_family,
        "os_version": dev.os_version,
        "uplinks": [],
    }


__all__ = ["Enricher", "POLICY_DEVICE_TYPES", "AUTH_PORTS"]
