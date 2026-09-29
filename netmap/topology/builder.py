"""Topology construction: turn discovery evidence into a graph, then analyse it.

Link sources, strongest first:
  1. CDP/LLDP neighbour records (0.9+)            -- device-reported adjacency
  2. MAC-table + ARP correlation (0.75)          -- "this MAC lives on that port"
  3. Default/longest-prefix route next-hop (0.55) -- L3 adjacency without L2 proof
  4. Same-subnet inference (0.35, opt-in)         -- last resort, clearly marked

Graph analytics that matter for risk, not for show: bridges (link SPOFs),
articulation points (device SPOFs), connected components (isolated segments),
redundant-path coverage, and cross-trust reachability for segmentation checks.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

from ..models import Device, Link, ScanSnapshot, Zone
from ..util import norm_ip, parse_mac

TRUST_RANK = {"untrusted": 0, "unknown": 1, "dmz": 2, "internal": 3, "restricted": 4, "out_of_band": 5}
# an adjacency crossing more than one trust step without a firewall is a
# segmentation problem, not a topology curiosity
TRUST_DISTANCE = {
    ("untrusted", "restricted"): 3,
    ("untrusted", "internal"): 2,
    ("untrusted", "out_of_band"): 3,
    ("dmz", "restricted"): 2,
    ("dmz", "internal"): 1,
    ("internal", "restricted"): 1,
}


@dataclass
class Graph:
    nodes: list[str] = field(default_factory=list)
    adjacency: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    edges: dict[frozenset, list[Link]] = field(default_factory=dict)

    def degree(self, node: str) -> int:
        return len(self.adjacency.get(node, set()))

    def neighbours(self, node: str) -> set[str]:
        return set(self.adjacency.get(node, set()))

    def components(self) -> list[list[str]]:
        seen: set[str] = set()
        out: list[list[str]] = []
        for start in self.nodes:
            if start in seen:
                continue
            comp: list[str] = []
            queue = deque([start])
            seen.add(start)
            while queue:
                node = queue.popleft()
                comp.append(node)
                for nb in sorted(self.adjacency.get(node, ())):
                    if nb not in seen:
                        seen.add(nb)
                        queue.append(nb)
            out.append(sorted(comp))
        return out

    def bridges(self) -> list[tuple[str, str]]:
        """Tarjan bridge search: a link whose removal splits a component."""
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        parent: dict[str, str | None] = {}
        out: list[tuple[str, str]] = []
        counter = [0]

        def dfs(root: str) -> None:
            stack: list[tuple[str, Iterable[str]]] = [(root, iter(sorted(self.adjacency.get(root, ()))))]
            index[root] = low[root] = counter[0]
            counter[0] += 1
            parent[root] = None
            while stack:
                node, it = stack[-1]
                advanced = False
                for nb in it:
                    edge = frozenset((node, nb))
                    # only the first parallel link of a bundle is a bridge candidate
                    if len(self.edges.get(edge, [])) > 1:
                        continue
                    if nb not in index:
                        index[nb] = low[nb] = counter[0]
                        counter[0] += 1
                        parent[nb] = node
                        stack.append((nb, iter(sorted(self.adjacency.get(nb, ())))))
                        advanced = True
                        break
                    if nb != parent.get(node):
                        low[node] = min(low[node], index[nb])
                if advanced:
                    continue
                stack.pop()
                if stack:
                    p = stack[-1][0]
                    low[p] = min(low[p], low[node])
                    if len(self.edges.get(frozenset((p, node)), [])) <= 1 and low[node] > index[p]:
                        out.append((p, node) if p <= node else (node, p))
        for node in self.nodes:
            if node not in index:
                dfs(node)
        return sorted(set(out))

    def articulation_points(self) -> list[str]:
        """Devices whose failure disconnects the rest of their component."""
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        parent: dict[str, str | None] = {}
        found: set[str] = set()
        counter = [0]

        for root in self.nodes:
            if root in index:
                continue
            stack: list[tuple[str, object, int]] = [(root, iter(sorted(self.adjacency.get(root, ()))), 0)]
            index[root] = low[root] = counter[0]
            counter[0] += 1
            parent[root] = None
            children_of_root = 0
            while stack:
                node, it, _ = stack[-1]
                advanced = False
                for nb in it:
                    if nb in index:
                        if nb != parent.get(node):
                            low[node] = min(low[node], index[nb])
                        continue
                    parent[nb] = node
                    index[nb] = low[nb] = counter[0]
                    counter[0] += 1
                    if node == root:
                        children_of_root += 1
                    stack[-1] = (node, it, 0)
                    stack.append((nb, iter(sorted(self.adjacency.get(nb, ()))), 0))
                    advanced = True
                    break
                if advanced:
                    continue
                stack.pop()
                if stack:
                    p = stack[-1][0]
                    low[p] = min(low[p], low[node])
                    if p != root and low[node] >= index[p]:
                        found.add(p)
            if children_of_root > 1:
                found.add(root)
        return sorted(found)

    def path(self, src: str, dst: str) -> list[str]:
        if src == dst:
            return [src]
        seen = {src}
        queue = deque([(src, [src])])
        while queue:
            node, walked = queue.popleft()
            for nb in sorted(self.adjacency.get(node, ())):
                if nb in seen:
                    continue
                if nb == dst:
                    return walked + [nb]
                seen.add(nb)
                queue.append((nb, walked + [nb]))
        return []


def identity_keys(dev: Device) -> set[str]:
    """All the strings that can be used to name this device in evidence."""
    keys = {dev.id}
    if dev.ip:
        keys.add(dev.ip)
        keys.add(f"ip:{dev.ip}")
    if dev.hostname:
        keys.add(dev.hostname.lower())
        keys.add(f"host:{dev.hostname.lower()}")
    for mac in {dev.mac} | {i.mac for i in dev.interfaces if i.mac}:
        if mac:
            keys.add(mac.lower())
    for intf in dev.interfaces:
        if intf.name:
            keys.add(f"{dev.id}#{intf.name}")
    return keys


class TopologyBuilder:
    def __init__(self, snapshot: ScanSnapshot, *, min_confidence: float = 0.4, infer_l3: bool = True, same_subnet: bool = False):
        self.snap = snapshot
        self.min_confidence = float(min_confidence)
        self.infer_l3 = bool(infer_l3)
        self.same_subnet = bool(same_subnet)
        self.by_key: dict[str, Device] = {}
        for dev in snapshot.devices:
            for key in identity_keys(dev):
                self.by_key.setdefault(str(key), dev)
        self.links: dict[str, Link] = {l.id: l for l in snapshot.links}
        self.notes: list[str] = []

    # -- resolution --------------------------------------------------------
    def resolve(self, token: str | None) -> Device | None:
        if not token:
            return None
        token = str(token).strip()
        dev = self.by_key.get(token) or self.by_key.get(token.lower())
        if dev:
            return dev
        ip = norm_ip(token)
        if ip:
            dev = self.by_key.get(ip)
            if dev:
                return dev
        mac = parse_mac(token)
        if mac:
            return self.by_key.get(mac)
        # chassis id may be a hostname variant
        base = token.split(".")[0].lower()
        for key, dev in self.by_key.items():
            if key.split(".")[0].lower() == base and ":" in key and key.startswith("ip:"):
                return dev
            host = dev.hostname or ""
            if host and host.split(".")[0].lower() == base:
                return dev
        return None

    def add_link(self, src: Device, dst: Device, *, src_if: str | None, dst_if: str | None, kind: str, confidence: float, derived_from: str, speed: int | None = None) -> Link | None:
        if src.id == dst.id:
            return None
        if confidence < self.min_confidence:
            return None
        a, b = sorted([src.id, dst.id])
        link_id = f"link:{a}~{b}"
        existing = self.links.get(link_id)
        if existing:
            # merge both directions of a correctly-running neighbour protocol
            improved = confidence > existing.confidence
            if existing.kind == "inferred-l3" and kind != "inferred-l3":
                improved = True
            if improved:
                existing.kind = kind
                existing.confidence = max(existing.confidence, confidence)
                existing.derived_from = derived_from
            if src.id == existing.src_device:
                existing.src_interface = existing.src_interface or src_if
                existing.dst_interface = existing.dst_interface or dst_if
            else:
                existing.src_interface = existing.src_interface or dst_if
                existing.dst_interface = existing.dst_interface or src_if
            if speed:
                existing.speed_mbps = min(existing.speed_mbps or speed, speed)
            return existing
        link = Link(
            id=link_id,
            src_device=src.id,
            dst_device=dst.id,
            src_interface=src_if,
            dst_interface=dst_if,
            kind=kind,
            confidence=round(float(confidence), 3),
            derived_from=derived_from,
            speed_mbps=speed,
        )
        self.links[link_id] = link
        return link

    # -- sources -----------------------------------------------------------
    def from_neighbours(self) -> int:
        count = 0
        for dev in self.snap.devices:
            for nb in dev.neighbors:
                peer = self.resolve(nb.remote_key) or self.resolve(nb.remote_system) or self.resolve(nb.remote_ip) or self.resolve(nb.remote_chassis_id)
                if peer is None:
                    self.notes.append(f"{dev.label}: neighbour {nb.remote_key or nb.remote_system} not discovered (adjacency recorded as dangling)")
                    continue
                speed = None
                local = dev.interface(nb.local_if)
                if local and local.speed_mbps:
                    speed = local.speed_mbps
                kind = "port-channel" if _is_bundle(nb.local_if) or _is_bundle(nb.remote_port) else "ethernet"
                link = self.add_link(
                    dev,
                    peer,
                    src_if=nb.local_if,
                    dst_if=nb.remote_port,
                    kind=kind,
                    confidence=nb.confidence,
                    derived_from=nb.via,
                    speed=speed,
                )
                if link is not None:
                    count += 1
        return count

    def from_mac_tables(self) -> int:
        """Attach hosts to switch ports using FDB + ARP correlation."""
        mac_to_host: dict[str, Device] = {}
        for dev in self.snap.devices:
            for mac in {dev.mac} | {i.mac for i in dev.interfaces if i.mac}:
                if mac:
                    mac_to_host.setdefault(mac.lower(), dev)
        count = 0
        for sw in self.snap.devices:
            if not sw.fdb:
                continue
            if_index_to_name = {i.if_index: i.name for i in sw.interfaces}
            arp_by_mac = {a.mac.lower(): a for a in sw.arp if a.mac}
            for entry in sw.fdb:
                if not entry.mac:
                    continue
                host = mac_to_host.get(entry.mac.lower())
                if host is None or host.id == sw.id:
                    continue
                if self.snap.links and any(
                    {sw.id, host.id} == {l.src_device, l.dst_device} for l in self.links.values()
                ):
                    continue  # already proven by CDP/LLDP
                arp = arp_by_mac.get(entry.mac.lower())
                if arp is None and host.ip and host.ip not in {a.ip for a in sw.arp}:
                    continue  # not learned on this switch: skip rather than guess
                port_name = if_index_to_name.get(entry.if_index) or (f"port-{entry.port}" if entry.port else None)
                kind = "port-channel" if _is_bundle(port_name) else "ethernet"
                link = self.add_link(
                    sw,
                    host,
                    src_if=port_name,
                    dst_if=None,
                    kind=kind,
                    confidence=0.75,
                    derived_from="mac_table+arp",
                    speed=None,
                )
                if link is not None:
                    count += 1
        return count

    def from_routing(self) -> int:
        if not self.infer_l3:
            return 0
        count = 0
        by_ip = {d.ip: d for d in self.snap.devices if d.ip}
        for dev in self.snap.devices:
            for route in dev.routes:
                hop = route.next_hop
                peer = by_ip.get(hop) if hop else None
                if peer is None or peer.id == dev.id:
                    continue
                already = any({dev.id, peer.id} == {l.src_device, l.dst_device} for l in self.links.values())
                if already:
                    continue
                is_default = str(route.dest or "").startswith("0.0.0.0")
                link = self.add_link(
                    dev,
                    peer,
                    src_if=dev.interface(_ifname(dev, route.if_index)).name if route.if_index else None,
                    dst_if=None,
                    kind="inferred-l3",
                    confidence=0.5 if is_default else 0.55,
                    derived_from="route-table",
                )
                if link is not None:
                    count += 1
        return count

    def from_subnets(self) -> int:
        if not self.same_subnet:
            return 0
        by_subnet: dict[str, list[Device]] = defaultdict(list)
        gateways = set()
        for gw in self.snap.zones:
            if gw.default_gateway:
                gateways.add(gw.default_gateway)
        for dev in self.snap.devices:
            if not dev.ip:
                continue
            try:
                subnet = ".".join(dev.ip.split(".")[:3])
                if len(subnet.split(".")) != 3:
                    continue
            except (AttributeError, ValueError):
                continue
            by_subnet[subnet].append(dev)
        count = 0
        for subnet, members in by_subnet.items():
            if len(members) < 2 or len(members) > 40:
                continue
            gw = next((m for m in members if m.ip in gateways), None)
            if gw is None:
                # No configured gateway: fall back to the subnet's first
                # usable address, but only if that host was actually
                # discovered, reachable, and serves something (typically the
                # home router's admin/DNS). Never invents a gateway.
                candidate = next((m for m in members if m.ip == f"{subnet}.1"), None)
                if (
                    candidate is None
                    or not candidate.reachable
                    or not any(s.is_open for s in candidate.services)
                ):
                    continue
                gw = candidate
            elif not gw.is_network_infrastructure:
                continue
            for dev in members:
                if dev.id == gw.id:
                    continue
                if any({dev.id, gw.id} == {l.src_device, l.dst_device} for l in self.links.values()):
                    continue
                link = self.add_link(gw, dev, src_if=None, dst_if=None, kind="virtual", confidence=0.4, derived_from="same-subnet")
                if link is not None:
                    count += 1
        return count

    # -- analysis ----------------------------------------------------------
    def graph(self) -> Graph:
        g = Graph(nodes=sorted(d.id for d in self.snap.devices))
        for link in self.links.values():
            g.adjacency[link.src_device].add(link.dst_device)
            g.adjacency[link.dst_device].add(link.src_device)
            g.edges.setdefault(frozenset((link.src_device, link.dst_device)), []).append(link)
        return g

    def annotate(self) -> dict:
        """Fill redundancy / SPOF / trust-crossing facts on links and devices."""
        g = self.graph()
        by_id = self.snap.device_map()
        bridges = set(g.bridges())
        articulation = set(g.articulation_points())
        groups: dict[str, int] = defaultdict(int)
        for link in self.links.values():
            pair = frozenset((link.src_device, link.dst_device))
            parallel = g.edges.get(pair, [])
            if len(parallel) > 1:
                for l in parallel:
                    l.redundant_group = f"{min(link.src_device, link.dst_device)}~{max(link.src_device, link.dst_device)}"
                    l.protected = True
            else:
                link.protected = False
            src, dst = by_id.get(link.src_device), by_id.get(link.dst_device)
            if src and dst:
                crossing = trust_distance(src.trust, dst.trust)
                if crossing >= 2:
                    link.carries.append(f"trust-crossing:{src.trust}->{dst.trust}")
                    link.risk_score = max(link.risk_score, 6.0 if min(src.criticality, dst.criticality) >= 4 else 4.0)
            if tuple(sorted((link.src_device, link.dst_device))) in bridges or frozenset((link.src_device, link.dst_device)) in {frozenset(b) for b in bridges}:
                link.is_spof = True
                link.risk_score = max(link.risk_score, 5.0)
        for dev in self.snap.devices:
            dev.raw["degree"] = g.degree(dev.id)
            dev.raw["component"] = None
            dev.raw["is_articulation_point"] = dev.id in articulation
            uplinks = [l for l in self.links.values() if dev.id in (l.src_device, l.dst_device)]
            dev.neighbors = dev.neighbors or []
            if not dev.uplink_count:
                dev.raw["uplinks_from_links"] = len(uplinks)
        comps = g.components()
        for i, comp in enumerate(comps):
            for node in comp:
                dev = by_id.get(node)
                if dev:
                    dev.raw["component"] = i
                    dev.raw["component_size"] = len(comp)
                    dev.raw["isolated"] = len(comp) == 1
        metrics = {
            "nodes": len(g.nodes),
            "edges": len(self.links),
            "components": len(comps),
            "isolated_nodes": sum(1 for c in comps if len(c) == 1),
            "largest_component": max((len(c) for c in comps), default=0),
            "bridges": len(bridges),
            "articulation_points": len(articulation),
            "redundant_pairs": sum(1 for l in self.links.values() if l.protected) // 2,
            "link_coverage_pct": round(100.0 * len({n for l in self.links.values() for n in (l.src_device, l.dst_device)}) / max(1, len(g.nodes)), 1),
            "mean_degree": round(2 * len(self.links) / max(1, len(g.nodes)), 2),
            "trust_crossings": _trust_crossings(self.links.values(), by_id),
        }
        return metrics


def _trust_crossings(links: Iterable[Link], by_id: dict[str, Device]) -> list[str]:
    out = set()
    for l in links:
        src, dst = by_id.get(l.src_device), by_id.get(l.dst_device)
        if not src or not dst:
            continue
        if src.trust != dst.trust:
            out.add(f"{src.trust}->{dst.trust}")
    return sorted(out)


def trust_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    key = (a, b) if TRUST_RANK.get(a, 1) <= TRUST_RANK.get(b, 1) else (b, a)
    if key in TRUST_DISTANCE:
        return TRUST_DISTANCE[key]
    return abs(TRUST_RANK.get(a, 1) - TRUST_RANK.get(b, 1))


def _is_bundle(name: str | None) -> bool:
    if not name:
        return False
    low = str(name).lower()
    return any(tok in low for tok in ("po-", "port-channel", "portchannel", "ae", "irb", "bundle", "lacp", "lag", "mc-lag"))


def _ifname(dev: Device, if_index: int | None) -> str | None:
    if not if_index:
        return None
    for intf in dev.interfaces:
        if intf.if_index == int(if_index):
            return intf.name
    return None


def build_topology(snapshot: ScanSnapshot, cfg_get=None) -> dict:
    """Entry point used by the CLI/web: build links, annotate, return metrics."""
    get = cfg_get or (lambda key, default=None: default)
    builder = TopologyBuilder(
        snapshot,
        min_confidence=float(get("topology.min_confidence", 0.4)),
        infer_l3=bool(get("topology.infer_l3_via_routing", True)),
        same_subnet=bool(get("topology.treat_same_subnet_as_adjacency", False)),
    )
    counts = {
        "neighbour_protocol": builder.from_neighbours(),
        "mac_table": builder.from_mac_tables(),
        "routing": builder.from_routing(),
        "same_subnet": builder.from_subnets(),
    }
    links = sorted(builder.links.values(), key=lambda l: l.id)
    snapshot.links = links
    metrics = builder.annotate()
    metrics["derived_from"] = counts
    metrics["notes"] = builder.notes[:20]
    return metrics


__all__ = ["Graph", "TopologyBuilder", "build_topology", "trust_distance", "TRUST_RANK", "TRUST_DISTANCE"]
