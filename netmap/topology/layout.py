"""Deterministic hierarchical layout for the topology picture.

Pure Python (no graphviz/networkx) so the SVG and the interactive view agree
exactly, and so re-running a scan does not move boxes around: the algorithm is
stable given identical input, ordered by device id.

Columns come from network position (perimeter -> core -> access -> endpoints),
rows from zone, then subnet, then address.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

from ..models import Device, Link, ScanSnapshot, Zone

TIER_OF_TRUST = {"untrusted": 0, "dmz": 1, "unknown": 2, "internal": 3, "restricted": 3, "out_of_band": 4}
TIER_NAMES = {
    0: "Perimeter / WAN",
    1: "Edge services & DMZ",
    2: "Core & distribution",
    3: "Server, storage & restricted tiers",
    4: "Access layer & device management",
    5: "Endpoints, IoT & print",
}
DEVICE_TIER = {
    "firewall": 0,
    "router": 1,
    "load_balancer": 1,
    "proxy": 1,
    "ips_ids": 1,
    "core": 2,
    "switch": 2,
    "wireless_controller": 2,
    "hypervisor": 3,
    "server": 3,
    "database": 3,
    "web": 3,
    "mail": 3,
    "directory": 3,
    "file": 3,
    "storage": 3,
    "dns": 3,
    "dhcp": 3,
    "monitoring": 4,
    "out_of_band": 4,
    "access_point": 5,
    "printer": 5,
    "camera": 5,
    "iot": 5,
    "voip": 5,
    "workstation": 5,
    "unknown": 4,
}


@dataclass
class Position:
    id: str
    x: float
    y: float
    tier: int
    row: int


def tier_for(device: Device) -> int:
    """Network tier: perimeter first, endpoints last.

    Role wins over type where they disagree: an access switch belongs one band
    closer to its hosts than a core/distribution switch, otherwise every floor
    switch is drawn inside the backbone and the picture stops matching reality.
    """
    base = DEVICE_TIER.get(device.device_type, 4)
    role = str(device.role or "").lower()
    if device.device_type == "switch" and role.startswith("access"):
        base = 4
    trust = TIER_OF_TRUST.get(device.trust, 2)
    if device.device_type in ("firewall", "router") and trust <= 1:
        return 0
    if device.criticality >= 4 and trust >= 3:
        return min(base, 3)
    return base


def layout(
    snapshot: ScanSnapshot,
    *,
    width: float = 1500.0,
    tier_gap: float = 250.0,
    node_gap: float = 108.0,
    margin: float = 70.0,
) -> dict:
    """Place devices in horizontal trust bands, top (perimeter) to bottom.

    Bands, not columns, because the picture is read the way a rack elevation is:
    the perimeter sits at the top, endpoints at the bottom, and every band label
    can then be drawn behind its own members. Within a band, devices are grouped
    by zone so a VLAN boundary is visible without any extra annotation.
    """
    devices = [d for d in snapshot.devices if d.reachable]
    tiers: dict[int, list[Device]] = {}
    for dev in devices:
        tiers.setdefault(tier_for(dev), []).append(dev)

    per_row = max(1, int((width - 2 * margin + (node_gap - 48)) // node_gap))
    positions: dict[str, Position] = {}
    bands: dict[int, dict] = {}
    y = margin
    for tier in sorted(tiers):
        members = sorted(tiers[tier], key=lambda d: (_zone_rank(snapshot, d), d.ip or d.id, d.id))
        grouped: dict[str, list[Device]] = {}
        for dev in members:
            grouped.setdefault(dev.zone or "unassigned", []).append(dev)
        band_top = y
        y += 30.0  # room for the band label
        row_x = 0
        row_y = y
        for zone in sorted(grouped):
            zone_members = grouped[zone]
            # keep a zone's devices contiguous: jump to the next row only when the
            # group cannot finish on the current one
            if row_x + len(zone_members) > per_row and row_x:
                row_x = 0
                row_y += node_gap
            for dev in zone_members:
                positions[dev.id] = Position(
                    id=dev.id,
                    x=margin + row_x * node_gap,
                    y=row_y,
                    tier=tier,
                    row=int((row_y - band_top) // max(1.0, node_gap)),
                )
                row_x += 1
                if row_x >= per_row:
                    row_x = 0
                    row_y += node_gap
            if row_x:  # one empty slot between zone groups on the same row
                row_x = min(per_row - 1, row_x + 1)
                if row_x >= per_row - 1:
                    row_x = 0
                    row_y += node_gap
        band_height = max(tier_gap * 0.55, row_y - band_top + 18.0)
        bands[tier] = {"y0": band_top, "height": band_height, "zones": sorted(grouped)}
        y = band_top + band_height

    height = (bands[sorted(bands)[-1]]["y0"] + bands[sorted(bands)[-1]]["height"]) if bands else margin * 2
    used_width = 2 * margin + per_row * node_gap
    bounds = {
        "width": max(width, used_width),
        "height": height,
        "tiers": {t: {**_tier_meta(t, tiers[t], snapshot), "y0": bands[t]["y0"], "band_height": bands[t]["height"]} for t in sorted(tiers)},
        "counts": {str(t): len(v) for t, v in tiers.items()},
        "per_row": per_row,
    }
    return {
        "nodes": {p.id: {"x": round(p.x, 1), "y": round(p.y, 1), "tier": p.tier} for p in positions.values()},
        "bounds": bounds,
    }


def _zone_rank(snapshot: ScanSnapshot, dev: Device) -> int:
    order = {z.name: i for i, z in enumerate(snapshot.zones)}
    return order.get(dev.zone or "", 99)


def _tier_meta(tier: int, devices: list[Device], snapshot: ScanSnapshot) -> dict:
    zones = sorted({d.zone or "unassigned" for d in devices})
    return {
        "name": TIER_NAMES.get(tier, f"Tier {tier}"),
        "devices": len(devices),
        "zones": zones,
        "worst_severity": _worst(devices),
        "mean_risk": round(sum(d.risk_score for d in devices) / max(1, len(devices)), 2),
    }


def _worst(devices: Iterable[Device]) -> str:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    best, best_score = "info", 0
    for dev in devices:
        score = dev.risk_score or 0
        if score > best_score:
            best_score = score
            best = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4.5 else "low"
    return best


def edges_with_layout(snapshot: ScanSnapshot, positions: dict) -> list[dict]:
    """Prepare SVG-ready edge records (curved when endpoints share a tier)."""
    out = []
    by_id = snapshot.device_map()
    for link in snapshot.links:
        a = positions.get(link.src_device)
        b = positions.get(link.dst_device)
        if not a or not b:
            continue
        src, dst = by_id.get(link.src_device), by_id.get(link.dst_device)
        same_tier = abs(a["x"] - b["x"]) < 1
        if same_tier:
            mid = ((a["x"] + b["x"]) / 2, min(a["y"], b["y"]) - 26)
            path = f"M {a['x']} {a['y']} Q {mid[0]} {mid[1]} {b['x']} {b['y']}"
        else:
            dx = (b["x"] - a["x"]) * 0.45
            path = (
                f"M {a['x']} {a['y']} C {a['x'] + dx} {a['y']}, "
                f"{b['x'] - dx} {b['y']}, {b['x']} {b['y']}"
            )
        out.append(
            {
                "id": link.id,
                "path": path,
                "src": link.src_device,
                "dst": link.dst_device,
                "src_label": src.label if src else link.src_device,
                "dst_label": dst.label if dst else link.dst_device,
                "src_if": link.src_interface,
                "dst_if": link.dst_interface,
                "kind": link.kind,
                "confidence": link.confidence,
                "speed": link.speed_mbps,
                "spof": link.is_spof,
                "protected": link.protected,
                "risk": link.risk_score,
                "carry": link.carries,
            }
        )
    return out


def cluster_summary(devices: list[Device], zones: list[Zone]) -> list[dict]:
    """Zone rollups used by the summary strip."""
    out = []
    for zone in zones:
        members = [d for d in devices if d.zone == zone.name]
        if not members:
            continue
        out.append(
            {
                "zone": zone.name,
                "trust": zone.trust,
                "devices": len(members),
                "criticality": max(d.criticality for d in members),
                "risk": round(sum(d.risk_score for d in members) / len(members), 2),
                "types": sorted({d.device_type for d in members}),
                "cidrs": zone.cidrs,
                "vlans": zone.vlans,
            }
        )
    out.sort(key=lambda r: -r["risk"])
    return out


__all__ = ["layout", "edges_with_layout", "tier_for", "cluster_summary", "TIER_NAMES", "DEVICE_TIER", "TIER_OF_TRUST"]
