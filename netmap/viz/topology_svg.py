"""Trust-tier topology rendering as a self-contained SVG.

The picture is the deliverable network teams actually look at, so it is drawn
by hand (no graphviz, no JS library) and stays readable when embedded in a HTML
report, a slide, or an offline iframe: every style is an attribute on the
element, every tooltip is a ``<title>``, and no external file is referenced.
"""

from __future__ import annotations

import html
from typing import Any

from ..models import ScanSnapshot
from ..topology.layout import edges_with_layout, layout
from ..util import SEVERITY_ORDER

SEV_COLORS = {
    "critical": "#b3261e",
    "high": "#d8530e",
    "medium": "#b58900",
    "low": "#3b78c4",
    "info": "#6b7280",
    "none": "#2f855a",
}
TIER_BAND = ["#fde8e8", "#fff4e5", "#fefce8", "#eef6ff", "#f0fdf4", "#faf5ff"]
TYPE_GLYPH = {
    "firewall": "FW",
    "router": "RT",
    "switch": "SW",
    "access_point": "AP",
    "wireless_controller": "WC",
    "load_balancer": "LB",
    "server": "SV",
    "web": "WEB",
    "database": "DB",
    "directory": "AD",
    "storage": "ST",
    "hypervisor": "HV",
    "out_of_band": "BMC",
    "workstation": "PC",
    "laptop": "LT",
    "printer": "PRT",
    "camera": "CAM",
    "phone": "PH",
    "iot": "IOT",
    "voip": "VOIP",
    "unknown": "??",
}


def _sev_for(risk: float, findings: int) -> str:
    if findings <= 0:
        return "none"
    if risk >= 9:
        return "critical"
    if risk >= 7:
        return "high"
    if risk >= 4.5:
        return "medium"
    if risk >= 2:
        return "low"
    return "info"


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_svg(
    snapshot: ScanSnapshot,
    *,
    width: float = 1500.0,
    title: str | None = None,
    max_nodes: int = 260,
    show_ports: bool = True,
) -> str:
    """Return an SVG document (string) of the mapped network, tiered by trust."""
    devices = list(snapshot.devices)
    truncated = len(devices) > max_nodes
    if truncated:
        devices = sorted(devices, key=lambda d: (-(d.risk_score or 0), d.label))[:max_nodes]
    view = ScanSnapshot(devices=devices, links=snapshot.links, zones=snapshot.zones, findings=snapshot.findings)
    count = max(1, len(devices))
    band_top = 60.0
    node_gap = 108.0 if count <= 18 else (92.0 if count <= 40 else 76.0)
    placed = layout(view, width=width, node_gap=node_gap, tier_gap=240.0 if count <= 40 else 200.0)
    pos = placed["nodes"]
    tiers = (placed["bounds"] or {}).get("tiers") or {}
    height = float(placed["bounds"]["height"]) + 84

    findings_by_dev: dict[str, list[dict]] = {}
    for f in snapshot.findings:
        if f.scope != "device" or not f.target_id:
            continue
        findings_by_dev.setdefault(f.target_id, []).append({"sev": f.severity, "title": f.rule_title, "rule": f.rule_id})

    def node_of(dev_id: str) -> dict:
        return pos.get(dev_id) or {"x": 0.0, "y": 0.0, "tier": 0}

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'width="100%" height="auto" font-family="ui-sans-serif,Segoe UI,Roboto,Helvetica,Arial,sans-serif" '
        f'font-size="11" role="img" aria-label="network topology">'
    )
    parts.append(
        "<defs>"
        '<marker id="nm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#9aa3af"/></marker>'
        '<filter id="nm-shadow" x="-30%" y="-30%" width="160%" height="160%">'
        '<feDropShadow dx="0" dy="1" stdDeviation="1.4" flood-color="#0f172a" flood-opacity="0.18"/></filter>'
        "</defs>"
    )
    parts.append(f'<rect x="0" y="0" width="{width:.0f}" height="{height:.0f}" fill="#ffffff"/>')
    top = title or f"NetMap topology - {len(snapshot.devices)} devices, {len(snapshot.links)} links"
    parts.append(f'<text x="24" y="26" font-size="16" font-weight="700" fill="#0f172a">{_esc(top)}</text>')
    parts.append(f'<text x="24" y="44" font-size="11" fill="#64748b">{_esc(snapshot.mode)} scan &#8226; {_esc(snapshot.finished or snapshot.started or "")}</text>')

    # ---- tier bands (geometry comes from the layout, so labels sit behind their own row)
    for idx in sorted({int(meta_key) for meta_key in tiers} | {int(p["tier"]) for p in pos.values()}):
        meta = tiers.get(str(idx)) or tiers.get(idx) or {}
        y0 = float(meta.get("y0") or (70.0 + idx * 240.0)) - 16.0
        band_h = float(meta.get("band_height") or 224.0)
        parts.append(
            f'<rect x="16" y="{y0:.1f}" width="{width - 32:.0f}" height="{band_h:.1f}" rx="10" '
            f'fill="{TIER_BAND[idx % len(TIER_BAND)]}" stroke="#e2e8f0" stroke-width="1"/>'
        )
        label = meta.get("name") or f"tier {idx}"
        extra = f"{meta.get('devices', 0)} devices"
        if meta.get("zones"):
            extra += " • " + ", ".join(str(z) for z in meta["zones"][:6])
        parts.append(f'<text x="30" y="{y0 + 15:.1f}" font-size="11.5" font-weight="700" fill="#475569">{_esc(label.upper())}</text>')
        parts.append(f'<text x="30" y="{y0 + 29:.1f}" font-size="10" fill="#64748b">{_esc(extra)}</text>')
    # ---- links ------------------------------------------------------------
    edges = edges_with_layout(view, pos)
    for edge in edges:
        spof = bool(edge.get("spof"))
        protected = bool(edge.get("protected"))
        colour = "#c2410c" if spof else ("#0f766e" if protected else "#94a3b8")
        dash = ' stroke-dasharray="6 4"' if spof else ""
        width_attr = 2.6 if spof else (2.2 if protected else 1.4)
        tip = f"{edge['src_label']}:{edge.get('src_if') or '?'}  <->  {edge['dst_label']}:{edge.get('dst_if') or '?'}"
        bits = [f"{edge.get('kind') or 'ethernet'}"]
        if edge.get("speed"):
            bits.append(f"{int(edge['speed'])} Mbps")
        if spof:
            bits.append("single point of failure")
        if protected:
            bits.append("redundant (protected)")
        bits.append(f"confidence {edge.get('confidence')}")
        tip += "  |  " + ", ".join(bits)
        parts.append(
            f'<path d="{edge["path"]}" fill="none" stroke="{colour}" stroke-width="{width_attr}"{dash} '
            f'marker-end="url(#nm-arrow)"><title>{_esc(tip)}</title></path>'
        )
        if protected:
            parts.append(f'<path d="{edge["path"]}" fill="none" stroke="{colour}" stroke-opacity="0.25" stroke-width="6"/>')

    # ---- nodes ------------------------------------------------------------
    by_id = {d.id: d for d in devices}
    for dev in devices:
        p = node_of(dev.id)
        x, y = float(p["x"]), float(p["y"])
        hits = findings_by_dev.get(dev.id) or []
        worst_order = min([SEVERITY_ORDER.index(h["sev"]) for h in hits], default=99)
        sev = _sev_for(dev.risk_score or 0.0, len(hits))
        colour = SEV_COLORS.get(sev, "#64748b")
        worst_is_crit = worst_order <= 1
        w, h = 128.0, 46.0
        stroke = colour if worst_is_crit else "#cbd5e1"
        sw = 2.4 if worst_is_crit else 1.2
        glyph = TYPE_GLYPH.get(dev.device_type or "unknown", "?")
        label = dev.hostname or dev.ip or dev.id
        sub = f"{dev.ip or ''} · {len(dev.open_ports)} ports" if show_ports else (dev.device_type or "")
        parts.append(
            f'<g class="nm-node" data-id="{_esc(dev.id)}" data-zone="{_esc(dev.zone)}" data-sev="{sev}" filter="url(#nm-shadow)">'
        )
        parts.append(
            f'<rect x="{x - w / 2:.1f}" y="{y - h / 2:.1f}" width="{w:.0f}" height="{h:.0f}" rx="9" '
            f'fill="#ffffff" stroke="{stroke}" stroke-width="{sw}"/>'
        )
        parts.append(
            f'<rect x="{x - w / 2:.1f}" y="{y - h / 2:.1f}" width="26" height="{h:.0f}" rx="9" fill="{colour}" fill-opacity="0.16" stroke="none"/>'
        )
        parts.append(f'<text x="{x - w / 2 + 13:.1f}" y="{y + 4:.1f}" text-anchor="middle" font-size="9.5" font-weight="700" fill="{colour}">{_esc(glyph)}</text>')
        parts.append(f'<text x="{x - w / 2 + 32:.1f}" y="{y - 5:.1f}" font-size="11" font-weight="650" fill="#0f172a">{_esc(label[:22])}</text>')
        parts.append(f'<text x="{x - w / 2 + 32:.1f}" y="{y + 9:.1f}" font-size="9.5" fill="#64748b">{_esc(sub[:34])}</text>')
        badges = []
        if not dev.documented:
            badges.append(("undocumented", "#b3261e"))
        if dev.exposed_to_wan:
            badges.append(("WAN", "#b3261e"))
        if (dev.snmp or {}).get("readable"):
            badges.append(("SNMP", "#1d4ed8"))
        if any((svc.name or "") in ("telnet", "ftp", "http", "snmp") and svc.is_open for svc in dev.services):
            badges.append(("cleartext", "#c2410c"))
        if dev.is_network_infrastructure and int(dev.uplink_count or 0) <= 1:
            badges.append(("1 uplink", "#0f766e"))
        for i, (text, col) in enumerate(badges[:3]):
            bx = x - w / 2 + 32 + i * 33
            parts.append(
                f'<rect x="{bx:.1f}" y="{y + 12:.1f}" width="31" height="11" rx="5.5" fill="{col}" fill-opacity="0.13"/>'
                f'<text x="{bx + 15.5:.1f}" y="{y + 20.5:.1f}" text-anchor="middle" font-size="7.5" font-weight="700" fill="{col}">{_esc(text)}</text>'
            )
        if hits:
            parts.append(
                f'<circle cx="{x + w / 2 - 12:.1f}" cy="{y - h / 2 + 12:.1f}" r="10.5" fill="{colour}"/>'
                f'<text x="{x + w / 2 - 12:.1f}" y="{y - h / 2 + 15.5:.1f}" text-anchor="middle" font-size="9.5" font-weight="700" fill="#ffffff">{len(hits)}</text>'
            )
        tooltip = (
            f"{label} — {dev.device_type or 'unknown'}\n"
            f"zone {dev.zone or '—'} · trust {dev.trust or '—'} · criticality {dev.criticality}\n"
            f"risk {float(dev.risk_score or 0):.1f}/10 · {len(hits)} finding(s)\n"
            + "\n".join(f"• {h['sev']}: {h['title']}" for h in sorted(hits, key=lambda h: SEVERITY_ORDER.index(h["sev"]))[:6])
        )
        parts.append(f"<title>{_esc(tooltip).replace(chr(10), '&#10;')}</title>")
        parts.append("</g>")

    # ---- legend -----------------------------------------------------------
    ly = height - 40
    parts.append(f'<text x="24" y="{ly - 6:.0f}" font-size="10.5" font-weight="700" fill="#475569">LEGEND</text>')
    lx = 24.0
    for name, colour in (("critical", SEV_COLORS["critical"]), ("high", SEV_COLORS["high"]), ("medium", SEV_COLORS["medium"]), ("low", SEV_COLORS["low"]), ("clean", SEV_COLORS["none"])):
        parts.append(f'<rect x="{lx:.0f}" y="{ly:.0f}" width="11" height="11" rx="3" fill="{colour}" fill-opacity="0.22" stroke="{colour}"/>')
        parts.append(f'<text x="{lx + 16:.0f}" y="{ly + 9:.0f}" font-size="10" fill="#334155">{name}</text>')
        lx += 74.0
    parts.append(f'<line x1="{lx:.0f}" y1="{ly + 5.5:.0f}" x2="{lx + 26:.0f}" y2="{ly + 5.5:.0f}" stroke="#c2410c" stroke-width="2.4" stroke-dasharray="6 4"/>')
    parts.append(f'<text x="{lx + 32:.0f}" y="{ly + 9:.0f}" font-size="10" fill="#334155">SPOF link</text>')
    lx += 128.0
    parts.append(f'<line x1="{lx:.0f}" y1="{ly + 5.5:.0f}" x2="{lx + 26:.0f}" y2="{ly + 5.5:.0f}" stroke="#0f766e" stroke-width="2.2"/>')
    parts.append(f'<text x="{lx + 32:.0f}" y="{ly + 9:.0f}" font-size="10" fill="#334155">redundant link</text>')
    lx += 132.0
    if truncated:
        parts.append(f'<text x="{lx + 8:.0f}" y="{ly + 9:.0f}" font-size="10" fill="#b3261e">showing the {count} highest-risk of {len(snapshot.devices)} devices</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def render_svg_data_uri(snapshot: ScanSnapshot, **kw) -> str:
    import base64

    svg = render_svg(snapshot, **kw)
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")


__all__ = ["render_svg", "render_svg_data_uri", "SEV_COLORS"]
