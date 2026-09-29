"""Self-contained HTML view (dashboard export).

Everything the reader needs is in one file: CSS, the topology SVG, the finding
table and a few lines of vanilla JS for filtering. It has to survive being
emailed as an attachment or opened from a sandboxed preview with no network
access, so nothing here references a CDN, a font file or an image.
"""

from __future__ import annotations

import html
import json
from typing import Any

from ..models import ScanSnapshot
from ..util import SEVERITY_ORDER

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;
--critical:#b3261e;--high:#d8530e;--medium:#b58900;--low:#3b78c4;--info:#6b7280;--ok:#0f766e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1360px;margin:0 auto;padding:22px 20px 60px}
header.top{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;
background:linear-gradient(135deg,#0f172a,#1e293b);color:#f8fafc;border-radius:14px;padding:18px 20px}
header.top h1{margin:0;font-size:20px;letter-spacing:.2px}
header.top .sub{color:#cbd5e1;font-size:12.5px;margin-top:4px}
.score{display:flex;align-items:center;gap:14px}
.score .num{font-size:34px;font-weight:800;line-height:1}
.score .band{font-size:12px;text-transform:uppercase;letter-spacing:.12em;opacity:.85}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.card .v{font-size:22px;font-weight:700;margin-top:3px}
.card .n{font-size:11.5px;color:var(--muted)}
section{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:16px 0;overflow:hidden}
section>h2{margin:0;padding:14px 16px;font-size:14.5px;border-bottom:1px solid var(--line);
display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}
section>.body{padding:14px 16px}
table{width:100%;border-collapse:collapse;font-size:12.8px}
th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:#f8fafc;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#475569;
position:sticky;top:0;cursor:pointer;user-select:none}
tbody tr:hover{background:#f8fafc}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;
color:#fff;white-space:nowrap}
.chip.critical{background:var(--critical)}.chip.high{background:var(--high)}
.chip.medium{background:var(--medium)}.chip.low{background:var(--low)}
.chip.info{background:var(--info)}.chip.ok{background:var(--ok)}
.chip.ghost{background:#eef2f7;color:#475569;font-weight:600}
.bar{height:7px;border-radius:4px;background:#eef2f7;overflow:hidden;min-width:70px}
.bar i{display:block;height:100%}
.tools{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.tools input,.tools select{padding:5px 9px;border:1px solid var(--line);border-radius:8px;font:inherit;font-size:12.5px}
.tools button{padding:5px 10px;border:1px solid var(--line);background:#fff;border-radius:999px;cursor:pointer;font-size:12px}
.tools button[aria-pressed=true]{background:#0f172a;color:#fff;border-color:#0f172a}
.scroll{max-height:520px;overflow:auto}
.svg-wrap{padding:8px;background:#fff;overflow:auto}
.svg-wrap svg{max-width:100%;height:auto}
details{border-top:1px solid var(--line);padding:0}
summary{cursor:pointer;padding:9px 12px;background:#f8fafc;font-weight:650;font-size:12.8px}
.ev{margin:6px 0 0;padding-left:16px;font-size:12.3px;color:#334155}
.ev li{margin:2px 0}
.refs{font-size:11.5px;color:var(--muted)}
.refs code{background:#f1f5f9;padding:1px 5px;border-radius:5px;font-size:11px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
footer{color:var(--muted);font-size:11.5px;text-align:center;margin-top:18px}
.hidden{display:none}
h3.mini{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:14px 0 6px}
@media print{.tools{display:none}section{break-inside:avoid;border:none}body{background:#fff}}
"""

JS = """
(function(){
  var t = document.getElementById('findings');
  if(!t) return;
  var sev = {}, search = '';
  function apply(){
    t.querySelectorAll('tbody tr').forEach(function(tr){
      var okSev = !Object.keys(sev).length || sev[tr.dataset.sev];
      var hay = (tr.dataset.hay||'');
      var okText = !search || hay.indexOf(search) > -1;
      tr.classList.toggle('hidden', !(okSev && okText));
    });
    var n = t.querySelectorAll('tbody tr:not(.hidden)').length;
    var el = document.getElementById('fcount'); if(el) el.textContent = n + ' shown';
  }
  document.querySelectorAll('[data-sev-filter]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var k = btn.dataset.sevFilter;
      sev[k] = !sev[k];
      btn.setAttribute('aria-pressed', sev[k] ? 'true':'false');
      apply();
    });
  });
  var box = document.getElementById('fsearch');
  if(box) box.addEventListener('input', function(){ search = box.value.toLowerCase().trim(); apply(); });
  t.querySelectorAll('th').forEach(function(th, i){
    th.addEventListener('click', function(){
      var tb = t.tBodies[0], rows = Array.prototype.slice.call(tb.rows);
      var dir = th.dataset.dir === 'asc' ? 'desc' : 'asc'; th.dataset.dir = dir;
      rows.sort(function(a,b){
        var x = a.cells[i].innerText.trim(), y = b.cells[i].innerText.trim();
        var nx = parseFloat(x), ny = parseFloat(y);
        var c = (!isNaN(nx) && !isNaN(ny)) ? nx - ny : x.localeCompare(y);
        return dir === 'asc' ? c : -c;
      });
      rows.forEach(function(r){ tb.appendChild(r); });
    });
  });
})();
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _chip(sev: str) -> str:
    return f'<span class="chip {_e(sev)}">{_e(sev)}</span>'


def _bar(pct: float, colour: str = "#0f766e") -> str:
    pct = max(0.0, min(100.0, float(pct)))
    return f'<div class="bar"><i style="width:{pct:.0f}%;background:{colour}"></i></div>'


def _gauge(score: float) -> str:
    pct = max(0.0, min(1.0, float(score) / 10.0))
    colour = "#b3261e" if pct > 0.85 else "#d8530e" if pct > 0.65 else "#b58900" if pct > 0.4 else "#0f766e"
    r, cx, cy = 26.0, 32.0, 32.0
    import math

    def point(frac):
        a = math.pi * (1 - frac)
        return cx + r * math.cos(a), cy - r * math.sin(a)

    x1, y1 = point(0)
    x2, y2 = point(pct)
    large = 1 if pct > 0.5 else 0
    return (
        f'<svg width="64" height="44" viewBox="0 0 64 44" aria-hidden="true">'
        f'<path d="M {x1:.1f} {y1:.1f} A {r:.0f} {r:.0f} 0 0 1 {cx + r:.1f} {cy:.1f}" fill="none" stroke="#334155" stroke-width="7" stroke-linecap="round" opacity=".35"/>'
        f'<path d="M {x1:.1f} {y1:.1f} A {r:.0f} {r:.0f} 0 {large} 1 {x2:.1f} {y2:.1f}" fill="none" stroke="{colour}" stroke-width="7" stroke-linecap="round"/>'
        f"</svg>"
    )


def render_html(snapshot: ScanSnapshot, *, svg: str | None = None, title: str | None = None, include_svg: bool = True) -> str:
    risk = snapshot.risk or {}
    summary = snapshot.summary or {}
    score = float(risk.get("score") or 0)
    band = str(risk.get("band") or "unknown")
    counts = {sev: sum(1 for f in snapshot.findings if f.severity == sev and f.status == "open") for sev in SEVERITY_ORDER}
    metrics = (snapshot.config or {}).get("topology_metrics") or {}
    doc_title = title or f"NetMap - {snapshot.snapshot_id or 'network report'}"

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{_e(doc_title)}</title>",
        f"<style>{CSS}</style></head><body><div class='wrap'>",
    ]
    # ---------------------------------------------------------------- header
    parts.append(
        "<header class='top'><div>"
        f"<h1>{_e(doc_title)}</h1>"
        f"<div class='sub'>mode {_e(snapshot.mode)} &nbsp;•&nbsp; {_e(snapshot.operator or 'operator not set')} "
        f"&nbsp;•&nbsp; started {_e(snapshot.started)} &nbsp;•&nbsp; finished {_e(snapshot.finished)} "
        f"&nbsp;•&nbsp; {_e(snapshot.duration_seconds)}s &nbsp;•&nbsp; schema {_e(snapshot.schema_version)}"
        f"&nbsp;•&nbsp; netmap {_e(snapshot.scanner_version)}</div>"
        "</div>"
        f"<div class='score'>{_gauge(score)}<div><div class='num'>{score:.1f}</div>"
        f"<div class='band'>{_e(band)} risk</div></div></div></header>"
    )
    # ---------------------------------------------------------------- KPI cards
    devices = snapshot.devices
    cards = [
        ("Devices", len(devices), f"{sum(1 for d in devices if d.reachable)} reachable"),
        ("Links", len(snapshot.links), f"{metrics.get('bridges', 0)} SPOF bridges, {metrics.get('isolated_nodes', 0)} isolated"),
        ("Critical", counts.get("critical", 0), f"{counts.get('high', 0)} high"),
        ("Medium+", counts.get("medium", 0) + counts.get("high", 0) + counts.get("critical", 0), f"{counts.get('low', 0)} low, {counts.get('info', 0)} info"),
        ("Services", sum(len(d.open_ports) for d in devices), f"{len({p for d in devices for p in d.open_ports})} distinct ports"),
        ("Undocumented", f"{summary.get('devices', {}).get('undocumented_pct', 0)}%", f"{summary.get('devices', {}).get('undocumented', 0)} devices"),
        ("SNMP coverage", f"{metrics.get('snmp_coverage_pct', risk.get('coverage', {}).get('snmp_pct', 0)) or 0}%", "readable devices"),
        ("Accepted risk", len(snapshot.findings) - sum(counts.values()), "suppressed / excepted"),
    ]
    parts.append("<div class='cards'>")
    for key, val, note in cards:
        parts.append(f"<div class='card'><div class='k'>{_e(key)}</div><div class='v'>{_e(val)}</div><div class='n'>{_e(note)}</div></div>")
    parts.append("</div>")

    # ---------------------------------------------------------------- families + zones
    families = risk.get("families") or {}
    if families:
        parts.append("<section><h2>Where the risk comes from</h2><div class='body'><table><thead><tr>"
                     "<th>Rule family</th><th>Findings</th><th>Weighted score</th><th>Worst</th><th>Share</th></tr></thead><tbody>")
        total = max(1.0, sum(float(v.get("score") or 0) for v in families.values()))
        for fam, meta in families.items():
            share = 100.0 * float(meta.get("score") or 0) / total
            parts.append(
                f"<tr><td><b>{_e(fam)}</b></td><td class='num'>{_e(meta.get('count'))}</td>"
                f"<td class='num'>{_e(meta.get('score'))}</td><td>{_chip(meta.get('worst') or 'info')}</td>"
                f"<td>{_bar(share, '#b3261e' if share > 30 else '#d8530e')}</td></tr>"
            )
        parts.append("</tbody></table></div></section>")

    # ---------------------------------------------------------------- findings
    parts.append(
        "<section><h2><span>Findings</span><span class='tools'>"
        + "".join(
            f"<button data-sev-filter='{sev}' aria-pressed='false'>{sev} ({counts.get(sev, 0)})</button>"
            for sev in ("critical", "high", "medium", "low")
            if counts.get(sev)
        )
        + "<input id='fsearch' placeholder='filter: ip, host, rule, port, zone…' size='30'>"
        + "<span id='fcount' class='chip ghost'></span></span></h2>"
        "<div class='scroll'><table id='findings'><thead><tr>"
        "<th>Sev</th><th>Rule</th><th>Target</th><th>Title</th><th>Score</th><th>Conf</th><th>Detail / fix</th>"
        "</tr></thead><tbody>"
    )
    for f in sorted((f for f in snapshot.findings), key=lambda x: x.sort_key):
        hay = _e(" ".join([f.rule_id, f.rule_title, f.target_label, f.severity, f.zone or "", " ".join(ev.get("text", "") for ev in f.evidence)])).lower()
        detail = "".join(f"<li>{_e(ev.get('text'))}</li>" for ev in f.evidence[:4])
        refs = " ".join(f"<code>{_e(k)}: {_e(v)}</code>" for k, v in (f.refs or {}).items() if k != "family")
        status_badge = f"<div class='refs'>{_e(f.status)}</div>"
        parts.append(
            f"<tr data-sev='{_e(f.severity)}' data-hay='{hay}'>"
            f"<td>{_chip(f.severity)}</td>"
            f"<td><code>{_e(f.rule_id)}</code><div class='refs'>v{_e(f.rule_version)}</div></td>"
            f"<td>{_e(f.target_label)}<div class='refs'>{_e(f.device_type or '')}</div></td>"
            f"<td><b>{_e(f.rule_title)}</b>{status_badge if f.status != 'open' else ''}</td>"
            f"<td class='num'>{f.score:.1f}</td><td class='num'>{f.confidence:.2f}</td>"
            f"<td><ul class='ev'>{detail}</ul><div style='margin-top:4px'>{_e(f.remediation)}</div>"
            f"<div class='refs' style='margin-top:4px'>{refs}</div></td></tr>"
        )
    parts.append("</tbody></table></div></section>")

    # ---------------------------------------------------------------- topology
    if include_svg:
        svg = svg if svg is not None else _inline_svg(snapshot)
        if svg:
            parts.append("<section><h2><span>Topology</span><span class='chip ghost'>trust-tiered</span></h2>"
                         f"<div class='svg-wrap'>{svg}</div></section>")

    # ---------------------------------------------------------------- zones
    parts.append("<section><h2>Zones &amp; segmentation</h2><div class='body scroll'><table><thead><tr>"
                 "<th>Zone</th><th>Trust</th><th>Devices</th><th>CIDRs</th><th>VLANs</th><th>Gateway</th><th>Enforcement</th></tr></thead><tbody>")
    for z in snapshot.zones:
        enforcement = _chip("ok") if z.segmentation_enforced else _chip("medium")
        note = f"<div class='refs'>{_e(z.segmentation_note)}</div>" if z.segmentation_note else ""
        parts.append(
            f"<tr><td><b>{_e(z.name)}</b>{note}</td><td>{_e(z.trust)}</td>"
            f"<td class='num'>{_e(z.device_count or len(snapshot.devices_by(zone=z.name)))}</td>"
            f"<td>{_e(', '.join(z.cidrs) or '—')}</td><td>{_e(', '.join(str(v) for v in z.vlans) or '—')}</td>"
            f"<td>{_e(z.default_gateway or '—')}</td><td>{enforcement}</td></tr>"
        )
    parts.append("</tbody></table></div></section>")

    # ---------------------------------------------------------------- devices
    parts.append("<section><h2>Devices</h2><div class='body scroll'><table><thead><tr>"
                 "<th>Host</th><th>Address</th><th>Type</th><th>OS / firmware</th><th>Zone</th><th>Ports</th>"
                 "<th>Crit</th><th>Risk</th><th>Findings</th><th>Sources</th></tr></thead><tbody>")
    find_count: dict[str, int] = {}
    for f in snapshot.findings:
        find_count[f.target_id] = find_count.get(f.target_id, 0) + 1
    for d in sorted(devices, key=lambda x: (-(x.risk_score or 0), x.label)):
        osbits = " ".join(str(x) for x in (d.os_family, d.os_version) if x) or "—"
        eol = ""
        if d.os_eol:
            eol = f"<div class='refs'>EOL {_e(d.os_eol)} ({_e(d.os_eol_basis or 'lifecycle table')})</div>"
        risk_val = float(d.risk_score or 0)
        model_badge = f"<div class='refs'>{_e(d.model or d.vendor or '')}</div>" if (d.model or d.vendor) else ""
        mac_badge = f"<div class='refs'>{_e(d.mac)}</div>" if d.mac else ""
        parts.append(
            f"<tr><td><b>{_e(d.hostname or '—')}</b>{model_badge}</td>"
            f"<td><code>{_e(d.ip or '')}</code>{mac_badge}</td>"
            f"<td>{_e(d.device_type)}</td><td>{_e(osbits)}{eol}</td><td>{_e(d.zone or '—')}</td>"
            f"<td class='num'>{len(d.open_ports)}</td><td class='num'>{d.criticality}</td>"
            f"<td class='num'>{risk_val:.1f}<div>{_bar(risk_val * 10)}</div></td>"
            f"<td class='num'>{find_count.get(d.id, 0)}</td><td class='refs'>{_e(', '.join(d.discovery_sources))}</td></tr>"
        )
    parts.append("</tbody></table></div></section>")

    # ---------------------------------------------------------------- links
    if snapshot.links:
        parts.append("<section><h2>Links</h2><div class='body scroll'><table><thead><tr>"
                     "<th>From</th><th>To</th><th>Kind</th><th>Speed</th><th>Source</th><th>Conf</th><th>Risk</th><th>Notes</th>"
                     "</tr></thead><tbody>")
        by_id = snapshot.device_map()
        for l in sorted(snapshot.links, key=lambda x: (-float(x.risk_score or 0), x.id)):
            src, dst = by_id.get(l.src_device), by_id.get(l.dst_device)
            notes = []
            if l.is_spof:
                notes.append("single point of failure")
            if l.protected:
                notes.append("redundant")
            if l.redundant_group:
                notes.append(f"group {l.redundant_group}")
            parts.append(
                f"<tr><td>{_e(src.label if src else l.src_device)}<div class='refs'>{_e(l.src_interface or '')}</div></td>"
                f"<td>{_e(dst.label if dst else l.dst_device)}<div class='refs'>{_e(l.dst_interface or '')}</div></td>"
                f"<td>{_e(l.kind)}</td><td class='num'>{_e(l.speed_mbps or '—')}</td>"
                f"<td class='refs'>{_e(', '.join(l.derived_from))}</td><td class='num'>{_e(l.confidence)}</td>"
                f"<td class='num'>{_e(round(float(l.risk_score or 0), 1))}</td>"
                f"<td class='refs'>{_e('; '.join(notes))}</td></tr>"
            )
        parts.append("</tbody></table></div></section>")

    # ---------------------------------------------------------------- methodology
    audit = (snapshot.config or {}).get("risk_audit") or {}
    auth = snapshot.authorization or {}
    parts.append(
        "<section><h2>Method, scope and caveats</h2><div class='body grid2'>"
        "<div><h3 class='mini'>Authorization</h3><table><tbody>"
        + "".join(f"<tr><th style='position:static'>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in sorted(auth.items()))
        + "</tbody></table>"
        "<h3 class='mini'>Coverage</h3><table><tbody>"
        + "".join(
            f"<tr><th style='position:static'>{_e(k)}</th><td>{_e(v)}</td></tr>"
            for k, v in sorted((snapshot.counters or {}).items())
        )
        + "</tbody></table></div>"
        "<div><h3 class='mini'>Rules</h3><div>"
        f"{_e(audit.get('rules_active', 0))} of {_e(audit.get('rules_total', 0))} catalog rules evaluated; "
        f"{_e(len(audit.get('skipped') or {}))} skipped by configuration."
        + (f"<ul class='ev'>" + "".join(f"<li>{_e(k)}: {_e(v)}</li>" for k, v in list((audit.get("skipped") or {}).items())[:12]) + "</ul>" if audit.get("skipped") else "")
        + "</div>"
        + ("<h3 class='mini'>Scan errors</h3><ul class='ev'>" + "".join(f"<li><b>{_e(e.stage)}</b> {_e(e.message)}</li>" for e in snapshot.errors[:25]) + "</ul>" if snapshot.errors else "")
        + "<h3 class='mini'>Caveats</h3><ul class='ev'>"
        + "".join(f"<li>{_e(n)}</li>" for n in (snapshot.notes or [])[:12])
        + "<li>Passive/agentless discovery cannot see devices that do not answer: printers in deep sleep, "
          "single-homed hosts behind unqueried switches, and anything on an unscanned VLAN are invisible here.</li>"
        + "<li>Findings are inferred from banner and SNMP evidence; confirm on the device before changing config.</li>"
        + "</ul></div></div></section>"
    )
    if snapshot.drift:
        parts.append("<section><h2>Change since baseline</h2><div class='body'><pre style='font-size:12px;overflow:auto'>"
                     + _e(json.dumps(snapshot.drift, indent=2)[:6000])
                     + "</pre></div></section>")
    parts.append(
        "<footer>Generated by NetMap. Findings are advisory; validate on the device before "
        "changing production configuration.</footer></div>"
        f"<script>{JS}</script></body></html>"
    )
    return "\n".join(parts)


def _inline_svg(snapshot: ScanSnapshot) -> str:
    try:
        from .topology_svg import render_svg

        return render_svg(snapshot)
    except Exception:  # noqa: BLE001 - a report without the picture still ships
        return ""


__all__ = ["render_html"]
