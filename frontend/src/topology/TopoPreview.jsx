import React from 'react';
import { SEV_COLORS, TYPE_ICON } from './icons';

// Auto-drawn zone-grouped SVG preview of a network snapshot. Used on the
// Dashboard and in the Discovery watch room; the full interactive canvas
// lives in pages/Topology.jsx.
const MAX_PREVIEW_NODES = 60;

export function TopoPreview({ graph, onOpen }) {
  if (!graph || !graph.nodes || graph.nodes.length === 0) return null;
  const nodes = [...graph.nodes].sort((a, b) => (b.risk || 0) - (a.risk || 0)).slice(0, MAX_PREVIEW_NODES);
  const keep = new Set(nodes.map((n) => n.id));
  const edges = (graph.edges || graph.links || []).filter((e) => keep.has(e.source || e.src) && keep.has(e.target || e.dst));
  const zones = [...new Set(nodes.map((n) => n.zone || 'unzoned'))].sort();
  const W = 920;
  const cols = Math.min(6, zones.length);
  const colW = W / cols;
  // Distribute zones round-robin across columns so no two nodes share a slot.
  const colZones = Array.from({ length: cols }, () => []);
  zones.forEach((z, zi) => colZones[zi % cols].push(z));
  const pos = {};
  let maxRows = 1;
  colZones.forEach((list, col) => {
    const members = nodes.filter((n) => list.includes(n.zone || 'unzoned'));
    maxRows = Math.max(maxRows, members.length);
    const gap = Math.max(52, Math.min(64, 340 / Math.max(1, members.length)));
    members.forEach((n, mi) => {
      pos[n.id] = { x: col * colW + colW / 2, y: 46 + mi * gap };
    });
  });
  const H = Math.max(420, 46 + maxRows * 56);
  const short = (s) => (s && s.length > 14 ? s.slice(0, 13) + '…' : s || '');
  const colLabel = (list) => {
    const first = String(list[0] || 'unzoned');
    const name = first.length > 13 ? first.slice(0, 12) + '…' : first;
    return list.length > 1 ? `${name} +${list.length - 1}` : name;
  };
  const zoneSize = cols >= 5 ? 9 : 11;
  return (
    <div>
      <svg className="topo-preview" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Network topology preview">
        {colZones.map((list, col) => (
          <g key={col}>
            <text x={col * colW + colW / 2} y={18} textAnchor="middle" fontSize={zoneSize} fontWeight="800" fill="var(--accent)" style={{ letterSpacing: 1 }}>{colLabel(list).toUpperCase()}</text>
          </g>
        ))}
        {edges.slice(0, 300).map((e, i) => {
          const a = pos[e.source || e.src], b = pos[e.target || e.dst];
          if (!a || !b) return null;
          const spof = e.spof;
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={spof ? 'var(--sev-critical)' : 'var(--border-strong)'} strokeWidth={spof ? 2 : 1.2} strokeDasharray={spof ? '5 3' : e.protected ? '' : ''} opacity={0.9} />;
        })}
        {nodes.map((n) => {
          const p = pos[n.id];
          if (!p) return null;
          const c = SEV_COLORS[n.severity] || SEV_COLORS.none;
          return (
            <g key={n.id} onClick={() => onOpen && onOpen(n.id)} style={{ cursor: onOpen ? 'pointer' : 'default' }}>
              <title>{n.label} · {n.ip} · {(n.device_type || n.type)} · risk {n.risk}</title>
              <circle cx={p.x} cy={p.y} r={15} fill="var(--panel)" stroke={c} strokeWidth={2.5} />
              <text x={p.x} y={p.y + 5} textAnchor="middle" fontSize="13">{TYPE_ICON[n.device_type || n.type] || TYPE_ICON.unknown}</text>
              <text x={p.x} y={p.y + 30} textAnchor="middle" fontSize="10" fontWeight="700" fill="var(--text-secondary)">{short(n.label)}</text>
            </g>
          );
        })}
      </svg>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <span><span style={{ color: 'var(--sev-critical)' }}>●</span> critical</span>
        <span><span style={{ color: 'var(--sev-high)' }}>●</span> high</span>
        <span><span style={{ color: 'var(--sev-medium)' }}>●</span> medium</span>
        <span><span style={{ color: 'var(--sev-low)' }}>●</span> low</span>
        <span>┄ dashed red = single point of failure</span>
        {graph.nodes.length > MAX_PREVIEW_NODES && <span>showing highest-risk {MAX_PREVIEW_NODES} of {graph.nodes.length}</span>}
      </div>
    </div>
  );
}
