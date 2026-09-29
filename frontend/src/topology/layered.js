import { tierOf } from './layout.js';

// Layered topology layout with barycenter crossing minimization
// (Sugiyama-style): tiers come from device role/zone so the required order
//   INTERNET → Firewall → Router → Core → Access → Servers/Clients/IoT
// is exact, then nodes within each tier are ordered by the barycenter of
// their neighbours so links run vertically instead of crossing the map.
// (dagre was evaluated: it overwrites node ranks, so it cannot pin this
// required tier order — hence domain ranks + barycenter ordering.)
function adjacency(nodes, edges) {
  const ids = new Set(nodes.map((n) => n.id));
  const m = {};
  edges.forEach((e) => {
    const s = e.source || e.src, t = e.target || e.dst;
    if (!s || !t || !ids.has(s) || !ids.has(t)) return;
    (m[s] = m[s] || new Set()).add(t);
    (m[t] = m[t] || new Set()).add(s);
  });
  return m;
}

function barycenterSweep(tiers, keys, adj, dir) {
  const order = keys.slice().sort((a, b) => a - b);
  if (dir < 0) order.reverse();
  for (const t of order) {
    const members = tiers[t];
    const ref = tiers[t + dir];
    if (!ref) continue;
    const refPos = {};
    ref.forEach((n, i) => { refPos[n.id] = i; });
    const scored = members.map((n, i) => {
      const nbs = [...(adj[n.id] || [])].map((id) => refPos[id]).filter((v) => v !== undefined);
      const bc = nbs.length ? nbs.reduce((a, b) => a + b, 0) / nbs.length : Infinity;
      return { n, bc, i };
    });
    scored.sort((a, b) => (a.bc === b.bc ? a.i - b.i : a.bc - b.bc));
    tiers[t] = scored.map((s) => s.n);
  }
}

export function layoutLayered(nodes, edges) {
  const GAP_X = 190, ROW_H = 205, TIER_PAD = 80;
  const tiers = {};
  nodes.forEach((n) => {
    const t = n.id === '__internet' ? 0 : tierOf(n);
    (tiers[t] = tiers[t] || []).push(n);
  });
  Object.values(tiers).forEach((members) => members.sort((a, b) => (b.risk || 0) - (a.risk || 0)));
  const adj = adjacency(nodes, edges || []);
  for (let k = 0; k < 2; k++) {
    barycenterSweep(tiers, Object.keys(tiers).map(Number), adj, +1);
    barycenterSweep(tiers, Object.keys(tiers).map(Number), adj, -1);
  }
  const pos = {};
  let y = 60, minX = Infinity, maxX = -Infinity, maxY = 0;
  Object.keys(tiers).map(Number).sort((a, b) => a - b).forEach((t) => {
    const members = tiers[t];
    const perRow = Math.max(2, Math.min(8, Math.ceil(Math.sqrt(members.length * 2.5))));
    const rows = Math.ceil(members.length / perRow);
    members.forEach((n, i) => {
      const r = Math.floor(i / perRow), c = i % perRow;
      const rowCount = Math.min(perRow, members.length - r * perRow);
      const x = (c - (rowCount - 1) / 2) * GAP_X;
      const yy = y + r * ROW_H;
      pos[n.id] = { x, y: yy };
      minX = Math.min(minX, x); maxX = Math.max(maxX, x); maxY = Math.max(maxY, yy);
    });
    y += rows * ROW_H + TIER_PAD;
  });
  if (!isFinite(minX)) { minX = -200; maxX = 200; maxY = 200; }
  return { pos, bounds: [[minX - 500, -300], [maxX + 500, maxY + 400]] };
}
