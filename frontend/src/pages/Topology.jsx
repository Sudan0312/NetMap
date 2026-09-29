import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import ReactFlow, { Background, MiniMap, Handle, Position, ReactFlowProvider, useReactFlow, useViewport, useStore } from 'reactflow';
import 'reactflow/dist/style.css';
import { api } from '../services/api';
import { DeviceDrawer, LoadingState, ErrorState, RiskBadge, StageBanner, LiveDot } from '../components';
import { useScan } from '../store/ScanContext';
import { useTheme } from '../store/ThemeContext';
import { SEV_COLORS, iconFor, roleLabel } from '../topology/icons';
import { layoutLayered } from '../topology/layered';
import { isLoopbackNodes } from '../utils/network';

function ZoomBar() {
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  const { zoom } = useViewport();
  const big = { fontSize: 20, fontWeight: 800, padding: '6px 14px', lineHeight: 1 };
  return (
    <div style={{ position: 'absolute', top: 12, right: 12, zIndex: 6, display: 'flex', gap: 6, alignItems: 'center', background: 'var(--map-panel-bg)', border: '2px solid var(--border)', borderRadius: 12, padding: 6, boxShadow: '0 2px 10px rgba(0,0,0,.25)' }}>
      <button className="btn" style={big} onClick={() => zoomOut({ duration: 200 })} title="Zoom out (−)">−</button>
      <span style={{ fontSize: 13, fontWeight: 800, minWidth: 52, textAlign: 'center' }}>{Math.round(zoom * 100)}%</span>
      <button className="btn" style={big} onClick={() => zoomIn({ duration: 200 })} title="Zoom in (+)">+</button>
      <button className="btn primary" style={{ fontSize: 13 }} onClick={() => fitView({ padding: 0.12, duration: 300 })} title="Fit entire network on screen">⤢ Entire network</button>
    </div>
  );
}

function FitOnce({ count }) {
  const { fitView } = useReactFlow();
  const prev = useRef(0);
  useEffect(() => {
    if (prev.current === 0 && count > 0) fitView({ padding: 0.12, duration: 300 });
    prev.current = count;
  }, [count, fitView]);
  return null;
}

function PanScrollbars({ bounds }) {
  const { setViewport } = useReactFlow();
  const vp = useViewport();
  const size = useStore((s) => ({ w: s.width, h: s.height }));
  const geom = useRef({});
  const [[minX, minY], [maxX, maxY]] = bounds;
  const pad = 250;
  const cx0 = minX - pad, cy0 = minY - pad;
  const cw = Math.max(1, maxX - minX + pad * 2), ch = Math.max(1, maxY - minY + pad * 2);
  const zoom = vp.zoom || 1;
  const vw = (size.w || 800) / zoom, vh = (size.h || 600) / zoom;
  const tx = Math.max(0.04, Math.min(1, vw / cw));
  const ty = Math.max(0.04, Math.min(1, vh / ch));
  const cl = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const fx = cl((-vp.x / zoom - cx0) / Math.max(1, cw - vw), 0, 1);
  const fy = cl((-vp.y / zoom - cy0) / Math.max(1, ch - vh), 0, 1);
  geom.current = { tx, ty, cx0, cy0, cw, ch, vw, vh, zoom };
  const jumpTo = (horiz, frac) => {
    const g = geom.current;
    const f = cl(frac, 0, 1);
    if (horiz) setViewport({ x: -(g.cx0 + f * Math.max(0, g.cw - g.vw)) * g.zoom, y: vp.y, zoom: g.zoom });
    else setViewport({ x: vp.x, y: -(g.cy0 + f * Math.max(0, g.ch - g.vh)) * g.zoom, zoom: g.zoom });
  };
  const nudge = (horiz, dir) => jumpTo(horiz, (horiz ? fx : fy) + dir * 0.15);
  const onThumb = (horiz) => (e) => {
    e.stopPropagation();
    e.preventDefault();
    const el = e.currentTarget;
    el.setPointerCapture(e.pointerId);
    const startC = horiz ? e.clientX : e.clientY;
    const track = el.parentElement.getBoundingClientRect();
    const g = geom.current;
    const t = horiz ? g.tx : g.ty;
    const len = (horiz ? track.width : track.height) * (1 - t);
    const startF = horiz ? fx : fy;
    const move = (ev) => {
      const d = (horiz ? ev.clientX : ev.clientY) - startC;
      jumpTo(horiz, startF + (len > 0 ? d / len : 0));
    };
    const up = () => {
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
  };
  const onTrack = (horiz) => (e) => {
    if (e.target !== e.currentTarget) return;
    const r = e.currentTarget.getBoundingClientRect();
    const g = geom.current;
    const t = horiz ? g.tx : g.ty;
    const click = ((horiz ? e.clientX - r.left : e.clientY - r.top) / (horiz ? r.width : r.height) - t / 2) / Math.max(0.001, 1 - t);
    jumpTo(horiz, click);
  };
  return (
    <>
      <div className="panbar-h">
        <button className="panarrow" onClick={() => nudge(true, -1)} title="Scroll network left">◀</button>
        <div className="pantrack-h" onPointerDown={onTrack(true)}>
          <div className="panthumb" style={{ left: `${fx * (1 - tx) * 100}%`, width: `${tx * 100}%` }} onPointerDown={onThumb(true)} />
        </div>
        <button className="panarrow" onClick={() => nudge(true, 1)} title="Scroll network right">▶</button>
      </div>
      <div className="panbar-v" onPointerDown={onTrack(false)}>
        <div className="panthumb" style={{ top: `${fy * (1 - ty) * 100}%`, height: `${ty * 100}%` }} onPointerDown={onThumb(false)} />
      </div>
    </>
  );
}

function DevNode({ data }) {
  const online = (data.status || 'online') === 'online';
  const sev = (data.severity || 'none').toLowerCase();
  const pillInk = ['medium', 'low', 'info', 'none'].includes(sev) ? '#101828' : '#fff';
  return (
    <div style={{ border: `3px solid ${SEV_COLORS[data.severity] || SEV_COLORS.none}`, borderRadius: 12, background: 'var(--panel)', padding: '8px 10px', minWidth: 150, maxWidth: 176, boxShadow: '0 2px 10px rgba(0,0,0,.25)' }}>
      <Handle type="target" position={Position.Top} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ width: 12, height: 12, borderRadius: '50%', background: online ? 'var(--good)' : 'var(--text-muted)', boxShadow: online ? '0 0 6px var(--good)' : 'none' }} title={online ? 'online' : 'offline'} />
        <span style={{ fontSize: 12, fontWeight: 800, letterSpacing: '1px', color: 'var(--text-secondary)' }}>{data.roleLabel}</span>
      </div>
      <div style={{ fontSize: 30, textAlign: 'center', margin: '2px 0' }}>{data.icon}</div>
      <div style={{ fontSize: 15, fontWeight: 800, textAlign: 'center', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: "Georgia, 'Times New Roman', serif", color: 'var(--text)' }}>{data.label}</div>
      <div style={{ fontSize: 12, textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'ui-monospace, monospace' }}>{data.ip}</div>
      <div style={{ textAlign: 'center', marginTop: 4 }}>
        <span style={{ fontSize: 12, fontWeight: 800, background: 'var(--good-bg)', color: 'var(--good)', borderRadius: 999, padding: '1px 8px' }}>{data.zone || 'unzoned'}</span>
      </div>
      <div style={{ textAlign: 'center', marginTop: 4, fontSize: 12 }}>
        <span style={{ background: SEV_COLORS[data.severity] || SEV_COLORS.none, color: pillInk, borderRadius: 999, padding: '1px 8px', fontWeight: 800 }}>{(data.severity || 'none').toUpperCase()}</span>{' '}
        <span style={{ color: 'var(--text-secondary)', fontWeight: 800 }}>⑂{data.risk}</span>
      </div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

function CloudNode() {
  return (
    <div style={{ border: '3px dashed #b45309', borderRadius: 16, background: '#fffbeb', padding: '10px 22px', textAlign: 'center' }}>
      <Handle type="source" position={Position.Bottom} />
      <div style={{ fontSize: 30 }}>☁️</div>
      <div style={{ fontSize: 13, fontWeight: 800, letterSpacing: 1.5, color: '#92400e' }}>INTERNET</div>
    </div>
  );
}
const nodeTypes = { dev: DevNode, cloud: CloudNode };

const LEGEND = [
  ['firewall', 'Firewall', '🛡️'], ['router', 'Router', '🔀'],
  ['core', 'Core Switch', '🖧'], ['access-switch', 'Access Switch', '🔗'],
  ['server', 'Server', '⚙️'], ['database', 'Database', '🗄️'],
  ['workstation', 'Workstation', '🖥️'], ['laptop', 'Laptop', '💻'],
  ['access_point', 'Access Point', '📡'], ['iot', 'IoT', '📟'], ['unknown', 'Unknown Device', '❓'],
];

function legendPresent(nodes) {
  const has = {
    firewall: nodes.some((n) => (n.device_type || n.type) === 'firewall'),
    router: nodes.some((n) => (n.device_type || n.type) === 'router'),
    core: nodes.some((n) => (n.device_type || n.type) === 'switch' && ((n.role || '') === 'core' || (n.zone || '') === 'core')),
    'access-switch': nodes.some((n) => (n.device_type || n.type) === 'switch' && !((n.role || '') === 'core' || (n.zone || '') === 'core')),
    server: nodes.some((n) => ['server', 'web', 'hypervisor', 'directory', 'dns', 'storage'].includes(n.device_type || n.type)),
    database: nodes.some((n) => (n.device_type || n.type) === 'database'),
    workstation: nodes.some((n) => (n.device_type || n.type) === 'workstation'),
    laptop: nodes.some((n) => (n.device_type || n.type) === 'laptop'),
    access_point: nodes.some((n) => (n.device_type || n.type) === 'access_point'),
    iot: nodes.some((n) => ['iot', 'camera', 'voip'].includes(n.device_type || n.type)),
    unknown: nodes.some((n) => (n.device_type || n.type) === 'unknown'),
  };
  return has;
}

export default function Topology() {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState('');
  const [typeF, setTypeF] = useState('all');
  const [sevF, setSevF] = useState('all');
  const [zoneF, setZoneF] = useState('all');
  const [sel, setSel] = useState(null);
  const [selDetail, setSelDetail] = useState(null);
  const [liveJob, setLiveJob] = useState(null);
  const [snapId, setSnapId] = useState('latest');
  const [expanded, setExpanded] = useState(false);
  const [flash, setFlash] = useState(null);
  const snapRef = useRef('latest');
  const liveRef = useRef(null);
  useEffect(() => { snapRef.current = snapId; });
  useEffect(() => { liveRef.current = liveJob; });

  // Base data (latest snapshot) comes from the global store; older snapshots
  // are fetched on demand. Zones/history are snapshot-scoped lists from store.
  const {
    graph: storeGraph, zones: storeZones, history: storeHistory, snapshotId: storeSnap,
    refreshToken: topoTick, reload: reloadStore, loading: storeLoading, error: storeError,
  } = useScan();
  const [oldGraph, setOldGraph] = useState(null);
  const [oldError, setOldError] = useState(null);
  const [oldTick, setOldTick] = useState(0);
  useEffect(() => {
    if (snapId === 'latest') {
      setOldGraph(null);
      setOldError(null);
      return;
    }
    let stop = false;
    api.graph(snapId)
      .then((g) => { if (!stop) { setOldGraph(g); setOldError(null); } })
      .catch((e) => { if (!stop) setOldError(e); });
    return () => { stop = true; };
  }, [snapId, topoTick, oldTick]);
  const graph = snapId === 'latest' ? storeGraph : oldGraph;
  const zones = storeZones;
  const snaps = storeHistory;
  const error = snapId === 'latest' ? storeError : oldError;

  // Live mode: if a scan is running anywhere, stream its emerging topology here.
  useEffect(() => {
    let stop = false, es = null, poll = null, watched = null;
    const watch = (id) => {
      watched = id;
      const apply = (j) => { if (!stop) setLiveJob(j); };
      try {
        es = new EventSource(`/api/scan/${id}/events`);
        es.onmessage = (ev) => { try { apply(JSON.parse(ev.data)); } catch { /* ignore */ } };
        es.onerror = () => {
          if (es) es.close();
          es = null;
          if (!poll) poll = setInterval(async () => { try { apply(await api.job(id)); } catch { /* keep trying */ } }, 1000);
        };
      } catch { /* EventSource unavailable */ }
      if (!es) poll = setInterval(async () => { try { apply(await api.job(id)); } catch { /* keep trying */ } }, 1000);
    };
    (async () => {
      try {
        const jobs = await api.jobs();
        const active = jobs.find((j) => j.status === 'running' || j.status === 'queued');
        if (active && !stop) watch(active.job_id);
      } catch { /* no live scan */ }
    })();
    return () => { stop = true; if (es) es.close(); if (poll) clearInterval(poll); };
  }, []);

  const pick = (id) => { setSnapId(id); setSel(null); setSelDetail(null); };
  // Map-updated stamp: recomputed key flips whenever nodes/edges/job change.
  const [graphAt, setGraphAt] = useState(null);
  // Refresh the open device drawer when the underlying snapshot changes
  // (selection itself is always preserved).
  // Global signal: the store already refreshed base data; just announce it.
  useEffect(() => {
    if (topoTick <= 0) return;
    if (snapRef.current === 'latest' && !liveRef.current) {
      setLiveJob(null);
      setFlash('Network updated — showing the newest discovery.');
    } else {
      setFlash('A newer discovery exists — switch to Latest scan to view it.');
    }
    const t = setTimeout(() => setFlash(null), 6000);
    return () => clearTimeout(t);
  }, [topoTick]);

  const source = (snapId === 'latest' && liveJob && (liveJob.status === 'running' || liveJob.status === 'queued' || ((liveJob.live_devices || []).length > 0 && liveJob.status !== 'completed')))
    ? { nodes: liveJob.live_devices || [], edges: liveJob.live_links || [], live: true, job: liveJob }
    : graph ? { ...graph, live: false } : null;

  const filtered = useMemo(() => {
    if (!source) return { nodes: [], edges: [] };
    let nodes = source.nodes;
    if (q) { const s = q.toLowerCase(); nodes = nodes.filter((n) => (n.label || '').toLowerCase().includes(s) || (n.ip || '').includes(s)); }
    if (typeF !== 'all') {
      nodes = nodes.filter((n) => {
        const t = n.device_type || n.type;
        if (typeF === 'core') return t === 'switch' && ((n.role || '') === 'core' || (n.zone || '') === 'core');
        if (typeF === 'access-switch') return t === 'switch' && !((n.role || '') === 'core' || (n.zone || '') === 'core');
        return t === typeF;
      });
    }
    if (sevF !== 'all') nodes = nodes.filter((n) => n.severity === sevF);
    if (zoneF !== 'all') nodes = nodes.filter((n) => n.zone === zoneF);
    const keep = new Set(nodes.map((n) => n.id));
    const edges = (source.edges || source.links || []).filter((e) => keep.has(e.source || e.src) && keep.has(e.target || e.dst));
    // INTERNET cloud for the perimeter firewalls (display-only, not a device).
    const fw = nodes.filter((n) => ((n.device_type || n.type) === 'firewall' || (n.zone || '') === 'wan-edge'));
    const cloud = fw.length > 0 ? [{ id: '__internet', cloud: true }] : [];
    const cloudEdges = fw.map((f, i) => ({ id: `inet-${i}`, source: '__internet', target: f.id, kind: 'uplink', dashed: true }));
    return { nodes: [...cloud, ...nodes], edges: [...cloudEdges, ...edges] };
  }, [source, q, typeF, sevF, zoneF]);

  const { theme } = useTheme();
  // Canvas palette follows the theme: glowing edges on the dark NOC canvas,
  // high-contrast flat edges on the light canvas.
  const dark = theme !== 'light';
  const edgeBase = (e) => {
    if (dark) {
      const glow = (c) => `drop-shadow(0 0 5px ${c})`;
      if (e.spof) return { stroke: '#ff7a70', filter: glow('rgba(255,122,112,.9)') };
      if (e.protected) return { stroke: '#3ddc97', filter: glow('rgba(61,220,151,.8)') };
      if (e.dashed) return { stroke: '#ffcf5c', filter: glow('rgba(255,207,92,.7)') };
      return { stroke: '#9db8a6' };
    }
    if (e.spof) return { stroke: '#d92d20' };
    if (e.protected) return { stroke: '#067647' };
    if (e.dashed) return { stroke: '#b54708' };
    return { stroke: '#98a2b3' };
  };

  const rf = useMemo(() => {
    const { pos, bounds } = layoutLayered(filtered.nodes, filtered.edges);
    const nodes = filtered.nodes.map((n) => n.cloud
      ? { id: n.id, type: 'cloud', position: pos[n.id] || { x: 0, y: 60 }, data: {} }
      : {
          id: n.id, type: 'dev', position: pos[n.id] || { x: 0, y: 400 },
          data: { ...n, icon: iconFor(n), roleLabel: roleLabel(n), status: n.status || 'online' },
        });
    const edges = filtered.edges.map((e, i) => ({
      id: e.id || `e-${i}`,
      source: e.source || e.src,
      target: e.target || e.dst,
      label: e.kind,
      type: 'smoothstep',
      pathOptions: { borderRadius: 18 },
      animated: filtered.edges.length < 80 || !!e.spof,
      labelStyle: { fill: dark ? '#f5f4ef' : '#101828', fontWeight: 800, fontSize: 11 },
      labelBgPadding: [5, 4],
      labelBgBorderRadius: 5,
      labelBgStyle: { fill: dark ? 'rgba(20,26,23,.85)' : 'rgba(255,255,255,.9)' },
      style: {
        ...edgeBase(e),
        strokeWidth: e.spof ? 3 : 2,
        strokeDasharray: e.dashed ? '7 5' : undefined,
      },
    }));
    return { nodes, edges, bounds };
  }, [filtered, dark]);

  const fallbackDetail = (id) => {
    const n = (source?.nodes || []).find((x) => x.id === id) || {};
    return {
      id, name: n.label, label: n.label, ip: n.ip,
      device_type: n.device_type || n.type, type: n.device_type || n.type,
      zone: n.zone, trust: n.trust, role: n.role, status: n.status || 'online',
      risk_score: n.risk, risk: n.risk, severity: n.severity,
      open_ports: n.ports || [], ports: n.ports || [],
      services: [], findings: [], neighbors: [], neighbours: [],
      discovery_sources: ['snapshot'],
    };
  };

  // Deep link: /topology?focus=<device-id> (e.g. from a risk finding).
  // Selects the node and opens its drawer; the param is consumed, not stored.
  useEffect(() => {
    const fid = sp.get('focus');
    if (!fid || !source || sel) return;
    const hit = (source.nodes || []).find((n) => n.id === fid || n.ip === fid || n.label === fid);
    if (!hit || hit.cloud) {
      setSp({}, { replace: true });
      return;
    }
    setSel(hit.id);
    api.device(hit.id).then(setSelDetail).catch(() => setSelDetail(fallbackDetail(hit.id)));
    setSp({}, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sp, source]);

  const onNodeClick = async (_, node) => {
    if (node.id === '__internet') return;
    setSel(node.id);
    try {
      setSelDetail(await api.device(node.id));
    } catch {
      // Node from an older snapshot (or live feed): show what the graph knows.
      const n = (source?.nodes || []).find((x) => x.id === node.id) || {};
      setSelDetail({
        id: node.id, name: n.label, label: n.label, ip: n.ip,
        device_type: n.device_type || n.type, type: n.device_type || n.type,
        zone: n.zone, trust: n.trust, role: n.role, status: n.status || 'online',
        risk_score: n.risk, risk: n.risk, severity: n.severity,
        open_ports: n.ports || [], ports: n.ports || [],
        services: [], findings: [], neighbors: [], neighbours: [],
        discovery_sources: ['snapshot'],
      });
    }
  };

  // Subtle persistent indicator: stamp updates whenever the drawn map changes.
  // (Above the early returns: hooks must run unconditionally.)
  const sourceKey = `${snapId}|${(source?.nodes || []).length}|${(source?.edges || source?.links || []).length}|${liveJob?.status || 'idle'}`;
  useEffect(() => { setGraphAt(new Date()); }, [sourceKey]);
  // Keep the selected device's detail fresh across snapshot changes.
  useEffect(() => {
    if (!sel || sel === '__internet' || snapId !== 'latest') return;
    api.device(sel).then(setSelDetail).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storeSnap]);

  if (error && !source) return <ErrorState error={error} retry={() => { setLiveJob(null); if (snapId === 'latest') reloadStore(); else setOldTick((t) => t + 1); }} />;
  if (!source) return <LoadingState text="Loading topology graph…" />;

  const present = legendPresent(source.nodes);
  const types = [...new Set(source.nodes.map((n) => n.device_type || n.type))].sort();
  const resetFilters = () => { setQ(''); setTypeF('all'); setSevF('all'); setZoneF('all'); };
  const loopbackView = isLoopbackNodes(source.nodes);
  return (
    <div>
      {source.live && (
        <div className="card" style={{ borderColor: '#d97706', borderWidth: 2 }}>
          <h3><LiveDot /> LIVE — scan in progress</h3>
          <div className="hint">This map is assembling in real time from the running scan. Nodes and links appear as the backend discovers them.</div>
          <StageBanner job={source.job} />
        </div>
      )}
      {!source.live && liveJob?.status === 'completed' && (
        <div className="alert">✓ Latest scan finished — this is the resulting network. <Link className="btn" to="/discovery">Run another scan</Link></div>
      )}
      {flash && <div className="alert flash-in">✓ {flash}</div>}
      {!source.live && loopbackView && (
        <div className="alert warn">⚠ Viewing a <b>loopback test scan (127.0.0.1)</b> — not an enterprise network. <Link className="btn" to="/discovery?autostart=demo" style={{ marginLeft: 8 }}>Try demo network</Link></div>
      )}
      <div className="toolbar">
        <select className="input" value={snapId} onChange={(e) => pick(e.target.value)} title="Choose which scan to view" style={{ maxWidth: 300, fontWeight: 800 }}>
          <option value="latest">Latest scan</option>
          {snaps.map((s) => (
            <option key={s.snapshot_id} value={s.snapshot_id}>
              {(s.environment || s.mode) + ' · ' + (s.devices ?? '?') + ' devices · ' + (s.finished || '').slice(5, 16).replace('T', ' ')}
            </option>
          ))}
        </select>
        <input className="input" placeholder="Search devices…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 200 }} />
        <select className="input" value={typeF} onChange={(e) => setTypeF(e.target.value)}>
          <option value="all">All types</option>
          <option value="firewall">Firewall</option><option value="router">Router</option>
          <option value="core">Core Switch</option><option value="access-switch">Access Switch</option>
          <option value="server">Server</option><option value="database">Database</option>
          <option value="workstation">Workstation</option><option value="laptop">Laptop</option>
          <option value="access_point">Access Point</option><option value="iot">IoT</option>
          <option value="unknown">Unknown</option>
          {types.filter((t) => !['firewall', 'router', 'switch', 'server', 'database', 'workstation', 'laptop', 'access_point', 'iot', 'unknown'].includes(t)).map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="input" value={sevF} onChange={(e) => setSevF(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option><option value="none">None</option>
        </select>
        <select className="input" value={zoneF} onChange={(e) => setZoneF(e.target.value)}>
          <option value="all">All zones</option>{zones.map((z) => <option key={z.name} value={z.name}>{z.name}</option>)}
        </select>
        <button className="btn" onClick={() => { setLiveJob(null); if (snapId === 'latest') reloadStore(); else setOldTick((t) => t + 1); }}>Refresh</button>
        <button className="btn" onClick={resetFilters} title="Clear search and all filters">Reset filters</button>
        <button className="btn" onClick={() => setExpanded((e) => !e)} title="Expand the map to fill the screen">{expanded ? '⤡ Compress' : '⤢ Expand map'}</button>
        <span style={{ fontSize: 13, color: 'var(--text-muted)', fontWeight: 700 }}>{filtered.nodes.length} of {source.nodes.length} match · {filtered.edges.length} links {snapId !== 'latest' && '· viewing older scan'} · map updated {graphAt ? graphAt.toLocaleTimeString() : '…'} {sel && <>· selected <b>{sel}</b></>}</span>
      </div>
      <div className={`topo-wrap${expanded ? ' expanded' : ''}`}>
        <ReactFlowProvider>
          <ReactFlow nodes={rf.nodes} edges={rf.edges} nodeTypes={nodeTypes} onNodeClick={onNodeClick}
            minZoom={0.05} maxZoom={3.5} translateExtent={rf.bounds} defaultViewport={{ x: 0, y: 0, zoom: 0.6 }}>
            <Background color={dark ? '#3d5247' : '#d4dbe7'} gap={28} />
            <MiniMap maskColor={dark ? 'rgba(14,8,24,.78)' : 'rgba(238,241,246,.8)'} nodeColor={(n) => SEV_COLORS[n.data?.severity] || '#8fa398'} pannable zoomable />
            <ZoomBar />
            <FitOnce count={rf.nodes.length} />
            <PanScrollbars bounds={rf.bounds} />
          </ReactFlow>
        </ReactFlowProvider>
        {source.nodes.length > 0 && filtered.nodes.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 7, pointerEvents: 'none' }}>
            <div className="card" style={{ margin: 0, textAlign: 'center', pointerEvents: 'auto', maxWidth: 440 }}>
              <h3>No nodes match these filters</h3>
              <div className="hint">
                This scan has {source.nodes.length} device(s), but none match
                {[q && `search "${q}"`, typeF !== 'all' && `type ${typeF}`, sevF !== 'all' && `severity ${sevF}`, zoneF !== 'all' && `zone ${zoneF}`].filter(Boolean).join(' + ') || 'the current filters'} at once. Loosen the filters.
              </div>
              <button className="btn primary" onClick={resetFilters}>Reset filters — show all {source.nodes.length}</button>
            </div>
          </div>
        )}
        {source.nodes.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 7, pointerEvents: 'none' }}>
            <div className="card" style={{ margin: 0, textAlign: 'center', pointerEvents: 'auto', maxWidth: 440 }}>
              <h3>NO NETWORK DISCOVERED</h3>
              <div className="hint">This scan discovered no devices. Start your first discovery.</div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'center', flexWrap: 'wrap' }}>
                <Link className="btn primary" to="/discovery?autostart=demo">TRY DEMO NETWORK</Link>
                <Link className="btn" to="/discovery?env=live">LIVE DISCOVERY</Link>
              </div>
            </div>
          </div>
        )}
        <div className="topo-legend" style={{ flexWrap: 'wrap', maxWidth: '70%' }}>
          {LEGEND.map(([key, label, icon]) => (
            <span key={key} style={{ opacity: present[key] ? 1 : 0.35 }} title={present[key] ? label : `${label} (none in this network)`}>{icon} {label}</span>
          ))}
        </div>
      </div>
      <div className="card" style={{ marginTop: 12 }}>
        <h3>How to read a node</h3>
        <div className="hint">Every node communicates four things at a glance</div>
        <div style={{ fontSize: 14, display: 'flex', gap: 18, flexWrap: 'wrap', fontWeight: 600 }}>
          <span>🛡️ icon + role label = <b>device type</b></span>
          <span><span style={{ color: 'var(--good)' }}>●</span> glowing dot = <b>status</b> (green online / gray offline)</span>
          <span><RiskBadge severity="critical" /> ring + pill = <b>risk severity</b></span>
          <span><span style={{ background: 'var(--good-bg)', color: 'var(--good)', borderRadius: 999, padding: '1px 8px' }}>core</span> chip = <b>zone</b></span>
        </div>
      </div>
      {sel && !selDetail && <div className="alert">Loading device {sel}…</div>}
      <DeviceDrawer device={selDetail} onClose={() => { setSel(null); setSelDetail(null); }} />
    </div>
  );
}
