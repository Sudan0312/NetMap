import React, { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../services/api';
import { RiskBadge, StatusBadge, LoadingState, ErrorState, DeviceDrawer } from '../components';
import { useScan } from '../store/ScanContext';

function ipCmp(a, b) {
  const pa = String(a || '').split('.'), pb = String(b || '').split('.');
  if (pa.length === 4 && pb.length === 4 && pa.every((x) => /^\d+$/.test(x)) && pb.every((x) => /^\d+$/.test(x))) {
    for (let i = 0; i < 4; i++) {
      const d = Number(pa[i]) - Number(pb[i]);
      if (d !== 0) return d;
    }
    return 0;
  }
  return String(a || '').localeCompare(String(b || ''));
}

export default function Devices() {
  // Inventory comes from the global store; filters + sort apply client-side
  // and are never reset by incoming snapshots.
  const { devices: all, zones, loading, error, reload: load, snapshotId } = useScan();
  const [q, setQ] = useState('');
  const [typeF, setTypeF] = useState('all');
  const [riskF, setRiskF] = useState('all');
  const [zoneF, setZoneF] = useState('all');
  const [statusF, setStatusF] = useState('all');
  const [sortKey, setSortKey] = useState('risk');
  const [sortDir, setSortDir] = useState('desc');
  const [sel, setSel] = useState(null);
  const [selError, setSelError] = useState(null);
  // Devices added/removed by the latest snapshot transition.
  const [addedIds, setAddedIds] = useState(new Set());
  const [removedCount, setRemovedCount] = useState(0);
  const prevIds = useRef(null);

  useEffect(() => {
    const ids = new Set((all || []).map((d) => d.id));
    if (prevIds.current === null) {
      prevIds.current = ids;
      return;
    }
    const added = new Set([...ids].filter((id) => !prevIds.current.has(id)));
    setAddedIds(added);
    setRemovedCount([...prevIds.current].filter((id) => !ids.has(id)).length);
    prevIds.current = ids;
  }, [snapshotId, all]);

  // A selected device that no longer exists cannot keep showing stale detail.
  useEffect(() => {
    if (sel && (all || []).length > 0 && !all.some((d) => d.id === sel.id)) setSel(null);
  }, [all, sel]);

  const rows = useMemo(() => {
    const s = q.toLowerCase();
    const filtered = (all || []).filter((d) => {
      if (typeF !== 'all' && (d.device_type || '') !== typeF) return false;
      if (riskF !== 'all' && (d.severity || 'none') !== riskF) return false;
      if (zoneF !== 'all' && (d.zone || '') !== zoneF) return false;
      if (statusF !== 'all' && (d.status || '') !== statusF) return false;
      if (s && !((d.name || '').toLowerCase().includes(s) || (d.ip || '').includes(s) || (d.vendor || '').toLowerCase().includes(s) || (d.label || '').toLowerCase().includes(s))) return false;
      return true;
    });
    const val = (d) => {
      switch (sortKey) {
        case 'ip': return d.ip || '';
        case 'type': return d.device_type || '';
        case 'vendor': return d.vendor || '';
        case 'os': return d.os || '';
        case 'zone': return d.zone || '';
        case 'ports': return d.port_count ?? (d.open_ports || []).length;
        case 'risk': return d.risk_score ?? d.risk ?? 0;
        case 'status': return d.status || '';
        default: return (d.name || d.label || '');
      }
    };
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const va = val(a), vb = val(b);
      const c = sortKey === 'ip' ? ipCmp(va, vb) : (typeof va === 'number' && typeof vb === 'number' ? va - vb : String(va).localeCompare(String(vb)));
      return c * dir;
    });
  }, [all, q, typeF, riskF, zoneF, statusF, sortKey, sortDir]);

  const sortBy = (key) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'risk' || key === 'ports' ? 'desc' : 'asc');
    }
  };
  const arrow = (key) => (sortKey === key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '');

  const open = async (id) => { try { setSelError(null); setSel(await api.device(id)); } catch (e) { setSelError(e); } };
  if (loading && (all || []).length === 0 && !error) return <LoadingState text="Loading device inventory…" />;
  if (error && (all || []).length === 0) return <ErrorState error={error} retry={load} />;

  const types = [...new Set(rows.map((r) => r.device_type))].sort();
  return (
    <div>
      <div className="filters">
        <input className="input" placeholder="Search name / IP / vendor…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 220 }} />
        <select className="input" value={typeF} onChange={(e) => setTypeF(e.target.value)}><option value="all">All types</option>{types.map((t) => <option key={t} value={t}>{t}</option>)}</select>
        <select className="input" value={riskF} onChange={(e) => setRiskF(e.target.value)}><option value="all">All risks</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="none">None</option></select>
        <select className="input" value={zoneF} onChange={(e) => setZoneF(e.target.value)}><option value="all">All zones</option>{zones.map((z) => <option key={z.name} value={z.name}>{z.name}</option>)}</select>
        <select className="input" value={statusF} onChange={(e) => setStatusF(e.target.value)}><option value="all">Any status</option><option value="online">Online</option><option value="offline">Offline</option></select>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>{rows.length} of {(all || []).length} devices</span>
        {addedIds.size > 0 && <span className="badge" style={{ background: 'var(--good-bg)', color: 'var(--good)', alignSelf: 'center' }}>+{addedIds.size} new</span>}
        {removedCount > 0 && <span className="badge" style={{ background: 'var(--sev-none-bg)', color: 'var(--text-muted)', alignSelf: 'center' }}>−{removedCount} removed</span>}
      </div>
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="tbl-scroll">
        <table className="tbl">
          <thead><tr>
            {['name|Device', 'ip|IP', 'type|Type', 'vendor|Vendor', 'os|OS', 'zone|Zone', 'ports|Ports', 'risk|Risk', 'status|Status'].map((col) => {
              const [key, label] = col.split('|');
              return <th key={key} onClick={() => sortBy(key)} style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }} title={`Sort by ${label}`}>{label}{arrow(key)}</th>;
            })}
          </tr></thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.id} className="clickable" onClick={() => open(d.id)} style={addedIds.has(d.id) ? { background: 'var(--good-bg)' } : undefined}>
                <td><b>{d.name || d.label}</b>{addedIds.has(d.id) && <span className="badge online" style={{ marginLeft: 6 }}>new</span>}<div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{d.finding_count ?? d.findings} findings</div></td>
                <td><code className="inline">{d.ip}</code></td>
                <td>{d.device_type}</td><td>{d.vendor || '—'}</td><td>{d.os || '—'}</td><td>{d.zone}</td>
                <td>{d.port_count ?? (d.open_ports || []).length}</td>
                <td><b>{d.risk_score ?? d.risk}</b> <RiskBadge severity={d.severity} /></td>
                <td><StatusBadge status={d.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        {rows.length === 0 && <div className="state-box"><h4>No devices match</h4><p>Adjust filters or run a new scan.</p><button className="btn primary" onClick={() => { setQ(''); setTypeF('all'); setRiskF('all'); setZoneF('all'); setStatusF('all'); load(); }}>Reset filters</button></div>}
      </div>
      <DeviceDrawer device={sel} onClose={() => setSel(null)} />
      {selError && <div className="alert error">{String(selError.message || selError)}</div>}
    </div>
  );
}
