import React, { useMemo, useState } from 'react';
import { RiskBadge, StatusBadge, LoadingState, ErrorState } from '../components';
import { useScan } from '../store/ScanContext';

// Service inventory: one row per open service per device, joined with the
// device's risk and status from the same snapshot. All data is backend state.
export default function Services() {
  const { devices, loading, error, reload } = useScan();
  const [q, setQ] = useState('');
  const [protoF, setProtoF] = useState('all');

  const rows = useMemo(() => {
    const out = [];
    for (const d of devices || []) {
      for (const s of d.services || []) {
        out.push({
          id: `${d.id}:${s.port}/${s.protocol}`,
          service: s.name || s.product || `port ${s.port}`,
          port: s.port,
          protocol: s.protocol,
          device: d.hostname || d.ip || d.label,
          ip: d.ip,
          risk: d.risk_score ?? d.risk ?? 0,
          severity: d.severity || 'none',
          status: d.status || (d.reachable ? 'online' : 'offline'),
        });
      }
    }
    const needle = q.toLowerCase();
    return out
      .filter((r) => (protoF === 'all' || r.protocol === protoF) &&
        (!needle || (r.service || '').toLowerCase().includes(needle) || String(r.port).includes(needle) ||
          (r.device || '').toLowerCase().includes(needle) || (r.ip || '').includes(needle)))
      .sort((a, b) => b.risk - a.risk || a.port - b.port);
  }, [devices, q, protoF]);

  if (loading && (devices || []).length === 0 && !error) return <LoadingState text="Loading service inventory…" />;
  if (error && (devices || []).length === 0) return <ErrorState error={error} retry={reload} />;

  return (
    <div>
      <div className="filters">
        <input className="input" placeholder="Search service / port / device…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 240 }} aria-label="Search services" />
        <select className="input" value={protoF} onChange={(e) => setProtoF(e.target.value)} aria-label="Protocol filter">
          <option value="all">All protocols</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <span style={{ fontSize: 13, color: 'var(--text-muted)', alignSelf: 'center', fontWeight: 700 }}>{rows.length} open services</span>
      </div>
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="tbl-scroll">
          <table className="tbl">
            <thead><tr><th>Service</th><th>Port</th><th>Protocol</th><th>Device</th><th>IP</th><th>Risk</th><th>Status</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td><b>{r.service}</b></td>
                  <td><b>{r.port}</b></td>
                  <td>{r.protocol}</td>
                  <td>{r.device}</td>
                  <td><code className="inline">{r.ip}</code></td>
                  <td><b>{r.risk}</b> <RiskBadge severity={r.severity} /></td>
                  <td><StatusBadge status={r.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {rows.length === 0 && <div className="state-box"><h4>No services match</h4><p>Adjust the search or run a new discovery scan.</p></div>}
      </div>
    </div>
  );
}
