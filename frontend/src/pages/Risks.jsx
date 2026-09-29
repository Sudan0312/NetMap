import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { RiskBadge, LoadingState, ErrorState, LiveDot } from '../components';
import { useScan } from '../store/ScanContext';

const fkey = (f) => `${f.rule_id || ''}|${f.target_id || ''}`;

export default function Risks() {
  // Register reads the global store; live flag comes from the store too.
  const { findings: all, summary, running: live, loading, error, reload: load, snapshotId } = useScan();
  const [sev, setSev] = useState('all');
  const [q, setQ] = useState('');
  const [expanded, setExpanded] = useState(null);
  const [expandAll, setExpandAll] = useState(false);
  // Findings that appeared / disappeared with the latest snapshot.
  const [newKeys, setNewKeys] = useState(new Set());
  const [resolvedCount, setResolvedCount] = useState(0);
  const prevKeys = useRef(null);
  useEffect(() => {
    const keys = new Set((all || []).map(fkey));
    if (prevKeys.current === null) {
      prevKeys.current = keys;
      return;
    }
    setNewKeys(new Set([...keys].filter((k) => !prevKeys.current.has(k))));
    setResolvedCount([...prevKeys.current].filter((k) => !keys.has(k)).length);
    prevKeys.current = keys;
  }, [snapshotId, all]);
  const snap = summary ? `${summary.snapshot_id} · ${summary.devices} devices · mode ${summary.mode}` : '';

  if (error && all.length === 0) return <ErrorState error={error} retry={load} />;
  if (loading && all.length === 0 && !error) return <LoadingState text="Loading risk register…" />;

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  all.forEach((r) => { if (counts[r.severity] !== undefined) counts[r.severity] += 1; });
  const sq = q.toLowerCase();
  const rows = all.filter((r) =>
    (sev === 'all' || r.severity === sev) &&
    (!sq || (r.title || '').toLowerCase().includes(sq) || (r.device || '').toLowerCase().includes(sq) || (r.rule_id || '').toLowerCase().includes(sq) || (r.ip || '').includes(sq))
  );

  return (
    <div>
      {live && <div className="alert"><LiveDot /> LIVE — a scan is running and new risks appear below in real time ({all.length} identified so far).</div>}
      {(newKeys.size > 0 || resolvedCount > 0) && (
        <div className="alert flash-in">
          {newKeys.size > 0 && <span>⚠ <b>{newKeys.size} new</b> finding{newKeys.size === 1 ? '' : 's'} in this scan. </span>}
          {resolvedCount > 0 && <span>✓ <b>{resolvedCount} resolved</b> since the previous scan.</span>}
        </div>
      )}
      <div className="sev-row bump" key={snapshotId || 'none'}>
        {Object.entries(counts).map(([s, n]) => (
          <button key={s} className="sev-block" style={{ cursor: 'pointer', background: sev === s ? 'var(--panel-3)' : undefined, outline: sev === s ? '3px solid var(--accent)' : 'none' }} onClick={() => setSev(sev === s ? 'all' : s)} title={`Filter ${s}`}>
            <RiskBadge severity={s} /><b>{n}</b><div style={{ fontSize: 11, color: 'var(--text-muted)' }}>total open</div>
          </button>
        ))}
      </div>
      <div className="filters">
        <select className="input" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <input className="input" placeholder="Search title / device / rule…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 240 }} />
        <button className="btn" onClick={load}>Refresh</button>
        <span style={{ fontSize: 13, color: 'var(--text-muted)', alignSelf: 'center', fontWeight: 700 }}>{rows.length} of {all.length} findings · {snap}</span>
      </div>
      {all.length === 0 && (
        <div className="state-box">
          <h4>No risks in this scan</h4>
          <p>The current snapshot ({snap || 'unknown'}) contains zero open findings. Run a discovery scan — demo mode with risk scenarios produces 100+ realistic findings.</p>
          <Link className="btn primary" to="/discovery">Run a discovery scan</Link>
        </div>
      )}
      {all.length > 0 && rows.length === 0 && (
        <div className="state-box"><h4>No findings match</h4><p>No {sev} findings{sq ? ` matching "${q}"` : ''} — try another severity or clear the search.</p></div>
      )}
      {rows.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <button className="btn" onClick={() => setExpandAll(true)}>Expand all</button>
          <button className="btn" onClick={() => { setExpandAll(false); setExpanded(null); }}>Collapse all</button>
        </div>
      )}
      <div className="risk-grid">
      {rows.map((f) => {
        const open = expandAll || expanded === f.id;
        return (
        <div className="card" key={f.id} style={{ margin: 0, ...(newKeys.has(fkey(f)) ? { borderColor: '#f59e0b', borderWidth: 2 } : {}) }}>
          <div className="risk-card-head" onClick={() => { setExpandAll(false); setExpanded(open ? null : f.id); }} title={open ? 'Collapse' : 'Expand'}>
            <div style={{ flex: 1 }}>
              <div className="risk-title" style={{ fontSize: 17 }}><RiskBadge severity={f.severity} /> <b>{f.title}</b>{newKeys.has(fkey(f)) && <span className="badge" style={{ background: 'var(--good-bg)', color: 'var(--good)', marginLeft: 6 }}>new</span>}</div>
              <div style={{ fontSize: 13, marginTop: 4 }}><b>{f.device || f.target}</b> {f.ip && <code className="inline">{f.ip}</code>} · score {f.score}</div>
            </div>
            <span className="risk-chev">{open ? '▾' : '▸'}</span>
          </div>
          {open && (
          <div style={{ marginTop: 10 }}>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 700 }}><code className="inline">{f.rule_id}</code> · Zone: <b>{f.zone || '—'}</b></div>
          {(f.evidence || []).map((e, i) => <div className="evidence" key={i}>{e}</div>)}
          {f.description && <div style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>{f.description}</div>}
          {f.recommendation && <div className="fixbox"><b>🔧 FIX:</b> {f.recommendation}</div>}
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6, fontWeight: 700 }}>Source: {f.source || f.rule_id} · First detected: {f.first_detected || f.first_seen || '—'} · Status: {f.status}</div>
          <div style={{ marginTop: 8, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {f.target_id && <Link className="btn" to={`/topology?focus=${encodeURIComponent(f.target_id)}`}>Show on topology</Link>}
          </div>
          </div>
          )}
        </div>
        );
      })}
      </div>
    </div>
  );
}
