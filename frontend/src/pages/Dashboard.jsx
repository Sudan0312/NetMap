import React, { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { MetricCard, RiskBadge, LoadingState, ErrorState, LiveDot } from '../components';
import { useScan } from '../store/ScanContext';
import { TopoPreview } from '../topology/TopoPreview';
import { timeAgo } from '../utils/format';
import { isLoopbackTargets } from '../utils/network';

const SEV_BAR_COLORS = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)' };

export default function Dashboard() {
  const nav = useNavigate();
  // All data comes from the global store (single invalidation point).
  const {
    summary: data, graph, findings: allFindings, changes,
    running: scanning, refreshToken, loading, error, reload: load, lastUpdated: updatedAt,
  } = useScan();
  const findings = (allFindings || []).slice(0, 8);

  // Flash whenever a new snapshot lands anywhere.
  const [flash, setFlash] = useState(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (refreshToken > 0) {
      setFlash('Network updated — a new discovery just landed. Every view now shows it.');
      const t = setTimeout(() => setFlash(null), 6000);
      return () => clearTimeout(t);
    }
  }, [refreshToken]);

  if (error) {
    // No scan on record at all: first-launch state, never an error wall.
    if (/no scan yet/i.test(String(error?.message || error || ''))) {
      return (
        <div className="card" style={{ textAlign: 'center', padding: '56px 24px' }}>
          <div style={{ fontSize: 44 }}>🛰️</div>
          <h3 style={{ fontSize: 24 }}>NO NETWORK DISCOVERED</h3>
          <div className="hint" style={{ fontSize: 15, maxWidth: 520, margin: '0 auto 18px' }}>
            Start your first discovery. Try the demo network for a full enterprise topology in seconds, or run a live discovery against your own authorized network.
          </div>
          <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button className="btn primary" style={{ fontSize: 16, padding: '12px 22px' }} onClick={() => nav('/discovery?autostart=demo')}>TRY DEMO NETWORK</button>
            <button className="btn" style={{ fontSize: 16, padding: '12px 22px' }} onClick={() => nav('/discovery?env=live')}>LIVE DISCOVERY</button>
          </div>
        </div>
      );
    }
    return <ErrorState error={error} retry={load} />;
  }
  if (!data) return <LoadingState text="Loading dashboard from /api/summary…" />;

  const sev = data.severity_counts || {};
  const loopback = isLoopbackTargets(data.targets);
  const sum = (changes && changes.summary) || {};
  const hasDiff = !!changes?.available;
  const delta = (v) => {
    if (!hasDiff || v == null || v === 0) return null;
    return <span className="delta-tag">{v > 0 ? `+${v}` : v}</span>;
  };
  const deltaCrit = () => {
    const v = sum.new_critical;
    if (!hasDiff || v == null || v === 0) return null;
    return <span className="delta-tag crit">+{v} new</span>;
  };
  const sevMax = Math.max(1, ...['critical', 'high', 'medium', 'low'].map((s) => sev[s] ?? 0));
  return (
    <div>
      <div className="card" style={{ padding: '12px 18px' }}>
        <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', alignItems: 'center', fontSize: 14 }}>
          <b>LAST DISCOVERY</b>
          <span className="badge" style={{ background: 'var(--good-bg)', color: 'var(--good)' }}>{data.mode === 'lab' ? 'demo' : 'live'}</span>
          <span>Target <b>{(data.targets || []).join(', ') || '—'}</b></span>
          <span>Time <b>{data.finished ? data.finished.slice(0, 16).replace('T', ' ') : '—'}</b> ({timeAgo(data.finished)})</span>
          <span style={{ color: 'var(--text-muted)' }}>{data.snapshot_id}</span>
        </div>
        <div className="hint" style={{ margin: '4px 0 0' }}>Most recent completed scan — not a live feed. Run a new discovery to refresh it.</div>
      </div>
      {loopback && (
        <div className="alert warn">⚠ You are viewing a <b>loopback test scan (127.0.0.1)</b> — not an enterprise network. <Link className="btn" to="/discovery?autostart=demo" style={{ marginLeft: 8 }}>Try demo network</Link> <Link className="btn" to="/discovery?env=live" style={{ marginLeft: 4 }}>Live discovery</Link></div>
      )}
      <div className="metrics">
        <MetricCard label="Devices" value={data.devices} sub={`${data.online ?? data.devices} online`} />
        <MetricCard label="Links" value={data.links} sub="topology edges" />
        <MetricCard label="Services" value={data.services ?? data.open_ports ?? 0} sub="open ports" />
        <MetricCard label="Risks" value={data.risks ?? data.findings} sub={`band: ${data.risk_band || data.risk?.band || '—'}`} />
        <MetricCard label="Critical Risks" value={data.critical ?? sev.critical ?? 0} sub="needs action now" accent="var(--sev-critical)" />
      </div>
      <div className="card" style={{ border: '2px solid rgba(13,122,95,.4)', boxShadow: '0 0 0 4px rgba(13,122,95,.07), 0 16px 40px -20px rgba(13,122,95,.55)' }}>
        <h3>Network topology — auto-drawn from the latest scan</h3>
        <div className="hint">Nodes grouped by zone · ring color = worst open severity · click a node for details</div>
        {flash && <div className="alert flash-in">✓ {flash}</div>}
        {!graph && <LoadingState text="Drawing network…" />}
        {graph && (
          <div className="map-hero">
            {scanning && <div className="scan-shimmer"><span><span className="live-dot" /> DISCOVERING — map refreshes on completion</span></div>}
            <div className="map-mode"><span className="map-chip light">{data.mode === 'lab' ? '◎ DEMO NETWORK' : '◉ LIVE DISCOVERY'}</span></div>
            <div className="map-chips bump" key={data.snapshot_id}>
              <span className="map-chip">🖧 {data.devices} devices {delta(sum.devices_added - sum.devices_removed)}</span>
              <span className="map-chip">🔗 {data.links} links</span>
              <span className="map-chip">🖥️ {data.services ?? data.open_ports ?? 0} services</span>
              <span className="map-chip">⚠ {data.risks ?? data.findings} risks {delta(sum.findings_appeared - sum.findings_resolved)}</span>
              <span className={`map-chip${(data.critical ?? sev.critical ?? 0) > 0 ? ' alert-red' : ''}`}>🔥 {data.critical ?? sev.critical ?? 0} critical {deltaCrit()}</span>
              <span className="map-chip">⑂ {data.risk_score ?? data.risk?.score ?? '—'} {hasDiff && sum.risk_delta != null && sum.risk_delta !== 0 ? <span className="delta-tag">{sum.risk_delta > 0 ? `+${sum.risk_delta}` : sum.risk_delta}</span> : null}</span>
            </div>
            <TopoPreview graph={graph} onOpen={() => nav('/topology')} />
          </div>
        )}
        <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <Link className="btn primary" to="/topology">Open interactive topology</Link>
          <span style={{ fontSize: 13, color: 'var(--text-muted)', fontWeight: 700 }}><LiveDot title="Dashboard follows every discovery" /> LIVE · updated {updatedAt ? updatedAt.toLocaleTimeString() : '…'} · refreshes on every discovery</span>
        </div>
      </div>

      <div className="grid2">
        <div>
          <div className="card">
            <h3>Risk overview</h3>
            <div className="hint">Open findings by severity · from /api/findings</div>
            <div className="sev-row">
              {['critical', 'high', 'medium', 'low'].map((s) => (
                <div className="sev-block" key={s}>
                  <RiskBadge severity={s} /><b>{sev[s] ?? 0}</b>
                  <div className="sev-bar"><div style={{ width: `${100 * (sev[s] ?? 0) / sevMax}%`, background: SEV_BAR_COLORS[s] }} /></div>
                </div>
              ))}
            </div>
            <Link className="btn" to="/risks">Open risk register</Link>{' '}
            <Link className="btn" to="/topology">View topology</Link>
          </div>

          <div className="card">
            <h3>Critical Risks</h3>
            <div className="hint">Highest-priority open findings — act on these first</div>
            {(findings.filter((f) => f.severity === 'critical').slice(0, 5)).length === 0 && (
              <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>No open critical findings. 🎉</p>
            )}
            <div className="tbl-scroll">
            <table className="tbl">
              <tbody>
                {findings.filter((f) => f.severity === 'critical').slice(0, 5).map((f) => (
                  <tr key={f.id}><td><RiskBadge severity={f.severity} /></td><td>{f.title}</td><td>{f.device || f.target}</td></tr>
                ))}
              </tbody>
            </table>
            </div>
          </div>

          <div className="card">
            <h3>Recent Discovery</h3>
            <div className="hint">Highest-scored open findings from the latest scan</div>
            <div className="tbl-scroll">
            <table className="tbl">
              <thead><tr><th>Severity</th><th>Finding</th><th>Target</th></tr></thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}><td><RiskBadge severity={f.severity} /></td><td>{f.title}</td><td>{f.device || f.target}</td></tr>
                ))}
              </tbody>
            </table>
            </div>
          </div>
        </div>

        <div>
          <div className="card">
            <h3>Network changes</h3>
            <div className="hint">Diff of the last two scans · /api/changes</div>
            {!changes?.available && <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>{changes?.reason || 'Run at least two scans to compare.'}</p>}
            {changes?.available && (
              <div style={{ fontSize: 13 }}>
                <div>＋ {changes.summary.devices_added} devices · － {changes.summary.devices_removed} removed</div>
                <div>⚠ {changes.summary.findings_appeared} new risks · ✓ {changes.summary.findings_resolved} resolved</div>
                <div>Risk Δ {changes.summary.risk_delta ?? 0}</div>
                <div style={{ marginTop: 8 }}><Link className="btn" to="/history">Inspect history</Link></div>
              </div>
            )}
          </div>
          <div className="card">
            <h3>Scan info</h3>
            <div className="hint">Provenance — demo vs live is always explicit</div>
            <div style={{ fontSize: 13 }}>
              <div>Snapshot <code className="inline">{data.snapshot_id}</code></div>
              <div>Mode <b>{data.mode}</b> {data.mode === 'lab' ? '(demo / synthetic)' : '(live discovery)'}</div>
              <div>Targets <code className="inline">{(data.targets || []).join(', ')}</code></div>
              <div>Finished {data.finished} · {data.duration}s</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
