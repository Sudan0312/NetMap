import React, { useEffect, useRef, useState } from 'react';

// Shared UI atoms (cards, badges, drawers, progress). Topology iconography
// and layout live in topology/; API access lives in services/.

export function MetricCard({ label, value, sub, accent }) {
  const numeric = typeof value === 'number' && Number.isInteger(value);
  const texty = typeof value === 'string' && value.length > 12;
  return (
    <div className="metric">
      <div className="k">{label}</div>
      <div className="v" style={{ ...(accent ? { color: accent } : {}), ...(texty ? { fontSize: 16 } : {}) }}>{numeric ? <CountUp value={value} /> : value}</div>
      {sub && <div className="s">{sub}</div>}
    </div>
  );
}

export function CountUp({ value, duration = 900 }) {
  const target = Number(value) || 0;
  const [display, setDisplay] = useState(target);
  const from = useRef(0);
  useEffect(() => {
    const start = from.current;
    from.current = target;
    if (start === target) { setDisplay(target); return; }
    let raf;
    const t0 = performance.now();
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / duration);
      setDisplay(Math.round(start + (target - start) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target]);
  return <>{display}</>;
}

export function LiveDot({ off, title }) {
  return <span className={`live-dot${off ? ' gray' : ''}`} title={title} />;
}

export function RiskBadge({ severity }) {
  const s = (severity || 'none').toLowerCase();
  const dot = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵', none: '⚪' }[s] || '⚪';
  return <span className={`badge ${s}`}>{dot} {s}</span>;
}

export function StatusBadge({ status }) {
  const s = (status || 'unknown').toLowerCase();
  return <span className={`badge ${s}`}>{s}</span>;
}

export function LoadingState({ text }) {
  return (
    <div className="state-box">
      <div className="skel" style={{ height: 20, width: '38%', margin: '0 auto 10px' }} />
      <div className="skel" style={{ height: 13, width: '68%', margin: '0 auto 8px' }} />
      <div className="skel" style={{ height: 13, width: '52%', margin: '0 auto 10px' }} />
      <p>{text || 'Fetching live data from the NetMap API.'}</p>
    </div>
  );
}

export function EmptyState({ title, hint, action }) {
  return (
    <div className="state-box">
      <h4>{title || 'No data yet'}</h4>
      <p>{hint || 'Run a discovery scan to populate this view.'}</p>
      {action}
    </div>
  );
}

export function ErrorState({ error, retry }) {
  const isEmpty = /no scan yet/i.test(String(error?.message || error || ''));
  return (
    <div className="state-box">
      <h4>{isEmpty ? 'No scan yet' : 'Something went wrong'}</h4>
      <p>{isEmpty ? 'Run a discovery scan first — demo mode needs no network access.' : String(error?.message || error)}</p>
      {retry && <button className="btn" onClick={retry}>Retry</button>}
    </div>
  );
}

export function ScanProgress({ job }) {
  if (!job) return null;
  const pct = job.progress ?? job.done ?? 0;
  return (
    <div>
      <div className="bar"><div style={{ width: `${pct}%` }} /></div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>{pct}% · {job.message || job.stage}</div>
      <div className="progress-stages">
        {(job.stages || []).map((s) => (
          <div className="stage-row" key={s.id}>
            <span className={`dot ${s.state}`}>{s.state === 'done' ? '✓' : s.state === 'running' ? '●' : s.state === 'error' ? '!' : '○'}</span>
            <span style={{ fontWeight: s.state === 'running' ? 700 : 400 }}>{s.label}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{s.state}</span>
          </div>
        ))}
      </div>
      {(job.counts) && (
        <div style={{ fontSize: 13 }}>
          Devices: <b>{job.counts.devices || 0}</b> · Services: <b>{job.counts.services || 0}</b> · Links: <b>{job.counts.links || 0}</b> · Risks: <b>{job.counts.risks || 0}</b>
        </div>
      )}
      {job.error && <div className="alert error">{job.error}</div>}
    </div>
  );
}

export function DeviceDrawer({ device, onClose }) {
  if (!device) return null;
  const ports = device.open_ports || device.ports || [];
  const neighbours = device.neighbors || device.neighbours || [];
  return (
    <div className="drawer" role="dialog" aria-label={`Device details for ${device.name || device.label || device.ip}`}>
      <div className="drawer-head">
        <div>
          <div style={{ fontSize: 12, fontWeight: 800, letterSpacing: '0.8px', color: 'var(--text-muted)' }}>DEVICE</div>
          <h3 style={{ margin: '2px 0', fontSize: 22 }}>{device.name || device.label}</h3>
          <div style={{ marginTop: 6 }}><RiskBadge severity={device.severity} /> <StatusBadge status={device.status} /></div>
        </div>
        <button className="btn" onClick={onClose} aria-label="Close device details">✕</button>
      </div>
      <div className="drawer-section">
        <h4>Identity</h4>
        <dl className="kv">
          <dt>IP</dt><dd><code className="inline">{device.ip || '—'}</code></dd>
          <dt>MAC</dt><dd>{device.mac || '—'}</dd>
          <dt>Vendor</dt><dd>{device.vendor || '—'}</dd>
          <dt>Model</dt><dd>{device.model || '—'}</dd>
          <dt>OS</dt><dd>{device.os || '—'}</dd>
          <dt>Device type</dt><dd>{device.device_type || device.type}</dd>
          <dt>Zone</dt><dd>{device.zone || '—'} ({device.trust || '?'})</dd>
          <dt>Status</dt><dd><StatusBadge status={device.status} /></dd>
        </dl>
      </div>
      <div className="drawer-section">
        <h4>Risk score</h4>
        <div style={{ fontSize: 34, fontWeight: 800, fontVariantNumeric: 'tabular-nums' }}>{device.risk_score ?? device.risk ?? 0}</div>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>{device.finding_count ?? (device.findings || []).length ?? 0} open findings</div>
      </div>
      <div className="drawer-section">
        <h4>Services ({(device.services || []).length})</h4>
        {(device.services || []).length === 0 && <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>No open services recorded.</p>}
        {(device.services || []).map((s, i) => (
          <div className="evidence" key={i}><b>{s.port} {s.name || s.product || ''}</b>{s.protocol ? ` · ${s.protocol}` : ''}{s.version ? ` · ${s.version}` : ''}</div>
        ))}
        <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6 }}>Ports: {ports.length ? ports.join(', ') : '—'}</div>
      </div>
      <div className="drawer-section">
        <h4>Security findings ({(device.findings || []).length})</h4>
        {(device.findings || []).map((f, i) => (
          <div className="evidence" key={i}>
            <RiskBadge severity={f.severity} /> <b>{f.title}</b>
            <div style={{ marginTop: 4 }}>{(f.evidence || []).slice(0, 2).join(' · ')}</div>
            {f.remediation && <div style={{ marginTop: 4, color: 'var(--text-secondary)' }}>Fix: {f.remediation}</div>}
          </div>
        ))}
        {(device.findings || []).length === 0 && <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>No findings for this device.</p>}
      </div>
      <div className="drawer-section">
        <h4>Neighbours ({neighbours.length})</h4>
        {neighbours.map((n, i) => (
          <div className="evidence" key={i}>{n.remote} via {n.local_if} ({n.via})</div>
        ))}
        {neighbours.length === 0 && <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>No recorded adjacencies.</p>}
      </div>
      <div className="drawer-section">
        <h4>Discovery</h4>
        <dl className="kv">
          <dt>First seen</dt><dd>{device.first_seen || device.last_seen || '—'}</dd>
          <dt>Last seen</dt><dd>{device.last_seen || '—'}</dd>
          <dt>Sources</dt><dd>{(device.discovery_sources || device.sources || []).join(', ') || '—'}</dd>
        </dl>
      </div>
    </div>
  );
}

export function StageBanner({ job }) {
  // Staged, backend-driven transitions: DISCOVERING → DEVICES → LINKS → RISKS → READY.
  if (!job) return null;
  const nDev = (job.live_devices || []).length || job.counts?.devices || 0;
  const nLinks = (job.live_links || []).length || job.counts?.links || 0;
  const nRisks = (job.live_findings || []).length || job.counts?.risks || 0;
  const done = job.status === 'completed';
  const stages = [
    { label: 'DISCOVERING', state: 'done', sub: job.environment === 'demo' ? 'demo' : 'live' },
    { label: `${nDev} DEVICES DISCOVERED`, state: nDev > 0 || done ? 'done' : job.status === 'running' ? 'active' : 'locked' },
    { label: `${nLinks} LINKS MAPPED`, state: nLinks > 0 || done ? 'done' : 'locked' },
    { label: `${nRisks} RISKS IDENTIFIED`, state: nRisks > 0 || done ? 'done' : 'locked' },
    { label: 'NETWORK READY', state: done ? 'done' : 'locked' },
  ];
  return (
    <div className="stage-banner">
      {stages.map((s, i) => (
        <div key={i} className={`sb-chip ${s.state}`}>
          <span className="sb-dot">{s.state === 'done' ? '✓' : s.state === 'active' ? '●' : '○'}</span>
          <span><b>{s.label}</b>{s.sub && <span className="sb-sub">{s.sub}</span>}</span>
        </div>
      ))}
    </div>
  );
}
