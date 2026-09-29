import React, { useEffect, useRef, useState } from 'react';
import { api, reportUrl } from '../services/api';
import { LoadingState, ErrorState } from '../components';
import { Icon } from '../components/icons';
import { useFetch } from '../hooks/useFetch';
import { useScan } from '../store/ScanContext';
import { ThemeToggle } from '../store/ThemeContext';

export function History() {
  // List comes from the global store (auto-invalidated on new snapshots);
  // compare + row detail stay local.
  const { history: rows, loading, error, reload: load } = useScan();
  const [flash, setFlash] = useState(null);
  const [freshId, setFreshId] = useState(null);
  const seenIds = useRef(null);
  // A scan landing mid-session announces itself and highlights its row.
  useEffect(() => {
    const ids = (rows || []).map((r) => r.snapshot_id);
    if (seenIds.current === null) {
      seenIds.current = new Set(ids);
      return;
    }
    const added = ids.filter((id) => !seenIds.current.has(id));
    seenIds.current = new Set(ids);
    if (added.length > 0) {
      setFreshId(added[0]);
      setFlash(`History updated — ${added.length} new scan${added.length === 1 ? '' : 's'} added. Change detection now compares against the newest.`);
      const t = setTimeout(() => setFlash(null), 8000);
      return () => clearTimeout(t);
    }
  }, [rows]);
  const [cmp, setCmp] = useState(null);
  const [sel, setSel] = useState([]);
  const [openId, setOpenId] = useState(null);
  const [detail, setDetail] = useState({});
  const compare = async () => {
    if (sel.length !== 2) return;
    setCmp(await api.compare(sel[0], sel[1]));
  };
  const toggle = async (id) => {
    if (openId === id) { setOpenId(null); return; }
    setOpenId(id);
    if (!detail[id]) {
      try {
        const det = await api.historyOne(id);
        setDetail((d) => ({ ...d, [id]: det }));
      } catch { /* keep closed data */ }
    }
  };
  const dur = (r) => (r.duration != null ? `${r.duration}s` : '—');
  if (error) return <ErrorState error={error} retry={load} />;
  if (loading || !rows) return <LoadingState text="Loading scan history…" />;
  return (
    <div>
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '16px 18px 4px' }}>
          <h3 style={{ margin: 0 }}>Scan history</h3>
          <div className="hint">Every completed scan persists a snapshot with its times and risks. Click a row for detail. Select two rows to compare.</div>
        </div>
        {flash && <div className="alert flash-in" style={{ margin: '0 18px 8px' }}>✓ {flash}</div>}
        <div className="tbl-scroll">
        <table className="tbl">
          <thead><tr><th></th><th></th><th>Scan</th><th>Started</th><th>Duration</th><th>Devices</th><th>Risks detected</th><th>Status</th></tr></thead>
          <tbody>
            {rows.map((r) => {
              const sc = r.severity_counts || {};
              const open = openId === r.snapshot_id;
              const det = detail[r.snapshot_id];
              const fresh = freshId === r.snapshot_id;
              return (
                <React.Fragment key={r.snapshot_id}>
                  <tr className="clickable" onClick={() => toggle(r.snapshot_id)} style={fresh ? { background: 'var(--good-bg)' } : undefined}>
                    <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={sel.includes(r.snapshot_id)} onChange={() => setSel((s) => s.includes(r.snapshot_id) ? s.filter((x) => x !== r.snapshot_id) : [...s, r.snapshot_id].slice(-2))} /></td>
                    <td>{open ? '▾' : '▸'}</td>
                    <td><b>{r.environment}</b> <code className="inline">{r.target}</code>{fresh && <span className="badge" style={{ background: 'var(--good-bg)', color: 'var(--good)', marginLeft: 6 }}>new</span>}<div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{r.snapshot_id}</div></td>
                    <td style={{ fontSize: 13 }}>{(r.started || '').slice(0, 16).replace('T', ' ')}</td>
                    <td><b>{dur(r)}</b></td>
                    <td><b>{r.devices}</b></td>
                    <td><b>{r.findings}</b> {(sc.critical > 0 || sc.high > 0) && <span style={{ fontSize: 11 }}><span className="badge critical">{sc.critical || 0}C</span> <span className="badge high">{sc.high || 0}H</span></span>}</td>
                    <td>{r.status}</td>
                  </tr>
                  {open && (
                    <tr>
                      <td colSpan={8} style={{ background: 'var(--panel-2)' }}>
                        {!det && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>Loading detail…</span>}
                        {det && (
                          <div style={{ display: 'flex', gap: 22, flexWrap: 'wrap', padding: '6px 4px' }}>
                            <div style={{ fontSize: 14 }}>
                              <div><b>Scan time:</b> {(r.started || '').slice(0, 16).replace('T', ' ')} → {(r.finished || '').slice(0, 16).replace('T', ' ')} ({dur(r)})</div>
                              <div><b>Result:</b> {det.devices} devices · {det.links} links · {det.findings} findings</div>
                              <div><b>Risk band:</b> {(det.summary && (det.summary.risk_band || (det.summary.summary || {}).risk_band)) || '—'}</div>
                            </div>
                            <div style={{ fontSize: 14 }}>
                              <b>Risks detected:</b>
                              <div className="sev-row" style={{ margin: '6px 0 0' }}>
                                {['critical', 'high', 'medium', 'low'].map((s) => (
                                  <div className="sev-block" key={s} style={{ minWidth: 84 }}><span className={`badge ${s}`}>{s}</span><b>{(det.severity_counts || {})[s] ?? 0}</b></div>
                                ))}
                              </div>
                            </div>
                            <div style={{ fontSize: 14, flex: '1 1 260px' }}>
                              <b>Top findings:</b>
                              {(det.top_findings || []).map((f, i) => (
                                <div className="evidence" key={i}><b>[{f.severity}]</b> {f.title} — {f.device}</div>
                              ))}
                              {(det.top_findings || []).length === 0 && <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>No open findings in this scan.</div>}
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
        </div>
        <div style={{ padding: '0 18px 16px' }}><button className="btn" disabled={sel.length !== 2} onClick={compare}>Compare selected</button></div>
      </div>
      {cmp && (
        <div className="card">
          <h3>Comparison: {cmp.old_id} → {cmp.new_id}</h3>
          <div style={{ fontSize: 13 }}>
            <div>＋ {cmp.summary.devices_added} devices · － {cmp.summary.devices_removed} removed · {cmp.summary.device_changes} changed</div>
            <div>⚠ {cmp.summary.findings_appeared} new risks · ✓ {cmp.summary.findings_resolved} resolved · critical {cmp.summary.new_critical}</div>
            {(cmp.changes.devices_added || []).slice(0, 10).map((d, i) => <div className="evidence" key={i}>+ {d}</div>)}
            {(cmp.changes.devices_removed || []).slice(0, 10).map((d, i) => <div className="evidence" key={i}>− {d}</div>)}
          </div>
        </div>
      )}
      {rows.length < 2 && <div className="alert">Run another scan (Discovery → Start discovery) to enable change detection.</div>}
    </div>
  );
}

const REPORT_CARDS = [
  { format: 'md', ico: 'executive', title: 'Executive Report', desc: 'Nine-section management summary: posture, top risks, zones and drift. Markdown.' },
  { format: 'json', ico: 'technical', title: 'Technical Report', desc: 'Full machine-readable snapshot: devices, links, findings, scores. JSON.' },
  { format: 'html', ico: 'html', title: 'HTML', desc: 'Standalone offline dashboard with embedded topology. HTML.' },
  { format: 'sarif', ico: 'sarif', title: 'SARIF', desc: 'Static-analysis results for CI pipelines. SARIF 2.1.0.' },
  { format: 'cef', ico: 'cef', title: 'CEF', desc: 'ArcSight feed lines for SIEM ingest, one per finding. CEF.' },
  { format: 'csv', ico: 'csv', title: 'CSV tables', desc: 'Findings and devices as spreadsheet tables. CSV.' },
];

export function Reports() {
  const { data: list } = useFetch(() => api.reports().catch(() => []), []);
  const available = new Set((list || []).map((r) => r.format));
  return (
    <div>
      <div className="card">
        <h3>Reports</h3>
        <div className="hint">Generated on demand from the current snapshot — never hardcoded.</div>
        {REPORT_CARDS.filter((c) => available.has(c.format)).map((c) => (
          <div className="report-card" key={c.format}>
            <span className="report-ico" aria-hidden="true"><Icon name={c.ico} size={24} /></span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 16, fontWeight: 700 }}>{c.title}</div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>{c.desc}</div>
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              <a className="btn" href={reportUrl(c.format)} target="_blank" rel="noreferrer">Generate</a>
              <a className="btn primary" href={reportUrl(c.format)} download>Download</a>
            </div>
          </div>
        ))}
        {(list || []).filter((r) => !REPORT_CARDS.some((c) => c.format === r.format)).map((r) => (
          <div className="report-card" key={r.format}>
            <span className="report-ico" aria-hidden="true"><Icon name="file" size={24} /></span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 16, fontWeight: 700 }}>{r.label}</div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Additional export format.</div>
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              <a className="btn" href={reportUrl(r.format)} target="_blank" rel="noreferrer">Generate</a>
              <a className="btn primary" href={reportUrl(r.format)} download>Download</a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function Settings() {
  const [caps, setCaps] = useState(null);
  const [health, setHealth] = useState(null);
  const [snmp, setSnmp] = useState(null);
  const [snmpInput, setSnmpInput] = useState('');
  const [snmpMsg, setSnmpMsg] = useState('');
  const refreshCaps = () => {
    api.capabilities().then(setCaps).catch(() => {});
    api.health().then(setHealth).catch(() => {});
    api.snmpGet().then(setSnmp).catch(() => {});
  };
  useEffect(() => { refreshCaps(); }, []);
  const saveSnmp = async () => {
    try {
      setSnmpMsg('');
      await api.snmpSave(snmpInput.trim());
      setSnmpInput('');
      setSnmpMsg('Saved for this backend session.');
      refreshCaps();
    } catch (e) { setSnmpMsg(String(e.message || e)); }
  };
  const clearSnmp = async () => {
    await api.snmpClear().catch(() => {});
    setSnmpMsg('Cleared.');
    refreshCaps();
  };
  return (
    <div>
      <div className="card">
        <h3>Appearance</h3>
        <div className="hint">Dark and light mode apply to the entire application and persist on this device.</div>
        <ThemeToggle />
      </div>
      <div className="card">
        <h3>API status</h3>
        <div className="hint">Backend connection backing every view.</div>
        <div style={{ fontSize: 14 }}>
          <div>Backend <code className="inline">{window.location.origin}/api/health</code></div>
          <div style={{ marginTop: 6 }}>
            {health ? (
              <>✓ Reachable — NetMap v{health.version} (code {health.code_version || 'pre-handshake'}) · {health.scans} stored scans · snapshot <code className="inline">{health.snapshot_id || 'none'}</code></>
            ) : '… connecting'}
          </div>
        </div>
      </div>
      <div className="card">
        <h3>Discovery capabilities</h3>
        <div className="hint">Method availability on this scanner host.</div>
        <div style={{ fontSize: 14 }}>
          {(Object.entries(caps?.methods || {})).map(([k, v]) => (
            <div key={k} style={{ marginTop: 8 }}>{v.available === false ? '⚠' : '✓'} <b>{v.label || k}</b> {v.note ? `— ${v.note}` : v.configured === false ? '— not configured' : ''}</div>
          ))}
          {!caps && <div>… loading</div>}
        </div>
      </div>
      <div className="card">
        <h3>SNMP credentials</h3>
        <div className="hint">One community tried first on every scan. Session-only: kept in backend memory, never written to disk, never shown back, cleared on restart.</div>
        <div style={{ fontSize: 14 }}>
          <div>Status: <b>{snmp ? (snmp.configured ? `✓ configured (${snmp.source})` : 'not configured') : '… loading'}</b></div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10, maxWidth: 440 }}>
            <input className="input" type="password" value={snmpInput} onChange={(e) => setSnmpInput(e.target.value)} placeholder="e.g. public" autoComplete="off" aria-label="SNMP community" />
            <button className="btn primary" onClick={saveSnmp} disabled={!snmpInput.trim()}>Save</button>
            <button className="btn" onClick={clearSnmp}>Clear</button>
          </div>
          {snmpMsg && <div style={{ marginTop: 8, fontSize: 13 }}>{snmpMsg}</div>}
        </div>
      </div>
      <div className="card">
        <h3>Safety & authorization</h3>
        <div className="hint">Scanning is authorized-discovery only.</div>
        <div style={{ fontSize: 14 }}>No exploits, no brute-force, no config changes — read-only probes and banner grabs. Live scans require explicit confirmation and private/loopback targets only.</div>
      </div>
    </div>
  );
}
