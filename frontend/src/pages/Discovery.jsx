import React, { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../services/api';
import { ScanProgress, RiskBadge, StageBanner, LiveDot } from '../components';
import { TopoPreview } from '../topology/TopoPreview';

const DEFAULT_METHODS = { arp: true, tcp: true, udp: true, dns: true, tls: true, snmp: true, cdp_lldp: true };
const METHOD_LABELS = {
  arp: 'Host Discovery', tcp: 'Port Discovery (TCP)', udp: 'Port Discovery (UDP)',
  dns: 'DNS', tls: 'Service Detection', snmp: 'SNMP', cdp_lldp: 'CDP / LLDP',
};

export default function Discovery() {
  const [target, setTarget] = useState('192.168.1.0/24');
  const [methods, setMethods] = useState(DEFAULT_METHODS);
  const [scanMode, setScanMode] = useState('normal');
  const [env, setEnv] = useState('demo');
  const [size, setSize] = useState('medium');
  const [seed, setSeed] = useState(7);
  const [includeRisks, setIncludeRisks] = useState(true);
  const [snmpCommunity, setSnmpCommunity] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [caps, setCaps] = useState(null);
  const [job, setJob] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [stream, setStream] = useState('sse'); // sse | polling — which channel delivered the last update
  const [sp, setSp] = useSearchParams();
  const autoDone = useRef(null);
  const beginRef = useRef(null);

  useEffect(() => { api.capabilities().then(setCaps).catch(() => {}); }, []);

  useEffect(() => {
    if (!job || job.status === 'completed' || job.status === 'failed') return;
    const id = job.job_id;
    let poll = null;
    let es = null;
    const startPolling = () => {
      if (poll) return;
      poll = setInterval(async () => {
        try {
          const j = await api.job(id);
          setStream('polling');
          setJob(j);
          if (j.status === 'completed' || j.status === 'failed') { clearInterval(poll); }
        } catch { /* keep polling */ }
      }, 700);
    };
    try {
      es = new EventSource(`/api/scan/${id}/events`);
      es.onmessage = (ev) => {
        try {
          const j = JSON.parse(ev.data);
          setStream('sse');
          setJob(j);
          if (j.status === 'completed' || j.status === 'failed') { es.close(); }
        } catch { /* ignore malformed chunk */ }
      };
      es.onerror = () => { es.close(); es = null; startPolling(); };
    } catch { startPolling(); }
    const guard = setTimeout(() => { if (!es) startPolling(); }, 2500);
    return () => { clearTimeout(guard); if (es) es.close(); if (poll) clearInterval(poll); };
  }, [job?.job_id]);

  const start = async (over = {}) => {
    try {
      setError(null); setBusy(true);
      const useEnv = over.environment || env;
      const body = {
        target, environment: useEnv, size, seed: Number(seed) || 0, include_risks: includeRisks,
        mode: scanMode, methods, confirmAuthorized: over.confirmAuthorized ?? confirm, statement: 'web UI authorized scan',
      };
      if (useEnv === 'live' && snmpCommunity.trim()) body.snmp_community = snmpCommunity.trim();
      const j = await api.scan(body);
      if (JSON.stringify(j).toLowerCase().includes((snmpCommunity || 'zzz-no-match').toLowerCase()) && snmpCommunity.trim()) {
        throw new Error('Backend echoed the SNMP secret — refusing to continue.');
      }
      setSnmpCommunity('');
      setJob(j);
    } catch (e) { setError(e.message || String(e)); }
    finally { setBusy(false); }
  };

  const toggle = (k) => setMethods((m) => ({ ...m, [k]: !m[k] }));

  // ---- guided flow -------------------------------------------------------
  const [step, setStep] = useState(0); // 0 Environment · 1 Target · 2 Launch
  const watchRef = useRef(null);
  const targetValid = env === 'demo' ? true : target.trim().length > 0;
  const canLaunch = targetValid && (env === 'demo' || confirm) && !busy;
  const phase = livePhase(job); // 3..7 once a job exists, else null
  const active = job ? phase : step;

  const begin = async (overEnv) => {
    await start(overEnv ? { environment: overEnv } : undefined);
    setTimeout(() => watchRef.current && watchRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' }), 150);
  };
  const startOver = () => { setJob(null); setStep(0); setError(null); autoDone.current = null; };
  beginRef.current = begin;

  // One-click entry: /discovery?autostart=demo launches immediately,
  // /discovery?env=live preselects live. Params are consumed, not stored.
  useEffect(() => {
    const a = sp.get('autostart');
    const e = sp.get('env');
    if (e === 'live' || e === 'demo') setEnv(e);
    if ((a === 'demo' || a === 'live') && autoDone.current !== a && !job) {
      autoDone.current = a;
      setEnv(a);
      setSp({}, { replace: true });
      setTimeout(() => { if (beginRef.current) beginRef.current(a); }, 400);
    } else if (a || e) {
      setSp({}, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sp]);

  return (
    <div>
      <Stepper active={active} job={job} goto={(s) => { if (!job && s <= 2) setStep(s); }} />

      {!job && step === 0 && (
        <div className="card">
          <h3>Step 1 — Select environment</h3>
          <div className="hint">Live discovery really probes the wire. Demo builds a labelled synthetic enterprise network — nothing leaves this machine.</div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <button className="btn" style={env === 'live' ? { borderColor: 'var(--accent)', color: 'var(--accent)', borderWidth: 2 } : undefined} onClick={() => setEnv('live')}>
              <b>◉ Live network</b><div style={{ fontSize: 12, fontWeight: 400 }}>ARP / TCP / UDP / DNS / TLS / SNMP against your target. Authorization required.</div>
            </button>
            <button className="btn" style={env === 'demo' ? { borderColor: 'var(--accent)', color: 'var(--accent)', borderWidth: 2 } : undefined} onClick={() => setEnv('demo')}>
              <b>◎ Demo network</b><div style={{ fontSize: 12, fontWeight: 400 }}>Synthetic campus: firewalls, switches, servers, IoT, DMZ + realistic risks. No network needed.</div>
            </button>
          </div>
          <div style={{ marginTop: 16 }}><button className="btn primary" onClick={() => setStep(1)}>Next: target →</button></div>
        </div>
      )}

      {!job && step === 1 && (
        <div className="card">
          <h3>Step 2 — Enter target {env === 'demo' ? '(demo options)' : 'network'}</h3>
          {error && <div className="alert error">{error}</div>}
          {env === 'demo' ? (
            <div>
              <div className="hint">No packets are sent. Size, seed and risk scenarios shape the generated enterprise network — change them to produce genuine drift between scans.</div>
              <div className="form-section" style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <div>
                  <label style={{ fontSize: 12 }}>Demo size</label>
                  <select className="input" value={size} onChange={(e) => setSize(e.target.value)}>
                    <option value="small">Small (~40 devices)</option><option value="medium">Medium (~50 devices)</option><option value="large">Large (~60 devices)</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 12 }}>Seed (change for drift)</label>
                  <input className="input" type="number" min="0" max="999999" value={seed} onChange={(e) => setSeed(e.target.value)} style={{ width: 120 }} />
                </div>
                <label style={{ fontSize: 13 }}><input type="checkbox" checked={includeRisks} onChange={(e) => setIncludeRisks(e.target.checked)} /> Include risk scenarios</label>
              </div>
            </div>
          ) : (
            <div>
              <div className="form-section" style={{ marginTop: 0 }}>
                <label style={{ fontSize: 12, fontWeight: 700 }}>TARGET NETWORK</label>
                <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="192.168.1.0/24" style={{ maxWidth: 320, marginTop: 6 }} />
                {!targetValid && <div className="alert warn" style={{ marginTop: 8 }}>Enter an IP or CIDR to continue — e.g. <code className="inline">192.168.1.0/24</code> (loopback <code className="inline">127.0.0.1/32</code> is allowed for safe local testing).</div>}
              </div>
              <div className="form-section">
                <div style={{ fontSize: 12, fontWeight: 700 }}>DISCOVERY METHODS</div>
                <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 8 }}>
                  {Object.keys(DEFAULT_METHODS).map((k) => (
                    <label key={k} style={{ fontSize: 14 }} title={k.toUpperCase()}><input type="checkbox" checked={methods[k]} onChange={() => toggle(k)} /> {METHOD_LABELS[k] || k.toUpperCase()}</label>
                  ))}
                </div>
                {caps?.methods?.snmp && !caps.methods.snmp.configured && (
                  <div className="alert warn" style={{ marginTop: 10 }}>⚠ SNMP: not configured (no NETMAP_SNMP_RO). Only the <code className="inline">public</code> community will be tried; SNMP results may be partial.</div>
                )}
                {caps?.methods?.cdp_lldp && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>CDP/LLDP passive capture: {caps.methods.cdp_lldp.available ? 'available — an 8s capture window runs during live scans' : 'unavailable on this host (no capture tool) — neighbour rows from SNMP are still used'}.</div>}
              </div>
              <div className="form-section">
                <div style={{ fontSize: 12, fontWeight: 700 }}>SCAN MODE</div>
                <div style={{ display: 'flex', gap: 14, marginTop: 8 }}>
                  {['fast', 'normal', 'deep'].map((m) => (<label key={m} style={{ fontSize: 14 }}><input type="radio" checked={scanMode === m} onChange={() => setScanMode(m)} /> {m}</label>))}
                </div>
                <div style={{ marginTop: 10, maxWidth: 340 }}>
                  <label style={{ fontSize: 12, fontWeight: 700 }}>SNMP community <span style={{ fontWeight: 400 }}>(optional, sent once, never stored)</span></label>
                  <input className="input" type="password" value={snmpCommunity} onChange={(e) => setSnmpCommunity(e.target.value)} placeholder="e.g. public" autoComplete="off" style={{ marginTop: 6 }} />
                </div>
              </div>
              <div className="alert warn" style={{ marginTop: 14 }}>
                <label style={{ fontSize: 14 }}><input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I confirm this scan is <b>authorized</b> on {target || 'the target'} (private/loopback ranges only).</label>
              </div>
            </div>
          )}
          <div style={{ marginTop: 16, display: 'flex', gap: 8 }}>
            <button className="btn" onClick={() => setStep(0)}>← Back</button>
            <button className="btn primary" onClick={() => setStep(2)} disabled={!targetValid}>Next: review →</button>
          </div>
        </div>
      )}

      {!job && step === 2 && (
        <div className="card">
          <h3>Step 3 — Review & start discovery</h3>
          <div className="hint">Check the plan, then launch. Watching begins automatically.</div>
          {error && <div className="alert error">{error}</div>}
          <dl className="kv" style={{ maxWidth: 520 }}>
            <dt>Environment</dt><dd>{env === 'demo' ? 'Demo network (synthetic, labelled)' : 'Live network (real probing)'}</dd>
            <dt>Target</dt><dd>{env === 'demo' ? `demo:${size} · seed ${seed} · risks ${includeRisks ? 'on' : 'off'}` : target}</dd>
            {env === 'live' && <><dt>Mode</dt><dd>{scanMode}</dd><dt>Methods</dt><dd>{Object.entries(methods).filter(([, v]) => v).map(([k]) => METHOD_LABELS[k] || k).join(', ') || 'none'}</dd></>}
          </dl>
          <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
            <button className="btn" onClick={() => setStep(1)}>← Back</button>
            <button className="btn primary" onClick={() => begin()} disabled={!canLaunch}>START DISCOVERY</button>
          </div>
        </div>
      )}

      {job && (
        <div ref={watchRef}>
          <div className="grid2">
            <div className="card">
              <h3>{job && job.status === 'running' ? <><LiveDot /> Scanning — watch it happen</> : 'Step 4 — Watch discovery happen'}</h3>
              <div className="hint">Streams /api/scan/:job/events (SSE){stream === 'polling' ? ' — SSE unavailable, polling fallback active' : ''} — progress reflects real backend stages.</div>
              <ScanProgress job={job} />
              <div style={{ marginTop: 10 }}><button className="btn" onClick={startOver}>↺ Start over</button></div>
            </div>
            <div className="card">
              <PhaseHint phase={phase} job={job} />
            </div>
          </div>
          <WatchRoom job={job} />
        </div>
      )}
    </div>
  );
}

const STEPS = ['Environment', 'Target', 'Launch', 'Watch', 'Devices', 'Topology', 'Risks', 'Explore'];

function livePhase(job) {
  if (!job) return null;
  if (job.status === 'completed') return 7;
  if (job.status === 'failed') return 3;
  if ((job.live_findings || []).length) return 6;
  if ((job.live_links || []).length) return 5;
  if ((job.live_devices || []).length) return 4;
  return 3;
}

function Stepper({ active, job, goto }) {
  return (
    <div className="steps">
      {STEPS.map((label, i) => {
        const state = i < active ? 'done' : i === active ? 'active' : 'locked';
        const clickable = !job && i <= 2;
        return (
          <button key={label} className={`step ${state}`} disabled={!clickable} onClick={() => goto(i)} title={clickable ? `Go to ${label}` : label}>
            <span className="step-n">{i < active ? '✓' : i + 1}</span> {label}
          </button>
        );
      })}
    </div>
  );
}

function PhaseHint({ phase, job }) {
  const copy = {
    3: ['Watching discovery', 'Host sweep and port probing are running. Devices appear below as soon as hosts respond.'],
    4: ['Devices appearing', `${(job.live_devices || []).length} devices identified so far — fingerprinting services and resolving names.`],
    5: ['Topology under construction', `${(job.live_links || []).length} links assembled from neighbour evidence. The map is drawing itself below.`],
    6: ['Risks being identified', `${(job.live_findings || []).length} findings raised so far — the 53-rule engine is scoring every device.`],
    7: ['Explore the network', `Scan complete: ${job.counts?.devices || 0} devices · ${job.counts?.links || 0} links · ${job.counts?.risks || 0} risks. Jump into the interactive views.`],
  };
  const [title, text] = copy[phase] || copy[3];
  return (
    <div>
      <h3>{title}</h3>
      <div className="hint">{text}</div>
      {phase === 7 && job.status === 'completed' && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 6 }}>
          <Link className="btn primary" to="/topology">Explore topology</Link>
          <Link className="btn" to="/devices">Devices</Link>
          <Link className="btn" to="/risks">Risks</Link>
          <Link className="btn" to="/">Dashboard</Link>
        </div>
      )}
      {job.status === 'failed' && <div className="alert error">{job.error || 'Scan failed.'}</div>}
    </div>
  );
}

function WatchRoom({ job }) {
  const logRef = useRef(null);
  const events = job.events || [];
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events.length]);
  const STAGE_COLORS = {
    host_discovery: 'var(--accent)', port_scan: 'var(--sev-high)', service_fingerprint: 'var(--accent-hover)',
    dns_resolution: 'var(--text-muted)', snmp_enumeration: 'var(--accent)', topology: 'var(--good)',
    risk_analysis: 'var(--sev-critical)', persist: 'var(--text-muted)',
  };
  const liveGraph = (job.live_devices && job.live_devices.length > 0)
    ? { nodes: job.live_devices, edges: job.live_links || [] }
    : null;
  const liveDevices = job.live_devices || [];
  const liveFindings = job.live_findings || [];
  return (
    <div className="card">
      <h3>Watch room — the network as it is discovered</h3>
      <div className="hint">Devices, links and risks appear here the moment the backend produces them — no refresh needed.</div>
      <StageBanner job={job} />
      <div className="grid2">
        <div>
          <h4 style={{ margin: '4px 0 8px' }}>Topology assembling ({liveDevices.length} devices{(job.live_links || []).length ? ` · ${(job.live_links || []).length} links` : ''})</h4>
          {!liveGraph && <div className="state-box"><h4>Waiting for first hosts…</h4><p>Nodes appear as host discovery reports in.</p></div>}
          {liveGraph && <TopoPreview graph={liveGraph} />}
          {liveDevices.length > 0 && (
            <table className="tbl" style={{ marginTop: 12 }}>
              <thead><tr><th>Device (live)</th><th>IP</th><th>Type</th><th>Zone</th><th>Ports</th></tr></thead>
              <tbody>
                {liveDevices.slice(0, 10).map((d) => (
                  <tr key={d.id}><td><b>{d.label}</b></td><td><code className="inline">{d.ip}</code></td><td>{d.device_type || d.type}</td><td>{d.zone}</td><td>{(d.ports || []).length}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {liveDevices.length > 10 && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>…and {liveDevices.length - 10} more (full list on the Devices page after completion).</div>}
        </div>
        <div>
          <h4 style={{ margin: '4px 0 10px', fontSize: 16 }}>Discovery narrative</h4>
          <div ref={logRef} style={{ maxHeight: 320, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px', background: 'var(--panel-2)' }}>
            {events.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Connecting to event stream…</div>}
            {events.map((e, i) => (
              <div key={i} style={{ fontSize: 13, fontWeight: 600, padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ fontFamily: 'ui-monospace, monospace', color: 'var(--text-muted)' }}>{(e.t || '').slice(11, 19)}</span>{' '}
                <b style={{ color: STAGE_COLORS[e.stage] || 'var(--text)' }}>{e.stage}</b> — {e.msg}
              </div>
            ))}
          </div>
          <h4 style={{ margin: '16px 0 10px', fontSize: 16 }}>Risks surfacing ({liveFindings.length}{job.status === 'completed' ? '' : ' so far'})</h4>
          {liveFindings.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No findings yet — the risk engine runs after topology assembly.</div>}
          {liveFindings.slice(0, 6).map((f, i) => (
            <div className="evidence" key={i}><RiskBadge severity={f.severity} /> <b>{f.title}</b><div style={{ marginTop: 2 }}>{f.device}</div></div>
          ))}
          {job.status === 'completed' && (
            <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <Link className="btn primary" to="/topology">Interact with the network</Link>
              <Link className="btn" to="/">Dashboard</Link>
              <Link className="btn" to="/risks">All risks</Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
