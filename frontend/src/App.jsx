import React, { useEffect, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { api, EXPECTED_BACKEND, REQUIRED_FEATURES } from './services/api';
import { LiveDot } from './components';
import { Icon, IconSprite } from './components/icons';
import { ScanProvider, useScan } from './store/ScanContext';
import Dashboard from './pages/Dashboard';
import Topology from './pages/Topology';
import Devices from './pages/Devices';
import Discovery from './pages/Discovery';
import Risks from './pages/Risks';
import Services from './pages/Services';
import { History, Reports, Settings } from './pages/More';
import Landing from './pages/Landing';
import { ThemeToggle } from './store/ThemeContext';

const LINKS = [
  ['/overview', 'Overview', 'overview'], ['/topology', 'Topology', 'topology'], ['/devices', 'Devices', 'devices'],
  ['/discovery', 'Discovery', 'discovery'], ['/risks', 'Risks', 'risks'], ['/services', 'Services', 'services'],
  ['/history', 'History', 'history'], ['/reports', 'Reports', 'reports'],
];
const BOTTOM_LINKS = [
  ['/settings', 'Settings', 'settings'],
];
const PAGES = {  '/overview': Dashboard,
  '/topology': Topology,
  '/devices': Devices,
  '/discovery': Discovery,
  '/risks': Risks,
  '/services': Services,
  '/history': History,
  '/reports': Reports,
  '/settings': Settings,
};
const TITLES = {
  '/overview': ['Network Overview', 'Monitor discovered infrastructure, topology and security risks.'],
  '/topology': ['Topology', 'Interactive device graph — zoom, pan, drag, filter, select'],
  '/devices': ['Devices', 'Searchable inventory from backend scan data'],
  '/discovery': ['Discovery', 'Start live or demo network discovery'],
  '/risks': ['Risks', 'Rule-engine findings with evidence and remediation'],
  '/services': ['Services', 'Open-service inventory across the current snapshot'],
  '/history': ['History', 'Snapshots and change detection'],
  '/reports': ['Reports', 'Real generated reports — view or download'],
  '/settings': ['Settings', 'Appearance, connection, capabilities and safety'],
};

export default function App() {
  const loc = useLocation();
  const nav = useNavigate();
  const active = PAGES[loc.pathname] ? loc.pathname : '/overview';
  const [env, setEnv] = useState('none');
  const [meta, setMeta] = useState('');
  const [stale, setStale] = useState(null);
  const [apiUp, setApiUp] = useState(false);

  // Keep-alive tabs: every visited page stays mounted (hidden when inactive),
  // so filters, selections, drawers, map viewport and running scans survive
  // tab switches. URLs stay real, so refresh/bookmarks still work.
  const [visited, setVisited] = useState([active]);
  const scrolls = useRef({});
  const prev = useRef(active);
  useEffect(() => {
    setVisited((v) => (v.includes(active) ? v : [...v, active]));
    scrolls.current[prev.current] = window.scrollY;
    const y = scrolls.current[active] || 0;
    requestAnimationFrame(() => window.scrollTo(0, y));
    prev.current = active;
  }, [active]);

  useEffect(() => {
    const check = () => api.health().then((h) => {
      setApiUp(true);
      if (!h.snapshot) { setEnv('none'); setMeta('no scan yet'); }
      else {
        setEnv(h.mode === 'lab' ? 'demo' : 'live');
        setMeta(h.snapshot_id || '');
      }
      const feats = h.features || [];
      const missing = REQUIRED_FEATURES.filter((f) => !feats.includes(f));
      if (!h.code_version || h.code_version !== EXPECTED_BACKEND || missing.length > 0) {
        setStale(`Backend code ${h.code_version || 'pre-handshake'} is outdated (UI needs ${EXPECTED_BACKEND}). Live watch, snapshot switching and SSE need a backend restart: Ctrl+C in the backend terminal, then re-run the uvicorn command.`);
      } else setStale(null);
    }).catch(() => { setApiUp(false); });
    check();
    const t = setInterval(check, 5000);
    return () => clearInterval(t);
  }, [active]);
  const entry = TITLES[active] || ['NetMap', ''];

  // The landing page stands alone: no sidebar, no keep-alive tabs.
  if (loc.pathname === '/') return <Landing />;

  return (
    <ScanProvider>
    <div className="app-shell">
      <IconSprite />
      <aside className="sidebar">
        <div className="brand">
          <h1>NET<span>MAP</span></h1>
          <p>Enterprise Network Intelligence</p>
          <EnvBadge />
        </div>
        <nav className="nav" aria-label="Primary">
          {LINKS.map(([to, label, ico]) => <NavLink key={to} to={to} end={to === '/overview'} className={({ isActive }) => isActive ? 'active' : ''}><span className="nav-ico" aria-hidden="true"><Icon name={ico} /></span>{label}</NavLink>)}
        </nav>
        <ScanStatusBlock />
        <div className="side-section">
          <nav className="nav" aria-label="Secondary" style={{ padding: 0 }}>
            {BOTTOM_LINKS.map(([to, label, ico]) => <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'active' : ''}><span className="nav-ico" aria-hidden="true"><Icon name={ico} /></span>{label}</NavLink>)}
          </nav>
          <SystemStatus apiUp={apiUp} meta={meta} />
        </div>
      </aside>
      <div className="main">
        <nav className="mobile-nav" aria-label="Mobile">
          {[...LINKS, ...BOTTOM_LINKS].map(([to, label]) => <NavLink key={to} to={to} end={to === '/overview'} className={({ isActive }) => isActive ? 'active' : ''}>{label}</NavLink>)}
        </nav>
        <header className="topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button className="btn" onClick={() => nav(-1)} title="Back to previous tab">← Back</button>
            <div><h2>{entry[0]}</h2><div className="sub">{entry[1]}</div></div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)' }} title={apiUp ? 'Backend reachable' : 'Backend unreachable'}>
              <LiveDot off={!apiUp} /> API {apiUp ? 'LIVE' : 'DOWN'}
            </span>
            <TopbarScanPill />
            <ThemeToggle />
            <NavLink className="btn primary" to="/discovery">＋ New discovery</NavLink>
          </div>
        </header>
        <div className="content">
          {stale && <div className="alert error" style={{ fontSize: 15 }}>⚠ {stale}</div>}
          {visited.map((path) => {
            const Page = PAGES[path];
            return (
              <div key={path} hidden={path !== active}>
                <Page />
              </div>
            );
          })}
        </div>
      </div>
    </div>
    </ScanProvider>
  );
}

function EnvBadge() {
  const { environment } = useScan();
  return (
    <span className={`env-badge ${environment === 'none' ? 'none' : environment}`}>
      {environment === 'none' ? '○ NO SCAN' : environment === 'demo' ? '● DEMO' : '● LIVE'}
    </span>
  );
}

function SystemStatus({ apiUp, meta }) {
  return (
    <div className="side-foot">
      <div><LiveDot off={!apiUp} /> {apiUp ? 'System operational' : 'Backend unreachable'}</div>
      <div>{meta || 'run a scan to begin'}</div>
    </div>
  );
}

function TopbarScanPill() {
  const { activeJob, running } = useScan();
  if (!running || !activeJob) return null;
  const pct = activeJob.progress ?? activeJob.done ?? 0;
  return (
    <span className="scan-pill" title={activeJob.message || activeJob.stage || 'scanning'}>
      ◉ DISCOVERY {pct}%
    </span>
  );
}

function ScanStatusBlock() {
  const { activeJob, running, snapshotId } = useScan();
  const [doneInfo, setDoneInfo] = useState(null);
  const wasRunning = useRef(false);
  useEffect(() => {
    if (running) {
      wasRunning.current = true;
      setDoneInfo(null);
      return;
    }
    if (wasRunning.current) {
      wasRunning.current = false;
      setDoneInfo({ at: new Date(), snap: snapshotId });
      const t = setTimeout(() => setDoneInfo(null), 15000);
      return () => clearTimeout(t);
    }
  }, [running]);
  if (running && activeJob) {
    const st = (activeJob.stages || []).find((s) => s.state === 'running');
    const stageLabel = st ? st.label : activeJob.stage || activeJob.message || 'working';
    const pct = activeJob.progress ?? activeJob.done ?? 0;
    return (
      <div className="scan-status">
        <div className="scan-status-title"><span className="live-dot" /> DISCOVERY RUNNING</div>
        <div>Stage: <b>{stageLabel}</b></div>
        <div>Progress: <b>{pct}%</b></div>
        <div className="bar" style={{ marginTop: 6 }}><div style={{ width: `${pct}%` }} /></div>
      </div>
    );
  }
  if (doneInfo) {
    return (
      <div className="scan-status done">
        <div className="scan-status-title">✓ DISCOVERY COMPLETE</div>
        <div>Snapshot updated{doneInfo.at ? ` ${doneInfo.at.toLocaleTimeString()}` : ''}</div>
      </div>
    );
  }
  return null;
}
