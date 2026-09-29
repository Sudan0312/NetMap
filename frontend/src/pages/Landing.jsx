import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { api } from '../services/api';
import { Icon, IconSprite } from '../components/icons';
import { LiveDot } from '../components';
import { ThemeToggle } from '../store/ThemeContext';

/* Public landing page at `/` — no sidebar, just the pitch + a way in.
   All data is live from the backend; when the backend is down the page
   still renders and says so honestly. */

const STEPS = [
  { ico: 'discovery', title: '1 · Scan', desc: 'Point NetMap at your own network. It pings every address, checks open ports and reads device nameplates.' },
  { ico: 'topology', title: '2 · Map', desc: 'Switches are interrogated for wiring clues; everything is drawn as a connection map with honest confidence labels.' },
  { ico: 'reports', title: '3 · Understand', desc: 'Risks are graded by rule, changes tracked between scans, and reports generated on demand.' },
];

const FEATURES = [
  { ico: 'topology', title: 'Live topology map', desc: 'Routers on top, PCs at the bottom. Click any device for its full file.' },
  { ico: 'risks', title: 'Plain-English risks', desc: 'Every weakness graded critical to low, with evidence and what to do.' },
  { ico: 'history', title: 'Change detection', desc: 'New, missing or riskier devices since your last scan — automatically.' },
  { ico: 'file', title: 'One-click reports', desc: 'Management summary, technical JSON, spreadsheet, SIEM feed and more.' },
];

export default function Landing() {
  const [apiUp, setApiUp] = useState(false);
  const [summary, setSummary] = useState(null);
  useEffect(() => {
    api.health()
      .then((h) => {
        setApiUp(true);
        if (h.snapshot) return api.summary().then(setSummary).catch(() => {});
        setSummary(null);
      })
      .catch(() => setApiUp(false));
  }, []);

  return (
    <div className="landing">
      <IconSprite />
      <header className="landing-nav">
        <div className="brand" style={{ border: 'none', padding: 0 }}>
          <h1>NET<span>MAP</span></h1>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="landing-status" title={apiUp ? 'Backend reachable' : 'Backend unreachable'}>
            <LiveDot off={!apiUp} /> API {apiUp ? 'LIVE' : 'DOWN'}
          </span>
          <ThemeToggle />
          <NavLink className="btn primary" to="/overview">Open app →</NavLink>
        </div>
      </header>

      <main className="landing-main">
        <section className="landing-hero">
          <div className="landing-badge">ENTERPRISE NETWORK INTELLIGENCE</div>
          <h2>See every device on your network.</h2>
          <p className="landing-sub">
            NetMap discovers your routers, computers, printers and phones, draws how
            they connect, grades every risk — and proves what changed since last time.
          </p>
          <div className="landing-cta">
            <NavLink className="btn primary landing-big" to="/discovery">＋ Start discovery</NavLink>
            <NavLink className="btn landing-big" to="/overview">Open dashboard</NavLink>
          </div>
          <div className="landing-stats" aria-live="polite">
            {summary ? (
              <>
                <div><b>{summary.devices ?? '–'}</b><span>devices</span></div>
                <div><b>{summary.links ?? '–'}</b><span>links</span></div>
                <div><b>{summary.findings ?? '–'}</b><span>findings</span></div>
              </>
            ) : (
              <div className="landing-nostat">{apiUp ? 'No scan yet — run your first discovery to populate the dashboard.' : 'Backend is offline — start it, then run your first discovery.'}</div>
            )}
          </div>
        </section>

        <section className="landing-grid" aria-label="How it works">
          {STEPS.map((s) => (
            <div className="card landing-card" key={s.title}>
              <span className="report-ico" aria-hidden="true"><Icon name={s.ico} size={24} /></span>
              <h3>{s.title}</h3>
              <p>{s.desc}</p>
            </div>
          ))}
        </section>

        <section aria-label="Features">
          <h3 className="landing-section-title">Everything included</h3>
          <div className="landing-grid four">
            {FEATURES.map((f) => (
              <div className="card landing-card" key={f.title}>
                <span className="report-ico" aria-hidden="true"><Icon name={f.ico} size={24} /></span>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
              </div>
            ))}
          </div>
        </section>

        <p className="landing-safety">Read-only and authorized: NetMap only scans private networks you confirm, and never changes anything on your devices.</p>
      </main>

      <footer className="landing-foot">NETMAP · local-first network discovery · data never leaves your machine</footer>
    </div>
  );
}
