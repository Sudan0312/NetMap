import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { api } from '../services/api';

// GLOBAL REAL-TIME STATE — the application's single concept of:
//   current snapshot · snapshot_id · summary · scan status/progress/stage
//   environment · last updated
// The store owns one canonical copy of every snapshot-scoped endpoint:
// /api/summary, /api/graph, /api/devices, /api/findings, /api/services,
// /api/history, /api/changes (+ zones for filters).
// Flow: user starts scan → POST /api/scan → job_id → SSE progress → scan
// completes → new snapshot_id → invalidation here → exactly those endpoints
// refresh once → refreshToken bumps → all pages react. No browser reload.
// Discovery keeps its own SSE stream untouched.
const ScanContext = createContext({
  refreshToken: 0,
  snapshotId: null,
  summary: null,
  graph: null,
  devices: [],
  findings: [],
  services: [],
  history: [],
  changes: null,
  zones: [],
  activeJob: null,
  running: false,
  environment: 'none',
  lastUpdated: null,
  loading: true,
  error: null,
  reload: async () => {},
});

export function useScan() {
  return useContext(ScanContext);
}

export function ScanProvider({ children }) {
  const [refreshToken, setRefreshToken] = useState(0);
  const [snapshotId, setSnapshotId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [graph, setGraph] = useState(null);
  const [devices, setDevices] = useState([]);
  const [findings, setFindings] = useState([]);
  const [services, setServices] = useState([]);
  const [history, setHistory] = useState([]);
  const [changes, setChanges] = useState(null);
  const [zones, setZones] = useState([]);
  const [activeJob, setActiveJob] = useState(null);
  const [running, setRunning] = useState(false);
  const [environment, setEnvironment] = useState('none');
  const [lastUpdated, setLastUpdated] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const seen = useRef(null);
  const init = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refreshAll = async () => {
    setLoading(true);
    try {
      const [s, g, d, f, sv, h, c, z] = await Promise.all([
        api.summary(),
        api.graph().catch(() => null),
        api.devices().catch(() => []),
        api.findings().catch(() => []),
        api.services().catch(() => []),
        api.history().catch(() => []),
        api.changes().catch(() => null),
        api.zones().catch(() => []),
      ]);
      if (!mounted.current) return;
      setSummary(s);
      setSnapshotId(s.snapshot_id || null);
      setGraph(g);
      setDevices(Array.isArray(d) ? d : []);
      setFindings(Array.isArray(f) ? f : []);
      setServices(Array.isArray(sv) ? sv : []);
      setHistory(Array.isArray(h) ? h : []);
      setChanges(c);
      setZones(Array.isArray(z) ? z : []);
      setEnvironment(s.mode === 'lab' ? 'demo' : s.mode === 'live' ? 'live' : 'none');
      setLastUpdated(new Date());
      setError(null);
    } catch (e) {
      if (mounted.current) setError(e);
    } finally {
      if (mounted.current) setLoading(false);
    }
  };

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        const [h, jobs] = await Promise.all([api.health().catch(() => null), api.jobs().catch(() => [])]);
        if (stop || !h) return;
        const active = (jobs || []).find((j) => j.status === 'running' || j.status === 'queued') || null;
        setActiveJob(active);
        setRunning(!!active);
        const cur = h.snapshot_id || null;
        if (!init.current) {
          seen.current = cur;
          init.current = true;
          if (cur) await refreshAll();
          else if (mounted.current) setLoading(false);
          return;
        }
        // GLOBAL INVALIDATION: backend minted a new snapshot → refresh the
        // snapshot-scoped endpoints exactly once, then notify subscribers.
        if (cur && cur !== seen.current) {
          seen.current = cur;
          await refreshAll();
          if (!stop) setRefreshToken((t) => t + 1);
        }
      } catch {
        /* transient failure: keep old state */
      }
    };
    const t = setInterval(tick, 3000);
    tick();
    return () => {
      stop = true;
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <ScanContext.Provider
      value={{
        refreshToken, snapshotId, summary, graph, devices, findings, services,
        history, changes, zones, activeJob, running, environment, lastUpdated,
        loading, error, reload: refreshAll,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
}
