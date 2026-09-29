const BASE = '';

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      detail = j.detail || j.error || detail;
    } catch { /* keep default */ }
    throw new Error(detail);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

export const api = {
  health: () => req('/api/health'),
  capabilities: () => req('/api/capabilities').catch(() => ({ methods: {} })),
  summary: () => req('/api/summary'),
  devices: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('/api/devices' + (q ? `?${q}` : ''));
  },
  device: (id) => req(`/api/devices/${encodeURIComponent(id)}`),
  graph: () => req('/api/graph'),
  links: () => req('/api/links'),
  zones: () => req('/api/zones'),
  findings: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req('/api/findings' + (q ? `?${q}` : ''));
  },
  finding: (id) => req(`/api/findings/${encodeURIComponent(id)}`),
  services: () => req('/api/services'),
  reports: () => req('/api/reports'),
  history: () => req('/api/history'),
  historyOne: (id) => req(`/api/history/${encodeURIComponent(id)}`),
  changes: () => req('/api/changes'),
  compare: (old_id, new_id) => req('/api/compare', { method: 'POST', body: JSON.stringify({ old_id, new_id }) }),
  jobs: () => req('/api/jobs'),
  job: (id) => req(`/api/scan/${encodeURIComponent(id)}`),
  scan: (body) => req('/api/scan', { method: 'POST', body: JSON.stringify(body) }),
};

export function reportUrl(fmt) {
  return `/api/report.${fmt}`;
}
