import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const must = [
  'package.json', 'vite.config.js', 'index.html',
  'src/main.jsx', 'src/App.jsx', 'src/services/api.js',
  'src/components.jsx', 'src/styles.css',
  'src/hooks/useFetch.js',
  'src/store/ScanContext.jsx',
  'src/topology/icons.js', 'src/topology/layout.js', 'src/topology/layered.js', 'src/topology/TopoPreview.jsx',
  'src/utils/format.js', 'src/utils/network.js',
  'src/pages/Dashboard.jsx', 'src/pages/Topology.jsx',
  'src/pages/Devices.jsx', 'src/pages/Discovery.jsx',
  'src/pages/Risks.jsx', 'src/pages/Services.jsx', 'src/pages/More.jsx',
  'src/pages/Landing.jsx',
];
let fail = 0;
for (const f of must) {
  const ok = fs.existsSync(path.join(root, f));
  console.log(((ok ? 'ok  ' : 'FAIL') + ' ' + f));
  if (!ok) fail++;
}
const app = fs.readFileSync(path.join(root, 'src', 'App.jsx'), 'utf8');
for (const r of ['/overview', '/topology', '/devices', '/discovery', '/risks', '/services', '/history', '/reports', '/settings']) {
  if (!app.includes(r)) { console.log('FAIL route ' + r); fail++; }
}
console.log(fail === 0 ? 'FRONTEND SMOKE PASSED' : `FRONTEND SMOKE FAILED (${fail})`);
process.exit(fail === 0 ? 0 : 1);
