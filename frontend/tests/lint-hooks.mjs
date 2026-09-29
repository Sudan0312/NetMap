// Guards against the blank-page class of bug: React hooks used in a file
// must be imported (esbuild will NOT catch this — the app builds fine and
// then crashes at runtime, unmounting the entire tree).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HOOKS = ['useState', 'useEffect', 'useRef', 'useMemo', 'useCallback', 'useContext', 'createContext'];
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.name.endsWith('.jsx') || e.name.endsWith('.js')) yield p;
  }
}

let fail = 0;
for (const p of walk(root)) {
  const t = fs.readFileSync(p, 'utf8');
  const imported = new Set();
  for (const m of t.matchAll(/import\s+([^;]+?)\s+from\s+['"][^'"]+['"]/g)) {
    for (const h of HOOKS) if (new RegExp(`\\b${h}\\b`).test(m[1])) imported.add(h);
  }
  for (const h of HOOKS) {
    if (new RegExp(`\\b${h}\\b`).test(t) && !imported.has(h)) {
      console.log(`FAIL ${path.relative(root, p)} uses ${h} without importing it`);
      fail++;
    }
  }
}
console.log(fail === 0 ? 'HOOK LINT PASSED' : `HOOK LINT FAILED (${fail})`);
process.exit(fail === 0 ? 0 : 1);
