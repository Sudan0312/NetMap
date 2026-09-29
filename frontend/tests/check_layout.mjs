import { layoutLayered } from '../src/topology/layered.js';

const nodes = [
  { id: 'fw', device_type: 'firewall', zone: 'wan-edge', risk: 9 },
  { id: 'core', device_type: 'switch', role: 'core', zone: 'core', risk: 7 },
  { id: 'acc', device_type: 'switch', role: 'access', zone: 'access', risk: 5 },
  { id: 'pc1', device_type: 'workstation', zone: 'access', risk: 2 },
  { id: 'pc2', device_type: 'workstation', zone: 'access', risk: 1 },
  { id: 'srv', device_type: 'server', zone: 'server-farm', risk: 6 },
];
const edges = [
  { source: 'fw', target: 'core', kind: 'ethernet' },
  { source: 'core', target: 'acc', kind: 'ethernet' },
  { source: 'acc', target: 'pc1', kind: 'ethernet' },
  { source: 'acc', target: 'pc2', kind: 'ethernet' },
  { source: 'core', target: 'srv', kind: 'ethernet' },
];
const { pos, bounds } = layoutLayered(nodes, edges);
const ys = Object.fromEntries(Object.entries(pos).map(([k, p]) => [k, p.y]));
console.log('y-order:', ys);
const assert = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } };
assert(ys.fw < ys.core, 'firewall above core');
assert(ys.core < ys.acc, 'core above access');
assert(ys.core < ys.srv, 'core above server');
assert(ys.acc < ys.pc1 && ys.acc < ys.pc2, 'access above endpoints');
assert(Array.isArray(bounds) && bounds.length === 2, 'bounds shape');
console.log('LAYERED LAYOUT OK');
