// Network-domain helpers shared across pages.
export function isLoopbackTargets(targets) {
  const t = targets || [];
  return t.length > 0 && t.every((x) => String(x).startsWith('127.'));
}

export function isLoopbackNodes(nodes) {
  const real = (nodes || []).filter((n) => !n.cloud);
  return real.length > 0 && real.every((n) => String(n.ip || '').startsWith('127.'));
}
