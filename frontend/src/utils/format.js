// Formatting helpers shared across pages.
export function timeAgo(iso) {
  if (!iso) return '';
  const ms = Date.now() - new Date(iso).getTime();
  if (isNaN(ms) || ms < 0) return '';
  const m = Math.floor(ms / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} hr ago`;
  return `${Math.floor(h / 24)} days ago`;
}

export function shortId(id, n = 18) {
  const s = String(id || '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
