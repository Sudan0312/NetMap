// Topology iconography + role labels. One shared vocabulary so the legend,
// node cards, and previews always agree on what a device looks like.
export const SEV_COLORS = {
  critical: '#f04438', high: '#f79009', medium: '#fdb022',
  low: '#12b76a', info: '#8494ad', none: '#98a2b3',
};

export const TYPE_ICON = {
  firewall: '🛡️', router: '🔀', switch: '🔗', core_switch: '🖧',
  server: '⚙️', database: '🗄️', workstation: '🖥️', laptop: '💻',
  access_point: '📡', iot: '📟', camera: '🎥', printer: '🖨️',
  web: '🌐', dns: '📖', directory: '👥', storage: '💾', hypervisor: '📦',
  load_balancer: '⚖️', wireless_controller: '🛰️', out_of_band: '🔧',
  voip: '📞', monitoring: '📊', mail: '📧', file: '📁', dhcp: '📋',
  ips_ids: '🚨', proxy: '🔁', unknown: '❓',
};

export function isCoreSwitch(n) {
  return (n.device_type || n.type) === 'switch' && ((n.role || '') === 'core' || (n.zone || '') === 'core');
}

export function iconFor(n) {
  const t = n.device_type || n.type || 'unknown';
  if (t === 'switch') return isCoreSwitch(n) ? TYPE_ICON.core_switch : TYPE_ICON.switch;
  return TYPE_ICON[t] || TYPE_ICON.unknown;
}

export function roleLabel(n) {
  const t = n.device_type || n.type || 'unknown';
  if (t === 'switch') return isCoreSwitch(n) ? 'CORE SWITCH' : ((n.role || '') === 'distribution' ? 'DIST SWITCH' : 'ACCESS SWITCH');
  if (t === 'access_point') return 'ACCESS POINT';
  if (t === 'out_of_band') return 'OOB MGMT';
  if (t === 'unknown') return 'UNKNOWN DEVICE';
  if (t === 'wireless_controller') return 'WLESS CTRL';
  if (t === 'load_balancer') return 'LOAD BALANCER';
  return t.replace(/_/g, ' ').toUpperCase();
}
