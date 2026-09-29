// Tier assignment for the required hierarchy:
// INTERNET → Firewall → Router → Core Switch → Access Switches → Servers / Clients / IoT.
// Coordinate assignment lives in layered.js (barycenter crossing minimization).
export function tierOf(n) {
  const zone = n.zone || '', role = n.role || '', type = n.device_type || n.type || '';
  if (type === 'firewall' || zone === 'wan-edge') return 1;
  if (role === 'core' || zone === 'core' || type === 'router') return 2;
  if (role === 'distribution' || ['server-farm', 'dmz', 'storage'].includes(zone)) return 3;
  if (['server', 'database', 'web', 'dns', 'directory', 'storage', 'hypervisor', 'load_balancer', 'monitoring', 'mail', 'file'].includes(type)) return 3;
  if (role === 'access' || type === 'switch' || type === 'access_point' || type === 'wireless_controller' || zone === 'management') return 4;
  return 5;
}
