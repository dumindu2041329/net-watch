export type PageId = 'dashboard' | 'devices' | 'topology' | 'traffic' | 'performance' | 'alerts' | 'about';

export interface Device {
  id: number;
  device_name: string;
  ip: string;
  mac: string;
  type: string;
  os: string;
  vendor?: string;
  status: 'up' | 'down' | 'warn' | 'unknown';
  ping_ms: number;
  uptime_pct: number;
  open_ports: string;
  last_seen: string;
  first_seen: string;
  is_gateway?: boolean;
}

export interface Alert {
  id: number;
  level: 'info' | 'warn' | 'crit' | 'new';
  message: string;
  device_ip?: string;
  created_at: string;
}

export interface Stats {
  total_devices: number;
  online: number;
  offline: number;
  avg_latency: number;
  warning?: number;
  new_devices?: number;
}

export interface TopologyNode {
  id: string;
  label: string;
  ip: string;
  type: string;
  x: number;
  y: number;
  status: 'up' | 'warn' | 'down';
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: [string, string][];
}

export interface NetworkInterface {
  name: string;
  speed: string;
  total_in: number;
  total_out: number;
  errors: number;
  status: 'UP' | 'DOWN';
  wifi_rx_mbps?: number | null;
  wifi_tx_mbps?: number | null;
}

export interface Talker {
  device_name: string;
  ip: string;
  sent_mb: number;
  recv_mb: number;
}

export interface User {
  id: string;
  username: string;
  role: string;
  permissions: string[];
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  user: User;
}

export interface ScanResult {
  status: string;
  devices_found: number;
  new_devices: number;
  scan_duration_ms: number;
  timestamp: string;
  network_cidr?: string;
  network_changed?: boolean;
  cleared_devices?: number;
}

export interface WifiInfo {
  connected: boolean;
  state: string;
  ssid: string;
  bssid: string;
  signal: number;
  channel: string;
  radio_type: string;
  authentication: string;
  rx_rate: string;
  tx_rate: string;
  visible_networks: number;
  hotspot_active: boolean;
  hotspot_clients: number;
  note?: string;
  connection_type?: string;
}

export interface AlertResponse {
  count: number;
  alerts: Alert[];
  critical?: number;
  warning?: number;
  new?: number;
  total?: number;
  info?: number;
  new_devices?: number;
}
