export type ProtocolScheme =
  | 'sftp'
  | 'scp'
  | 'ssh'
  | 'ftp'
  | 'ftps'
  | 'ftpes'
  | 'dav'
  | 'davs'
  | 'webdav'
  | 'webdavs'
  | 's3'
  | 'local'
  | 'rdp'
  | 'vnc'
  | 'spice'
  | 'x2go'
  | 'x11';

export interface TunnelConfig {
  enabled: boolean;
  host: string;
  port: number;
  username: string;
  keyfile?: string;
  hostkey: string;
  local_port: number;
}

export interface SessionConfig {
  name: string;
  protocol: ProtocolScheme;
  host: string;
  port: number;
  username: string;
  keyfile?: string;
  hostkey: string;
  initial_dir: string;
  local_dir: string;
  tunnel?: TunnelConfig;
}

export interface FileEntry {
  name: string;
  size: number;
  is_dir: boolean;
  is_symlink: boolean;
  broken_link: boolean;
  date: string;
  mtime: number;
  permissions: string;
  owner?: string;
  group?: string;
}

export type LocalRootKind = 'posix' | 'drive' | 'unc' | 'app_private' | 'saf_tree';

export interface LocalRootEntry {
  path: string;
  label: string;
  kind: LocalRootKind;
  read_only: boolean;
}

export type TransferMode = 'binary' | 'ascii' | 'automatic';

export interface UserPreferences {
  transfer: TransferMode;
  filemask: string;
  speed: number;
  resumesupport: string;
  resume: boolean;
  preserve_time: boolean;
  newer_only: boolean;
  append: boolean;
  no_permissions: boolean;
  priority: boolean;
  confirm_overwrite: boolean;
  confirm_delete: boolean;
}

export interface TabSummary {
  id: number;
  name: string;
  connected: boolean;
  local_dir: string;
  remote_dir: string;
  session?: SessionConfig;
  observed_hostkey: string;
  error: string;
  is_desktop?: boolean;
  protocol?: ProtocolScheme;
}

export interface DesktopTicket {
  kind: string;
  target: string;
  viewer: string;
  argv: string[];
  file_extension?: string;
  file_content?: string;
  tunneled: boolean;
  local_endpoint: string;
  has_file: boolean;
}

export const DESKTOP_PROTOCOLS: ProtocolScheme[] = ['rdp', 'vnc', 'spice', 'x2go', 'x11'];
export function isDesktopProtocol(p?: ProtocolScheme): boolean {
  return !!p && (DESKTOP_PROTOCOLS as string[]).includes(p);
}

export interface DesktopInstallScriptResponse {
  success: boolean;
  kind: string;
  package: string;
  description: string;
  probe_command: string;
  install_script: string;
}

export interface DesktopCheckRequest {
  tab?: number;
  via_tab?: number;
  host?: string;
  port?: number;
  kind?: string;
  protocol?: string;
}

export interface DesktopCheckPrompt {
  title: string;
  body: string;
  install_script: string;
  actions: string[];
}

export interface DesktopCheckResponse {
  success: boolean;
  available: boolean;
  checked: boolean;
  via_ssh?: boolean;
  via_tab?: number | null;
  kind: string;
  host: string;
  port: number;
  package: string;
  description: string;
  probe_command: string;
  install_script: string;
  reason: string;
  can_install: boolean;
  message?: string;
  prompt?: DesktopCheckPrompt;
}

export interface DesktopInstallRequest {
  via_tab?: number;
  tab?: number;
  host?: string;
  kind?: string;
  protocol?: string;
}

export interface DesktopInstallResponse {
  success: boolean;
  via_tab?: number;
  host: string;
  kind: string;
  package: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  now_available: boolean;
  install_script: string;
  message: string;
  error?: string;
}

export interface TransferQueueItem {
  id: number;
  type: string;
  status: string;
  source: string;
  destination: string;
  bytes_done: number;
  bytes_total: number;
  percent: number;
  detail: string;
  error: string;
}

export interface HostKeyChallenge {
  tab_id: number;
  role: 'destination' | 'tunnel';
  state: 'unknown' | 'changed';
  host: string;
  port: number;
  fingerprint: string;
}

export interface StatusResponse {
  connected: boolean;
  active_tab: number | null;
  tabs: TabSummary[];
  local_dir: string;
  local_roots: LocalRootEntry[];
  preferences: UserPreferences;
}

export interface ApiEnvelope {
  method: string;
  path: string;
  body?: unknown;
}

export interface ApiReply<T = unknown> {
  status: number;
  payload: T;
}

export interface TransportEventMap {
  'transfers:updated': { transfers: TransferQueueItem[] };
  'terminal:output': { tab_id: number; data: string };
  'native:file-drop': { paths: string[] };
}

export interface MonitorCpuThread { id: number; percent: number | null }
export interface MonitorCpuCore {
  socket: number | null;
  core: number;
  threads: MonitorCpuThread[];
}
export interface MonitorCpu {
  model: string;
  logical_count: number;
  percent: number | null;
  cores: MonitorCpuCore[];
}
export interface MonitorMemory {
  total_bytes: number;
  used_bytes: number;
  available_bytes: number;
  percent: number;
}
export interface MonitorDisk {
  device: string;
  mount: string;
  total_bytes: number;
  used_bytes: number;
  available_bytes: number;
  percent: number;
}
export interface MonitorGpu {
  index: number;
  vendor: string;
  name: string;
  percent: number | null;
  memory_used_bytes: number | null;
  memory_total_bytes: number | null;
  power_watts: number | null;
  power_limit_watts: number | null;
  temperature_c: number | null;
  temperature_limit_c: number | null;
  temperature_sensor: string;
  driver: string;
  pcie_generation: number | null;
  pcie_width: number | null;
}
export interface MonitorSwap {
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  percent: number;
}
export interface MonitorNetwork {
  rx_bytes_total: number;
  tx_bytes_total: number;
  rx_bytes_per_sec: number | null;
  tx_bytes_per_sec: number | null;
}
export type MonitorMetricParse = 'number' | 'regex' | 'text';
export type MonitorMetricDisplay = 'sparkline' | 'big_number' | 'text';
export type MonitorBuiltinMetric = 'cpu' | 'mem' | 'swap' | 'disk' | 'load' | 'net' | 'gpu';
export interface MonitorCustomMetric {
  id: string;
  name: string;
  command: string;
  parse: MonitorMetricParse;
  regex?: string | null;
  display: MonitorMetricDisplay;
  unit: string;
}
export interface MonitorCustomReading {
  id: string;
  name: string;
  parse: MonitorMetricParse;
  display: MonitorMetricDisplay;
  unit: string;
  value: number | null;
  text: string;
  error: string;
}
export interface MonitorSnapshot {
  hostname: string;
  primary_ip: string;
  uptime_seconds: number | null;
  load_average: number[];
  cpu: MonitorCpu;
  memory: MonitorMemory | null;
  swap?: MonitorSwap | null;
  network?: MonitorNetwork | null;
  disks: MonitorDisk[];
  gpus: MonitorGpu[];
  cuda_version: string;
  custom?: MonitorCustomReading[];
  warnings: string[];
}
export interface MonitorSample {
  tab: number;
  key?: string;
  name: string;
  host: string;
  port: number;
  protocol: string;
  status: 'ok' | 'error' | 'disconnected' | 'unsupported' | 'busy';
  sampled_at: number;
  latency_ms: number;
  error: string;
  snapshot: MonitorSnapshot | null;
  consecutive_failures?: number;
  outage_since_ms?: number | null;
  outage?: boolean;
  outage_started?: boolean;
  recovered?: boolean;
}
export interface MonitorTabCandidate {
  tab: number;
  name: string;
  host: string;
  port: number;
  protocol: ProtocolScheme;
  site: string | null;
  key?: string;
}
export interface MonitorSiteCandidate {
  name: string;
  host: string;
  port: number;
  protocol: ProtocolScheme;
  key?: string;
}
export interface MonitorHostsResponse {
  success: boolean;
  tabs: MonitorTabCandidate[];
  sites: MonitorSiteCandidate[];
  max_hosts: number;
  default_interval: number;
  default_timeout: number;
}
export interface MonitorSampleResponse { success: boolean; samples: MonitorSample[] }
export interface MonitorSettings {
  interval_secs: number;
  connect_timeout_secs: number;
  poll_timeout_secs: number;
  outage_threshold: number;
  notify_on_outage: boolean;
  beep_on_outage: boolean;
  beep_cooldown_secs: number;
}
export interface MonitorHostConfig {
  enabled_metrics: MonitorBuiltinMetric[];
  custom_metrics: MonitorCustomMetric[];
  paused: boolean;
}
export interface MonitorSettingsDocument {
  version: number;
  settings: MonitorSettings;
  hosts: Record<string, MonitorHostConfig>;
}
export interface MonitorSettingsResponse { success: boolean; document: MonitorSettingsDocument }
