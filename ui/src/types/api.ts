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
  tunneled: boolean;
  local_endpoint: string;
  has_file: boolean;
}

export const DESKTOP_PROTOCOLS: ProtocolScheme[] = ['rdp', 'vnc', 'spice', 'x2go', 'x11'];
export function isDesktopProtocol(p?: ProtocolScheme): boolean {
  return !!p && (DESKTOP_PROTOCOLS as string[]).includes(p);
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
