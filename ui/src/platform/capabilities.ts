/**
 * One description of what the shared frontend can do, whichever host embeds it.
 *
 * The same `ui/dist` bundle backs the Tauri desktop window, the standalone
 * browser server and the experimental Android app. Those hosts differ in what
 * the *backend* can reach (native IPC, Android Storage Access Framework, a
 * foreground service, server-side accounts), while the page has to look and
 * behave the same. Keeping the list here - instead of scattering `if
 * (window.__TAURI_INTERNALS__)` through the page - is what lets the parity test
 * assert that every app exposes the same feature surface.
 */

import type { TransportMode } from '../transport/client.js';
import { detectTransportMode } from '../transport/index.js';

export type HostPlatform =
  | 'linux'
  | 'windows'
  | 'macos'
  | 'android'
  | 'ios'
  | 'browser'
  | 'unknown';

export interface HostCapabilities {
  /** `tauri` when the page talks to the native shell, `http` in a browser. */
  transport: TransportMode;
  /** Operating system the *backend* runs on, as far as the page can tell. */
  platform: HostPlatform;
  /** In-process IPC (`invoke`) instead of fetch() + bearer token. */
  nativeIpc: boolean;
  /** `/api/local/roots` answers with drives, POSIX roots or app storage. */
  localRoots: boolean;
  /** A folder picker hands the backend a `content://` tree URI. */
  safTrees: boolean;
  /** Other apps can send files here (Android share sheet, OS "Open with"). */
  shareIntents: boolean;
  /** Transfers survive the window losing focus (Android foreground service). */
  foregroundTransfers: boolean;
  /** A file manager drop is delivered through the page's drop handlers. */
  fileDrop: boolean;
  /** The shell reports OS file drops as events instead of HTML5 drops. */
  nativeFileDrop: boolean;
  /** The backend can require a sign-in before answering. */
  accounts: boolean;
  /** Remote desktop viewers (RDP/VNC/SPICE/X2Go/X11) can be launched. */
  desktopLaunchers: boolean;
  /** An interactive terminal can be opened on a session. */
  terminal: boolean;
  /** Transfers keep running after the app is closed or backgrounded. */
  backgroundTransfers: boolean;
  /** The backend can ask an SSH agent for keys during login. */
  sshAgent: boolean;
  /** The backend can attempt Kerberos (GSSAPI) authentication. */
  gssapi: boolean;
  /** The backend honors GSSAPI key exchange. */
  gssapiKex: boolean;
}

export interface HostGlobals {
  navigator?: { userAgent?: string; platform?: string };
  navigator_platform?: string;
}

/**
 * `tauri` when the page is embedded in the native shell, otherwise `http`.
 *
 * The probe itself lives in the transport layer: host capability detection
 * must not open a second, private path to the native bridge.
 */
export function detectHostKind(host: unknown = globalThis): TransportMode {
  return detectTransportMode(host);
}

/**
 * Maps a `navigator.userAgent` / `navigator.platform` pair to a host platform.
 * A browser page served by the standalone HTTP server reports `browser`
 * because the page cannot see the server's operating system from there.
 */
export function detectHostPlatform(host: unknown = globalThis): HostPlatform {
  const candidate = host as HostGlobals | null | undefined;
  const nav = candidate?.navigator;
  const text = `${nav?.userAgent ?? ''} ${nav?.platform ?? candidate?.navigator_platform ?? ''}`.toLowerCase();
  if (!text.trim()) {
    return 'unknown';
  }
  if (text.includes('android')) {
    return 'android';
  }
  if (/iphone|ipad|ipod/.test(text)) {
    return 'ios';
  }
  if (text.includes('win')) {
    return 'windows';
  }
  if (text.includes('mac os') || text.includes('macintosh')) {
    return 'macos';
  }
  if (text.includes('linux') || text.includes('x11')) {
    return 'linux';
  }
  return 'browser';
}

export interface HostCapabilityOptions {
  /** The window to inspect; defaults to `globalThis`. */
  host?: unknown;
  /** Overrides the detected transport (used by tests and by the native shell). */
  transport?: TransportMode;
  /** Overrides the detected platform (the backend may know better). */
  platform?: HostPlatform;
  /** Backend answers `/api/local/roots` with something other than a fallback. */
  localRoots?: boolean;
  /** Android shell registers the SAF folder picker. */
  safTrees?: boolean;
  shareIntents?: boolean;
  foregroundTransfers?: boolean;
  nativeFileDrop?: boolean;
  accounts?: boolean;
  desktopLaunchers?: boolean;
  terminal?: boolean;
  /** Backend can reach an SSH agent (the shell may know better). */
  sshAgent?: boolean;
  /** Backend can attempt Kerberos (the shell may know better). */
  gssapi?: boolean;
  /** Backend honors GSSAPI key exchange (the shell may know better). */
  gssapiKex?: boolean;
}

/**
 * The capability set for one embedder.
 *
 * The Android native build registers its SAF, share-intent, and foreground
 * transfer plugin in `build_native_app`; only a native Android WebView may
 * advertise those integrations. A browser running on Android is still an HTTP
 * host and does not receive these capabilities. Native desktop launchers and
 * OS drop events are distinct from Android's intent-based viewer launch and
 * incoming share-sheet handling.
 */
export function hostCapabilities(options: HostCapabilityOptions = {}): HostCapabilities {
  const host = options.host ?? globalThis;
  const transport = options.transport ?? detectHostKind(host);
  const platform = options.platform ?? detectHostPlatform(host);
  const native = transport === 'tauri';
  const android = platform === 'android';
  const androidNative = native && android;
  const safTrees = options.safTrees ?? androidNative;
  const shareIntents = options.shareIntents ?? androidNative;
  const foregroundTransfers = options.foregroundTransfers ?? androidNative;
  return {
    transport,
    platform,
    nativeIpc: native,
    localRoots: options.localRoots ?? true,
    safTrees,
    shareIntents,
    foregroundTransfers,
    sshAgent: options.sshAgent ?? !android,
    // Only a native non-Linux build is known to lack Kerberos; anything else
    // fails open because the page cannot see the server OS, and the backend
    // refuses explicit Kerberos settings where it cannot honor them. Key
    // exchange is unwired on every build, so it stays off unless overridden.
    gssapi: options.gssapi ?? !(native && platform !== 'linux'),
    gssapiKex: options.gssapiKex ?? false,
    fileDrop: true,
    nativeFileDrop: options.nativeFileDrop ?? (native && !android),
    accounts: options.accounts ?? !native,
    desktopLaunchers: options.desktopLaunchers ?? (
      native && ['linux', 'windows', 'macos', 'android'].includes(platform)
    ),
    terminal: options.terminal ?? true,
    backgroundTransfers: foregroundTransfers || !android,
  };
}

/**
 * Intended common workflows across the native apps. This list is a contract,
 * not runtime evidence that each workflow is fully wired; behavioral parity
 * still requires per-platform acceptance tests. Platform-specific host
 * integrations are reported separately below.
 */
export const SHARED_FEATURES = [
  'paneListings',
  'paneTransfer',
  'queueControl',
  'savedSites',
  'workspaces',
  'bookmarks',
  'editor',
  'search',
  'checksum',
  'synchronize',
  'keepUpToDate',
  'terminal',
  'serverMonitor',
  'preferences',
  'logs',
] as const;

export type SharedFeature = (typeof SHARED_FEATURES)[number];

/** Feature list an app must offer; identical for every host by design. */
export function sharedFeatureSet(): SharedFeature[] {
  return [...SHARED_FEATURES];
}

/**
 * True when a host difference is expected rather than a parity gap. Callers use
 * it to explain - never to hide - a disabled control.
 */
export function hostDifferenceReason(
  capability: keyof HostCapabilities,
  caps: HostCapabilities,
): string | null {
  if (capability === 'safTrees' && !caps.safTrees) {
    return caps.platform === 'android'
      ? 'Android folder grants are not available in this build.'
      : 'Folder grants require the Android Storage Access Framework.';
  }
  if (capability === 'shareIntents' && !caps.shareIntents) {
    return 'File sharing from other apps is not integrated in this build.';
  }
  if ((capability === 'foregroundTransfers' || capability === 'backgroundTransfers') && !caps[capability]) {
    return 'Background transfer support is not available in this build.';
  }
  if (capability === 'nativeFileDrop' && !caps.nativeFileDrop) {
    return 'Operating-system file drops require a native desktop window.';
  }
  if (capability === 'desktopLaunchers' && !caps.desktopLaunchers) {
    return 'Remote desktop viewers require a supported native launcher integration.';
  }
  if (capability === 'accounts' && !caps.accounts) {
    return 'The native application does not require a sign-in.';
  }
  if (capability === 'sshAgent' && !caps.sshAgent) {
    return 'SSH agent authentication is not available on this build; use a private key file instead.';
  }
  if (capability === 'gssapi' && !caps.gssapi) {
    return 'Kerberos (GSSAPI) authentication is only available on Linux; this build cannot use these settings.';
  }
  if (capability === 'gssapiKex' && !caps.gssapiKex) {
    return 'GSSAPI key exchange is not supported; leave it off or the connection is refused.';
  }
  return null;
}

/**
 * Local actions the granted-folder bridge cannot perform. Listing, creating,
 * renaming, deleting, editing, reading properties, copying, moving,
 * transferring and synchronizing inside a granted folder work through
 * `LocalFs` or staged temporary files; these need a plain filesystem path
 * (symlinks cannot point into a `content://` tree, and POSIX modes do not
 * exist there), so the backend refuses them with a message that names the
 * limitation - and the page asks here first so it does not offer a control
 * that could only fail.
 */
export type SafLimitedAction =
  | 'permissions'
  | 'symlink';

/**
 * The reason a local action is not offered for `path`, or null when the path
 * is not a granted Android folder. The wording mirrors the service's own
 * refusals (`saf_unsupported` plus the bridge's permissions message) so the
 * page and the backend tell one story; an unknown action still gets the
 * generic limitation rather than silence.
 */
export function safLimitationReason(
  action: SafLimitedAction,
  path: string | null | undefined,
): string | null {
  if (typeof path !== 'string' || !path.startsWith('content://')) {
    return null;
  }
  switch (action) {
    case 'permissions':
      return 'POSIX permissions do not exist on a granted Android folder.';
    case 'symlink':
      return 'Creating symbolic links needs a folder in app storage, not a granted Android folder.';
    default:
      return 'This action needs a folder in app storage, not a granted Android folder.';
  }
}
