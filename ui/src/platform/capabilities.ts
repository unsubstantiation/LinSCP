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
}

/**
 * The capability set for one embedder.
 *
 * Defaults describe the desktop builds, where every feature is reachable: the
 * native window has local roots, terminal and remote-desktop launchers, and
 * only lacks the Android-specific bridges. The browser app has the same feature
 * surface except for the bridges that need a process on the user's machine and
 * the OS-level drop event. Android is the native app minus remote-desktop
 * viewers and with the SAF, share and foreground bridges in their place.
 */
export function hostCapabilities(options: HostCapabilityOptions = {}): HostCapabilities {
  const transport = options.transport ?? detectHostKind();
  const platform = options.platform ?? detectHostPlatform();
  const native = transport === 'tauri';
  const android = platform === 'android';
  return {
    transport,
    platform,
    nativeIpc: native,
    localRoots: options.localRoots ?? true,
    safTrees: options.safTrees ?? (native && android),
    shareIntents: options.shareIntents ?? (native && android),
    foregroundTransfers: options.foregroundTransfers ?? (native && android),
    fileDrop: true,
    nativeFileDrop: options.nativeFileDrop ?? native,
    accounts: options.accounts ?? !native,
    desktopLaunchers: options.desktopLaunchers ?? !android,
    terminal: options.terminal ?? true,
    backgroundTransfers: (options.foregroundTransfers ?? (native && android)) || !android,
  };
}

/**
 * The features every app must expose the same way. A capability that is only
 * reachable in one embedder is a parity bug, not a platform difference, so the
 * test suite compares these across desktop, browser and Android.
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
    return 'Folder grants are an Android feature.';
  }
  if (capability === 'desktopLaunchers' && !caps.desktopLaunchers) {
    return 'Remote desktop viewers need a desktop operating system.';
  }
  if (capability === 'accounts' && !caps.accounts) {
    return 'The native application does not require a sign-in.';
  }
  return null;
}
