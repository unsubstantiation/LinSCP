import { TransportError, type TransportClient, type TransportMode } from './client.js';
import { TauriTransport, type TauriInternalsLike } from './tauri.js';

export { TransportError, TauriTransport };
export type { TransportClient, TransportMode, TauriInternalsLike };

interface HostGlobal {
  __TAURI_INTERNALS__?: TauriInternalsLike;
}

/**
 * The one transport this application has: the native shell's in-process IPC.
 *
 * The page used to fall back to HTTP with a bearer token when there was no
 * `__TAURI_INTERNALS__`; there is no browser host any more, so a page outside
 * the shell has no backend to reach.
 */
export function detectTransportMode(_host: unknown = globalThis): TransportMode {
  return 'tauri';
}

export interface CreateTransportOptions {
  host?: unknown;
}

export function createTransport(options: CreateTransportOptions = {}): TransportClient | null {
  const host = (options.host ?? globalThis) as HostGlobal;
  return host && typeof host.__TAURI_INTERNALS__?.invoke === 'function'
    ? new TauriTransport(host.__TAURI_INTERNALS__)
    : null;
}

/**
 * The native command bridge, or `null` outside the Tauri shell.
 *
 * Platform modules need to call shell commands that are not part of the
 * `CommanderService` envelope (the Android folder picker, the share hand-off
 * and the foreground service). They must not reach for the global themselves:
 * `tools/check_repo_hygiene.py` keeps the transport boundary in this directory,
 * so this is the one door.
 */
export function nativeInvoker(
  host: unknown = globalThis,
): TauriInternalsLike | null {
  const candidate = host as HostGlobal | null | undefined;
  return candidate && typeof candidate.__TAURI_INTERNALS__?.invoke === 'function'
    ? candidate.__TAURI_INTERNALS__
    : null;
}
