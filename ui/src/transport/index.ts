import { TransportError, type TransportClient, type TransportMode } from './client.js';
import { HttpTransport, type HttpTransportOptions } from './http.js';
import { TauriTransport, type TauriInternalsLike } from './tauri.js';

export { TransportError, HttpTransport, TauriTransport };
export type { TransportClient, TransportMode, HttpTransportOptions, TauriInternalsLike };

interface HostGlobal {
  __TAURI_INTERNALS__?: TauriInternalsLike;
  __LINSCP_TOKEN__?: string;
}

export function detectTransportMode(host: unknown = globalThis): TransportMode {
  const candidate = host as HostGlobal | null | undefined;
  if (candidate && typeof candidate.__TAURI_INTERNALS__?.invoke === 'function') {
    return 'tauri';
  }
  return 'http';
}

export interface CreateTransportOptions extends HttpTransportOptions {
  host?: unknown;
}

export function createTransport(options: CreateTransportOptions = {}): TransportClient {
  const host = (options.host ?? globalThis) as HostGlobal;
  if (host && typeof host.__TAURI_INTERNALS__?.invoke === 'function') {
    return new TauriTransport(host.__TAURI_INTERNALS__);
  }
  return new HttpTransport({
    ...options,
    bearerToken: options.bearerToken ?? host?.__LINSCP_TOKEN__ ?? '',
  });
}

/**
 * The native command bridge, when the bundle is running inside the Tauri shell
 * and `null` in a browser.
 *
 * Platform modules need to call shell commands that are not part of the
 * `CommanderService` envelope (the Android folder picker, the share hand-off
 * and the foreground service). They must not reach for the global themselves:
 * `tools/check_repo_hygiene.py` keeps the transport boundary in this directory,
 * so this is the one door, and it reports the same thing
 * `detectTransportMode` does.
 */
export function nativeInvoker(
  host: unknown = globalThis,
): TauriInternalsLike | null {
  const candidate = host as HostGlobal | null | undefined;
  return candidate && typeof candidate.__TAURI_INTERNALS__?.invoke === 'function'
    ? candidate.__TAURI_INTERNALS__
    : null;
}
