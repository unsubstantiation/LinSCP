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
