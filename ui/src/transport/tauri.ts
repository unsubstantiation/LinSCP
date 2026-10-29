import type {
  ApiEnvelope,
  ApiReply,
  HostKeyChallenge,
  TransportEventMap,
} from '../types/api.js';
import { TransportError, type TransportClient } from './client.js';

export interface TauriInternalsLike {
  invoke<T = unknown>(cmd: string, args?: Record<string, unknown>): Promise<T>;
}

interface ErrorPayload {
  error?: string;
  hostkey_challenge?: HostKeyChallenge;
}

export class TauriTransport implements TransportClient {
  public readonly mode = 'tauri' as const;
  private readonly internals: TauriInternalsLike;
  private readonly listeners = new Map<
    keyof TransportEventMap,
    Set<(payload: never) => void>
  >();

  public constructor(internals: TauriInternalsLike) {
    this.internals = internals;
  }

  public setCsrfToken(_token: string): void {
    // Tauri IPC runs in-process over the WebView bridge without browser cookies.
  }

  public async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const envelope: ApiEnvelope = {
      method: method.toUpperCase(),
      path,
      body: body ?? {},
    };
    const reply = await this.internals.invoke<ApiReply<T & ErrorPayload>>(
      'linscp_invoke',
      { envelope },
    );
    if (reply.status >= 400) {
      const errBody = (reply.payload ?? {}) as ErrorPayload;
      throw new TransportError(
        errBody.error ?? `IPC error (${reply.status})`,
        reply.status,
        { hostKeyChallenge: errBody.hostkey_challenge, payload: errBody as Record<string, unknown> },
      );
    }
    return reply.payload;
  }

  public get<T = unknown>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  public post<T = unknown>(path: string, body: unknown = {}): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  public subscribe<K extends keyof TransportEventMap>(
    event: K,
    handler: (payload: TransportEventMap[K]) => void,
  ): () => void {
    let bucket = this.listeners.get(event);
    if (!bucket) {
      bucket = new Set();
      this.listeners.set(event, bucket);
    }
    const wrapped = handler as unknown as (payload: never) => void;
    bucket.add(wrapped);
    return () => {
      bucket?.delete(wrapped);
    };
  }

  public dispatchNativeEvent<K extends keyof TransportEventMap>(
    event: K,
    payload: TransportEventMap[K],
  ): void {
    const bucket = this.listeners.get(event);
    if (!bucket) {
      return;
    }
    for (const listener of bucket) {
      (listener as unknown as (data: TransportEventMap[K]) => void)(payload);
    }
  }
}
