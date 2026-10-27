import type { HostKeyChallenge, TransportEventMap } from '../types/api.js';
import { TransportError, type TransportClient } from './client.js';

export interface HttpTransportOptions {
  baseUrl?: string;
  bearerToken?: string;
  csrfToken?: string;
  fetchImpl?: typeof globalThis.fetch;
  onAuthRequired?: () => void;
}

interface ErrorBody {
  error?: string;
  login_required?: boolean;
  hostkey_challenge?: HostKeyChallenge;
}

export class HttpTransport implements TransportClient {
  public readonly mode = 'http' as const;
  private readonly baseUrl: string;
  private readonly bearerToken: string;
  private csrfToken: string;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly onAuthRequired?: () => void;
  private readonly listeners = new Map<
    keyof TransportEventMap,
    Set<(payload: never) => void>
  >();

  public constructor(options: HttpTransportOptions = {}) {
    this.baseUrl = (options.baseUrl ?? '').replace(/\/+$/, '');
    this.bearerToken = options.bearerToken ?? '';
    this.csrfToken = options.csrfToken ?? '';
    this.fetchFn = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.onAuthRequired = options.onAuthRequired;
  }

  public setCsrfToken(token: string): void {
    this.csrfToken = token;
  }

  public async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const upper = method.toUpperCase();
    const headers: Record<string, string> = {
      'X-LSCP-Token': this.bearerToken,
    };
    if (this.csrfToken) {
      headers['X-LSCP-CSRF'] = this.csrfToken;
    }
    const init: RequestInit = { method: upper, headers };
    if (body !== undefined && upper !== 'GET' && upper !== 'HEAD') {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    const response = await this.fetchFn(`${this.baseUrl}${path}`, init);
    const data = (await response.json().catch(() => ({}))) as T & ErrorBody;

    if (response.status === 401) {
      const loginRequired = Boolean(data.login_required);
      if (loginRequired && this.onAuthRequired) {
        this.onAuthRequired();
      }
      throw new TransportError(
        data.error ?? (loginRequired ? 'Sign in required' : 'Authentication refused by server'),
        401,
        { loginRequired },
      );
    }

    if (!response.ok) {
      throw new TransportError(
        data.error ?? `HTTP ${response.status}`,
        response.status,
        { hostKeyChallenge: data.hostkey_challenge },
      );
    }

    return data;
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

  public emitLocalEvent<K extends keyof TransportEventMap>(
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
