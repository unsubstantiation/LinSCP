import type { HostKeyChallenge, TransportEventMap } from '../types/api.js';

export type TransportMode = 'tauri' | 'http';

export class TransportError extends Error {
  public readonly status: number;
  public readonly loginRequired: boolean;
  public readonly hostKeyChallenge?: HostKeyChallenge;

  public constructor(
    message: string,
    status: number,
    options?: {
      loginRequired?: boolean;
      hostKeyChallenge?: HostKeyChallenge;
    },
  ) {
    super(message);
    this.name = 'TransportError';
    this.status = status;
    this.loginRequired = Boolean(options?.loginRequired);
    this.hostKeyChallenge = options?.hostKeyChallenge;
  }
}

export interface TransportClient {
  readonly mode: TransportMode;
  setCsrfToken(token: string): void;
  request<T = unknown>(method: string, path: string, body?: unknown): Promise<T>;
  get<T = unknown>(path: string): Promise<T>;
  post<T = unknown>(path: string, body?: unknown): Promise<T>;
  subscribe<K extends keyof TransportEventMap>(
    event: K,
    handler: (payload: TransportEventMap[K]) => void,
  ): () => void;
}
