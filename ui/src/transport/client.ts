import type { HostKeyChallenge, TransportEventMap } from '../types/api.js';

export type TransportMode = 'tauri';

export class TransportError extends Error {
  public readonly status: number;
  public readonly hostKeyChallenge?: HostKeyChallenge;
  public readonly payload?: Record<string, unknown>;

  public constructor(
    message: string,
    status: number,
    options?: {
      hostKeyChallenge?: HostKeyChallenge;
      payload?: Record<string, unknown>;
    },
  ) {
    super(message);
    this.name = 'TransportError';
    this.status = status;
    this.hostKeyChallenge = options?.hostKeyChallenge;
    this.payload = options?.payload;
  }
}

export interface TransportClient {
  readonly mode: TransportMode;
  request<T = unknown>(method: string, path: string, body?: unknown): Promise<T>;
  get<T = unknown>(path: string): Promise<T>;
  post<T = unknown>(path: string, body?: unknown): Promise<T>;
  subscribe<K extends keyof TransportEventMap>(
    event: K,
    handler: (payload: TransportEventMap[K]) => void,
  ): () => void;
}
