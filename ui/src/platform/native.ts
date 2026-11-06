import type { TransportClient } from '../transport/client.js';
import { TransportError } from '../transport/client.js';
import { nativeInvoker, type TauriInternalsLike } from '../transport/index.js';
import type { LocalRootEntry } from '../types/api.js';

/**
 * The Android Storage Access Framework folder picker.
 *
 * The WebView cannot open Android's document picker by itself: a `content://`
 * tree URI is only obtainable from platform code. The native shell therefore
 * exposes two `invoke` commands (`linscp_pick_saf_tree` to open the picker and
 * `linscp_request_saf_tree` to register a tree the caller already holds), and
 * this module is the one place that calls them.
 *
 * The same bundle runs in the browser and on the desktop, where there is no
 * SAF. There the picker resolves to `null` and the caller hides the control,
 * instead of every call site probing for `__TAURI_INTERNALS__` itself.
 */

/**
 * The `invoke` shape the shell exposes. It is the transport's own type, so a
 * command bridge and an API transport can never drift apart.
 */
export type NativeInvoker = TauriInternalsLike;

export interface SafRootEntry {
  path: string;
  label: string;
  kind: 'saf_tree';
  read_only: boolean;
}

interface SafTreeReply {
  success?: boolean;
  root?: SafRootEntry;
  error?: string;
  cancelled?: boolean;
}

export { nativeInvoker };

/** Builds a direct Android viewer URI; Android viewer apps cannot reuse an SSH jump tunnel. */
export function androidDesktopViewerUri(
  kind: string,
  endpoint: string,
  tunneled = false,
): string | null {
  const normalizedKind = kind.toLowerCase();
  const scheme = ['rdp', 'vnc', 'spice'].includes(normalizedKind) ? normalizedKind : null;
  if (!scheme || tunneled) return null;
  try {
    const target = new URL(`${scheme}://${endpoint}`);
    if (!target.hostname || target.username || target.password ||
        (target.pathname !== '' && target.pathname !== '/') || target.search || target.hash) return null;
    return `${scheme}://${target.host}`;
  } catch {
    return null;
  }
}

/** Opens a validated URL in an Android app registered for that scheme. */
export async function openExternalUri(
  uri: string,
  options: { invoker?: NativeInvoker | null } = {},
): Promise<boolean> {
  const invoker = options.invoker ?? nativeInvoker();
  if (!invoker) return false;
  try {
    const parsed = new URL(uri);
    if (!['http:', 'https:', 'rdp:', 'vnc:', 'spice:'].includes(parsed.protocol) ||
        !parsed.hostname || parsed.username || parsed.password) return false;
    const reply = await invoker.invoke<{ opened?: boolean }>('linscp_open_external_uri', { uri });
    return reply?.opened === true;
  } catch {
    return false;
  }
}

/**
 * Opens the Android folder picker and registers the granted tree as a local
 * root. Resolves to `null` when the shell has no SAF bridge, when the user
 * cancelled, or when the native side refused the URI.
 *
 * `registerTree` is used when the URI is already known (a share intent, a saved
 * root, or the shell's own `linscp_pick_saf_tree` that only returns a URI).
 */
export async function requestSafTree(options: {
  invoker?: NativeInvoker | null;
  registerTree?: (uri: string) => Promise<SafRootEntry | null>;
} = {}): Promise<LocalRootEntry | null> {
  const register = options.registerTree ?? (async (uri: string) => {
    const invoker = options.invoker ?? nativeInvoker();
    if (!invoker) {
      return null;
    }
    const reply = await invoker.invoke<SafTreeReply>('linscp_request_saf_tree', { uri });
    if (!reply || reply.success === false || !reply.root) {
      return null;
    }
    return reply.root;
  });

  const invoker = options.invoker ?? nativeInvoker();
  if (!invoker && !options.registerTree) {
    return null;
  }

  let uri: string | null = null;
  if (invoker) {
    const picked = await invoker
      .invoke<{ uri?: string; cancelled?: boolean }>('linscp_pick_saf_tree')
      .catch(() => null);
    if (picked && typeof picked.uri === 'string' && picked.uri.startsWith('content://')) {
      uri = picked.uri;
    }
  }
  if (!uri) {
    return null;
  }
  return register(uri);
}

/**
 * Fetches the local roots and turns each `content://` entry into a SAF root,
 * so a picker-selected folder survives a restart even though Android's
 * persisted permission is held by the shell rather than by the page.
 */
export async function listSafRoots(transport: TransportClient): Promise<LocalRootEntry[]> {
  try {
    const reply = await transport.get<{ roots: LocalRootEntry[] }>('/api/local/roots');
    return (reply?.roots ?? []).filter((root) => root.path.startsWith('content://'));
  } catch (error) {
    if (error instanceof TransportError && error.status >= 400) {
      return [];
    }
    return [];
  }
}

/**
 * Delivers files another Android application shared with LinSCP.
 *
 * The shell stages each URI into app-private storage and records the same
 * pending-upload manifest that the desktop `--shell-upload` hand-off uses, so
 * the page offers one confirmation flow on both apps.
 */
export async function handleShareIntent(
  uris: string[],
  options: { invoker?: NativeInvoker | null } = {},
): Promise<{ staged: string[]; manifest: Record<string, unknown> } | null> {
  const invoker = options.invoker ?? nativeInvoker();
  if (!invoker || uris.length === 0) {
    return null;
  }
  const reply = await invoker
    .invoke<{ success?: boolean; staged?: string[]; manifest?: Record<string, unknown> }>(
      'linscp_handle_share_intent',
      { uris },
    )
    .catch(() => null);
  if (!reply || reply.success === false || !reply.manifest) {
    return null;
  }
  return { staged: reply.staged ?? [], manifest: reply.manifest };
}

/** Starts or stops the Android foreground service that keeps transfers alive. */
export class ForegroundTransferBridge {
  private readonly invoker: NativeInvoker | null;
  private running = false;
  private lastProgress = -1;

  public constructor(invoker: NativeInvoker | null = nativeInvoker()) {
    this.invoker = invoker;
  }

  public get available(): boolean {
    return this.invoker !== null;
  }

  public get isRunning(): boolean {
    return this.running;
  }

  public async start(title: string, ongoing: number): Promise<boolean> {
    if (!this.invoker) {
      return false;
    }
    try {
      await this.invoker.invoke('linscp_foreground_start', { title, ongoing });
      this.running = true;
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Reports byte progress. Android rate-limits notification updates, and the
   * queue polls twice a second, so identical percentages are dropped here.
   */
  public async update(done: number, total: number): Promise<boolean> {
    if (!this.invoker || !this.running) {
      return false;
    }
    const percent = total > 0 ? Math.floor((done * 100) / total) : 0;
    if (percent === this.lastProgress && percent !== 100) {
      return true;
    }
    this.lastProgress = percent;
    try {
      await this.invoker.invoke('linscp_foreground_update', { done, total });
      return true;
    } catch {
      return false;
    }
  }

  public async stop(): Promise<boolean> {
    if (!this.invoker) {
      return false;
    }
    try {
      await this.invoker.invoke('linscp_foreground_stop');
      return true;
    } catch {
      return false;
    } finally {
      this.running = false;
      this.lastProgress = -1;
    }
  }
}
