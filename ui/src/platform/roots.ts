import type { TransportClient } from '../transport/client.js';
import type { FileEntry, LocalRootEntry } from '../types/api.js';

export interface LocalListResult {
  path: string;
  entries: FileEntry[];
}

export interface LocalRootSwitcherOptions {
  transport: TransportClient;
  selectElement: HTMLSelectElement;
  onNavigate: (result: LocalListResult) => void;
  onRequestAndroidSafTree?: () => Promise<LocalRootEntry | null>;
  /** Shown while the local root list is being read. */
  onBusy?: (busy: boolean) => void;
  /** Called with a translated-ready message when the switch fails. */
  onError?: (message: string) => void;
}

const SAF_ADD_SENTINEL = '__linscp_add_saf_tree__';

/**
 * Renders and drives a cross-platform Local Root Switcher:
 * - Windows: mounted logical drives (`C:\`, `D:\`, ...)
 * - Android: app-private storage + persisted SAF Document Trees + "Grant Folder Access..."
 * - Linux: `/` and `Home (~)`
 *
 * The switcher is the same component in the desktop window, the browser page
 * and the Android app; only the roots the backend answers with differ.
 */
export class LocalRootSwitcher {
  private readonly transport: TransportClient;
  private readonly selectEl: HTMLSelectElement;
  private readonly onNavigate: (result: LocalListResult) => void;
  private readonly onRequestSaf?: () => Promise<LocalRootEntry | null>;
  private readonly onBusy?: (busy: boolean) => void;
  private readonly onError?: (message: string) => void;
  private roots: LocalRootEntry[] = [];
  private currentPath = '';

  public constructor(options: LocalRootSwitcherOptions) {
    this.transport = options.transport;
    this.selectEl = options.selectElement;
    this.onNavigate = options.onNavigate;
    this.onRequestSaf = options.onRequestAndroidSafTree;
    this.onBusy = options.onBusy;
    this.onError = options.onError;

    this.selectEl.addEventListener('change', () => {
      void this.handleSelectionChange();
    });
  }

  /** The roots the last refresh returned. */
  public get availableRoots(): LocalRootEntry[] {
    return [...this.roots];
  }

  public async refreshRoots(currentPath?: string): Promise<LocalRootEntry[]> {
    this.onBusy?.(true);
    try {
      const res = await this.transport.get<{ roots: LocalRootEntry[] }>('/api/local/roots');
      this.roots = Array.isArray(res?.roots) ? res.roots : [];
    } catch (error) {
      this.onError?.(String((error as Error)?.message ?? error));
      this.roots = [];
    } finally {
      this.onBusy?.(false);
    }
    this.render(currentPath ?? this.currentPath);
    return this.roots;
  }

  /**
   * Renders the root list and marks the root that contains `currentPath`, so a
   * navigation inside one root does not move the selection back to it.
   */
  public render(currentPath?: string): void {
    if (currentPath !== undefined) {
      this.currentPath = currentPath;
    }
    const doc = this.selectEl.ownerDocument;
    while (this.selectEl.firstChild) {
      this.selectEl.removeChild(this.selectEl.firstChild);
    }

    if (this.roots.length === 0) {
      // An empty list still has to explain itself: a hidden, empty select in
      // the pane header looked like the path box had lost its roots.
      const empty = doc.createElement('option');
      empty.value = '';
      empty.textContent = 'No local roots';
      empty.disabled = true;
      empty.selected = true;
      this.selectEl.appendChild(empty);
    }

    for (const root of this.roots) {
      const opt = doc.createElement('option');
      opt.value = root.path;
      opt.textContent = root.read_only ? `${root.label} · read-only` : root.label;
      if (this.matchesRoot(this.currentPath, root.path)) {
        opt.selected = true;
      }
      this.selectEl.appendChild(opt);
    }

    if (this.onRequestSaf) {
      const grantOpt = doc.createElement('option');
      grantOpt.value = SAF_ADD_SENTINEL;
      grantOpt.textContent = '+ Grant Folder Access…';
      this.selectEl.appendChild(grantOpt);
    }

    this.selectEl.hidden = this.roots.length <= 1 && !this.onRequestSaf;
    this.selectEl.title = this.currentPath;
  }

  private matchesRoot(currentPath: string, rootPath: string): boolean {
    if (!currentPath) {
      return false;
    }
    if (currentPath === rootPath) {
      return true;
    }
    if (rootPath === '/' || /^[A-Za-z]:[\\/]?$/.test(rootPath)) {
      return rootPath === '/' || currentPath.toLowerCase().startsWith(rootPath.slice(0, 2).toLowerCase());
    }
    const normCurrent = currentPath.replace(/\\/g, '/').toLowerCase();
    const normRoot = rootPath.replace(/\\/g, '/').toLowerCase();
    return normCurrent.startsWith(normRoot);
  }

  private async handleSelectionChange(): Promise<void> {
    const chosen = this.selectEl.value;
    if (chosen === SAF_ADD_SENTINEL && this.onRequestSaf) {
      this.onBusy?.(true);
      let granted: LocalRootEntry | null = null;
      try {
        granted = await this.onRequestSaf();
      } catch (error) {
        this.onError?.(String((error as Error)?.message ?? error));
      } finally {
        this.onBusy?.(false);
      }
      if (!granted) {
        // The user dismissed the picker: put the selection back where it was
        // instead of leaving the sentinel showing as if it were a root.
        this.render();
        return;
      }
      await this.refreshRoots(granted.path);
      await this.navigateTo(granted.path);
      return;
    }

    if (chosen) {
      await this.navigateTo(chosen);
    }
  }

  private async navigateTo(path: string): Promise<void> {
    this.onBusy?.(true);
    try {
      const listing = await this.transport.get<LocalListResult>(
        `/api/local/list?path=${encodeURIComponent(path)}`,
      );
      this.currentPath = listing.path;
      this.render(this.currentPath);
      this.onNavigate(listing);
    } catch (error) {
      this.onError?.(String((error as Error)?.message ?? error));
      this.render();
    } finally {
      this.onBusy?.(false);
    }
  }
}
