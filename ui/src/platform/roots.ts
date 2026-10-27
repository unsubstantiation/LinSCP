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
}

const SAF_ADD_SENTINEL = '__linscp_add_saf_tree__';

/**
 * Renders and drives a cross-platform Local Root Switcher:
 * - Windows: mounted logical drives (`C:\`, `D:\`, ...)
 * - Android: app-private storage + persisted SAF Document Trees + "Grant Folder Access..."
 * - Linux: `/` and `Home (~)`
 */
export class LocalRootSwitcher {
  private readonly transport: TransportClient;
  private readonly selectEl: HTMLSelectElement;
  private readonly onNavigate: (result: LocalListResult) => void;
  private readonly onRequestSaf?: () => Promise<LocalRootEntry | null>;
  private roots: LocalRootEntry[] = [];

  public constructor(options: LocalRootSwitcherOptions) {
    this.transport = options.transport;
    this.selectEl = options.selectElement;
    this.onNavigate = options.onNavigate;
    this.onRequestSaf = options.onRequestAndroidSafTree;

    this.selectEl.addEventListener('change', () => {
      void this.handleSelectionChange();
    });
  }

  public async refreshRoots(currentPath?: string): Promise<LocalRootEntry[]> {
    const res = await this.transport.get<{ roots: LocalRootEntry[] }>('/api/local/roots');
    this.roots = res.roots ?? [];
    this.render(currentPath);
    return this.roots;
  }

  public render(currentPath?: string): void {
    const doc = this.selectEl.ownerDocument;
    while (this.selectEl.firstChild) {
      this.selectEl.removeChild(this.selectEl.firstChild);
    }

    for (const root of this.roots) {
      const opt = doc.createElement('option');
      opt.value = root.path;
      opt.textContent = root.label;
      if (currentPath && this.matchesRoot(currentPath, root.path)) {
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
  }

  private matchesRoot(currentPath: string, rootPath: string): boolean {
    if (currentPath === rootPath) {
      return true;
    }
    const normCurrent = currentPath.replace(/\\/g, '/').toLowerCase();
    const normRoot = rootPath.replace(/\\/g, '/').toLowerCase();
    return normRoot !== '/' && normCurrent.startsWith(normRoot);
  }

  private async handleSelectionChange(): Promise<void> {
    const chosen = this.selectEl.value;
    if (chosen === SAF_ADD_SENTINEL && this.onRequestSaf) {
      const granted = await this.onRequestSaf();
      if (!granted) {
        return;
      }
      await this.refreshRoots(granted.path);
      const listing = await this.transport.get<LocalListResult>(
        `/api/local/list?path=${encodeURIComponent(granted.path)}`,
      );
      this.onNavigate(listing);
      return;
    }

    if (chosen) {
      const listing = await this.transport.get<LocalListResult>(
        `/api/local/list?path=${encodeURIComponent(chosen)}`,
      );
      this.onNavigate(listing);
    }
  }
}
