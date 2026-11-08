import type { TransportClient } from '../transport/client.js';
import type {
  MonitorBuiltinMetric, MonitorCustomMetric, MonitorCustomReading, MonitorGpu, MonitorHostConfig, MonitorHostsResponse,
  MonitorSample, MonitorSampleResponse, MonitorSettingsDocument, MonitorSettingsResponse,
  MonitorSiteCandidate, MonitorSnapshot, MonitorTabCandidate,
} from '../types/api.js';

export type MonitorTranslate = (key: string, values?: Record<string, string | number>) => string;
export interface ServerMonitorOptions {
  root: HTMLElement;
  transport: Pick<TransportClient, 'get' | 'post'>;
  translate?: MonitorTranslate;
  /** Uses the application's existing connection and host-key approval flow. */
  connectSite: (site: MonitorSiteCandidate, timeoutSeconds: number) => Promise<number | null>;
  openTerminal: (tab: number) => void | Promise<void>;
  onClose: () => void;
  onError?: (message: string) => void;
  /** Outage/recovery notices. The backend logs them even when this is silent. */
  onNotice?: (message: string, tone: 'warn' | 'success') => void;
  /** Host-provided audible alert; the component applies the configured cooldown. */
  playAlert?: () => void;
}

/** The reference dashboard's non-linear thermal scale, not a temperature guess. */
export function thermalFill(temperature: number | null, limit: number | null): number | null {
  if (temperature === null || !Number.isFinite(temperature) || temperature < 0) return null;
  const ceiling = limit !== null && Number.isFinite(limit) && limit > 0 ? limit : 100;
  const ratio = Math.min(1, temperature / ceiling);
  return ratio <= 0.75 ? ratio / 0.75 * 20 : 20 + (ratio - 0.75) / 0.25 * 80;
}

/** Current-link heuristic only: the device's maximum link is not reported. */
export function pcieQuality(generation: number | null, width: number | null): number | null {
  if (generation === null || width === null || generation <= 0 || width <= 0) return null;
  return Math.min(100, (Math.min(generation, 5) / 5 * 60 + Math.min(width, 16) / 16 * 40));
}

export function memoryPercent(used: number | null, total: number | null): number | null {
  return used !== null && total !== null && total > 0 && used >= 0
    ? Math.min(100, used / total * 100) : null;
}

/** Network rates are shown in bits/s, the unit link speeds are rated in. */
export function formatBitsPerSec(bytesPerSec: number | null): string {
  if (bytesPerSec === null || !Number.isFinite(bytesPerSec) || bytesPerSec < 0) return 'N/A';
  const bits = bytesPerSec * 8;
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(2)} Gbps`;
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(2)} Mbps`;
  if (bits >= 1e3) return `${(bits / 1e3).toFixed(1)} Kbps`;
  return `${Math.round(bits)} bps`;
}

export function formatDuration(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

const HISTORY_POINTS = 60;
const BUILTIN_METRICS: MonitorBuiltinMetric[] = ['cpu', 'mem', 'swap', 'disk', 'load', 'net', 'gpu'];
const METRIC_LABELS: Record<MonitorBuiltinMetric, string> = {
  cpu: 'CPU', mem: 'RAM', swap: 'Swap', disk: 'Disk', load: 'Load 1m', net: 'Network', gpu: 'GPU',
};

function defaultHostConfig(): MonitorHostConfig {
  return { enabled_metrics: [...BUILTIN_METRICS], custom_metrics: [], paused: false };
}

function defaultDocument(): MonitorSettingsDocument {
  return {
    version: 1,
    settings: {
      interval_secs: 5, connect_timeout_secs: 10, poll_timeout_secs: 10,
      outage_threshold: 3, notify_on_outage: true, beep_on_outage: false, beep_cooldown_secs: 10,
    },
    hosts: {},
  };
}

function finite(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

interface HostState {
  sample: MonitorSample | null;
  snapshot: MonitorSnapshot | null;
  receivedAt: number;
  history: Record<string, number[]>;
}

/**
 * Shared multi-server display. The page owns the modal element and connection
 * callbacks; this component owns selection, rendering and a single-flight poll.
 * Closing/pausing stops polling, never disconnects a file-transfer session.
 * Remote strings are always textContent, never HTML.
 */
export class ServerMonitor {
  private readonly options: ServerMonitorOptions;
  private readonly root: HTMLElement;
  private readonly doc: Document;
  private readonly t: MonitorTranslate;
  private readonly selected = new Set<number>();
  private readonly hosts = new Map<number, HostState>();
  private readonly keys = new Map<number, string>();
  private sites: MonitorSiteCandidate[] = [];
  private tabs: MonitorTabCandidate[] = [];
  private maxHosts = 32;
  private interval = 5;
  private timeout = 10;
  private connectTimeout = 10;
  private compact = false;
  private overview = true;
  private current = 0;
  private opened = false;
  private paused = false;
  private picking = false;
  private connecting = false;
  private inFlight = false;
  private pollRequested = false;
  private generation = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private document: MonitorSettingsDocument = defaultDocument();
  private settingsOpen = false;
  private configKey: string | null = null;
  private configDraft: MonitorHostConfig | null = null;
  private configApproved = false;
  private customCounter = 0;
  private lastBeepAt = 0;
  private statusElement!: HTMLElement;
  private content!: HTMLElement;
  private settingsPanel!: HTMLElement;
  private pauseButton!: HTMLButtonElement;
  private viewButton!: HTMLButtonElement;
  private compactButton!: HTMLButtonElement;
  private previousButton!: HTMLButtonElement;
  private nextButton!: HTMLButtonElement;
  private shellButton!: HTMLButtonElement;
  private settingsButton!: HTMLButtonElement;

  public constructor(options: ServerMonitorOptions) {
    this.options = options;
    this.root = options.root;
    this.doc = options.root.ownerDocument;
    this.t = options.translate ?? ((key, values) => key.replace(/\{([a-z]+)\}/g,
      (match, name: string) => values?.[name] === undefined ? match : String(values[name])));
    this.build();
  }

  public get isOpen(): boolean { return this.opened; }
  public get selectedHosts(): number[] { return [...this.selected]; }
  public get currentHost(): number | null { return this.selected.has(this.current) ? this.current : null; }
  public get isPaused(): boolean { return this.paused; }

  public async open(): Promise<void> {
    this.opened = true;
    this.generation++;
    this.root.classList.add('monitor-open');
    if (!this.selected.size) this.picking = true;
    this.render();
    this.root.focus();
    await Promise.all([this.loadHosts(), this.loadSettings()]);
    if (this.opened && !this.paused && !this.picking) this.requestPoll();
  }

  public close(): void {
    if (!this.opened) return;
    this.opened = false;
    this.pollRequested = false;
    this.generation++;
    this.stopTimer();
    this.root.classList.remove('monitor-open');
    this.options.onClose();
  }

  public pause(): void {
    this.paused = true;
    this.pollRequested = false;
    this.generation++;
    this.stopTimer();
    this.renderStatus();
  }

  public resume(): void {
    if (!this.opened) return;
    this.paused = false;
    this.generation++;
    this.renderStatus();
    if (!this.picking) this.requestPoll();
  }

  public toggleOverview(): void {
    this.overview = !this.overview;
    if (!this.overview && !this.selected.has(this.current)) this.current = this.selectedHosts[0] ?? 0;
    this.render();
  }

  public toggleCompact(): void { this.compact = !this.compact; this.render(); }

  public nextHost(direction = 1): void {
    const ids = this.selectedHosts;
    if (!ids.length) return;
    const index = ids.indexOf(this.current);
    this.current = ids[(Math.max(0, index) + direction + ids.length) % ids.length]!;
    this.overview = false;
    this.render();
  }

  public async showPicker(): Promise<void> {
    this.picking = true;
    this.generation++;
    this.stopTimer();
    this.render();
    await this.loadHosts();
  }

  public async refresh(): Promise<void> {
    if (!this.opened || this.picking || this.paused || this.inFlight) return;
    this.pollRequested = false;
    this.inFlight = true;
    const generation = this.generation;
    const ids = this.activeHosts();
    this.renderStatus();
    try {
      if (!ids.length) return;
      const reply = await this.options.transport.post<MonitorSampleResponse>('/api/monitor/sample',
        { tabs: ids, timeout: this.timeout });
      if (!this.opened || generation !== this.generation || this.paused || this.picking) return;
      if (!reply.success || !Array.isArray(reply.samples)) throw new Error(this.t('The monitoring request failed.'));
      for (const sample of reply.samples) {
        if (!this.selected.has(sample.tab)) continue;
        if (sample.key) this.keys.set(sample.tab, sample.key);
        const previous = this.hosts.get(sample.tab);
        const snapshot = sample.status === 'ok' && sample.snapshot ? sample.snapshot : null;
        const history = { ...(previous?.history ?? {}) };
        if (snapshot) this.recordHistory(history, snapshot);
        this.hosts.set(sample.tab, {
          sample, snapshot: snapshot ?? previous?.snapshot ?? null,
          receivedAt: snapshot ? Date.now() : previous?.receivedAt ?? 0, history,
        });
        this.notifyOutage(sample);
      }
      this.renderContent();
    } catch (error) {
      if (this.opened && generation === this.generation) {
        this.options.onError?.(String((error as Error)?.message ?? error));
        this.statusElement.textContent = this.t('Monitoring could not reach the backend.');
      }
    } finally {
      this.inFlight = false;
      if (this.opened && !this.paused && !this.picking && this.activeHosts().length) {
        this.stopTimer();
        const immediate = this.pollRequested || generation !== this.generation;
        this.pollRequested = false;
        this.timer = setTimeout(() => this.requestPoll(), immediate ? 0 : this.interval * 1000);
      }
      if (this.opened) this.renderStatus();
    }
  }

  /** Scoped shortcuts. Return true only when this display consumed the key. */
  public handleKey(event: KeyboardEvent): boolean {
    if (!this.opened || event.ctrlKey || event.metaKey || event.altKey) return false;
    const target = event.target as HTMLElement | null;
    if (target?.closest('input, textarea, select, [contenteditable="true"]')) return false;
    const key = event.key.toLowerCase();
    if (!['t', 'n', 'm', 'c', 's', 'q'].includes(key)) return false;
    event.preventDefault();
    if (key === 't') this.toggleOverview();
    if (key === 'n') this.nextHost();
    if (key === 'm') this.toggleCompact();
    if (key === 'c') void this.showPicker();
    if (key === 's') void this.openShell();
    if (key === 'q') this.close();
    return true;
  }

  public dispose(): void { this.close(); this.root.replaceChildren(); }

  private requestPoll(): void { this.pollRequested = true; void this.refresh(); }
  private stopTimer(): void { if (this.timer !== null) clearTimeout(this.timer); this.timer = null; }
  private activeHosts(): number[] { return this.selectedHosts.filter(id => !this.isHostPaused(id)); }

  private hostKey(id: number): string {
    return this.hosts.get(id)?.sample?.key || this.keys.get(id)
      || this.tabs.find(tab => tab.tab === id)?.key || `tab:${id}`;
  }

  private hostConfig(key: string): MonitorHostConfig {
    return this.document.hosts[key] ?? defaultHostConfig();
  }

  private isHostPaused(id: number): boolean { return this.hostConfig(this.hostKey(id)).paused; }
  private enabled(id: number, metric: MonitorBuiltinMetric): boolean {
    return this.hostConfig(this.hostKey(id)).enabled_metrics.includes(metric);
  }

  private element<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', text?: string): HTMLElementTagNameMap[K] {
    const node = this.doc.createElement(tag);
    node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  private button(text: string, action: () => void, className = 'btn'): HTMLButtonElement {
    const button = this.element('button', className, this.t(text));
    button.type = 'button';
    button.addEventListener('click', action);
    return button;
  }
  private build(): void {
    this.root.tabIndex = -1;
    this.root.replaceChildren();
    const controls = this.element('div', 'monitor-controls');
    controls.append(this.button('Choose servers', () => void this.showPicker()));
    this.viewButton = this.button('Overview', () => this.toggleOverview());
    this.viewButton.title = this.t('Toggle overview and single-server detail (t)');
    this.previousButton = this.button('Previous server', () => this.nextHost(-1));
    this.nextButton = this.button('Next server', () => this.nextHost());
    this.nextButton.title = this.t('Next server (n)');
    this.compactButton = this.button('Compact GPUs', () => this.toggleCompact());
    this.compactButton.title = this.t('Toggle compact GPU cards (m)');
    this.shellButton = this.button('SSH shell', () => void this.openShell());
    this.shellButton.title = this.t('Open a shell on the current server; return here when it closes (s)');
    this.pauseButton = this.button('Pause', () => this.paused ? this.resume() : this.pause());
    this.settingsButton = this.button('Monitor settings', () => { this.settingsOpen = !this.settingsOpen; this.renderSettingsPanel(); });
    controls.append(this.viewButton, this.previousButton, this.nextButton, this.compactButton,
      this.shellButton, this.pauseButton, this.settingsButton, this.button('Refresh now', () => this.requestPoll()));
    this.settingsPanel = this.element('div', 'monitor-settings-panel');
    this.settingsPanel.hidden = true;
    this.statusElement = this.element('div', 'monitor-status');
    this.statusElement.setAttribute('role', 'status');
    this.statusElement.setAttribute('aria-live', 'polite');
    this.content = this.element('div', 'monitor-content');
    this.root.append(controls, this.settingsPanel, this.statusElement, this.content);
  }

  private numericInput(label: string, value: number, min: number, max: number, step: number): { wrapper: HTMLElement; input: HTMLInputElement } {
    const wrapper = this.element('label', 'monitor-number');
    const input = this.element('input', 'input-field');
    input.type = 'number'; input.min = String(min); input.max = String(max); input.step = String(step); input.value = String(value);
    wrapper.append(this.element('span', '', this.t(label)), input);
    return { wrapper, input };
  }

  private checkbox(label: string, checked: boolean): { wrapper: HTMLElement; input: HTMLInputElement } {
    const wrapper = this.element('label', 'monitor-check');
    const input = this.element('input'); input.type = 'checkbox'; input.checked = checked;
    wrapper.append(input, this.element('span', '', this.t(label)));
    return { wrapper, input };
  }

  private async loadSettings(): Promise<void> {
    try {
      const reply = await this.options.transport.get<MonitorSettingsResponse>('/api/monitor/settings');
      if (!reply?.success || !reply.document) return;
      this.document = { ...defaultDocument(), ...reply.document,
        settings: { ...defaultDocument().settings, ...reply.document.settings },
        hosts: reply.document.hosts ?? {} };
      this.interval = this.document.settings.interval_secs;
      this.timeout = this.document.settings.poll_timeout_secs;
      this.connectTimeout = this.document.settings.connect_timeout_secs;
      if (this.settingsOpen) this.renderSettingsPanel();
      if (this.opened && !this.picking) this.renderContent();
      if (this.opened) this.renderStatus();
    } catch (error) {
      this.options.onError?.(String((error as Error)?.message ?? error));
    }
  }

  private async saveDocument(next: MonitorSettingsDocument): Promise<boolean> {
    try {
      const reply = await this.options.transport.post<MonitorSettingsResponse>('/api/monitor/settings', next);
      if (!reply?.success || !reply.document) throw new Error(this.t('The monitoring request failed.'));
      this.document = reply.document;
      this.interval = this.document.settings.interval_secs;
      this.timeout = this.document.settings.poll_timeout_secs;
      this.connectTimeout = this.document.settings.connect_timeout_secs;
      return true;
    } catch (error) {
      this.options.onError?.(String((error as Error)?.message ?? error));
      return false;
    }
  }

  private renderSettingsPanel(): void {
    this.settingsPanel.hidden = !this.settingsOpen;
    this.settingsButton.setAttribute('aria-pressed', String(this.settingsOpen));
    this.settingsPanel.replaceChildren();
    if (!this.settingsOpen) return;
    const settings = this.document.settings;
    const interval = this.numericInput('Refresh every', settings.interval_secs, 0.1, 60, 0.1);
    const poll = this.numericInput('Sample timeout', settings.poll_timeout_secs, 0.1, 30, 0.1);
    const connect = this.numericInput('Connection timeout', settings.connect_timeout_secs, 1, 60, 1);
    const threshold = this.numericInput('Outage threshold', settings.outage_threshold, 1, 100, 1);
    const cooldown = this.numericInput('Beep cooldown', settings.beep_cooldown_secs, 0, 600, 1);
    const notify = this.checkbox('Notify on outage and recovery', settings.notify_on_outage);
    const beep = this.checkbox('Beep on outage', settings.beep_on_outage);
    const grid = this.element('div', 'monitor-settings-grid');
    grid.append(interval.wrapper, poll.wrapper, connect.wrapper, threshold.wrapper, cooldown.wrapper);
    const actions = this.element('div', 'monitor-picker-actions');
    const save = this.button('Save monitor settings', () => {
      const read = (input: HTMLInputElement, fallback: number): number => Number.isFinite(input.valueAsNumber) ? input.valueAsNumber : fallback;
      void this.saveDocument({ ...this.document, settings: {
        interval_secs: read(interval.input, settings.interval_secs),
        poll_timeout_secs: read(poll.input, settings.poll_timeout_secs),
        connect_timeout_secs: read(connect.input, settings.connect_timeout_secs),
        outage_threshold: Math.round(read(threshold.input, settings.outage_threshold)),
        notify_on_outage: notify.input.checked,
        beep_on_outage: beep.input.checked,
        beep_cooldown_secs: Math.round(read(cooldown.input, settings.beep_cooldown_secs)),
      } }).then(ok => {
        if (!ok) return;
        this.settingsOpen = false; this.renderSettingsPanel(); this.renderStatus();
        this.stopTimer(); if (!this.paused && !this.picking) this.requestPoll();
      });
    }, 'btn btn-primary');
    const test = this.button('Test beep', () => this.options.playAlert?.());
    actions.append(test, save);
    this.settingsPanel.append(this.element('h3', '', this.t('Monitor settings')), grid,
      notify.wrapper, beep.wrapper,
      this.element('p', 'hint', this.t('Seconds; outage threshold is consecutive failed polls. Settings are saved on this device.')), actions);
  }

  private async loadHosts(): Promise<void> {
    const generation = this.generation;
    try {
      const reply = await this.options.transport.get<MonitorHostsResponse>('/api/monitor/hosts');
      if (!this.opened || generation !== this.generation) return;
      if (!reply.success) throw new Error(this.t('Cannot list servers.'));
      this.tabs = Array.isArray(reply.tabs) ? reply.tabs : [];
      this.sites = Array.isArray(reply.sites) ? reply.sites : [];
      this.maxHosts = Math.max(1, Math.min(32, reply.max_hosts || 32));
      const live = new Set(this.tabs.map(tab => tab.tab));
      for (const id of this.selected) if (!live.has(id)) { this.selected.delete(id); this.hosts.delete(id); this.keys.delete(id); }
      if (this.picking) this.renderPicker(); else this.renderContent();
      this.renderStatus();
    } catch (error) {
      if (this.opened && generation === this.generation) this.options.onError?.(String((error as Error)?.message ?? error));
    }
  }

  private render(): void { this.renderStatus(); if (this.picking) this.renderPicker(); else this.renderContent(); }

  private renderStatus(): void {
    this.pauseButton.textContent = this.t(this.paused ? 'Resume monitoring' : 'Pause');
    this.viewButton.textContent = this.t(this.overview ? 'Overview' : 'Server detail');
    this.viewButton.setAttribute('aria-pressed', String(this.overview));
    this.compactButton.setAttribute('aria-pressed', String(this.compact));
    this.previousButton.disabled = this.selected.size < 2;
    this.nextButton.disabled = this.selected.size < 2;
    this.shellButton.disabled = !this.selected.size || this.picking;
    const samples = [...this.hosts.values()].filter(state => this.selected.has(state.sample?.tab ?? -1));
    const failed = samples.filter(state => state.sample?.status !== 'ok').length;
    const outages = samples.filter(state => state.sample?.outage).length;
    this.statusElement.textContent = this.picking ? this.t('Choose up to {count} Linux servers.', { count: this.maxHosts })
      : this.paused ? this.t('Monitoring paused. SSH sessions stay connected.')
      : !this.activeHosts().length && this.selected.size ? this.t('All selected servers are paused.')
      : this.inFlight ? this.t('Sampling selected servers…')
      : this.t('{count} servers selected · {failed} need attention · {outages} offline', { count: this.selected.size, failed, outages });
  }

  private renderPicker(): void {
    this.content.replaceChildren();
    const intro = this.element('p', 'hint', this.t('Select open sessions or saved SSH sites. New connections use the normal host-key verification. Removing a server here does not close its session.'));
    const list = this.element('div', 'monitor-picker-list');
    const pendingSites = new Set<string>();
    const pendingTabs = new Set(this.selected);
    const count = () => pendingTabs.size + pendingSites.size;
    const updateCount = () => { apply.disabled = !count() || count() > this.maxHosts || this.connecting; };
    for (const tab of this.tabs) {
      const label = this.element('label', 'monitor-picker-item');
      const check = this.element('input'); check.type = 'checkbox'; check.checked = this.selected.has(tab.tab);
      check.addEventListener('change', () => { if (check.checked) pendingTabs.add(tab.tab); else pendingTabs.delete(tab.tab); updateCount(); });
      const copy = this.element('span', 'monitor-picker-copy');
      copy.append(this.element('strong', '', tab.name), this.element('small', 'hint', `${tab.host}:${tab.port} · ${tab.protocol.toUpperCase()}`));
      label.append(check, copy, this.element('span', 'monitor-badge', this.t('Connected')));
      list.append(label);
    }
    for (const site of this.sites) {
      const label = this.element('label', 'monitor-picker-item');
      const check = this.element('input'); check.type = 'checkbox';
      check.addEventListener('change', () => { if (check.checked) pendingSites.add(site.name); else pendingSites.delete(site.name); updateCount(); });
      const copy = this.element('span', 'monitor-picker-copy');
      copy.append(this.element('strong', '', site.name), this.element('small', 'hint', `${site.host}:${site.port} · ${site.protocol.toUpperCase()}`));
      label.append(check, copy, this.element('span', 'hint', this.t('Saved site')));
      list.append(label);
    }
    if (!this.tabs.length && !this.sites.length) list.append(this.element('p', 'monitor-empty', this.t('No SSH servers yet. Add a site in the session manager, or import your OpenSSH configuration there first.')));
    const actions = this.element('div', 'monitor-picker-actions');
    const apply = this.button('Monitor selected servers', () => void applySelection(), 'btn btn-primary');
    const cancel = this.button('Cancel', () => { this.picking = false; this.render(); if (!this.paused) this.requestPoll(); });
    cancel.disabled = !this.selected.size;
    actions.append(cancel, apply);
    const applySelection = async (): Promise<void> => {
      if (this.connecting || !count() || count() > this.maxHosts) return;
      this.connecting = true; apply.disabled = true;
      this.statusElement.textContent = this.t('Connecting selected servers…');
      const generation = this.generation;
      // Sequential saved-site login lets the existing host-key dialog finish
      // before another connection can ask a different security question.
      for (const name of pendingSites) {
        if (!this.opened || generation !== this.generation) break;
        const site = this.sites.find(candidate => candidate.name === name);
        if (!site) continue;
        try {
          const id = await this.options.connectSite(site, this.connectTimeout);
          if (id !== null && this.opened && generation === this.generation) pendingTabs.add(id);
        } catch (error) { this.options.onError?.(String((error as Error)?.message ?? error)); }
      }
      this.connecting = false;
      if (!this.opened || generation !== this.generation) return;
      if (pendingTabs.size > this.maxHosts) {
        this.options.onError?.(this.t('Choose up to {count} Linux servers.', { count: this.maxHosts }));
        updateCount(); return;
      }
      this.selected.clear(); pendingTabs.forEach(id => this.selected.add(id));
      for (const id of this.hosts.keys()) if (!this.selected.has(id)) this.hosts.delete(id);
      this.current = this.selectedHosts[0] ?? 0;
      this.picking = false;
      await this.loadHosts();
      this.render();
      if (!this.paused) this.requestPoll();
    };
    updateCount();
    this.content.append(intro, list, actions);
  }

  private renderContent(): void {
    this.content.replaceChildren();
    if (this.configKey && this.configDraft) this.content.append(this.renderConfigPanel());
    if (!this.selected.size) {
      this.content.append(this.element('p', 'monitor-empty', this.t('Choose servers to start monitoring.')));
      return;
    }
    const ids = this.overview ? this.selectedHosts : [this.current];
    const grid = this.element('div', this.overview ? 'monitor-grid' : 'monitor-detail');
    for (const id of ids) grid.append(this.renderCard(id, this.hosts.get(id)));
    this.content.append(grid);
    this.renderStatus();
  }

  private renderCard(id: number, state?: HostState): HTMLElement {
    const sample = state?.sample;
    const snapshot = state?.snapshot;
    const paused = this.isHostPaused(id);
    const stale = !sample || sample.status !== 'ok';
    const outage = Boolean(sample?.outage) && !paused;
    const card = this.element('article', `monitor-card${stale ? ' monitor-stale' : ''}${outage ? ' monitor-outage' : ''}${paused ? ' monitor-paused' : ''}`);
    const header = this.element('header', 'monitor-card-header');
    const identity = this.element('div', 'monitor-identity');
    const title = this.element('h3', '', sample?.name || this.tabs.find(tab => tab.tab === id)?.name || `#${id}`);
    identity.append(title, this.element('p', 'hint', snapshot?.primary_ip || sample?.host || ''));
    if (snapshot?.hostname) identity.append(this.element('small', 'hint', snapshot.hostname));
    const badge = this.element('span', `monitor-badge ${outage ? 'monitor-badge-warn' : stale ? 'monitor-badge-warn' : 'monitor-badge-ok'}`,
      this.t(paused ? 'Paused' : outage ? 'Offline' : !sample ? 'Waiting for sample' : stale ? 'Stale / unavailable' : 'Live'));
    const actions = this.element('div', 'monitor-card-actions');
    const pause = this.button(paused ? 'Resume' : 'Pause', () => void this.toggleHostPaused(id), 'btn tiny');
    pause.setAttribute('aria-label', this.t(paused ? 'Resume monitoring this server' : 'Pause monitoring this server'));
    const configure = this.button('Configure', () => this.openConfig(id), 'btn tiny');
    const remove = this.button('Remove', () => {
      this.selected.delete(id); this.hosts.delete(id);
      if (this.current === id) this.current = this.selectedHosts[0] ?? 0;
      if (this.configKey === this.hostKey(id)) { this.configKey = null; this.configDraft = null; }
      this.render();
    }, 'btn tiny');
    remove.setAttribute('aria-label', this.t('Stop monitoring this server'));
    actions.append(pause, configure, remove);
    header.append(identity, badge, actions);
    if (this.overview) {
      title.tabIndex = 0; title.setAttribute('role', 'button');
      const detail = () => { this.current = id; this.overview = false; this.render(); };
      title.addEventListener('click', detail);
      title.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); detail(); } });
    }
    card.append(header);
    if (outage && sample?.outage_since_ms) {
      card.append(this.element('p', 'monitor-outage-strip', this.t('Offline for {duration}: {error}', {
        duration: formatDuration(Date.now() - sample.outage_since_ms), error: sample.error || this.t('No error reported'),
      })));
    } else if (sample?.error) card.append(this.element('p', 'monitor-error', sample.error));
    if (paused) card.append(this.element('p', 'hint', this.t('Monitoring paused for this server.')));
    if (!snapshot) {
      card.append(this.element('p', 'hint', this.t(sample?.status === 'disconnected'
        ? 'Reconnect this server in its session tab, then refresh the monitor.'
        : 'CPU usage needs two samples. Waiting for telemetry…')));
      return card;
    }
    if (stale && state?.receivedAt) card.append(this.element('p', 'monitor-stale-time', this.t('Last successful sample: {time}', { time: new Date(state.receivedAt).toLocaleTimeString() })));
    const history = state?.history ?? {};
    if (this.enabled(id, 'cpu')) {
      card.append(this.metric('CPU', snapshot.cpu.percent, snapshot.cpu.model || this.t('{count} logical CPUs', { count: snapshot.cpu.logical_count }), undefined, history.cpu));
    }
    if (this.enabled(id, 'mem')) {
      card.append(this.metric('RAM', snapshot.memory?.percent ?? null, snapshot.memory
        ? `${formatBytes(snapshot.memory.used_bytes)} / ${formatBytes(snapshot.memory.total_bytes)}` : this.t('Unavailable'), undefined, history.mem));
    }
    if (this.enabled(id, 'swap')) {
      card.append(this.metric('Swap', snapshot.swap?.percent ?? null, snapshot.swap
        ? `${formatBytes(snapshot.swap.used_bytes)} / ${formatBytes(snapshot.swap.total_bytes)}` : this.t('Unavailable'), undefined, history.swap));
    }
    if (this.enabled(id, 'disk')) {
      const diskPercent = snapshot.disks.length ? Math.max(...snapshot.disks.map(disk => disk.percent)) : null;
      card.append(this.metric('Disk', diskPercent, snapshot.disks.length ? this.t('Fullest of {count} mounts', { count: snapshot.disks.length }) : this.t('Unavailable'), undefined, history.disk));
    }
    if (this.enabled(id, 'load')) {
      const load = snapshot.load_average[0] ?? null;
      card.append(this.scalarMetric('Load 1m', load === null ? this.t('N/A') : load.toFixed(2), history.load,
        snapshot.load_average.map(n => n.toFixed(2)).join(', ') || this.t('Unavailable')));
    }
    if (this.enabled(id, 'net')) {
      const network = snapshot.network;
      card.append(this.scalarMetric('Net in', formatBitsPerSec(network?.rx_bytes_per_sec ?? null), history.net_in,
        network ? this.t('Total received: {bytes}', { bytes: formatBytes(network.rx_bytes_total) }) : this.t('Unavailable')));
      card.append(this.scalarMetric('Net out', formatBitsPerSec(network?.tx_bytes_per_sec ?? null), history.net_out,
        network ? this.t('Total sent: {bytes}', { bytes: formatBytes(network.tx_bytes_total) }) : this.t('Unavailable')));
    }
    const gpus = snapshot.gpus;
    if (this.enabled(id, 'gpu')) {
      const usages = gpus.map(gpu => gpu.percent).filter((n): n is number => n !== null);
      const gpuPercent = usages.length ? usages.reduce((sum, n) => sum + n, 0) / usages.length : null;
      card.append(this.metric('GPU', gpuPercent, gpus.length ? this.t('{count} GPUs · mean reported usage', { count: gpus.length }) : this.t('No GPU telemetry'), undefined, history.gpu));
      const power = gpus.map(gpu => gpu.power_watts).filter((n): n is number => n !== null);
      if (power.length) card.append(this.element('p', 'monitor-power', this.t('GPU power: {watts} W reported', { watts: power.reduce((sum, n) => sum + n, 0).toFixed(1) })));
    }
    for (const reading of snapshot.custom ?? []) card.append(this.customReading(reading, history));
    if (!this.overview) this.renderDetail(card, snapshot, id);
    else if (snapshot.warnings.length) card.append(this.element('p', 'hint monitor-warning', snapshot.warnings.map(warning => this.t(warning)).join(' ')));
    if (sample) card.append(this.element('footer', 'monitor-card-footer hint', `${sample.latency_ms} ms · ${new Date(sample.sampled_at).toLocaleTimeString()}`));
    return card;
  }

  private metric(label: string, value: number | null, description: string, fill = value, history?: number[]): HTMLElement {
    const wrapper = this.element('div', 'monitor-metric');
    const heading = this.element('div', 'monitor-metric-label');
    heading.append(this.element('strong', '', this.t(label)), this.element('span', '', value === null ? this.t('N/A') : `${value.toFixed(1)}%`));
    const track = this.element('div', 'monitor-meter');
    track.setAttribute('role', 'meter'); track.setAttribute('aria-label', this.t(label));
    track.setAttribute('aria-valuemin', '0'); track.setAttribute('aria-valuemax', '100');
    if (value !== null) track.setAttribute('aria-valuenow', String(Math.round(value * 10) / 10));
    track.setAttribute('aria-valuetext', value === null ? this.t('Unavailable') : `${value.toFixed(1)}%`);
    const bar = this.element('span', fill !== null && fill >= 90 ? 'monitor-meter-fill monitor-meter-hot' : 'monitor-meter-fill');
    bar.style.width = `${fill === null ? 0 : Math.max(0, Math.min(100, fill))}%`;
    track.append(bar);
    wrapper.append(heading, track);
    if (history && history.length > 1) wrapper.append(this.sparkline(history, label, 0, 100));
    wrapper.append(this.element('small', 'hint', description));
    return wrapper;
  }

  private scalarMetric(label: string, valueText: string, history: number[] | undefined, description: string): HTMLElement {
    const wrapper = this.element('div', 'monitor-metric monitor-scalar');
    const heading = this.element('div', 'monitor-metric-label');
    heading.append(this.element('strong', '', this.t(label)), this.element('span', '', valueText));
    wrapper.append(heading);
    if (history && history.length > 1) wrapper.append(this.sparkline(history, label));
    wrapper.append(this.element('small', 'hint', description));
    return wrapper;
  }

  private customReading(reading: MonitorCustomReading, history: Record<string, number[]>): HTMLElement {
    const wrapper = this.element('div', `monitor-metric monitor-custom${reading.error ? ' monitor-custom-error' : ''}`);
    const heading = this.element('div', 'monitor-metric-label');
    const value = reading.parse === 'text' ? reading.text || this.t('N/A')
      : reading.value === null ? this.t('N/A') : `${formatCustomNumber(reading.value)}${reading.unit ? ` ${reading.unit}` : ''}`;
    heading.append(this.element('strong', '', reading.name), this.element('span', reading.display === 'big_number' ? 'monitor-big-number' : '', value));
    wrapper.append(heading);
    if (reading.error) wrapper.append(this.element('small', 'monitor-error', reading.error));
    const series = history[`custom:${reading.id}`];
    if (reading.display === 'sparkline' && series && series.length > 1) wrapper.append(this.sparkline(series, reading.name));
    return wrapper;
  }

  private sparkline(history: number[], label: string, min?: number, max?: number): SVGSVGElement {
    const values = history.filter(finite);
    const svg = this.doc.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 400 48'); svg.setAttribute('class', 'monitor-sparkline');
    svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', `${this.t('Recent trend')}: ${this.t(label)}`);
    const low = min ?? Math.min(...values);
    const high = max ?? Math.max(...values);
    const span = high > low ? high - low : 1;
    const points = values.map((value, index) => {
      const x = values.length === 1 ? 200 : index / (values.length - 1) * 400;
      const y = 47 - Math.max(0, Math.min(1, (value - low) / span)) * 46;
      return `${x},${y}`;
    }).join(' ');
    const line = this.doc.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    line.setAttribute('points', points); line.setAttribute('fill', 'none'); line.setAttribute('stroke', 'currentColor'); line.setAttribute('stroke-width', '2');
    svg.append(line); return svg;
  }

  private renderDetail(card: HTMLElement, snapshot: MonitorSnapshot, id: number): void {
    if (snapshot.uptime_seconds !== null) card.append(this.element('p', 'hint', this.t('Uptime: {seconds} s · Load: {load}', {
      seconds: Math.floor(snapshot.uptime_seconds), load: snapshot.load_average.map(n => n.toFixed(2)).join(', ') || this.t('N/A'),
    })));
    if (this.enabled(id, 'cpu')) {
      const cores = this.element('section', 'monitor-section');
      cores.append(this.element('h4', '', this.t('CPU cores')));
      const coreGrid = this.element('div', 'monitor-core-grid');
      for (const core of snapshot.cpu.cores) {
        const node = this.element('div', 'monitor-core');
        const label = `${core.socket === null ? '' : `S${core.socket} / `}C${core.core}`;
        node.title = core.threads.map(thread => `CPU ${thread.id}: ${thread.percent === null ? this.t('N/A') : `${thread.percent.toFixed(1)}%`}`).join('\n');
        node.append(this.element('small', '', label));
        for (const thread of core.threads) {
          const track = this.element('div', 'monitor-core-thread');
          const fill = this.element('span'); fill.style.height = `${thread.percent ?? 0}%`; track.append(fill); node.append(track);
        }
        coreGrid.append(node);
      }
      if (!snapshot.cpu.cores.length) coreGrid.append(this.element('p', 'hint', this.t('Per-core telemetry is unavailable.')));
      cores.append(coreGrid); card.append(cores);
    }
    if (this.enabled(id, 'disk')) {
      const disks = this.element('section', 'monitor-section');
      disks.append(this.element('h4', '', this.t('Mounted filesystems')));
      for (const disk of snapshot.disks) disks.append(this.metric(disk.mount, disk.percent,
        `${disk.device} · ${formatBytes(disk.used_bytes)} / ${formatBytes(disk.total_bytes)} · ${formatBytes(disk.available_bytes)} ${this.t('available')}`));
      if (!snapshot.disks.length) disks.append(this.element('p', 'hint', this.t('Disk telemetry is unavailable.')));
      card.append(disks);
    }
    if (this.enabled(id, 'gpu')) {
      const gpuSection = this.element('section', 'monitor-section');
      gpuSection.append(this.element('h4', '', this.t('GPU usage')));
      if (snapshot.cuda_version) gpuSection.append(this.element('p', 'hint', `CUDA ${snapshot.cuda_version}`));
      const gpuGrid = this.element('div', this.compact ? 'monitor-gpu-grid monitor-gpu-compact' : 'monitor-gpu-grid');
      for (const gpu of snapshot.gpus) gpuGrid.append(this.renderGpu(gpu));
      if (!snapshot.gpus.length) gpuSection.append(this.element('p', 'hint', this.t('No GPU telemetry: install/vendor-enable nvidia-smi, amd-smi or rocm-smi, or this server has no supported GPU.')));
      gpuSection.append(gpuGrid);
      for (const warning of snapshot.warnings) gpuSection.append(this.element('p', 'hint monitor-warning', this.t(warning)));
      card.append(gpuSection);
    }
  }

  private renderGpu(gpu: MonitorGpu): HTMLElement {
    const card = this.element('div', 'monitor-gpu-card');
    const header = this.element('div', 'monitor-gpu-heading');
    header.append(this.element('strong', '', `${gpu.vendor} ${gpu.index} · ${gpu.name || this.t('GPU')}`));
    if (gpu.pcie_generation !== null && gpu.pcie_width !== null) {
      const quality = pcieQuality(gpu.pcie_generation, gpu.pcie_width);
      const link = this.element('span', 'monitor-pcie', `PCIe Gen${gpu.pcie_generation} ×${gpu.pcie_width}`);
      link.style.color = `hsl(${quality ?? 0} 65% 55%)`;
      link.title = this.t('Current link quality heuristic; the device maximum is not reported.');
      header.append(link);
    }
    card.append(header);
    card.append(this.metric('GPU', gpu.percent, gpu.driver ? `${this.t('Driver')} ${gpu.driver}` : this.t('Driver unavailable')));
    if (!this.compact) card.append(this.metric('VRAM', memoryPercent(gpu.memory_used_bytes, gpu.memory_total_bytes),
      gpu.memory_used_bytes !== null && gpu.memory_total_bytes !== null ? `${formatBytes(gpu.memory_used_bytes)} / ${formatBytes(gpu.memory_total_bytes)}` : this.t('Unavailable')));
    const temperature = this.element('p', 'monitor-gpu-stat', `${this.t('Temperature')} (${this.t(gpu.temperature_sensor)}): ${gpu.temperature_c === null ? this.t('N/A') : `${gpu.temperature_c.toFixed(1)} °C`}${gpu.temperature_limit_c === null ? '' : ` / ${gpu.temperature_limit_c} °C`}`);
    card.append(temperature);
    const fill = thermalFill(gpu.temperature_c, gpu.temperature_limit_c);
    if (fill !== null) {
      const track = this.element('div', 'monitor-meter monitor-thermal');
      track.setAttribute('role', 'img');
      track.setAttribute('aria-label', this.t('Thermal risk scale: normal temperatures fill slowly; the last quarter fills quickly.'));
      const bar = this.element('span', fill >= 80 ? 'monitor-meter-fill monitor-meter-hot' : 'monitor-meter-fill');
      bar.style.width = `${fill}%`; track.append(bar); card.append(track);
    }
    if (!this.compact || gpu.power_watts !== null) card.append(this.element('p', 'monitor-gpu-stat', `${this.t('Power')}: ${gpu.power_watts === null ? this.t('N/A') : `${gpu.power_watts.toFixed(1)} W`}${gpu.power_limit_watts === null ? '' : ` / ${gpu.power_limit_watts} W`}`));
    return card;
  }

  private openConfig(id: number): void {
    this.configKey = this.hostKey(id);
    this.configDraft = structuredClone(this.hostConfig(this.configKey));
    this.configApproved = false;
    this.renderContent();
  }

  private renderConfigPanel(): HTMLElement {
    const panel = this.element('section', 'monitor-config-panel');
    const draft = this.configDraft!;
    panel.append(this.element('h3', '', this.t('Server metrics')), this.element('p', 'hint', this.configKey ?? ''));
    const metrics = this.element('div', 'monitor-config-metrics');
    for (const metric of BUILTIN_METRICS) {
      const check = this.checkbox(METRIC_LABELS[metric], draft.enabled_metrics.includes(metric));
      check.input.addEventListener('change', () => {
        draft.enabled_metrics = check.input.checked
          ? [...draft.enabled_metrics, metric]
          : draft.enabled_metrics.filter(item => item !== metric);
      });
      metrics.append(check.wrapper);
    }
    panel.append(metrics);
    panel.append(this.element('h4', '', this.t('Custom metrics')));
    panel.append(this.element('p', 'hint', this.t('Custom commands run on the remote server every poll. Add only commands you trust; output is capped and parsed as a number, regex capture, or text.')));
    const list = this.element('div', 'monitor-custom-list');
    draft.custom_metrics.forEach((metric, index) => list.append(this.renderCustomEditor(metric, index)));
    if (!draft.custom_metrics.length) list.append(this.element('p', 'hint', this.t('No custom metrics.')));
    panel.append(list);
    const add = this.button('Add custom metric', () => {
      if (draft.custom_metrics.length >= 8) { this.options.onError?.(this.t('At most {count} custom metrics are allowed per server.', { count: 8 })); return; }
      draft.custom_metrics.push({ id: `m-${Date.now().toString(36)}-${this.customCounter++}`, name: '', command: '', parse: 'number', display: 'sparkline', unit: '' });
      this.renderContent();
    });
    const approval = this.checkbox('I approve running these custom commands on this server every poll.', this.configApproved);
    approval.input.addEventListener('change', () => { this.configApproved = approval.input.checked; });
    const actions = this.element('div', 'monitor-picker-actions');
    const cancel = this.button('Cancel', () => { this.configKey = null; this.configDraft = null; this.renderContent(); });
    const save = this.button('Apply server metrics', () => void this.saveConfig(), 'btn btn-primary');
    actions.append(add, cancel, save);
    panel.append(approval.wrapper, actions);
    return panel;
  }

  private renderCustomEditor(metric: MonitorCustomMetric, index: number): HTMLElement {
    const row = this.element('div', 'monitor-custom-editor');
    const name = this.element('input', 'input-field'); name.type = 'text'; name.value = metric.name; name.placeholder = this.t('Name');
    name.setAttribute('aria-label', this.t('Custom metric name'));
    name.addEventListener('input', () => { metric.name = name.value; });
    const command = this.element('textarea', 'input-field'); command.value = metric.command; command.rows = 2;
    command.placeholder = this.t('Remote command'); command.setAttribute('aria-label', this.t('Custom metric command'));
    command.addEventListener('input', () => { metric.command = command.value; });
    const parse = this.element('select', 'input-field'); parse.setAttribute('aria-label', this.t('Parse output'));
    for (const [value, label] of [['number', 'Number'], ['regex', 'Regex capture'], ['text', 'Raw text']] as const) {
      const option = this.element('option', '', this.t(label)); option.value = value; parse.append(option);
    }
    parse.value = metric.parse;
    const display = this.element('select', 'input-field'); display.setAttribute('aria-label', this.t('Display'));
    for (const [value, label] of [['sparkline', 'Sparkline'], ['big_number', 'Big number'], ['text', 'Text']] as const) {
      const option = this.element('option', '', this.t(label)); option.value = value; display.append(option);
    }
    display.value = metric.display;
    const unit = this.element('input', 'input-field'); unit.type = 'text'; unit.value = metric.unit; unit.placeholder = this.t('Unit');
    unit.setAttribute('aria-label', this.t('Custom metric unit'));
    unit.addEventListener('input', () => { metric.unit = unit.value; });
    const regex = this.element('input', 'input-field'); regex.type = 'text'; regex.value = metric.regex ?? '';
    regex.placeholder = this.t('Regex with one capture group'); regex.setAttribute('aria-label', this.t('Custom metric regex'));
    regex.hidden = metric.parse !== 'regex';
    regex.addEventListener('input', () => { metric.regex = regex.value; });
    parse.addEventListener('change', () => {
      metric.parse = parse.value as MonitorCustomMetric['parse'];
      regex.hidden = metric.parse !== 'regex';
      if (metric.parse === 'text') { metric.display = 'text'; display.value = 'text'; }
      display.disabled = metric.parse === 'text';
    });
    display.disabled = metric.parse === 'text';
    display.addEventListener('change', () => { metric.display = display.value as MonitorCustomMetric['display']; });
    const remove = this.button('Remove', () => { this.configDraft?.custom_metrics.splice(index, 1); this.renderContent(); }, 'btn tiny');
    row.append(name, command, parse, display, unit, regex, remove);
    return row;
  }

  private async saveConfig(): Promise<void> {
    if (!this.configKey || !this.configDraft) return;
    const draft = this.configDraft;
    if (draft.custom_metrics.length && !this.configApproved) {
      this.options.onError?.(this.t('Approve the custom commands before applying them.'));
      return;
    }
    for (const metric of draft.custom_metrics) {
      if (!metric.name.trim() || !metric.command.trim()) { this.options.onError?.(this.t('A custom metric name and command are required.')); return; }
      if (metric.parse === 'regex' && !(metric.regex ?? '').trim()) { this.options.onError?.(this.t('A regex custom metric needs a pattern.')); return; }
    }
    const next = { ...this.document, hosts: { ...this.document.hosts, [this.configKey]: draft } };
    if (await this.saveDocument(next)) {
      this.configKey = null; this.configDraft = null; this.configApproved = false;
      this.render(); this.requestPoll();
    }
  }

  private async toggleHostPaused(id: number): Promise<void> {
    const key = this.hostKey(id);
    const config = this.hostConfig(key);
    const next = { ...this.document, hosts: { ...this.document.hosts, [key]: { ...config, paused: !config.paused } } };
    if (await this.saveDocument(next)) {
      this.render();
      if (!config.paused) this.stopTimer(); else this.requestPoll();
    }
  }

  private recordHistory(history: Record<string, number[]>, snapshot: MonitorSnapshot): void {
    const push = (key: string, value: number | null | undefined): void => {
      if (!finite(value)) return;
      history[key] = [...(history[key] ?? []), value].slice(-HISTORY_POINTS);
    };
    push('cpu', snapshot.cpu.percent);
    push('mem', snapshot.memory?.percent);
    push('swap', snapshot.swap?.percent);
    push('disk', snapshot.disks.length ? Math.max(...snapshot.disks.map(disk => disk.percent)) : null);
    push('load', snapshot.load_average[0]);
    push('net_in', snapshot.network?.rx_bytes_per_sec);
    push('net_out', snapshot.network?.tx_bytes_per_sec);
    const usages = snapshot.gpus.map(gpu => gpu.percent).filter((n): n is number => n !== null);
    push('gpu', usages.length ? usages.reduce((sum, n) => sum + n, 0) / usages.length : null);
    for (const reading of snapshot.custom ?? []) push(`custom:${reading.id}`, reading.value);
  }

  private notifyOutage(sample: MonitorSample): void {
    const settings = this.document.settings;
    if (sample.outage_started) {
      if (settings.notify_on_outage) this.options.onNotice?.(this.t('{name} is offline: {error}', { name: sample.name, error: sample.error || this.t('No error reported') }), 'warn');
      const cooldown = Math.max(0, settings.beep_cooldown_secs) * 1000;
      const now = Date.now();
      if (settings.beep_on_outage && (cooldown === 0 || now - this.lastBeepAt >= cooldown)) {
        this.lastBeepAt = now;
        this.options.playAlert?.();
      }
    }
    if (sample.recovered && settings.notify_on_outage) {
      this.options.onNotice?.(this.t('{name} recovered.', { name: sample.name }), 'success');
    }
  }

  private async openShell(): Promise<void> {
    if (!this.selected.size || this.picking) return;
    if (!this.selected.has(this.current)) this.current = this.selectedHosts[0]!;
    const id = this.current;
    this.pause();
    try { await this.options.openTerminal(id); }
    catch (error) { this.options.onError?.(String((error as Error)?.message ?? error)); this.resume(); }
  }
}

function formatCustomNumber(value: number): string {
  const abs = Math.abs(value);
  return abs >= 100 ? value.toFixed(0) : abs >= 1 ? value.toFixed(2) : value.toFixed(3);
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return 'N/A';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let value = bytes; let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}
