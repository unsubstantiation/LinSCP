import type { TransportClient } from '../transport/client.js';
import type {
  MonitorGpu, MonitorHostsResponse, MonitorSample, MonitorSampleResponse,
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

interface HostState {
  sample: MonitorSample | null;
  snapshot: MonitorSnapshot | null;
  receivedAt: number;
  history: number[];
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
  private statusElement!: HTMLElement;
  private content!: HTMLElement;
  private pauseButton!: HTMLButtonElement;
  private viewButton!: HTMLButtonElement;
  private compactButton!: HTMLButtonElement;
  private previousButton!: HTMLButtonElement;
  private nextButton!: HTMLButtonElement;
  private shellButton!: HTMLButtonElement;

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
    await this.loadHosts();
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
    const ids = this.selectedHosts;
    this.renderStatus();
    try {
      if (!ids.length) return;
      const reply = await this.options.transport.post<MonitorSampleResponse>('/api/monitor/sample',
        { tabs: ids, timeout: this.timeout });
      if (!this.opened || generation !== this.generation || this.paused || this.picking) return;
      if (!reply.success || !Array.isArray(reply.samples)) throw new Error(this.t('The monitoring request failed.'));
      for (const sample of reply.samples) {
        if (!this.selected.has(sample.tab)) continue;
        const previous = this.hosts.get(sample.tab);
        const snapshot = sample.status === 'ok' && sample.snapshot ? sample.snapshot : null;
        const history = snapshot?.cpu.percent == null ? [] : [...(previous?.history ?? []), snapshot.cpu.percent].slice(-40);
        this.hosts.set(sample.tab, { sample, snapshot: snapshot ?? previous?.snapshot ?? null,
          receivedAt: Date.now(), history });
      }
      this.renderContent();
    } catch (error) {
      if (this.opened && generation === this.generation) {
        this.options.onError?.(String((error as Error)?.message ?? error));
        this.statusElement.textContent = this.t('Monitoring could not reach the backend.');
      }
    } finally {
      this.inFlight = false;
      if (this.opened && !this.paused && !this.picking) {
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
    controls.append(this.viewButton, this.previousButton, this.nextButton, this.compactButton,
      this.shellButton, this.pauseButton, this.button('Refresh now', () => this.requestPoll()));
    const settings = this.element('div', 'monitor-settings');
    settings.append(this.numericSetting('Refresh every', 5, 0.1, 60, 0.1, value => {
      this.interval = value; this.stopTimer(); if (!this.paused && !this.picking) this.requestPoll();
    }), this.numericSetting('Sample timeout', 10, 0.1, 30, 0.1, value => { this.timeout = value; }),
      this.numericSetting('Connection timeout', 10, 1, 60, 1, value => { this.connectTimeout = value; }));
    settings.append(this.element('span', 'hint', this.t('Seconds')));
    this.statusElement = this.element('div', 'monitor-status');
    this.statusElement.setAttribute('role', 'status');
    this.statusElement.setAttribute('aria-live', 'polite');
    this.content = this.element('div', 'monitor-content');
    this.root.append(controls, settings, this.statusElement, this.content);
  }

  private numericSetting(label: string, initial: number, min: number, max: number, step: number, change: (value: number) => void): HTMLElement {
    const wrapper = this.element('label', 'monitor-number');
    const input = this.element('input', 'input-field');
    input.type = 'number'; input.min = String(min); input.max = String(max); input.step = String(step); input.value = String(initial);
    input.addEventListener('change', () => {
      const value = input.valueAsNumber;
      if (!Number.isFinite(value) || value < min || value > max) {
        input.value = String(initial); change(initial);
        this.options.onError?.(this.t('Enter a value from {min} to {max}.', { min, max }));
        return;
      }
      change(value);
    });
    wrapper.append(this.element('span', '', this.t(label)), input);
    return wrapper;
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
      for (const id of this.selected) if (!live.has(id)) { this.selected.delete(id); this.hosts.delete(id); }
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
    this.statusElement.textContent = this.picking ? this.t('Choose up to {count} Linux servers.', { count: this.maxHosts })
      : this.paused ? this.t('Monitoring paused. SSH sessions stay connected.')
      : this.inFlight ? this.t('Sampling selected servers…')
      : this.t('{count} servers selected · {failed} need attention', { count: this.selected.size, failed });
  }

  private renderPicker(): void {
    this.content.replaceChildren();
    const intro = this.element('p', 'hint', this.t('Select open sessions or saved SSH sites. New connections use the normal host-key verification. Removing a server here does not close its session.'));
    const list = this.element('div', 'monitor-picker-list');
    const pendingSites = new Set<string>();
    let pendingTabs = new Set(this.selected);
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
    if (!this.selected.size) {
      this.content.append(this.element('p', 'monitor-empty', this.t('Choose servers to start monitoring.')));
      return;
    }
    const ids = this.overview ? this.selectedHosts : [this.current];
    const grid = this.element('div', this.overview ? 'monitor-grid' : 'monitor-detail');
    for (const id of ids) {
      const state = this.hosts.get(id);
      grid.append(this.renderCard(id, state));
    }
    this.content.append(grid);
    this.renderStatus();
  }

  private renderCard(id: number, state?: HostState): HTMLElement {
    const sample = state?.sample;
    const snapshot = state?.snapshot;
    const stale = !sample || sample.status !== 'ok';
    const card = this.element('article', `monitor-card${stale ? ' monitor-stale' : ''}`);
    const header = this.element('header', 'monitor-card-header');
    const identity = this.element('div', 'monitor-identity');
    const title = this.element('h3', '', sample?.name || this.tabs.find(tab => tab.tab === id)?.name || `#${id}`);
    identity.append(title, this.element('p', 'hint', snapshot?.primary_ip || sample?.host || ''));
    if (snapshot?.hostname) identity.append(this.element('small', 'hint', snapshot.hostname));
    const badge = this.element('span', `monitor-badge ${stale ? 'monitor-badge-warn' : 'monitor-badge-ok'}`,
      this.t(!sample ? 'Waiting for sample' : stale ? 'Stale / unavailable' : 'Live'));
    const remove = this.button('Remove', () => {
      this.selected.delete(id); this.hosts.delete(id);
      if (this.current === id) this.current = this.selectedHosts[0] ?? 0;
      this.render();
    }, 'btn tiny');
    remove.setAttribute('aria-label', this.t('Stop monitoring this server'));
    header.append(identity, badge, remove);
    if (this.overview) {
      title.tabIndex = 0; title.setAttribute('role', 'button');
      const detail = () => { this.current = id; this.overview = false; this.render(); };
      title.addEventListener('click', detail);
      title.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); detail(); } });
    }
    card.append(header);
    if (sample?.error) card.append(this.element('p', 'monitor-error', sample.error));
    if (!snapshot) {
      card.append(this.element('p', 'hint', this.t(sample?.status === 'disconnected'
        ? 'Reconnect this server in its session tab, then refresh the monitor.'
        : 'CPU usage needs two samples. Waiting for telemetry…')));
      return card;
    }
    if (stale && state) card.append(this.element('p', 'monitor-stale-time', this.t('Last successful sample: {time}', { time: new Date(state.receivedAt).toLocaleTimeString() })));
    card.append(this.metric('CPU', snapshot.cpu.percent, snapshot.cpu.model || this.t('{count} logical CPUs', { count: snapshot.cpu.logical_count })));
    if (!this.overview && state?.history.length) card.append(this.sparkline(state.history));
    card.append(this.metric('RAM', snapshot.memory?.percent ?? null, snapshot.memory
      ? `${formatBytes(snapshot.memory.used_bytes)} / ${formatBytes(snapshot.memory.total_bytes)}` : this.t('Unavailable')));
    const diskPercent = snapshot.disks.length ? Math.max(...snapshot.disks.map(disk => disk.percent)) : null;
    card.append(this.metric('Disk', diskPercent, snapshot.disks.length ? this.t('Fullest of {count} mounts', { count: snapshot.disks.length }) : this.t('Unavailable')));
    const gpus = snapshot.gpus;
    const usages = gpus.map(gpu => gpu.percent).filter((n): n is number => n !== null);
    const gpuPercent = usages.length ? usages.reduce((sum, n) => sum + n, 0) / usages.length : null;
    card.append(this.metric('GPU', gpuPercent, gpus.length ? this.t('{count} GPUs · mean reported usage', { count: gpus.length }) : this.t('No GPU telemetry')));
    const power = gpus.map(gpu => gpu.power_watts).filter((n): n is number => n !== null);
    if (power.length) card.append(this.element('p', 'monitor-power', this.t('GPU power: {watts} W reported', { watts: power.reduce((sum, n) => sum + n, 0).toFixed(1) })));
    if (!this.overview) this.renderDetail(card, snapshot);
    else if (snapshot.warnings.length) card.append(this.element('p', 'hint monitor-warning', snapshot.warnings.map(warning => this.t(warning)).join(' ')));
    if (sample) card.append(this.element('footer', 'monitor-card-footer hint', `${sample.latency_ms} ms · ${new Date(sample.sampled_at).toLocaleTimeString()}`));
    return card;
  }

  private metric(label: string, value: number | null, description: string, fill = value): HTMLElement {
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
    wrapper.append(heading, track, this.element('small', 'hint', description));
    return wrapper;
  }

  private sparkline(history: number[]): SVGSVGElement {
    const svg = this.doc.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 400 48'); svg.setAttribute('class', 'monitor-sparkline');
    svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', this.t('Recent CPU usage'));
    const points = history.map((value, index) => `${index / Math.max(1, history.length - 1) * 400},${47 - value / 100 * 46}`).join(' ');
    const line = this.doc.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    line.setAttribute('points', points); line.setAttribute('fill', 'none'); line.setAttribute('stroke', 'currentColor'); line.setAttribute('stroke-width', '2');
    svg.append(line); return svg;
  }

  private renderDetail(card: HTMLElement, snapshot: MonitorSnapshot): void {
    if (snapshot.uptime_seconds !== null) card.append(this.element('p', 'hint', this.t('Uptime: {seconds} s · Load: {load}', {
      seconds: Math.floor(snapshot.uptime_seconds), load: snapshot.load_average.map(n => n.toFixed(2)).join(', ') || this.t('N/A'),
    })));
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
    const disks = this.element('section', 'monitor-section');
    disks.append(this.element('h4', '', this.t('Mounted filesystems')));
    for (const disk of snapshot.disks) disks.append(this.metric(disk.mount, disk.percent,
      `${disk.device} · ${formatBytes(disk.used_bytes)} / ${formatBytes(disk.total_bytes)} · ${formatBytes(disk.available_bytes)} ${this.t('available')}`));
    if (!snapshot.disks.length) disks.append(this.element('p', 'hint', this.t('Disk telemetry is unavailable.')));
    card.append(disks);
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

  private async openShell(): Promise<void> {
    if (!this.selected.size || this.picking) return;
    if (!this.selected.has(this.current)) this.current = this.selectedHosts[0]!;
    const id = this.current;
    this.pause();
    try { await this.options.openTerminal(id); }
    catch (error) { this.options.onError?.(String((error as Error)?.message ?? error)); this.resume(); }
  }
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return 'N/A';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let value = bytes; let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}
