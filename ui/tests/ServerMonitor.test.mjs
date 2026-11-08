import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { ServerMonitor, thermalFill, pcieQuality, memoryPercent } from '../dist/linscp-core.mjs';

const dom = new JSDOM('<!doctype html><main id="monitor"></main>');
const doc = dom.window.document;
const snapshot = {
  hostname: 'worker', primary_ip: '10.0.0.2', uptime_seconds: 123, load_average: [0.1, 0.2, 0.3],
  cpu: { model: '<img src=x onerror=alert(1)>', logical_count: 2, percent: 42,
    cores: [{ socket: 0, core: 0, threads: [{ id: 0, percent: 40 }, { id: 1, percent: 44 }] }] },
  memory: { total_bytes: 1024, used_bytes: 512, available_bytes: 512, percent: 50 },
  disks: [{ device: '/dev/sda1', mount: '/data', total_bytes: 1000, used_bytes: 250, available_bytes: 750, percent: 25 }],
  gpus: [{ index: 0, vendor: 'NVIDIA', name: 'Test GPU', percent: 60, memory_used_bytes: 1024, memory_total_bytes: 4096,
    power_watts: 80, power_limit_watts: 200, temperature_c: 55, temperature_limit_c: 90,
    temperature_sensor: 'Hotspot', driver: '550', pcie_generation: 4, pcie_width: 16 }],
  cuda_version: '12.4', warnings: [],
};
const sample = (tab, status = 'ok', error = '') => ({
  tab, name: `server-${tab}`, host: '10.0.0.2', port: 22, protocol: 'sftp', status,
  sampled_at: Date.now(), latency_ms: 12, error, snapshot: status === 'ok' ? structuredClone(snapshot) : null,
});
function setup(overrides = {}) {
  const root = doc.createElement('div'); doc.body.append(root);
  const calls = []; const errors = []; const terminals = []; let closed = 0; let connected = 0;
  const transport = {
    async get(path) { calls.push(['GET', path]); return { success: true, max_hosts: 32, default_interval: 5, default_timeout: 10,
      tabs: [{ tab: 1, name: 'server-1', host: '10.0.0.2', port: 22, protocol: 'sftp', site: null },
        { tab: 2, name: 'server-2', host: '10.0.0.3', port: 22, protocol: 'ssh', site: 'saved' }],
      sites: [{ name: 'saved', host: '10.0.0.3', port: 22, protocol: 'ssh' }] }; },
    async post(path, body) { calls.push(['POST', path, body]); return { success: true, samples: body.tabs.map(id => sample(id)) }; },
    ...overrides.transport,
  };
  const monitor = new ServerMonitor({ root, transport,
    connectSite: async () => { connected++; return 2; },
    openTerminal: id => { terminals.push(id); },
    onClose: () => { closed++; }, onError: message => errors.push(message), ...overrides.options });
  return { monitor, root, calls, errors, terminals, closed: () => closed, connected: () => connected };
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const button = (root, text) => [...root.querySelectorAll('button')].find(node => node.textContent === text);

test('monitor visual scales are explicit about unknown sensors and link maxima', () => {
  assert.equal(thermalFill(null, 90), null);
  assert.equal(thermalFill(67.5, 90), 20);
  assert.equal(thermalFill(90, 90), 100);
  assert.ok(Math.abs(thermalFill(50, null) - 13.3333333333) < 1e-8);
  assert.equal(pcieQuality(4, 16), 88);
  assert.equal(pcieQuality(null, 16), null);
  assert.equal(memoryPercent(1, 0), null);
  assert.equal(memoryPercent(1, 4), 25);
});

test('selection opens normal tabs, polls once at a time, and keeps remote names as text', async () => {
  const s = setup();
  await s.monitor.open();
  assert.equal(s.root.querySelectorAll('.monitor-picker-item').length, 3);
  s.root.querySelector('input[type=checkbox]').click();
  button(s.root, 'Monitor selected servers').click();
  await flush(); await flush();
  assert.deepEqual(s.monitor.selectedHosts, [1]);
  assert.ok(s.calls.some(call => call[1] === '/api/monitor/sample' && call[2].tabs.join() === '1'));
  assert.equal(s.root.querySelectorAll('img').length, 0);
  assert.ok(s.root.textContent.includes('<img src=x onerror=alert(1)>'));
  const meters = [...s.root.querySelectorAll('[role=meter]')];
  assert.ok(meters.some(meter => meter.getAttribute('aria-valuenow') === '42'));
  s.monitor.dispose();
});

test('saved sites use the injected host-key-aware connection callback', async () => {
  const s = setup(); await s.monitor.open();
  s.root.querySelectorAll('.monitor-picker-item input')[2].click();
  button(s.root, 'Monitor selected servers').click();
  await flush(); await flush();
  assert.equal(s.connected(), 1);
  assert.deepEqual(s.monitor.selectedHosts, [2]);
  s.monitor.dispose();
});

test('a failed host keeps its last good values visibly stale without hiding healthy hosts', async () => {
  let fail = false;
  const s = setup({ transport: { async post(_path, body) {
    return { success: true, samples: body.tabs.map(id => fail && id === 1 ? sample(id, 'error', 'SSH channel closed') : sample(id)) };
  } } });
  await s.monitor.open();
  s.root.querySelectorAll('.monitor-picker-item input')[0].click();
  s.root.querySelectorAll('.monitor-picker-item input')[1].click();
  button(s.root, 'Monitor selected servers').click(); await flush(); await flush();
  fail = true; await s.monitor.refresh();
  const cards = [...s.root.querySelectorAll('.monitor-card')];
  assert.equal(cards.length, 2);
  assert.ok(cards[0].classList.contains('monitor-stale'));
  assert.ok(cards[0].textContent.includes('Last successful sample'));
  assert.ok(cards[0].textContent.includes('42.0%'));
  assert.ok(!cards[1].classList.contains('monitor-stale'));
  s.monitor.dispose();
});

test('pause/resume during an in-flight request cannot strand or overlap polling', async () => {
  let release; let posts = 0;
  const s = setup({ transport: { async post() { posts++; await new Promise(resolve => { release = resolve; }); return { success: true, samples: [sample(1)] }; } } });
  await s.monitor.open(); s.root.querySelector('.monitor-picker-item input').click();
  button(s.root, 'Monitor selected servers').click(); await flush(); await flush();
  assert.equal(posts, 1);
  const pending = s.monitor.refresh();
  s.monitor.pause(); s.monitor.resume();
  release(); await pending; await new Promise(resolve => setTimeout(resolve, 10)); await flush();
  assert.ok(posts >= 2);
  assert.equal(s.monitor.isPaused, false);
  s.monitor.pause(); const count = posts; await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(posts, count);
  s.monitor.dispose();
});

test('detail, compact GPUs, keyboard navigation and terminal pause/resume share one selection', async () => {
  const s = setup(); await s.monitor.open();
  s.root.querySelectorAll('.monitor-picker-item input')[0].click();
  s.root.querySelectorAll('.monitor-picker-item input')[1].click();
  button(s.root, 'Monitor selected servers').click(); await flush(); await flush();
  const key = k => s.monitor.handleKey(new dom.window.KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }));
  assert.equal(key('n'), true); assert.equal(s.monitor.currentHost, 2);
  assert.equal(s.root.querySelectorAll('.monitor-card').length, 1);
  assert.ok(s.root.textContent.includes('CPU cores'));
  key('m'); assert.ok(s.root.querySelector('.monitor-gpu-compact'));
  key('s'); assert.deepEqual(s.terminals, [2]); assert.equal(s.monitor.isPaused, true);
  s.monitor.resume(); assert.equal(s.monitor.isPaused, false);
  key('t'); assert.equal(s.root.querySelectorAll('.monitor-card').length, 2);
  key('q'); assert.equal(s.monitor.isOpen, false); assert.equal(s.closed(), 1);
  assert.deepEqual(s.monitor.selectedHosts, [1, 2]);
  s.monitor.dispose();
});

test('closing stops future polling but preserves selection for reopening', async () => {
  const s = setup(); await s.monitor.open(); s.root.querySelector('.monitor-picker-item input').click();
  button(s.root, 'Monitor selected servers').click(); await flush(); await flush();
  s.monitor.close(); const before = s.calls.filter(call => call[1] === '/api/monitor/sample').length;
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(s.calls.filter(call => call[1] === '/api/monitor/sample').length, before);
  await s.monitor.open(); await flush();
  assert.deepEqual(s.monitor.selectedHosts, [1]);
  s.monitor.dispose();
});

test('network formatters and outage duration are explicit', async () => {
  const { formatBitsPerSec, formatDuration } = await import('../dist/linscp-core.mjs');
  assert.equal(formatBitsPerSec(null), 'N/A');
  assert.equal(formatBitsPerSec(125), '1.0 Kbps');
  assert.equal(formatBitsPerSec(125000), '1.00 Mbps');
  assert.equal(formatDuration(61000), '1m 1s');
});

test('persisted settings, outage notices, beeps and recovery use the shared component', async () => {
  const notices = []; let beeps = 0; let phase = 0; let postedSettings = null;
  const document = { version: 1, settings: { interval_secs: 5, connect_timeout_secs: 10, poll_timeout_secs: 10,
    outage_threshold: 1, notify_on_outage: true, beep_on_outage: true, beep_cooldown_secs: 0 }, hosts: {} };
  const s = setup({
    transport: {
      async get(path) {
        if (path === '/api/monitor/settings') return { success: true, document };
        return { success: true, max_hosts: 32, tabs: [{ tab: 1, name: 'server-1', host: '10.0.0.2', port: 22, protocol: 'ssh', site: null, key: 'ssh:10.0.0.2:22' }], sites: [] };
      },
      async post(path, body) {
        if (path === '/api/monitor/settings') { postedSettings = body; return { success: true, document: body }; }
        const base = sample(1, phase === 0 ? 'error' : 'ok', phase === 0 ? 'SSH channel closed' : '');
        return { success: true, samples: [{ ...base, key: 'ssh:10.0.0.2:22',
          outage: phase === 0, outage_started: phase === 0, recovered: phase === 1,
          outage_since_ms: phase === 0 ? Date.now() - 61000 : null, consecutive_failures: phase === 0 ? 1 : 0 }] };
      },
    },
    options: { onNotice: (message, tone) => notices.push([message, tone]), playAlert: () => { beeps++; } },
  });
  await s.monitor.open();
  s.root.querySelector('.monitor-picker-item input').click();
  button(s.root, 'Monitor selected servers').click();
  await flush(); await flush();
  assert.ok(s.root.querySelector('.monitor-outage'));
  assert.ok(s.root.textContent.includes('Offline for'));
  assert.equal(beeps, 1);
  assert.ok(notices.some(([message, tone]) => tone === 'warn' && message.includes('offline')));
  phase = 1;
  await s.monitor.refresh();
  assert.ok(notices.some(([message, tone]) => tone === 'success' && message.includes('recovered')));
  assert.ok(!s.root.querySelector('.monitor-outage'));
  button(s.root, 'Monitor settings').click();
  const threshold = [...s.root.querySelectorAll('.monitor-settings-panel input[type=number]')]
    .find(input => input.closest('label').textContent.includes('Outage threshold'));
  threshold.value = '4';
  button(s.root, 'Save monitor settings').click();
  await flush();
  assert.equal(postedSettings?.settings.outage_threshold, 4);
  s.monitor.dispose();
});

test('per-server pause and metric/custom configuration are persisted and applied', async () => {
  let saved = null; const sampleBodies = [];
  const hosts = { success: true, max_hosts: 32,
    tabs: [{ tab: 1, name: 'server-1', host: '10.0.0.2', port: 22, protocol: 'ssh', site: null, key: 'ssh:10.0.0.2:22' },
      { tab: 2, name: 'server-2', host: '10.0.0.3', port: 22, protocol: 'ssh', site: null, key: 'ssh:10.0.0.3:22' }], sites: [] };
  const s = setup({ transport: {
    async get(path) { return path === '/api/monitor/settings' ? { success: true, document: saved ?? { version: 1, settings: { interval_secs: 5, connect_timeout_secs: 10, poll_timeout_secs: 10, outage_threshold: 3, notify_on_outage: true, beep_on_outage: false, beep_cooldown_secs: 10 }, hosts: {} } } : hosts; },
    async post(path, body) {
      if (path === '/api/monitor/settings') { saved = body; return { success: true, document: body }; }
      sampleBodies.push(body);
      return { success: true, samples: body.tabs.map(id => {
        const base = sample(id);
        base.snapshot.swap = { total_bytes: 1000, used_bytes: 250, free_bytes: 750, percent: 25 };
        base.snapshot.network = { rx_bytes_total: 1000, tx_bytes_total: 2000, rx_bytes_per_sec: 125000, tx_bytes_per_sec: 250000 };
        base.snapshot.custom = [{ id: 'users', name: 'Users', parse: 'number', display: 'sparkline', unit: '', value: 3, text: '', error: '' }];
        return { ...base, key: `ssh:10.0.0.${id + 1}:22` };
      }) };
    },
  } });
  await s.monitor.open();
  s.root.querySelectorAll('.monitor-picker-item input')[0].click();
  s.root.querySelectorAll('.monitor-picker-item input')[1].click();
  button(s.root, 'Monitor selected servers').click(); await flush(); await flush();
  assert.ok(s.root.textContent.includes('25.0%'));
  assert.ok(s.root.textContent.includes('1.00 Mbps'));
  assert.ok(s.root.textContent.includes('Users'));
  const firstPause = s.root.querySelector('.monitor-card [aria-label="Pause monitoring this server"]');
  firstPause.click(); await flush();
  assert.equal(saved.hosts['ssh:10.0.0.2:22'].paused, true);
  await s.monitor.refresh();
  assert.deepEqual(sampleBodies.at(-1).tabs, [2]);
  const cards = [...s.root.querySelectorAll('.monitor-card')];
  [...cards[1].querySelectorAll('button')].find(node => node.textContent === 'Configure').click();
  button(s.root, 'Add custom metric').click();
  s.root.querySelector('[aria-label="Custom metric name"]').value = 'Load file';
  s.root.querySelector('[aria-label="Custom metric name"]').dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  s.root.querySelector('[aria-label="Custom metric command"]').value = 'cat /proc/loadavg';
  s.root.querySelector('[aria-label="Custom metric command"]').dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  button(s.root, 'Apply server metrics').click(); await flush();
  assert.ok(s.errors.some(message => message.includes('Approve the custom commands')));
  const approval = [...s.root.querySelectorAll('.monitor-config-panel input[type=checkbox]')]
    .find(input => input.closest('label').textContent.includes('I approve'));
  approval.click();
  button(s.root, 'Apply server metrics').click(); await flush();
  const configured = saved.hosts['ssh:10.0.0.3:22'] ?? saved.hosts['tab:2'];
  assert.ok(configured.custom_metrics.some(metric => metric.name === 'Load file' && metric.command === 'cat /proc/loadavg'));
  s.monitor.dispose();
});
