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
