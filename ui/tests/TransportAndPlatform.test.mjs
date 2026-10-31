import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

import {
  EXTRA_KEYS,
  HttpTransport,
  I18nCatalog,
  LocalRootSwitcher,
  MobileShellController,
  TauriTransport,
  TransportError,
  applyCtrlModifier,
  createTransport,
  detectTransportMode,
  normalizeLocale,
} from '../dist/linscp-core.mjs';

const testsDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testsDir, '..', '..');

function loadUnifiedGuiBundles() {
  const bundles = {};
  for (const code of ['de', 'en', 'es', 'fr']) {
    const raw = fs.readFileSync(path.join(repoRoot, 'locales', `${code}.json`), 'utf8');
    bundles[code] = JSON.parse(raw).gui;
  }
  return bundles;
}

test('detectTransportMode and createTransport select Tauri vs HTTP automatically', async () => {
  assert.equal(detectTransportMode({}), 'http');
  assert.equal(
    detectTransportMode({ __TAURI_INTERNALS__: { invoke: async () => ({}) } }),
    'tauri',
  );

  const calls = [];
  const tauriClient = createTransport({
    host: {
      __TAURI_INTERNALS__: {
        invoke: async (cmd, args) => {
          calls.push({ cmd, args });
          return {
            status: 200,
            payload: { connected: false, local_roots: [{ path: 'C:\\', label: 'C:\\', kind: 'drive', read_only: false }] },
          };
        },
      },
    },
  });
  assert.equal(tauriClient.mode, 'tauri');
  assert.ok(tauriClient instanceof TauriTransport);

  const status = await tauriClient.get('/api/status');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, 'linscp_invoke');
  assert.deepEqual(calls[0].args.envelope, {
    method: 'GET',
    path: '/api/status',
    body: {},
  });
  assert.equal(status.local_roots[0].path, 'C:\\');
});

test('TauriTransport retains structured failures for connection and overwrite dialogs', async () => {
  const challenge = { tab: 7, role: 'destination', fingerprint: 'ssh-ed25519 SHA256:test' };
  const client = new TauriTransport({
    invoke: async (_cmd, { envelope }) => envelope.path === '/api/tabs/open'
      ? { status: 409, payload: { success: false, error: 'Verify host key', challenge } }
      : { status: 409, payload: { success: false, error: 'Already exists', conflicts: ['file.txt'] } },
  });
  await assert.rejects(() => client.post('/api/tabs/open', {}), (error) => {
    assert.deepEqual(error.payload.challenge, challenge);
    return true;
  });
  await assert.rejects(() => client.post('/api/transfer/upload', {}), (error) => {
    assert.deepEqual(error.payload.conflicts, ['file.txt']);
    return true;
  });
});

test('HttpTransport attaches X-LSCP-Token and X-LSCP-CSRF and surfaces login_required', async () => {
  const seen = [];
  let authPrompted = 0;

  const client = new HttpTransport({
    baseUrl: 'http://127.0.0.1:8765',
    bearerToken: 'tok-secret-123',
    onAuthRequired: () => {
      authPrompted += 1;
    },
    fetchImpl: async (url, init) => {
      seen.push({ url, init });
      if (String(url).endsWith('/api/protected')) {
        return {
          ok: false,
          status: 401,
          json: async () => ({ login_required: true, error: 'Session expired' }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ saved: true }),
      };
    },
  });

  client.setCsrfToken('csrf-abc');
  const res = await client.post('/api/preferences', { resume: true });
  assert.deepEqual(res, { saved: true });
  assert.equal(seen[0].init.headers['X-LSCP-Token'], 'tok-secret-123');
  assert.equal(seen[0].init.headers['X-LSCP-CSRF'], 'csrf-abc');

  await assert.rejects(
    () => client.get('/api/protected'),
    (err) => {
      assert.ok(err instanceof TransportError);
      assert.equal(err.status, 401);
      assert.equal(err.loginRequired, true);
      return true;
    },
  );
  assert.equal(authPrompted, 1);
});

test('I18nCatalog consumes unified locales/*.json with CLDR plurals and single-pass safety', () => {
  const catalog = new I18nCatalog(loadUnifiedGuiBundles());
  assert.equal(normalizeLocale('fr-CA.UTF-8'), 'fr');

  catalog.setLocale('fr-CA');
  assert.equal(catalog.tn('{count} match', '{count} matches', 0), '0 résultat');

  catalog.setLocale('es-MX');
  assert.equal(catalog.tn('{count} match', '{count} matches', 0), '0 coincidencias');
  assert.equal(
    catalog.t('Line {line}: {snippet}', { line: 4, snippet: '{line} $&' }),
    'Línea 4: {line} $&',
  );
});

test('LocalRootSwitcher renders Windows drives and Android SAF folder picker without raw fetch', async () => {
  const dom = new JSDOM('<!doctype html><select id="roots"></select>');
  const selectEl = dom.window.document.getElementById('roots');

  let roots = [
    { path: 'C:\\', label: 'C:\\', kind: 'drive', read_only: false },
    { path: 'D:\\', label: 'D:\\', kind: 'drive', read_only: false },
  ];
  const navigated = [];

  const mockTransport = new TauriTransport({
    invoke: async (_cmd, { envelope }) => {
      if (envelope.path === '/api/local/roots') {
        return { status: 200, payload: { roots } };
      }
      if (envelope.path.startsWith('/api/local/list?path=')) {
        const decoded = decodeURIComponent(envelope.path.split('=')[1]);
        return {
          status: 200,
          payload: { path: decoded, entries: [{ name: 'Projects', size: 0, is_dir: true }] },
        };
      }
      return { status: 404, payload: { error: 'not found' } };
    },
  });

  const switcher = new LocalRootSwitcher({
    transport: mockTransport,
    selectElement: selectEl,
    onNavigate: (listing) => navigated.push(listing),
    onRequestAndroidSafTree: async () => {
      const safRoot = {
        path: 'content://com.android.externalstorage.documents/tree/primary%3ADownload',
        label: 'Downloads (SAF)',
        kind: 'saf_tree',
        read_only: false,
      };
      roots = [...roots, safRoot];
      return safRoot;
    },
  });

  await switcher.refreshRoots('D:\\work');
  assert.equal(selectEl.hidden, false);
  assert.equal(selectEl.options.length, 3); // C:\, D:\, + Grant Folder Access...
  assert.equal(selectEl.value, 'D:\\');

  // Switch to C:\
  selectEl.value = 'C:\\';
  selectEl.dispatchEvent(new dom.window.Event('change'));
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(navigated.length, 1);
  assert.equal(navigated[0].path, 'C:\\');

  // Trigger Android SAF tree grant option
  selectEl.value = '__linscp_add_saf_tree__';
  selectEl.dispatchEvent(new dom.window.Event('change'));
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(navigated.length, 2);
  assert.ok(navigated[1].path.startsWith('content://'));
});

test('MobileShellController handles touch pane switching and terminal extra-key sequences', () => {
  const dom = new JSDOM('<!doctype html><div id="app"></div>');
  const root = dom.window.document.getElementById('app');
  const emitted = [];

  const mobile = new MobileShellController({
    rootElement: root,
    onTerminalInput: (seq) => emitted.push(seq),
  });

  assert.equal(EXTRA_KEYS.length, 12);
  assert.equal(mobile.pane, 'local');
  mobile.setActivePane('terminal');
  assert.equal(root.dataset.mobilePane, 'terminal');

  mobile.pressExtraKey('esc');
  mobile.pressExtraKey('up');
  assert.deepEqual(emitted, ['\x1b', '\x1b[A']);

  // Sticky Ctrl latch + 'c' => SIGINT (\x03) and auto-unlatches
  assert.equal(mobile.pressExtraKey('ctrl'), null);
  assert.equal(mobile.isCtrlLatched, true);
  assert.equal(mobile.transformTextInput('c'), '\x03');
  assert.equal(mobile.isCtrlLatched, false);
  assert.equal(applyCtrlModifier('d'), '\x04');
});

test('Built ui/dist/index.html boots inside Tauri IPC mode with zero HTTP calls', async () => {
  const distHtml = fs.readFileSync(path.join(repoRoot, 'ui', 'dist', 'index.html'), 'utf8');
  const ipcCalls = [];

  const dom = new JSDOM(distHtml, {
    url: 'http://ipc.localhost/',
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    beforeParse(window) {
      window.fetch = async () => {
        throw new Error('fetch() must never be called when Tauri IPC is active');
      };
      window.__TAURI_INTERNALS__ = {
        invoke: async (cmd, args) => {
          ipcCalls.push({ cmd, path: args.envelope.path });
          const p = args.envelope.path;
          if (p === '/api/test-challenge') {
            return { status: 409, payload: { success: false, error: 'Verify host key', challenge: { tab: 7, fingerprint: 'SHA256:test' } } };
          }
          if (p === '/api/test-conflict') {
            return { status: 409, payload: { success: true, conflicts: ['file.txt'] } };
          }
          if (p === '/api/status') {
            return {
              status: 200,
              payload: { connected: false, active_tab: null, tabs: [], local_dir: 'C:\\Users\\Alice' },
            };
          }
          if (p.startsWith('/api/local/list')) {
            return {
              status: 200,
              payload: { path: 'C:\\Users\\Alice', entries: [{ name: 'Documents', size: 0, is_dir: true, permissions: 'drwx------', date: '' }] },
            };
          }
          if (p === '/api/preferences') {
            return { status: 200, payload: { confirm_overwrite: true, confirm_delete: true } };
          }
          if (p === '/api/sessions') {
            return { status: 200, payload: { sessions: [] } };
          }
          if (p === '/api/bookmarks') {
            return { status: 200, payload: { bookmarks: {} } };
          }
          if (p === '/api/workspaces') {
            return { status: 200, payload: { workspaces: {} } };
          }
          if (p === '/api/transfers') {
            return { status: 200, payload: { transfers: [] } };
          }
          return { status: 200, payload: {} };
        },
      };
    },
  });

  await new Promise((r) => setTimeout(r, 80));
  assert.equal(dom.window.LinSCPTransport.mode, 'tauri');
  assert.ok(ipcCalls.some((c) => c.cmd === 'linscp_invoke' && c.path === '/api/status'));
  const challenge = await dom.window.api('/api/test-challenge', { method: 'POST', body: '{}' });
  assert.equal(challenge.success, false);
  assert.equal(challenge.challenge.fingerprint, 'SHA256:test');
  const conflict = await dom.window.api('/api/test-conflict', { method: 'POST', body: '{}' });
  assert.equal(conflict.success, false); // HTTP failure cannot claim success.
  assert.equal(conflict.conflicts[0], 'file.txt');
  dom.window.close();
});

test('overwrite confirmation forwards the original WebDAV conflict ETag', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source', 'gui', 'web', 'index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function queueWithOverwriteDecision\(endpoint, payload, conflicts\) \{[\s\S]*?\n  \}\n\n  async function transfer/);
  assert.ok(match, 'overwrite decision handler exists');
  const handlerSource = match[0].replace(/\n\n  async function transfer$/, '');
  const calls = [];
  const apiPost = async (endpoint, payload) => {
    calls.push({ endpoint, payload });
    return calls.length === 1
      ? { success: false, conflicts: ['file.txt'], conflict_versions: { 'file.txt': '"original"' } }
      : { success: true };
  };
  const handler = new Function('apiPost', 'preferences', 'confirm', 't', `${handlerSource}; return queueWithOverwriteDecision;`)(apiPost, {}, () => true, s => s);
  assert.equal((await handler('/api/transfer/upload', { overwrite: 'ask' }, [])).success, true);
  assert.deepEqual(calls[1].payload, { overwrite: 'overwrite', conflict_versions: { 'file.txt': '"original"' } });
});

test('directory merge requires explicit approval and forwards only approved roots', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source', 'gui', 'web', 'index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function queueWithOverwriteDecision\(endpoint, payload, conflicts\) \{[\s\S]*?\n  \}\n\n  async function transfer/);
  assert.ok(match);
  const source = match[0].replace(/\n\n  async function transfer$/, '');
  const calls = [];
  const apiPost = async (_endpoint, payload) => {
    calls.push(payload);
    return calls.length === 1 ? { success: false, directory_conflicts: ['tree'] } : { success: true };
  };
  let confirmations = 0;
  const handler = new Function('apiPost', 'preferences', 'confirm', 't', `${source}; return queueWithOverwriteDecision;`)(apiPost, { confirm_overwrite: false }, () => { confirmations++; return true; }, s => s);
  assert.equal((await handler('/api/transfer/upload', { names: ['tree', 'other'] }, [])).success, true);
  assert.equal(confirmations, 1);
  assert.deepEqual(calls[1].merge_directories, ['tree']);
});

test('FTP uploads require risk confirmation and separately confirm existing files', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source/gui/web/index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function queueWithOverwriteDecision\(endpoint, payload, conflicts\) \{[\s\S]*?\n  \}\n\n  async function transfer/);
  assert.ok(match);
  const source = match[0].replace(/\n\n  async function transfer$/, '');
  const calls = [];
  let confirmations = 0;
  const apiPost = async (_endpoint, payload) => {
    calls.push({ ...payload });
    if (!payload.accept_ftp_rename_risk) return { success: false, ftp_rename_risk: true };
    if (!payload.overwrite) return { success: false, conflicts: ['file.txt'] };
    return { success: true };
  };
  const handler = new Function('apiPost', 'preferences', 'confirm', 't', `${source}; return queueWithOverwriteDecision;`)(apiPost, { confirm_overwrite: false }, () => { confirmations++; return true; }, s => s);
  assert.equal((await handler('/api/transfer/upload', {}, [])).success, true);
  assert.equal(confirmations, 2);
  assert.equal(calls[1].accept_ftp_rename_risk, true);
  assert.equal(calls[2].overwrite, 'overwrite');
  const reject = new Function('apiPost', 'preferences', 'confirm', 't', `${source}; return queueWithOverwriteDecision;`)(apiPost, {}, () => false, s => s);
  const before = calls.length;
  await reject('/api/transfer/upload', {}, []);
  assert.equal(calls.length, before + 1);
});

test('same-session WebDAV move uses explicit move operation', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source/gui/web/index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function runRemoteTransfer\(moveItem\) \{[\s\S]*?\n  \}\n\n  \/\*/);
  assert.ok(match);
  const source = match[0].replace(/\n\n  \/\*$/, '');
  const values = { remoteTransferDirectory: { value: '/archive' }, remoteTransferTarget: { value: 'tab:8' }, remoteTransferMask: { value: '' }, remoteTransferStatus: { textContent: '' } };
  let call;
  const run = new Function('$', 'remoteTransferState', 'apiPost', 't', 'errorMessage', 'closeModal', 'toast', 'switchTab', 'refreshQueue', `${source}; return runRemoteTransfer;`)(
    id => values[id], { tab: 8, names: ['data'] }, async (path, payload) => { call = { path, payload }; return { success: true }; },
    s => s, s => s, () => {}, () => {}, () => {}, () => {});
  await run(true);
  assert.equal(call.path, '/api/remote/transfer');
  assert.deepEqual(call.payload, { tab: 8, names: ['data'], target: 'tab:8', directory: '/archive', filemask: '', operation: 'move' });
});

test('remote moves require separate confirmation for non-transactional and directory risks', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source/gui/web/index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function runRemoteTransfer\(moveItem\) \{[\s\S]*?\n  \}\n\n  \/\*/);
  assert.ok(match);
  const source = match[0].replace(/\n\n  \/\*$/, '');
  const values = { remoteTransferDirectory: { value: '/archive' }, remoteTransferTarget: { value: 'tab:9' }, remoteTransferMask: { value: '' }, remoteTransferStatus: { textContent: '' } };
  const calls = []; let confirmations = 0;
  const post = async (_path, payload) => {
    calls.push({ ...payload });
    if (!payload.accept_cross_move_risk) return { success: false, cross_move_risk: true };
    if (!payload.accept_directory_move_risk) return { success: false, directory_move_risk: true };
    return { success: true };
  };
  const run = new Function('$', 'remoteTransferState', 'apiPost', 't', 'errorMessage', 'closeModal', 'toast', 'switchTab', 'refreshQueue', 'confirm', `${source}; return runRemoteTransfer;`)(
    id => values[id], { tab: 8, names: ['data'] }, post, s => s, s => s, () => {}, () => {}, () => {}, () => {}, () => { confirmations++; return true; });
  await run(true);
  assert.equal(confirmations, 2);
  assert.equal(calls[1].accept_cross_move_risk, true);
  assert.equal(calls[2].accept_directory_move_risk, true);
  assert.equal(calls[2].accept_cross_move_risk, true);
});
