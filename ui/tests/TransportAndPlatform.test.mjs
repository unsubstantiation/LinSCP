import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

import {
  EXTRA_KEYS,
  HttpTransport,
  SHARED_FEATURES,
  ForegroundTransferBridge,
  hostCapabilities,
  hostDifferenceReason,
  I18nCatalog,
  LocalRootSwitcher,
  MobileShellController,
  TauriTransport,
  TransportError,
  applyCtrlModifier,
  androidDesktopViewerUri,
  createTransport,
  detectTransportMode,
  dropPaths,
  dropRequest,
  droppedLeafName,
  normalizeDropPayload,
  normalizeLocale,
  openExternalUri,
  requestSafTree,
  safLimitationReason,
  sharedFeatureSet,
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

test('Built ui/dist/index.html mounts the local root switcher in the browser app too', async () => {
  const distHtml = fs.readFileSync(path.join(repoRoot, 'ui', 'dist', 'index.html'), 'utf8');
  const requested = [];

  const dom = new JSDOM(distHtml, {
    url: 'http://127.0.0.1:8080/',
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    beforeParse(window) {
      window.fetch = async (url) => {
        const target = String(url);
        requested.push(target);
        let payload = { success: true };
        if (target.includes('/api/vault/status')) {
          payload = { success: true, vault: 'unlocked' };
        } else if (target.includes('/api/status')) {
          payload = { connected: false, active_tab: null, tabs: [], local_dir: '/home/alice' };
        } else if (target.includes('/api/local/roots')) {
          payload = {
            success: true,
            roots: [
              { path: '/', label: '/', kind: 'posix', read_only: false },
              { path: '/home/alice', label: 'Home', kind: 'posix', read_only: false },
            ],
          };
        } else if (target.includes('/api/local/list')) {
          payload = { success: true, path: '/home/alice', entries: [] };
        } else if (target.includes('/api/accounts')) {
          payload = { enabled: false };
        }
        return {
          ok: true,
          status: 200,
          json: async () => payload,
          text: async () => JSON.stringify(payload),
        };
      };
    },
  });

  await new Promise((resolve) => setTimeout(resolve, 400));
  const select = dom.window.document.getElementById('localRootSelect');
  assert.ok(select, 'the local pane header owns the root selector');
  assert.ok(requested.some((url) => url.includes('/api/local/roots')));
  assert.deepEqual(
    [...select.options].map((option) => option.textContent),
    ['/', 'Home'],
  );
  // More than one root means the control is visible; one root hides it again.
  assert.equal(select.hidden, false);
  dom.window.close();
});

test('all native targets expose the shared feature contract and report only installed host integrations', () => {
  const debian = hostCapabilities({ transport: 'tauri', platform: 'linux' });
  const windows = hostCapabilities({ transport: 'tauri', platform: 'windows' });
  const android = hostCapabilities({ transport: 'tauri', platform: 'android' });
  const browser = hostCapabilities({ transport: 'http', platform: 'browser' });

  // The shared service/frontend contract is identical across Debian, Windows,
  // and Android. Host integrations are checked separately and never inferred
  // from an OS name if no implementation was registered.
  assert.deepEqual(sharedFeatureSet(), [...SHARED_FEATURES]);
  assert.equal(sharedFeatureSet().length, 14);

  for (const caps of [debian, windows, android, browser]) {
    for (const feature of ['localRoots', 'fileDrop', 'terminal']) {
      assert.equal(caps[feature], true, `${feature} must exist on ${caps.platform}`);
    }
  }

  assert.equal(debian.desktopLaunchers, true);
  assert.equal(windows.desktopLaunchers, true);
  assert.equal(android.desktopLaunchers, true);
  assert.equal(browser.desktopLaunchers, false);
  assert.equal(debian.nativeFileDrop, true);
  assert.equal(windows.nativeFileDrop, true);
  assert.equal(android.nativeFileDrop, false);
  assert.equal(browser.nativeFileDrop, false);
  assert.equal(browser.nativeIpc, false);

  // The native Android shell registers these implementations. OS detection
  // alone is insufficient: an Android browser remains an HTTP host below.
  for (const bridge of ['safTrees', 'shareIntents', 'foregroundTransfers', 'desktopLaunchers']) {
    assert.equal(android[bridge], true, `${bridge} is registered by the Android host`);
  }
  assert.equal(android.backgroundTransfers, true);
  const missingAndroidBridge = hostCapabilities({ transport: 'tauri', platform: 'android', safTrees: false, shareIntents: false });
  assert.match(hostDifferenceReason('safTrees', missingAndroidBridge) ?? '', /not available/);
  assert.match(hostDifferenceReason('shareIntents', missingAndroidBridge) ?? '', /not integrated/);

  // SSH agent lookup is the inverse: every build assumes an agent except the
  // Android backend, which has none, and the gap always has a stated reason.
  assert.equal(debian.sshAgent, true);
  assert.equal(windows.sshAgent, true);
  assert.equal(browser.sshAgent, true);
  assert.equal(android.sshAgent, false);
  assert.equal(hostDifferenceReason('sshAgent', debian), null);
  assert.match(hostDifferenceReason('sshAgent', android) ?? '', /private key file/);

  // Kerberos is a Linux-backend ability: native non-Linux builds lack it, a
  // browser fails open because the page cannot see the server OS, and key
  // exchange is unwired everywhere so it is off on all four hosts.
  assert.equal(debian.gssapi, true);
  assert.equal(windows.gssapi, false);
  assert.equal(android.gssapi, false);
  assert.equal(browser.gssapi, true);
  assert.equal(hostDifferenceReason('gssapi', debian), null);
  assert.match(hostDifferenceReason('gssapi', windows) ?? '', /only available on Linux/);
  for (const caps of [debian, windows, android, browser]) {
    assert.equal(caps.gssapiKex, false, `key exchange is unwired on ${caps.platform}`);
  }
  assert.match(hostDifferenceReason('gssapiKex', debian) ?? '', /not supported/);

  // A missing control always has a stated reason; silent capability gaps are
  // the parity bug this inventory exists to catch.
  assert.equal(hostDifferenceReason('desktopLaunchers', android), null);
  assert.match(hostDifferenceReason('desktopLaunchers', browser) ?? '', /launcher integration/);
  assert.match(hostDifferenceReason('accounts', debian) ?? '', /sign-in/);
  assert.equal(hostDifferenceReason('terminal', android), null);

  // The description is derived from the window the page runs in, so the page
  // can ask it instead of probing the native bridge at each call site.
  const fakeBrowser = { navigator: { userAgent: 'Mozilla/5.0 (X11; Linux x86_64)' } };
  assert.deepEqual(
    [hostCapabilities({ host: fakeBrowser }).transport, hostCapabilities({ host: fakeBrowser }).platform],
    ['http', 'linux'],
  );
  const fakeAndroid = {
    navigator: { userAgent: 'Mozilla/5.0 (Linux; Android 14)' },
    __TAURI_INTERNALS__: { invoke: async () => ({}) },
  };
  const detected = hostCapabilities({ host: fakeAndroid });
  assert.equal(detected.transport, 'tauri');
  assert.equal(detected.platform, 'android');
  // The actual native Android build registers the Kotlin host plugin.
  assert.equal(detected.safTrees, true);
  assert.equal(detected.shareIntents, true);
  assert.equal(detected.foregroundTransfers, true);
  assert.equal(detected.desktopLaunchers, true);
  assert.equal(hostCapabilities({ host: fakeBrowser }).shareIntents, false);
  assert.equal(hostCapabilities({ host: fakeBrowser }).foregroundTransfers, false);
});

test('Android desktop viewer URIs allow direct RDP/VNC/SPICE targets and reject unsupported or unsafe targets', () => {
  assert.equal(androidDesktopViewerUri('rdp', 'desktop.example:3389'), 'rdp://desktop.example:3389');
  assert.equal(androidDesktopViewerUri('vnc', 'desktop.example:5900'), 'vnc://desktop.example:5900');
  assert.equal(androidDesktopViewerUri('spice', 'desktop.example:5900'), 'spice://desktop.example:5900');
  assert.equal(androidDesktopViewerUri('x2go', 'desktop.example:22'), null);
  assert.equal(androidDesktopViewerUri('toString', 'desktop.example:3389'), null);
  assert.equal(androidDesktopViewerUri('rdp', 'desktop.example:3389', true), null);
  assert.equal(androidDesktopViewerUri('rdp', 'user:secret@desktop.example:3389'), null);
  assert.equal(androidDesktopViewerUri('rdp', 'desktop.example/path'), null);
  assert.equal(androidDesktopViewerUri('rdp', 'desktop.example:3389?password=secret'), null);
});

test('Android external URI dispatch allows supported viewers and rejects unsafe or credential-bearing URIs', async () => {
  const calls = [];
  const invoker = {
    invoke: async (command, payload) => {
      calls.push({ command, payload });
      return { opened: true };
    },
  };
  assert.equal(await openExternalUri('rdp://server.example:3389', { invoker }), true);
  assert.equal(await openExternalUri('vnc://server.example:5900', { invoker }), true);
  assert.equal(await openExternalUri('spice://server.example:5900', { invoker }), true);
  assert.deepEqual(calls.map((call) => call.command), Array(3).fill('linscp_open_external_uri'));
  assert.deepEqual(calls.map((call) => call.payload.uri), [
    'rdp://server.example:3389',
    'vnc://server.example:5900',
    'spice://server.example:5900',
  ]);

  assert.equal(await openExternalUri('javascript:alert(1)', { invoker }), false);
  assert.equal(await openExternalUri('rdp://user:password@server.example:3389', { invoker }), false);
  assert.equal(await openExternalUri('rdp:///missing-host', { invoker }), false);
  assert.equal(await openExternalUri('rdp://server.example:3389', { invoker: null }), false);
  assert.equal(calls.length, 3);
});

test('the SAF picker degrades to null where no shell can open one', async () => {
  // No `__TAURI_INTERNALS__`: the browser build must not throw or claim a
  // folder. This is what lets the same bundle serve the HTTP app.
  assert.equal(await requestSafTree({ invoker: null }), null);

  const invoked = [];
  const granted = await requestSafTree({
    registerTree: async (uri) => {
      invoked.push(uri);
      return { path: uri, label: 'Granted', kind: 'saf_tree', read_only: false };
    },
    invoker: {
      invoke: async (cmd) => {
        assert.equal(cmd, 'linscp_pick_saf_tree');
        return { uri: 'content://com.android.externalstorage.documents/tree/primary%3ADownload' };
      },
    },
  });
  assert.equal(granted?.kind, 'saf_tree');
  assert.deepEqual(invoked, ['content://com.android.externalstorage.documents/tree/primary%3ADownload']);

  // A cancelled picker is not an error and not a root.
  assert.equal(
    await requestSafTree({ invoker: { invoke: async () => ({ cancelled: true }) } }),
    null,
  );
});

test('the foreground bridge drops duplicate percentages and stops cleanly', async () => {
  const calls = [];
  const bridge = new ForegroundTransferBridge({
    invoke: async (cmd, args) => {
      calls.push([cmd, args]);
      return {};
    },
  });
  assert.equal(bridge.available, true);
  assert.equal(await bridge.start('Uploading 3 files', 3), true);
  assert.equal(await bridge.update(1, 10), true);
  assert.equal(await bridge.update(1, 10), true); // same percent: no invoke
  assert.equal(await bridge.update(5, 10), true);
  assert.equal(await bridge.stop(), true);
  assert.deepEqual(
    calls.map(([cmd]) => cmd),
    ['linscp_foreground_start', 'linscp_foreground_update', 'linscp_foreground_update', 'linscp_foreground_stop'],
  );
  assert.equal(bridge.isRunning, false);

  // Without a shell the bridge is inert rather than throwing at every call.
  const absent = new ForegroundTransferBridge(null);
  assert.equal(absent.available, false);
  assert.equal(await absent.start('x', 1), false);
  assert.equal(await absent.update(1, 2), false);
  assert.equal(await absent.stop(), false);
});

test('the page gates each Android-only bridge on the capability it needs', () => {
  // The page asks the bundle what this host can do instead of probing the
  // native bridge at each call site. A bridge that is not offered here is one
  // the host cannot serve, and the difference is explained rather than hidden.
  const html = fs.readFileSync(path.join(repoRoot, 'source', 'gui', 'web', 'index.html'), 'utf8');
  assert.match(html, /function hostCaps\(\)/, 'the page asks the bundle for capabilities');
  assert.match(html, /typeof window\.LinSCPCore\.hostCapabilities !== 'function'/);
  assert.match(html, /hostDifferenceReason/);

  // Folder grants, share hand-offs and the foreground service each read the
  // capability that names them, so a host without the bridge never calls it.
  const canGrant = html.match(/const canGrantFolders = \(\) => Boolean\([\s\S]*?\);/);
  assert.ok(canGrant, 'the SAF control is gated');
  assert.match(canGrant[0], /safTrees/);

  const share = html.match(/async function queueSharedFiles\(item\) \{[\s\S]*?\n  \}/);
  assert.ok(share, 'the share hand-off exists');
  assert.match(share[0], /shareIntents/);

  const foreground = html.match(/function foregroundService\(\) \{[\s\S]*?\n  \}/);
  assert.ok(foreground, 'the foreground service is started from the queue');
  assert.match(foreground[0], /foregroundTransfers/);
  assert.match(html, /syncForegroundService\(\);/, 'the queue drives the service');

  const drops = html.match(/function listenForNativeDrops\(\) \{[\s\S]*?\n  \}/);
  assert.ok(drops, 'the native drop listener exists');
  assert.match(drops[0], /nativeFileDrop/);

  // Every capability the page asks about is one the bundle actually reports,
  // so a rename cannot leave the gate silently always-false.
  const caps = hostCapabilities({ transport: 'tauri', platform: 'android' });
  for (const name of ['safTrees', 'shareIntents', 'foregroundTransfers', 'nativeFileDrop']) {
    assert.equal(typeof caps[name], 'boolean', `${name} is reported`);
    assert.ok(html.includes(name), `${name} is consulted by the page`);
  }
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
          if (p === '/api/vault/status') {
            return { status: 200, payload: { success: true, vault: 'unlocked' } };
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

/**
 * The page's one conflict/approval loop, as a function the tests can call.
 *
 * Every way a file arrives (a pane transfer, a browser byte drop, a native
 * path drop) goes through `applyDropApprovals`, so the tests load that and the
 * transfer wrapper together instead of a copy that could drift.
 */
function loadApprovalDecision(apiPost, preferences, confirm, t) {
  const html = fs
    .readFileSync(path.join(repoRoot, 'source', 'gui', 'web', 'index.html'), 'utf8')
    .replace(/\r\n/g, '\n');
  const approvals = html.match(/async function applyDropApprovals\(send, options\) \{[\s\S]*?\n  \}\n/);
  const pane = html.match(/async function queueWithOverwriteDecision\(endpoint, payload\) \{[\s\S]*?\n  \}\n/);
  assert.ok(approvals, 'the shared approval loop exists');
  assert.ok(pane, 'a pane transfer uses the shared approval loop');
  return new Function(
    'apiPost',
    'preferences',
    'confirm',
    't',
    `${approvals[0]}\n${pane[0]}; return queueWithOverwriteDecision;`,
  )(apiPost, preferences, confirm, t);
}

test('overwrite confirmation forwards the original WebDAV conflict ETag', async () => {
  const calls = [];
  const apiPost = async (endpoint, payload) => {
    calls.push({ endpoint, payload });
    return calls.length === 1
      ? { success: false, conflicts: ['file.txt'], conflict_versions: { 'file.txt': '"original"' } }
      : { success: true };
  };
  const handler = loadApprovalDecision(apiPost, {}, () => true, s => s);
  assert.equal((await handler('/api/transfer/upload', { overwrite: 'ask' }, [])).success, true);
  assert.deepEqual(calls[1].payload, { overwrite: 'overwrite', conflict_versions: { 'file.txt': '"original"' } });
});

test('directory merge requires explicit approval and forwards only approved roots', async () => {
  const calls = [];
  const apiPost = async (_endpoint, payload) => {
    calls.push(payload);
    return calls.length === 1 ? { success: false, directory_conflicts: ['tree'] } : { success: true };
  };
  let confirmations = 0;
  const handler = loadApprovalDecision(apiPost, { confirm_overwrite: false }, () => { confirmations++; return true; }, s => s);
  assert.equal((await handler('/api/transfer/upload', { names: ['tree', 'other'] }, [])).success, true);
  assert.equal(confirmations, 1);
  assert.deepEqual(calls[1].merge_directories, ['tree']);
});

test('WebDAV tree downloads separately confirm snapshot and merge risks', async () => {
  for (const accepted of [false, true]) {
    const calls = [];
    const apiPost = async (_endpoint, payload) => {
      calls.push({ ...payload });
      if (!payload.accept_directory_copy_risk) return { success: false, directory_copy_risk: true };
      if (!payload.merge_directories) return { success: false, directory_conflicts: ['tree'] };
      return { success: true };
    };
    const handler = loadApprovalDecision(apiPost, {}, () => accepted, s => s);
    const result = await handler('/api/transfer/download', { names: ['tree'] }, []);
    assert.equal(calls.length, accepted ? 3 : 1);
    if (accepted) {
      assert.equal(result.success, true);
      assert.equal(calls[2].accept_directory_copy_risk, true);
      assert.deepEqual(calls[2].merge_directories, ['tree']);
    }
  }
});

test('FTP uploads require risk confirmation and separately confirm existing files', async () => {
  const calls = [];
  let confirmations = 0;
  const apiPost = async (_endpoint, payload) => {
    calls.push({ ...payload });
    if (!payload.accept_ftp_rename_risk) return { success: false, ftp_rename_risk: true };
    if (!payload.overwrite) return { success: false, conflicts: ['file.txt'] };
    return { success: true };
  };
  const handler = loadApprovalDecision(apiPost, { confirm_overwrite: false }, () => { confirmations++; return true; }, s => s);
  assert.equal((await handler('/api/transfer/upload', {}, [])).success, true);
  assert.equal(confirmations, 2);
  assert.equal(calls[1].accept_ftp_rename_risk, true);
  assert.equal(calls[2].overwrite, 'overwrite');
  const reject = loadApprovalDecision(apiPost, {}, () => false, s => s);
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

test('SFTP remote copy requires explicit source-race confirmation', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source/gui/web/index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function runRemoteTransfer\(moveItem\) \{[\s\S]*?\n  \}\n\n  \/\*/);
  assert.ok(match);
  const source = match[0].replace(/\n\n  \/\*$/, '');
  for (const accepted of [false, true]) {
    const values = { remoteTransferDirectory: { value: '/archive' }, remoteTransferTarget: { value: 'tab:9' }, remoteTransferMask: { value: '' }, remoteTransferStatus: { textContent: '' } };
    const calls = []; let confirmations = 0;
    const post = async (_path, payload) => {
      calls.push({ ...payload });
      return payload.accept_sftp_copy_risk ? { success: true } : { success: false, sftp_copy_risk: true, error: 'Confirmation required' };
    };
    const run = new Function('$', 'remoteTransferState', 'apiPost', 't', 'errorMessage', 'closeModal', 'toast', 'switchTab', 'refreshQueue', 'confirm', `${source}; return runRemoteTransfer;`)(
      id => values[id], { tab: 8, names: ['tree'] }, post, s => s, s => s, () => {}, () => {}, () => {}, () => {}, () => { confirmations++; return accepted; });
    await run(false);
    assert.equal(confirmations, 1);
    assert.equal(calls.length, accepted ? 2 : 1);
    if (accepted) assert.equal(calls[1].accept_sftp_copy_risk, true);
  }
});

test('WebDAV directory copy requires explicit non-snapshot confirmation', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source/gui/web/index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function runRemoteTransfer\(moveItem\) \{[\s\S]*?\n  \}\n\n  \/\*/);
  assert.ok(match);
  const source = match[0].replace(/\n\n  \/\*$/, '');
  for (const accepted of [false, true]) {
    const values = { remoteTransferDirectory: { value: '/' }, remoteTransferTarget: { value: 'tab:9' }, remoteTransferMask: { value: '' }, remoteTransferStatus: { textContent: '' } };
    const calls = [];
    const post = async (_path, payload) => {
      calls.push({ ...payload });
      return payload.accept_directory_copy_risk ? { success: true } : { success: false, directory_copy_risk: true, error: 'Confirmation required' };
    };
    const run = new Function('$', 'remoteTransferState', 'apiPost', 't', 'errorMessage', 'closeModal', 'toast', 'switchTab', 'refreshQueue', 'confirm', `${source}; return runRemoteTransfer;`)(
      id => values[id], { tab: 8, names: ['tree'] }, post, s => s, s => s, () => {}, () => {}, () => {}, () => {}, () => accepted);
    await run(false);
    assert.equal(calls.length, accepted ? 2 : 1);
    if (accepted) assert.equal(calls[1].accept_directory_copy_risk, true);
  }
});

test('reconnect surfaces host-key challenges instead of reporting success', async () => {
  const html = fs.readFileSync(path.join(repoRoot, 'source/gui/web/index.html'), 'utf8').replace(/\r\n/g, '\n');
  const match = html.match(/async function reconnectTab\(\) \{[\s\S]*?\n  \}\n\n  \/\*/);
  assert.ok(match);
  const source = match[0].replace(/\n\n  \/\*$/, '');
  const challenge = { tab: 8, fingerprint: 'ssh-ed25519 SHA256:test' };
  let shown, refreshes = 0, toasts = [];
  const reconnect = new Function('activeTab', 'apiPost', 'toast', 't', 'refreshStatus', 'loadRemote', 'state', 'errorMessage', 'showHostKeyChallenge', `${source}; return reconnectTab;`)(
    () => ({ id: 8 }), async () => ({ success: false, error: 'Host key changed', challenge }),
    message => toasts.push(message), s => s, async () => { refreshes++; }, async () => {}, { remote: { path: '/' } }, s => s, ch => { shown = ch; });
  await reconnect();
  assert.equal(shown, challenge);
  assert.equal(refreshes, 1);
  assert.deepEqual(toasts, ['Host key changed']);
});

test('the touch shell is mounted from the shared bundle in every host', async () => {
  const { AppShell, SHELL_ACTIONS, isTouchLayout, mountAppShell } = await import(
    '../dist/linscp-core.mjs'
  );

  // The reviewed order of the floating bar; nothing here is host specific.
  assert.deepEqual(SHELL_ACTIONS, ['copy', 'delete', 'selectAll', 'clear', 'cancel']);
  assert.equal(typeof mountAppShell, 'function');
  assert.equal(typeof AppShell, 'function');

  // A coarse pointer or a narrow window is the touch layout; a wide, fine
  // pointer window is not. This is the same question the stylesheet asks.
  assert.equal(isTouchLayout({ matchMedia: () => ({ matches: true }), innerWidth: 1400 }), true);
  assert.equal(isTouchLayout({ matchMedia: () => ({ matches: false }), innerWidth: 420 }), true);
  assert.equal(isTouchLayout({ matchMedia: () => ({ matches: false }), innerWidth: 1400 }), false);
  assert.equal(isTouchLayout({}), false);

  const dom = new JSDOM(`<!doctype html><body>
    <div id="app"></div>
    <div class="commander-main"><div class="pane" id="localPane"></div><div class="pane" id="remotePane"></div></div>
    <nav id="nav"></nav><div id="bar"></div><div id="keys"></div>
    <table><tbody id="localFileList"></tbody></table>
  </body>`, { url: 'http://127.0.0.1:8080/' });
  const doc = dom.window.document;
  // A 375px phone viewport: the app runs in this, so the shell must build for it.
  Object.defineProperty(dom.window, 'innerWidth', { value: 375, configurable: true });
  const input = [];
  const selections = [];
  const actions = [];
  const panes = [];

  const shell = new AppShell({
    rootElement: doc.getElementById('app'),
    bottomNavElement: doc.getElementById('nav'),
    swipeContainer: doc.querySelector('.commander-main'),
    extraKeysElement: doc.getElementById('keys'),
    actionBarElement: doc.getElementById('bar'),
    paneLabel: (pane) => pane,
    actionLabel: (action) => action,
    onTerminalInput: (data) => input.push(data),
    onSelectionChange: (selection) => selections.push(selection),
    onAction: (action) => actions.push(action),
    onPaneChange: (pane) => panes.push(pane),
  });

  assert.equal(shell.touchLayout, true);
  // Four panes, drawn from the shared controller rather than by each host.
  assert.deepEqual(
    [...doc.querySelectorAll('#nav [data-pane]')].map((b) => b.dataset.pane),
    ['local', 'remote', 'queue', 'terminal'],
  );
  // Twelve extra keys, in the reviewed order, with the modifiers marked.
  assert.equal(doc.querySelectorAll('#keys .extra-key').length, 12);
  assert.equal(doc.querySelector('#keys .extra-key[data-extra-key="ctrl"]').getAttribute('aria-pressed'), 'false');

  // Bottom navigation drives the pane, and the page is told once.
  doc.querySelector('#nav [data-pane="remote"]').dispatchEvent(
    new dom.window.MouseEvent('click', { bubbles: true }),
  );
  assert.equal(shell.pane, 'remote');
  assert.deepEqual(panes, ['remote']);
  // A pane change the page made itself is not echoed back to it.
  shell.syncPane('local');
  assert.deepEqual(panes, ['remote']);

  // A latched Ctrl turns the next key into a control byte, and the key row
  // and the keyboard share the encoding.
  doc.querySelector('#keys .extra-key[data-extra-key="ctrl"]').dispatchEvent(
    new dom.window.MouseEvent('click', { bubbles: true }),
  );
  assert.equal(doc.querySelector('#keys [data-extra-key="ctrl"]').getAttribute('aria-pressed'), 'true');
  assert.equal(shell.transformTextInput('c'), '\x03');
  // The latch is spent, so the next key is literal again.
  assert.equal(shell.transformTextInput('c'), 'c');
  doc.querySelector('#keys .extra-key[data-extra-key="up"]').dispatchEvent(
    new dom.window.MouseEvent('click', { bubbles: true }),
  );
  assert.deepEqual(input, ['\x1b[A']);

  // A long press selects a row and raises the floating bar; a second long
  // press on the same row removes it again.
  const tbody = doc.getElementById('localFileList');
  tbody.innerHTML = '<tr data-name="a.txt"></tr><tr data-name="b.txt"></tr>';
  shell.refreshRows('local', tbody);
  const row = tbody.querySelector('tr[data-name="a.txt"]');
  row.dispatchEvent(new dom.window.MouseEvent('mousedown', { bubbles: true }));
  await new Promise((resolve) => setTimeout(resolve, 520));
  row.dispatchEvent(new dom.window.MouseEvent('mouseup', { bubbles: true }));
  assert.deepEqual(shell.selection('local'), ['a.txt']);
  assert.equal(doc.getElementById('bar').classList.contains('visible'), true);
  assert.equal(doc.querySelector('#bar .fab-count').textContent, '1');
  assert.deepEqual(selections.at(-1), { pane: 'local', names: ['a.txt'] });
  row.classList.contains('selected-touch');

  // The floating bar is wired to the same actions the function keys run.
  for (const action of SHELL_ACTIONS) {
    doc.querySelector(`#bar [data-shell-action="${action}"]`).dispatchEvent(
      new dom.window.MouseEvent('click', { bubbles: true }),
    );
  }
  assert.deepEqual(actions, [...SHELL_ACTIONS]);

  // Replacing the selection is reflected in the bar, and clearing hides it.
  shell.setSelection('local', ['a.txt', 'b.txt']);
  assert.equal(doc.querySelector('#bar .fab-count').textContent, '2');
  shell.setSelection('local', []);
  assert.equal(doc.getElementById('bar').classList.contains('visible'), false);

  shell.destroy();
  dom.window.close();
});

test('an operating-system drop names paths once and the queue answers once', async () => {
  // The desktop window and the Android share sheet hand over paths; a browser
  // hands over bytes. The request shape is what keeps them one behaviour, so it
  // is asserted directly instead of through a window that cannot drop.
  const requests = [];
  const transport = {
    post: async (endpoint, body) => {
      requests.push({ endpoint, body });
      return { success: true, task_id: 't1' };
    },
  };
  const items = normalizeDropPayload({
    paths: ['/home/me/report.txt', '/home/me/project', ''],
    directories: ['/home/me/project'],
  });
  assert.deepEqual(items, [
    { path: '/home/me/report.txt', isDirectory: false },
    { path: '/home/me/project', isDirectory: true },
  ]);

  // One request for the whole drop, into the remote panel of a tab, with the
  // folder of every directory named so the backend copies trees as trees.
  const request = dropRequest(items, { target: 'remote', directory: '/incoming', tab: 3 });
  assert.equal(request.endpoint, '/api/transfer/drop');
  assert.deepEqual(request.payload.source_paths, ['/home/me/report.txt', '/home/me/project']);
  assert.deepEqual(request.payload.directories, ['/home/me/project']);
  assert.equal(request.payload.remote_dir, '/incoming');
  assert.equal(request.payload.tab, 3);
  assert.equal(request.payload.name, 'report.txt');
  // Several items are not reported as one folder, whichever order they come in.
  assert.equal(request.payload.source_kind, 'file');

  const outcome = await dropPaths(transport, items, { target: 'remote', directory: '/incoming', tab: 3 });
  assert.equal(requests.length, 1, 'one drop is one request');
  assert.equal(outcome.queued, 2);
  assert.deepEqual(outcome.failed, []);
  assert.equal(requests[0].endpoint, '/api/transfer/drop');

  // The local panel is a different endpoint and carries no tab, and a refusal
  // keeps the backend's answer so the page can ask the same question it asks
  // for a byte drop.
  const local = dropRequest(items, { target: 'local', directory: '/home/me' });
  assert.equal(local.endpoint, '/api/local/drop');
  assert.equal(local.payload.local_dir, '/home/me');
  assert.equal(local.payload.tab, undefined);

  const refusing = {
    post: async () => ({ success: false, error: 'Destination exists', conflicts: ['project'] }),
  };
  const refused = await dropPaths(refusing, items, { target: 'local', directory: '/home/me' });
  assert.equal(refused.queued, 0);
  assert.deepEqual(refused.result.conflicts, ['project']);
  assert.equal(refused.failed.length, 2);
  assert.equal(refused.failed[0].error, 'Destination exists');

  // An approval is the same request plus one decision, which is what makes a
  // retry safe: nothing else about the drop changes.
  const approved = dropRequest(items, {
    target: 'local',
    directory: '/home/me',
    approvals: { overwrite: 'overwrite' },
  });
  assert.deepEqual(approved.payload, { ...local.payload, overwrite: 'overwrite' });

  // A drop that wrote some of its items says so, and the page reports the
  // same count the endpoint does instead of claiming the whole drop landed.
  const partial = {
    post: async () => ({ success: true, saved: ['report.txt'], refused: ["Cannot save 'project': denied"] }),
  };
  const partly = await dropPaths(partial, items, { target: 'local', directory: '/home/me' });
  assert.equal(partly.queued, 1);
  assert.equal(partly.failed.length, 1);
  assert.match(partly.failed[0].error, /denied/);
  // A host that only refusals without a `saved` list still counts what landed.
  const counted = await dropPaths(
    { post: async () => ({ success: true, refused: ['nope'] }) },
    items,
    { target: 'local', directory: '/home/me' },
  );
  assert.equal(counted.queued, 1);
  assert.equal(counted.failed.length, 1);

  // A path with a control character is not a drop, on either separator.
  assert.deepEqual(normalizeDropPayload({ paths: ['bad\u0000path'] }), []);
  assert.deepEqual(normalizeDropPayload('not a payload'), []);
  assert.deepEqual(normalizeDropPayload({ paths: 'nope' }), []);
  assert.equal(droppedLeafName('/home/me/project/'), 'project');
  assert.equal(droppedLeafName('C:\\Users\\me\\report.txt'), 'report.txt');
});

test('granted Android folders name the app-storage limitation per action', () => {
  const granted = 'content://com.android.externalstorage.documents/tree/primary%3ADownload';
  const document = granted + '/document/primary%3ADownload%2Fnote.txt';
  const leads = {
    transfer: 'Transferring files',
    copyMove: 'Copying or moving files',
    move: 'Moving files',
    synchronize: 'Synchronizing',
    keepUpToDate: 'Keep up to date',
    symlink: 'Creating symbolic links',
  };
  for (const [action, lead] of Object.entries(leads)) {
    // The tree root and a document below it are limited alike.
    for (const path of [granted, document]) {
      const reason = safLimitationReason(action, path);
      assert.ok(reason.startsWith(lead), `${action}: ${reason}`);
      assert.match(reason, /app storage/);
      assert.match(reason, /granted Android folder/);
    }
  }
  // chmod carries the bridge's own message, shared with the service refusal.
  assert.equal(
    safLimitationReason('permissions', document),
    'POSIX permissions do not exist on a granted Android folder.',
  );
  // A plain path is never limited, on either separator, whatever the action.
  for (const plain of ['/home/user/photos', 'C:\\Photos', '', null, undefined]) {
    for (const action of [...Object.keys(leads), 'permissions']) {
      assert.equal(safLimitationReason(action, plain), null, `${action} on ${plain}`);
    }
  }
  // An unknown action still fails closed with the generic limitation.
  assert.match(safLimitationReason('watch', granted) ?? '', /app storage/);
});
