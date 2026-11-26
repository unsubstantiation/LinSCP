// Runs against the debug WebView through Chrome DevTools. The WebDAV fixture
// is reached through adb reverse; all IPC executes inside the installed APK.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
const port = Number(process.argv[2]);
// The installed package, handed over by the harness that read it from the
// configuration, so the storage this run finds is the storage of *this* app.
const application = process.argv[3];
// Where to record the app-private root the service reported, so the harness can
// compare it with the directory the device reports for the installed package.
const rootFile = process.argv[4];
const phase = process.argv[5] || 'initial';
assert.ok(['initial', 'reopen-vault', 'tampered-key', 'tampered-sessions', 'backup-restore', 'portable-export', 'portable-setup', 'portable-import', 'portable-reopen', 'damaged-journal'].includes(phase), 'unknown smoke phase');
assert.ok(application && application.includes('.'), 'the harness must pass the application ID');
const portableFile = process.argv[6];
if (phase.startsWith('portable-')) assert.ok(portableFile, 'portable backup phase requires a private host file');
const portableBackup = ['portable-import', 'portable-reopen'].includes(phase) ? JSON.parse(readFileSync(portableFile, 'utf8')) : null;

let pages;
for (let i = 0; i < 60; i++) {
  try {
    pages = await (await fetch('http://127.0.0.1:9222/json')).json();
    if (pages.some(page => page.type === 'page' && page.webSocketDebuggerUrl && page.url.includes('tauri.localhost'))) break;
  } catch (_) { /* WebView still starting */ }
  await new Promise(resolve => setTimeout(resolve, 1000));
}
const page = pages?.find(item => item.type === 'page' && item.webSocketDebuggerUrl && item.url.includes('tauri.localhost'));
assert.ok(page, `No debuggable WebView: ${JSON.stringify(pages)}`);
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
const expression = `
(async () => {
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  for (let i = 0; i < 60 && !window.LinSCPTransport; i++) await sleep(1000);
  if (window.LinSCPTransport?.mode !== 'tauri') throw new Error('Tauri frontend transport not initialized');
  const invoke = (method, path, body = {}) => window.LinSCPTransport.request(method, path, body);
  async function verifyAndroidVaultRestart() {
    const status = await invoke('GET', '/api/vault/status');
    if (status.vault !== 'locked') throw new Error('Restart did not lock vault: ' + JSON.stringify(status));
    let rejected = false;
    try { await invoke('POST', '/api/vault/unlock', {password: 'wrong vault password'}); }
    catch (error) { rejected = error.status === 400; }
    if (!rejected) throw new Error('Wrong vault password was not rejected');
    const afterWrong = await invoke('GET', '/api/vault/status');
    if (afterWrong.vault !== 'locked') throw new Error('Wrong password unlocked the vault');
    await invoke('POST', '/api/vault/unlock', {password: 'android smoke vault password'});
    const sessions = await invoke('GET', '/api/sessions');
    if (!sessions.sessions?.some(site => site.name === 'android-smoke-vault-site')) throw new Error('Saved site missing after restart');
    if (JSON.stringify(sessions).includes('testpass')) throw new Error('Saved site listing exposed password');
    // Authentication against the fixture proves the password was recovered,
    // without exposing it through the list API.
    const opened = await invoke('POST', '/api/tabs/open', {site_name: 'android-smoke-vault-site'});
    if (!opened.tab?.connected) throw new Error('Saved site did not reconnect after restart: ' + JSON.stringify(opened));
    const root = (await invoke('GET', '/api/status')).local_dir;
    return {root, vaultRestart: true, wrongPasswordRefused: true, savedSiteReconnect: true};
  }
  async function verifyAndroidVaultTampering() {
    const phase = ${JSON.stringify(phase)};
    const status = await invoke('GET', '/api/vault/status');
    if (status.vault !== 'locked') throw new Error('Damaged vault did not start locked');
    let unlockStatus;
    try { await invoke('POST', '/api/vault/unlock', {password: 'android smoke vault password'}); }
    catch (error) { unlockStatus = error.status; }
    const expected = phase === 'tampered-key' ? 400 : 500;
    if (unlockStatus !== expected) throw new Error('Damaged vault unlock did not fail as expected: ' + unlockStatus);
    if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Damaged vault did not remain locked');
    let saveStatus;
    try { await invoke('POST', '/api/sessions/save', {name: 'must-not-replace-store', session: {protocol: 'dav', host: 'invalid.example', username: 'test', password: 'test'}}); }
    catch (error) { saveStatus = error.status; }
    if (!saveStatus || saveStatus < 400) throw new Error('Save unexpectedly accepted with damaged vault');
    const root = (await invoke('GET', '/api/status')).local_dir;
    return {root, tamperedVaultRefused: phase};
  }
  async function verifyAndroidFullBackupRestore() {
    if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Expected locked vault before backup test');
    await invoke('POST', '/api/vault/unlock', {password: 'android smoke vault password'});
    const backupPassword = 'independent android backup password';
    const backup = await invoke('POST', '/api/backup/export', {password: backupPassword});
    if (!backup.success || !backup.data_base64 || !atob(backup.data_base64).startsWith('LSCPBAK1')) throw new Error('Invalid encrypted backup envelope');
    const encrypted = atob(backup.data_base64);
    for (const secret of ['android-smoke-vault-site', 'testuser', 'testpass']) {
      if (encrypted.includes(secret)) throw new Error('Backup exposed site metadata in plaintext');
    }
    await invoke('POST', '/api/sessions/save', {name: 'after-backup-site', session: {protocol: 'sftp', host: 'after-backup.example', username: 'other'}});
    async function names() { return (await invoke('GET', '/api/sessions')).sessions.map(site => site.name).sort(); }
    const expectedBefore = JSON.stringify(['after-backup-site', 'android-smoke-vault-site'].sort());
    if (JSON.stringify(await names()) !== expectedBefore) throw new Error('Backup precondition sites missing');
    async function rejected(body, expected, label) {
      let status;
      try { await invoke('POST', '/api/backup/import', body); } catch (error) { status = error.status; }
      if (status !== expected) throw new Error(label + ' returned unexpected status: ' + status);
      if (JSON.stringify(await names()) !== expectedBefore) throw new Error(label + ' altered saved sites');
    }
    const good = {password: backupPassword, data_base64: backup.data_base64, confirm_replace: true};
    await rejected({...good, confirm_replace: false}, 400, 'Unconfirmed restore');
    await rejected({...good, password: 'incorrect backup password'}, 400, 'Wrong backup password');
    const tamperedBytes = Uint8Array.from(encrypted, c => c.charCodeAt(0));
    tamperedBytes[tamperedBytes.length - 1] ^= 1;
    const tamperedBase64 = btoa(Array.from(tamperedBytes, b => String.fromCharCode(b)).join(''));
    await rejected({...good, data_base64: tamperedBase64}, 400, 'Corrupted backup');
    const connected = await invoke('POST', '/api/tabs/open', {site_name: 'android-smoke-vault-site'});
    if (!connected.tab?.connected) throw new Error('Cannot connect for active-session restore guard');
    await rejected(good, 409, 'Restore with an active remote session');
    await invoke('POST', '/api/tabs/close', {tab: connected.tab.id});
    const restored = await invoke('POST', '/api/backup/import', good);
    if (!restored.success || JSON.stringify(await names()) !== JSON.stringify(['android-smoke-vault-site'])) throw new Error('Restored saved sites differ from backup');
    const reopened = await invoke('POST', '/api/tabs/open', {site_name: 'android-smoke-vault-site'});
    if (!reopened.tab?.connected) throw new Error('Restored saved credentials cannot connect');
    const root = (await invoke('GET', '/api/status')).local_dir;
    return {root, backupRestore: true, restoreRefusals: true};
  }
  async function verifyAndroidBackupAcrossVaults() {
    const phase = ${JSON.stringify(phase)};
    const status = await invoke('GET', '/api/vault/status');
    const expected = phase === 'portable-setup' ? 'setup_required' : 'locked';
    if (status.vault !== expected) throw new Error('Unexpected portable backup vault status: ' + status.vault);
    const password = phase === 'portable-export' ? 'android smoke vault password' : 'different destination vault password';
    await invoke('POST', '/api/vault/unlock', {password});
    const root = (await invoke('GET', '/api/status')).local_dir;
    if (phase === 'portable-setup') return {root, destinationVaultSetUp: true};
    // A deliberately nonfunctional private-key fixture: this exercises vault
    // encryption and backup rewrapping, not SSH parsing or authentication.
    const keyFixture = 'android portable backup private key fixture';
    if (phase === 'portable-export') {
      const key = await invoke('POST', '/api/vault/keys/import', {name: 'portable-fixture-key', private_key: keyFixture});
      if (!key.success || !(key.reference?.startsWith('vaultkey://') && /^[a-f0-9]{32}$/.test(key.reference.slice(11)))) throw new Error('Fixture key import failed');
      await invoke('POST', '/api/sessions/save', {name: 'portable-key-site', session: {protocol: 'sftp', host: 'fixture.invalid', username: 'test', keyfile: key.reference}});
      const exported = await invoke('POST', '/api/backup/export', {password: 'portable android backup password'});
      if (!exported.success || !atob(exported.data_base64).startsWith('LSCPBAK1')) throw new Error('Portable backup export failed');
      return {root, portableData: {backupBase64: exported.data_base64, keyReference: key.reference}};
    }
    const portable = ${JSON.stringify(portableBackup)};
    if (phase === 'portable-import') {
      const restored = await invoke('POST', '/api/backup/import', {password: 'portable android backup password', data_base64: portable.backupBase64, confirm_replace: true});
      if (!restored.success) throw new Error('Portable backup restore failed');
    }
    const sessions = await invoke('GET', '/api/sessions');
    if (!sessions.sessions?.some(site => site.name === 'android-smoke-vault-site')) throw new Error('Portable restore omitted saved site');
    const keySite = sessions.sessions?.find(site => site.name === 'portable-key-site');
    if (keySite?.private_key !== portable.keyReference) throw new Error('Restored site key reference differs');
    const listedKeys = await invoke('GET', '/api/vault/keys');
    if (!listedKeys.keys?.some(key => key.reference === portable.keyReference && key.label === 'portable-fixture-key')) throw new Error('Restored key metadata missing');
    // Import deduplication opens existing encrypted keys and compares the
    // plaintext, so this also checks the restored key decrypts under the
    // destination vault without exposing private bytes through a read API.
    const duplicate = await invoke('POST', '/api/vault/keys/import', {name: 'portable-fixture-key', private_key: keyFixture});
    if (!duplicate.deduplicated || duplicate.reference !== portable.keyReference) throw new Error('Restored key cannot be decrypted to the original fixture');
    const opened = await invoke('POST', '/api/tabs/open', {site_name: 'android-smoke-vault-site'});
    if (!opened.tab?.connected) throw new Error('Portable restored credential failed to authenticate');
    return {root, portableBackupPhase: phase};
  }
  async function verifyAndroidDamagedRestoreJournal() {
    if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Expected locked vault with a pending journal');
    async function expectUnavailable(method, path, body) {
      let status;
      try { await invoke(method, path, body); } catch (error) { status = error.status; }
      if (status !== 503) throw new Error('Expected recovery gate for ' + path + ': ' + status);
    }
    await expectUnavailable('GET', '/api/sessions', {});
    await expectUnavailable('POST', '/api/vault/unlock', {password: 'different destination vault password'});
    await expectUnavailable('POST', '/api/sessions/save', {name: 'must-not-save', session: {protocol: 'sftp', host: 'fixture.invalid'}});
    if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Failed recovery left vault unlocked');
    return {damagedJournalRefused: true};
  }
  if (${JSON.stringify(phase)} === 'damaged-journal') return await verifyAndroidDamagedRestoreJournal();
  if (['portable-export', 'portable-setup', 'portable-import', 'portable-reopen'].includes(${JSON.stringify(phase)})) return await verifyAndroidBackupAcrossVaults();
  if (${JSON.stringify(phase)} === 'backup-restore') return await verifyAndroidFullBackupRestore();
  if (${JSON.stringify(phase)} === 'reopen-vault') return await verifyAndroidVaultRestart();
  if (${JSON.stringify(phase)} === 'tampered-key' || ${JSON.stringify(phase)} === 'tampered-sessions') return await verifyAndroidVaultTampering();
  const caps = window.LinSCPCore.hostCapabilities({host: window});
  for (const bridge of ['safTrees', 'shareIntents', 'foregroundTransfers', 'desktopLaunchers']) {
    if (!caps[bridge]) throw new Error('Native Android capability not registered: ' + bridge);
  }
  const nativeInvoke = window.__TAURI_INTERNALS__.invoke;
  // Invoke the native command directly, not the validating JS helper: the
  // Kotlin bridge must reject viewer options and credentials on its own.
  async function verifyAndroidViewerUriRefusals() {
    for (const uri of ['javascript:alert(1)', 'rdp://example.com/path',
                       'vnc://example.com/?password=secret', 'spice://example.com/#fragment',
                       'rdp://user:secret@example.com/', 'rdp://example.com/with space']) {
      let unsafeUriRejected = false;
      try { await nativeInvoke('linscp_open_external_uri', {uri}); }
      catch (_) { unsafeUriRejected = true; }
      if (!unsafeUriRejected) throw new Error('Android external URI bridge accepted an unsafe URI: ' + uri);
    }
  }
  await verifyAndroidViewerUriRefusals();
  await nativeInvoke('linscp_foreground_start', {title: 'Android smoke transfer', ongoing: 1});
  await nativeInvoke('linscp_foreground_update', {done: 512, total: 1024});
  await nativeInvoke('linscp_foreground_stop');
  const status = await invoke('GET', '/api/status');
  const root = status.local_dir;
  if (!root || !root.includes(${JSON.stringify(application)})) throw new Error('Not using app-private storage: ' + root);
  const mkdir = await invoke('POST', '/api/local/mkdir', {name: 'smoke-download'});
  if (!mkdir.success) throw new Error('Local mkdir failed: ' + JSON.stringify(mkdir));
  const save = await invoke('POST', '/api/local/save', {path: root + '/smoke-upload.txt', content: 'Android Rust-backed transfer'});
  if (!save.success) throw new Error('Local save failed: ' + JSON.stringify(save));
  // Keep one file the harness can look for from the device side: the DevTools
  // check and the sandbox listing then report the same directory instead of
  // trusting the path string alone.
  const marker = await invoke('POST', '/api/local/save', {path: root + '/android-smoke-marker.txt', content: 'android-smoke'});
  if (!marker.success) throw new Error('Marker write failed: ' + JSON.stringify(marker));
  async function verifyAndroidWebViewRendering() {
    const guiState = window.eval('state');
    const previousTabs = guiState.tabs, previousActive = guiState.activeTab;
    const previousEntries = guiState.local.entries, previousSelection = guiState.local.selection;
    const originalRequest = window.LinSCPTransport.request;
    const hostileName = '<img src=x onerror=alert(1)>.txt';
    const saved = await invoke('POST', '/api/local/save', {path: root + '/' + hostileName, content: 'rendering fixture'});
    if (!saved.success) throw new Error('Cannot create rendering fixture');
    try {
      // A real app-private filename crosses the Rust IPC listing boundary.
      const listing = await invoke('GET', '/api/local/list?path=' + encodeURIComponent(root));
      if (!listing.entries?.some(entry => entry.name === hostileName)) throw new Error('Hostile-looking file missing from IPC listing');
      guiState.local.entries = listing.entries;
      guiState.local.selection = new Set();
      window.renderPane('local');
      const pane = document.getElementById('localFileList');
      const hostileRow = Array.from(pane.querySelectorAll('tr')).find(row => row.dataset.name === hostileName);
      if (!hostileRow || !hostileRow.textContent.includes(hostileName) || hostileRow.querySelector('img,svg,[onerror]')) throw new Error('Filename became executable WebView markup');
      guiState.tabs = [{id: '1)\" onmouseover=\"window.__tabPwned=1', name: hostileName, connected: false}];
      guiState.activeTab = null;
      window.renderTabs();
      const tabs = document.getElementById('tabStrip');
      if (!tabs.textContent.includes(hostileName) || tabs.querySelector('img,svg,[onmouseover],[onerror]')) throw new Error('Tab data became executable WebView markup');
      // The real service supplies numeric IDs; override just this response to
      // test the frontend boundary against a malformed IPC payload.
      window.LinSCPTransport.request = function(method, path, body) {
        if (method === 'GET' && path === '/api/transfers') return Promise.resolve({paused: false, transfers: [
          {id: '1)\" onmouseover=\"window.__queuePwned=1', status: 'Queued', type: 'Download'},
          {id: 7, status: 'Running', type: hostileName, source: hostileName, bytes_total: 10, bytes_done: 1, percent: '0\" onmouseover=\"window.__queuePwned=1'}
        ]});
        return originalRequest.call(this, method, path, body);
      };
      await window.refreshQueue();
      const queue = document.getElementById('queueList');
      if (queue.children.length !== 1 || !queue.textContent.includes(hostileName) || queue.querySelector('img,svg,[onmouseover],[onerror]') || queue.querySelector('.progress-bar')?.style.width !== '0%') throw new Error('Malformed queue data became executable WebView markup');
    } finally {
      window.LinSCPTransport.request = originalRequest;
      guiState.tabs = previousTabs; guiState.activeTab = previousActive;
      guiState.local.entries = previousEntries; guiState.local.selection = previousSelection;
      window.renderTabs(); window.renderPane('local');
      await window.refreshQueue();
    }
  }
  await verifyAndroidWebViewRendering();
  const opened = await invoke('POST', '/api/tabs/open', {session: {protocol: 'dav', host: '127.0.0.1', port: ${port}, username: 'testuser', password: 'testpass', local_dir: root, initial_dir: '/'}});
  if (!opened.success || !opened.tab?.connected) throw new Error('WebDAV connect failed: ' + JSON.stringify(opened));
  const tab = opened.tab.id;
  async function waitTransfer(index) {
    for (let i = 0; i < 120; i++) {
      const task = (await invoke('GET', '/api/transfers')).transfers[index];
      if (task?.status === 'Completed') return;
      if (task?.status === 'Failed' || task?.status === 'Cancelled') throw new Error('Transfer failed: ' + JSON.stringify(task));
      await sleep(250);
    }
    throw new Error('Transfer timed out');
  }
  await invoke('POST', '/api/transfer/upload', {tab, local_dir: root, remote_dir: '/', names: ['smoke-upload.txt']});
  await waitTransfer(0);
  await invoke('POST', '/api/transfer/download', {tab, local_dir: root + '/smoke-download', remote_dir: '/', names: ['smoke-upload.txt']});
  await waitTransfer(1);
  const list = await invoke('GET', '/api/local/list?path=' + encodeURIComponent(root + '/smoke-download'));
  if (!list.entries?.some(entry => entry.name === 'smoke-upload.txt')) throw new Error('Downloaded file not listed');
  let conflict = false;
  try { await invoke('POST', '/api/transfer/download', {tab, local_dir: root + '/smoke-download', remote_dir: '/', names: ['smoke-upload.txt']}); }
  catch (error) { conflict = error.status === 409; }
  if (!conflict) throw new Error('Existing download was not protected from overwrite');
  await invoke('GET', '/api/local/list?path=' + encodeURIComponent(root));
  const resumeMkdir = await invoke('POST', '/api/local/mkdir', {tab, name: 'smoke-resume'});
  if (!resumeMkdir.success) throw new Error('Resume mkdir failed: ' + JSON.stringify(resumeMkdir));
  const partialSave = await invoke('POST', '/api/local/save', {path: root + '/smoke-resume/smoke-upload.txt.filepart', content: 'Android'});
  if (!partialSave.success) throw new Error('Partial save failed: ' + JSON.stringify(partialSave));
  await invoke('POST', '/api/transfer/download', {tab, local_dir: root + '/smoke-resume', remote_dir: '/', names: ['smoke-upload.txt'], resume: true});
  await waitTransfer(2);
  const resumedTab = await invoke('POST', '/api/tabs/local', {local_dir: root + '/smoke-resume', remote_dir: root});
  const resumed = await invoke('GET', '/api/local/edit?tab=' + resumedTab.tab.id + '&path=smoke-upload.txt');
  if (resumed.content !== 'Android Rust-backed transfer') throw new Error('Resumed bytes differ');
  // A stale checkpoint and a changed ETag must leave the checkpoint intact
  // and never publish a final file. These calls run inside the Android APK
  // against the disposable WebDAV fixture, not the host-side mock bridge.
  async function verifyAndroidWebDavResumeRefusals() {
    async function waitFailed(index) {
      for (let i = 0; i < 120; i++) {
        const task = (await invoke('GET', '/api/transfers')).transfers[index];
        if (task?.status === 'Failed') return task;
        if (task?.status === 'Completed' || task?.status === 'Cancelled') throw new Error('Expected resume refusal: ' + JSON.stringify(task));
        await sleep(250);
      }
      throw new Error('Expected failed resume task timed out');
    }
    async function makeCheckpoint(dir, partial) {
      const made = await invoke('POST', '/api/local/mkdir', {tab, name: dir});
      if (!made.success) throw new Error('Cannot create resume safety directory: ' + dir);
      const saved = await invoke('POST', '/api/local/save', {path: root + '/' + dir + '/smoke-upload.txt.filepart', content: partial});
      if (!saved.success) throw new Error('Cannot create resume safety checkpoint');
    }
    async function assertCheckpointUnchanged(dir, expected) {
      const dirPath = root + '/' + dir;
      const listing = await invoke('GET', '/api/local/list?path=' + encodeURIComponent(dirPath));
      if (listing.entries?.some(entry => entry.name === 'smoke-upload.txt')) throw new Error('Rejected resume published a final file');
      const localTab = await invoke('POST', '/api/tabs/local', {local_dir: dirPath, remote_dir: root});
      const checkpoint = await invoke('GET', '/api/local/edit?tab=' + localTab.tab.id + '&path=smoke-upload.txt.filepart');
      if (checkpoint.content !== expected) throw new Error('Rejected resume changed its checkpoint');
    }
    await makeCheckpoint('smoke-stale', 'incorrect');
    await invoke('POST', '/api/transfer/download', {tab, local_dir: root + '/smoke-stale', remote_dir: '/', names: ['smoke-upload.txt'], resume: true});
    const stale = await waitFailed(3);
    if (!String(stale.error || '').toLowerCase().includes('match')) throw new Error('Stale prefix failed for an unexpected reason: ' + JSON.stringify(stale));
    await assertCheckpointUnchanged('smoke-stale', 'incorrect');

    await makeCheckpoint('smoke-changed', 'Android');
    await invoke('POST', '/api/queue/pause');
    await invoke('POST', '/api/transfer/download', {tab, local_dir: root + '/smoke-changed', remote_dir: '/', names: ['smoke-upload.txt'], resume: true});
    // Change the remote bytes after the task pins the ETag but before it runs.
    const changed = await invoke('POST', '/api/remote/save', {tab, path: '/smoke-upload.txt', content: 'Android Xust-backed transfer'});
    if (!changed.success) throw new Error('Cannot change the remote fixture: ' + JSON.stringify(changed));
    await invoke('POST', '/api/queue/resume');
    const changedTask = await waitFailed(4);
    if (!/etag|precondition|changed|conditional prefix range/i.test(String(changedTask.error || ''))) throw new Error('Changed representation failed for an unexpected reason: ' + JSON.stringify(changedTask));
    await assertCheckpointUnchanged('smoke-changed', 'Android');
  }
  await verifyAndroidWebDavResumeRefusals();
  const local = await invoke('POST', '/api/tabs/local', {local_dir: root + '/smoke-download', remote_dir: root});
  const contents = await invoke('GET', '/api/local/edit?tab=' + local.tab.id + '&path=smoke-upload.txt');
  if (contents.content !== 'Android Rust-backed transfer') throw new Error('Downloaded bytes differ');
  await invoke('POST', '/api/local/rename', {tab: local.tab.id, old_name: 'smoke-upload.txt', new_name: 'renamed.txt'});
  const vault = await invoke('GET', '/api/vault/status');
  if (vault.vault !== 'setup_required') throw new Error('Expected a fresh emulator vault: ' + JSON.stringify(vault));
  await invoke('POST', '/api/vault/unlock', {password: 'android smoke vault password'});
  const savedSite = await invoke('POST', '/api/sessions/save', {name: 'android-smoke-vault-site', session: {protocol: 'dav', host: '127.0.0.1', port: ${port}, username: 'testuser', password: 'testpass', local_dir: root, initial_dir: '/'}});
  if (!savedSite.success) throw new Error('Cannot save Android vault site');
  const locked = await invoke('POST', '/api/vault/lock');
  if (!locked.success || (await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Vault did not lock');
  return {transport: window.LinSCPTransport.mode, root, title: document.title, upload: true, download: true, resume: true, resumeSafetyRefusals: true, conflict: true, externalUriValidation: true, webViewRendering: true};
})()`;
let nextId = 0;
async function evaluate(expression, timeout = 10000) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('DevTools evaluation timed out')), timeout);
    socket.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.id !== id) return;
      clearTimeout(timer);
      resolve(message);
    };
    socket.onerror = reject;
    socket.send(JSON.stringify({id, method: 'Runtime.evaluate', params: {expression, awaitPromise: true, returnByValue: true}}));
  });
}
// Tauri can navigate its initial document while the DevTools endpoint is
// already available. Only start mutating state after two stable ready probes.
let stable = 0;
for (let i = 0; i < 60 && stable < 2; i++) {
  const probe = await evaluate("document.readyState === 'complete' && window.LinSCPTransport?.mode === 'tauri'");
  stable = probe.result?.result?.value === true ? stable + 1 : 0;
  if (stable < 2) await new Promise(resolve => setTimeout(resolve, 1000));
}
assert.equal(stable, 2, 'WebView did not become ready');
const reply = await evaluate(expression, ['backup-restore', 'portable-export', 'portable-setup', 'portable-import', 'portable-reopen'].includes(phase) ? 300000 : 120000);
socket.close();
if (reply.error || reply.result?.exceptionDetails) throw new Error(JSON.stringify(reply));
if (phase === 'portable-export') {
  const value = reply.result.result.value;
  assert.ok(typeof value.portableData?.backupBase64 === 'string' && value.portableData.backupBase64.length > 0, 'portable backup missing');
  writeFileSync(portableFile, JSON.stringify(value.portableData), {mode: 0o600});
  delete value.portableData; // never print backup bytes in CI logs
}
if (rootFile && phase !== 'damaged-journal') writeFileSync(rootFile, String(reply.result.result.value.root));
console.log('Android WebView and Rust service smoke test passed:', JSON.stringify(reply.result.result.value));
