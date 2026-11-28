// Runs against the debug WebView through Chrome DevTools. The WebDAV fixture
// is reached through adb reverse; all IPC executes inside the installed APK.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
const port = Number(process.argv[2]);
const sshPort = Number(process.env.LINSCP_ANDROID_SSH_PORT);
assert.ok(Number.isInteger(sshPort) && sshPort > 0 && sshPort < 65536, 'SSH fixture port is required');
const fixtureKey = process.env.LINSCP_ANDROID_SSH_KEY_B64;
assert.ok(fixtureKey && /^[A-Za-z0-9+/=]+$/.test(fixtureKey), 'disposable SSH fixture key is required');
// The installed package, handed over by the harness that read it from the
// configuration, so the storage this run finds is the storage of *this* app.
const application = process.argv[3];
// Where to record the app-private root the service reported, so the harness can
// compare it with the directory the device reports for the installed package.
const rootFile = process.argv[4];
const phase = process.argv[5] || 'initial';
assert.ok(['initial', 'reopen-vault', 'tampered-key', 'tampered-sessions', 'backup-restore', 'portable-export', 'portable-setup', 'portable-import', 'portable-reopen', 'damaged-journal', 'saf-pick-start', 'saf-pick-finish', 'saf-reopen', 'share-fail', 'share-intent', 'bio-setup', 'bio-enroll-start', 'bio-enroll-finish', 'bio-unlock-start', 'bio-wrong-check', 'bio-unlock-finish', 'bio-invalidated'].includes(phase), 'unknown smoke phase');
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
  async function verifyAndroidBiometrics() {
    const phase = ${JSON.stringify(phase)};
    const native = window.__TAURI_INTERNALS__;
    const root = (await invoke('GET', '/api/status')).local_dir;
    if (phase === 'bio-setup') {
      if ((await invoke('GET', '/api/vault/status')).vault !== 'setup_required') throw new Error('Biometric fixture expected a fresh vault');
      await invoke('POST', '/api/vault/unlock', {password: 'different destination vault password'});
      await invoke('POST', '/api/sessions/save', {name: 'android-smoke-vault-site', session: {protocol: 'dav', host: '127.0.0.1', port: ${port}, username: 'testuser', password: 'testpass', local_dir: root, initial_dir: '/'}});
      return {root, biometricFixture: true};
    }
    if (phase === 'bio-enroll-start') {
      if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Biometric enrollment expected a locked vault');
      await invoke('POST', '/api/vault/unlock', {password: 'different destination vault password'});
      const status = await native.invoke('linscp_biometric_status');
      if (!status.available || status.enabled) throw new Error('Enrolled emulator fingerprint unavailable: ' + JSON.stringify(status));
      window.__bioResult = native.invoke('linscp_biometric_enroll', {password: 'different destination vault password'}).then(() => ({ok: true}), error => ({ok: false, error: String(error)}));
      return {root, biometricPrompt: 'enroll'};
    }
    if (phase === 'bio-enroll-finish') {
      const result = await window.__bioResult;
      if (!result.ok || !(await native.invoke('linscp_biometric_status')).enabled) throw new Error('Biometric enrollment failed: ' + JSON.stringify(result));
      // The password-bearing native plugin must not be callable directly from
      // the WebView; only the Rust command may consume the decrypted password.
      const direct = await Promise.race([
        native.invoke('plugin:linscp-android|biometricUnlock').then(() => 'accepted', () => 'refused'),
        sleep(3000).then(() => 'pending'),
      ]);
      if (direct !== 'refused') throw new Error('WebView could invoke password-bearing biometric plugin: ' + direct);
      return {root, biometricEnrolled: true, directPluginRefused: true};
    }
    if (phase === 'bio-invalidated') {
      if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Invalidation test expected locked vault');
      let refused = false;
      try { await native.invoke('linscp_biometric_unlock'); } catch (_) { refused = true; }
      if (!refused || (await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Enrollment change did not invalidate biometric unlock');
      await invoke('POST', '/api/vault/unlock', {password: 'different destination vault password'});
      const opened = await invoke('POST', '/api/tabs/open', {site_name: 'android-smoke-vault-site'});
      if (!opened.tab?.connected) throw new Error('Password recovery after biometric invalidation failed');
      await invoke('POST', '/api/tabs/close', {tab: opened.tab.id});
      await native.invoke('linscp_biometric_disable');
      return {root, enrollmentChangeInvalidated: true, passwordRecovery: true};
    }
    if (phase === 'bio-unlock-start') {
      if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Biometric unlock expected a locked vault');
      if (!(await native.invoke('linscp_biometric_status')).enabled) throw new Error('Biometric enrollment did not survive restart');
      window.__bioResult = native.invoke('linscp_biometric_unlock').then(() => ({ok: true}), error => ({ok: false, error: String(error)}));
      return {root, biometricPrompt: 'unlock'};
    }
    if (phase === 'bio-wrong-check') {
      if ((await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Unenrolled fingerprint unlocked the vault');
      return {root, wrongFingerprintRefused: true};
    }
    const result = await window.__bioResult;
    if (!result.ok || (await invoke('GET', '/api/vault/status')).vault !== 'unlocked') throw new Error('Biometric vault unlock failed: ' + JSON.stringify(result));
    const opened = await invoke('POST', '/api/tabs/open', {site_name: 'android-smoke-vault-site'});
    if (!opened.tab?.connected) throw new Error('Biometric unlock did not recover saved credentials');
    await invoke('POST', '/api/tabs/close', {tab: opened.tab.id});
    await native.invoke('linscp_biometric_disable');
    if ((await native.invoke('linscp_biometric_status')).enabled) throw new Error('Biometric disable left the credential enabled');
    await invoke('POST', '/api/vault/lock');
    let refused = false;
    try { await native.invoke('linscp_biometric_unlock'); } catch (_) { refused = true; }
    if (!refused || (await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Disabled biometrics still unlocked the vault');
    await invoke('POST', '/api/vault/unlock', {password: 'different destination vault password'});
    return {root, biometricUnlock: true, savedCredentialRecovered: true, disableAndPasswordFallback: true};
  }
  if (${JSON.stringify(phase)}.startsWith('bio-')) return await verifyAndroidBiometrics();
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
    if (sessions.sessions.some(site => site.name.startsWith('android-site-manager/'))) throw new Error('Deleted site manager fixtures returned after restart');
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
    // This disposable key is authorized only by the test SFTP server. The
    // backup must restore usable private key bytes, not just its metadata.
    const keyFixture = atob(${JSON.stringify(fixtureKey)});
    if (phase === 'portable-export') {
      const key = await invoke('POST', '/api/vault/keys/import', {name: 'portable-fixture-key', private_key: keyFixture});
      if (!key.success || !(key.reference?.startsWith('vaultkey://') && /^[a-f0-9]{32}$/.test(key.reference.slice(11)))) throw new Error('Fixture key import failed');
      await invoke('POST', '/api/sessions/save', {name: 'portable-key-site', session: {protocol: 'sftp', host: '127.0.0.1', port: ${sshPort}, username: 'testuser', keyfile: key.reference, local_dir: root, initial_dir: '/'}});
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
    let sshConnection;
    try { sshConnection = await invoke('POST', '/api/tabs/open', {site_name: 'portable-key-site'}); }
    catch (error) {
      if (error.status !== 409 || !error.payload?.challenge) throw error;
      const challenge = error.payload.challenge;
      if (challenge.host !== '127.0.0.1' || challenge.port !== ${sshPort}) throw new Error('Unexpected SSH fixture host-key challenge');
      sshConnection = await invoke('POST', '/api/tabs/verify', {tab: challenge.tab, role: challenge.role, fingerprint: challenge.fingerprint, remember: false});
    }
    if (!sshConnection.tab?.connected) throw new Error('Restored private key failed SFTP authentication');
    const sshList = await invoke('GET', '/api/remote/list?tab=' + sshConnection.tab.id + '&path=' + encodeURIComponent('/'));
    if (!Array.isArray(sshList.entries)) throw new Error('Restored SSH connection could not list the fixture');
    await invoke('POST', '/api/tabs/close', {tab: sshConnection.tab.id});
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
  async function verifyAndroidGrantedSafEditing() {
    const phase = ${JSON.stringify(phase)};
    if (phase === 'saf-pick-start') {
      // Do not await: the host must drive the real system picker before the
      // pending activity-result promise can resolve.
      window.__smokeSafPicker = window.__TAURI_INTERNALS__.invoke('linscp_pick_saf_tree');
      return {safPickerStarted: true};
    }
    const roots = await invoke('GET', '/api/local/roots');
    let tree;
    if (phase === 'saf-pick-finish') {
      const picked = await window.__smokeSafPicker;
      if (!picked.success || picked.cancelled || !picked.uri) throw new Error('System picker did not grant a folder');
      tree = picked.uri;
      if (!tree.includes('LinSCP-Ungranted-Smoke')) throw new Error('Picker returned the wrong folder: ' + tree);
    } else {
      tree = roots.roots?.find(entry => entry.kind === 'saf_tree' && entry.path.includes('LinSCP-Ungranted-Smoke'))?.path;
    }
    if (!tree) throw new Error('Persisted SAF root missing');
    const rootsAfter = await invoke('GET', '/api/local/roots');
    if (!rootsAfter.roots?.some(entry => entry.path === tree && !entry.read_only)) throw new Error('Writable SAF root not listed');
    const root = (await invoke('GET', '/api/status')).local_dir;
    const localTab = await invoke('POST', '/api/tabs/local', {local_dir: tree, remote_dir: root});
    const tab = localTab.tab.id;
    const listing = await invoke('GET', '/api/local/list?tab=' + tab + '&path=' + encodeURIComponent(tree));
    if (!listing.entries?.some(entry => entry.name === 'marker.txt')) throw new Error('SAF provider did not list marker');
    const before = await invoke('GET', '/api/local/edit?tab=' + tab + '&path=marker.txt');
    const expected = phase === 'saf-pick-finish' ? 'saf-original' : 'saf-edited';
    if (before.content !== expected) throw new Error('Unexpected provider bytes');
    if (phase === 'saf-pick-finish') {
      // A later invalid URI must roll back the first staged provider file.
      const document = tree + '/document/' + encodeURIComponent('primary:Documents/LinSCP-Ungranted-Smoke/marker.txt');
      let refusal = '';
      try { await window.__TAURI_INTERNALS__.invoke('linscp_handle_share_intent', {uris: [document, 'file:///not-a-content-uri']}); }
      catch (error) { refusal = String(error); }
      if (!refusal.includes('only content URIs')) throw new Error('Mixed share did not reach the invalid second URI: ' + refusal);
      const stale = String(BigInt(before.info.mtime) * 1000000000n - 1n);
      let rejected;
      try { await invoke('POST', '/api/local/save', {tab, path: 'marker.txt', content: 'stale write', base_mtime_ns: stale}); }
      catch (error) { rejected = error.status === 400; }
      if (!rejected) throw new Error('Stale SAF editor save was not refused');
      await invoke('POST', '/api/local/save', {tab, path: 'marker.txt', content: 'saf-edited'});
      const edited = await invoke('GET', '/api/local/edit?tab=' + tab + '&path=marker.txt');
      if (edited.content !== 'saf-edited') throw new Error('SAF edited bytes differ');
      await invoke('POST', '/api/local/save', {tab, path: 'created.txt', content: 'created via SAF'});
      const created = await invoke('GET', '/api/local/edit?tab=' + tab + '&path=created.txt');
      if (created.content !== 'created via SAF') throw new Error('SAF created bytes differ');
      const properties = await invoke('POST', '/api/local/properties', {tab, names: ['created.txt']});
      if (properties.properties?.[0]?.name !== 'created.txt' || properties.properties[0].size !== 15 || properties.properties[0].is_dir) throw new Error('SAF file properties differ: ' + JSON.stringify(properties));
      await verifyAndroidSafEditorBoundary(tree, tab, root);
      await verifyAndroidGrantedSafTransfers(tree, tab, root);
    }
    return {root, safEditing: phase};
  }
  async function verifyAndroidSafEditorBoundary(tree, tab, root) {
    await invoke('POST', '/api/local/mkdir', {tab, name: 'editor-boundary'});
    const subdir = tree + '/document/editor-boundary';
    const nested = await invoke('POST', '/api/tabs/local', {local_dir: subdir, remote_dir: root});
    const nestedTab = nested.tab.id;
    await invoke('POST', '/api/local/save', {tab: nestedTab, path: 'inside.txt', content: 'inside'});
    const own = subdir + '/document/inside.txt';
    const read = await invoke('GET', '/api/local/edit?tab=' + nestedTab + '&path=' + encodeURIComponent(own));
    if (read.content !== 'inside') throw new Error('SAF pane cannot open its direct child');
    // A literal name equal to the URI separator is still a name.
    await invoke('POST', '/api/local/mkdir', {tab: nestedTab, name: 'document'});
    const documentDir = subdir + '/document/document';
    const docTab = (await invoke('POST', '/api/tabs/local', {local_dir: documentDir, remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/save', {tab: docTab, path: 'document', content: 'literal document'});
    const literal = await invoke('GET', '/api/local/edit?tab=' + docTab + '&path=document');
    if (literal.content !== 'literal document') throw new Error('SAF literal document name did not resolve');
    const sibling = tree + '/document/marker.txt';
    for (const method of ['read', 'save']) {
      let refused = false;
      try {
        if (method === 'read') await invoke('GET', '/api/local/edit?tab=' + nestedTab + '&path=' + encodeURIComponent(sibling));
        else await invoke('POST', '/api/local/save', {tab: nestedTab, path: sibling, content: 'outside overwrite'});
      } catch (error) { refused = error.status === 400; }
      if (!refused) throw new Error('SAF pane accepted a sibling editor ' + method);
    }
    // Shared storage IDs are absolute within the grant. A provider can resolve
    // a grandchild's ID directly, even though it is not a direct child of the
    // root pane. The bridge must walk the root's child listing instead.
    const grantId = decodeURIComponent(tree.split('/tree/')[1]);
    const directChild = tree + '/document/' + encodeURIComponent(grantId + '/marker.txt');
    const marker = await invoke('GET', '/api/local/edit?tab=' + tab + '&path=' + encodeURIComponent(directChild));
    if (marker.content !== 'saf-edited') throw new Error('Direct child provider ID did not resolve');
    const descendantAlias = tree + '/document/' + encodeURIComponent(grantId + '/editor-boundary/inside.txt');
    let aliasRefused = false;
    try { await invoke('GET', '/api/local/edit?tab=' + tab + '&path=' + encodeURIComponent(descendantAlias)); }
    catch (error) { aliasRefused = error.status === 400; }
    if (!aliasRefused) throw new Error('SAF pane accepted a descendant document ID as a direct child');
    const unchanged = await invoke('GET', '/api/local/edit?tab=' + tab + '&path=marker.txt');
    if (unchanged.content !== 'saf-edited') throw new Error('Refused sibling save changed provider bytes');
  }
  async function verifyAndroidGrantedSafTransfers(tree, localTab, root) {
    const opened = await invoke('POST', '/api/tabs/open', {session: {protocol: 'dav', host: '127.0.0.1', port: ${port}, username: 'testuser', password: 'testpass', local_dir: root, initial_dir: '/'}});
    if (!opened.tab?.connected) throw new Error('Cannot open WebDAV for SAF transfers');
    const tab = opened.tab.id;
    async function runTask(path, body) {
      const previous = new Set((await invoke('GET', '/api/transfers')).transfers.map(task => task.id));
      const reply = await invoke('POST', path, body);
      if (!reply.success) throw new Error('SAF transfer was not queued');
      for (let i = 0; i < 120; i++) {
        const task = (await invoke('GET', '/api/transfers')).transfers.find(task => !previous.has(task.id));
        if (task?.status === 'Completed') return;
        if (task?.status === 'Failed' || task?.status === 'Cancelled') throw new Error('SAF transfer failed: ' + JSON.stringify(task));
        await sleep(250);
      }
      throw new Error('SAF transfer timed out');
    }
    await verifyAndroidGrantedSafLocalCopyMove(tree, localTab, root, runTask);
    await runTask('/api/transfer/upload', {tab, local_dir: tree, remote_dir: '/', names: ['created.txt']});
    const remote = await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/created.txt'));
    if (remote.content !== 'created via SAF') throw new Error('SAF upload bytes differ on WebDAV');
    await invoke('POST', '/api/remote/save', {tab, path: '/saf-down.txt', content: 'download into SAF'});
    let refused = false;
    try { await invoke('POST', '/api/transfer/download', {tab, local_dir: tree, remote_dir: '/', names: ['saf-down.txt'], resume: true}); }
    catch (error) { refused = error.status === 400 && /verified resume.*granted folders/i.test(error.message || ''); }
    if (!refused) throw new Error('Verified resume into a granted folder was not refused');
    await runTask('/api/transfer/download', {tab, local_dir: tree, remote_dir: '/', names: ['saf-down.txt']});
    const downloaded = await invoke('GET', '/api/local/edit?tab=' + localTab + '&path=saf-down.txt');
    if (downloaded.content !== 'download into SAF') throw new Error('SAF download bytes differ');
    let conflict = false;
    try { await invoke('POST', '/api/transfer/download', {tab, local_dir: tree, remote_dir: '/', names: ['saf-down.txt']}); }
    catch (error) { conflict = error.status === 409; }
    if (!conflict || (await invoke('GET', '/api/local/edit?tab=' + localTab + '&path=saf-down.txt')).content !== 'download into SAF') throw new Error('Existing SAF destination was not protected');
    await invoke('POST', '/api/remote/save', {tab, path: '/saf-move.txt', content: 'move into SAF'});
    await runTask('/api/transfer/move', {tab, direction: 'download', local_dir: tree, remote_dir: '/', names: ['saf-move.txt']});
    const moved = await invoke('GET', '/api/local/edit?tab=' + localTab + '&path=saf-move.txt');
    if (moved.content !== 'move into SAF') throw new Error('SAF move bytes differ');
    const listing = await invoke('GET', '/api/remote/list?tab=' + tab + '&path=' + encodeURIComponent('/'));
    if (listing.entries?.some(entry => entry.name === 'saf-move.txt')) throw new Error('WebDAV move did not delete its source');
    await verifyAndroidRemoteEditingAndInterruptedDelete(tab);
    await verifyAndroidGrantedSafSync(tree, localTab, root, tab, runTask);
    await verifyAndroidGrantedSafNestedSync(tree, localTab, root, tab, runTask);
    await verifyAndroidGrantedSafTreeTransfers(tree, localTab, root, tab, runTask);
    await verifyAndroidGrantedSafDocumentCap(tree, root, tab);
  }
  async function verifyAndroidRemoteEditingAndInterruptedDelete(tab) {
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'android-encoding'});
    await invoke('POST', '/api/remote/save', {tab, path: '/android-encoding/legacy.txt', content: 'café\\r\\n', encoding: 'windows-1252', eol: 'crlf'});
    let refused = false;
    try { await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/android-encoding/legacy.txt')); }
    catch (error) { refused = error.status === 400; }
    if (!refused) throw new Error('Non-UTF-8 remote file opened as UTF-8');
    const edit = await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/android-encoding/legacy.txt') + '&encoding=windows-1252');
    if (edit.content !== 'café\\r\\n' || edit.info.encoding !== 'windows-1252') throw new Error('Remote legacy text decoded incorrectly');
    const search = await invoke('POST', '/api/remote/search', {tab, path: '/android-encoding', pattern: '*.txt', search_contents: true, content_query: 'café', encoding: 'windows-1252'});
    if (search.matches?.length !== 1 || search.matches[0].name !== 'legacy.txt') throw new Error('Remote legacy text search failed: ' + JSON.stringify(search));
    await invoke('POST', '/api/remote/save', {tab, path: '/android-encoding/legacy.txt', content: 'naïve\\n', encoding: 'windows-1252', eol: 'crlf', base_mtime: edit.info.mtime});
    const saved = await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/android-encoding/legacy.txt') + '&encoding=windows-1252');
    if (saved.content !== 'naïve\\r\\n') throw new Error('Remote legacy text save failed');
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'android-partial'});
    for (const name of ['a.txt', 'b.txt']) await invoke('POST', '/api/remote/save', {tab, path: '/android-partial/' + name, content: name});
    await invoke('POST', '/api/remote/save', {tab, path: '/android-other.txt', content: 'other'});
    const result = await invoke('POST', '/api/remote/delete', {tab, names: ['android-other.txt', 'android-partial']});
    if (result.deleted?.join(',') !== 'android-other.txt' || result.failed?.[0]?.name !== 'android-partial' || !/partially deleted/.test(result.failed[0].error)) throw new Error('Interrupted remote delete was not reported: ' + JSON.stringify(result));
    const remaining = await invoke('GET', '/api/remote/list?tab=' + tab + '&path=' + encodeURIComponent('/android-partial'));
    if (remaining.entries?.some(entry => entry.name === 'a.txt') || !remaining.entries?.some(entry => entry.name === 'b.txt')) throw new Error('Interrupted delete did not leave expected partial tree');
  }
  async function verifyAndroidGrantedSafDocumentCap(tree, root, tab) {
    const dir = tree + '/document/cap-fixture';
    const local = (await invoke('POST', '/api/tabs/local', {local_dir: dir, remote_dir: root})).tab.id;
    const entries = (await invoke('GET', '/api/local/list?tab=' + local + '&path=' + encodeURIComponent(dir))).entries;
    if (!entries?.some(entry => entry.name === 'oversize.bin' && entry.size === 67108865)) throw new Error('Provider cap fixture missing or wrong size: ' + JSON.stringify(entries));
    async function expectCap(path, body) {
      let refused = false;
      try { await invoke('POST', path, body); }
      catch (error) { refused = error.status === 400 && /oversize[.]bin/.test(error.message || '') && /64 MiB/.test(error.message || ''); }
      if (!refused) throw new Error('Expected named provider document-cap refusal from ' + path);
    }
    // The remote fixture is independently served by WebDAV and is one byte
    // over the provider limit. Refuse both copy and move before queuing, and
    // ensure the source survives (especially the destructive move path).
    const remoteName = 'oversize-download.bin';
    const beforeQueue = (await invoke('GET', '/api/transfers')).transfers.length;
    for (const [path, extra] of [['/api/transfer/download', {}], ['/api/transfer/move', {direction: 'download'}]]) {
      let refused = false;
      try { await invoke('POST', path, {tab, local_dir: tree, remote_dir: '/', names: [remoteName], ...extra}); }
      catch (error) { refused = error.status === 400 && (error.message || '').includes(remoteName) && /64 MiB/.test(error.message || ''); }
      if (!refused) throw new Error('Expected over-cap WebDAV to SAF refusal from ' + path);
    }
    if ((await invoke('GET', '/api/transfers')).transfers.length !== beforeQueue) throw new Error('Over-cap SAF download was queued');
    const rootSafTab = (await invoke('POST', '/api/tabs/local', {local_dir: tree, remote_dir: root})).tab.id;
    const target = (await invoke('GET', '/api/local/list?tab=' + rootSafTab + '&path=' + encodeURIComponent(tree))).entries;
    if (target?.some(entry => entry.name === remoteName)) throw new Error('Over-cap download created a provider document');
    const source = (await invoke('GET', '/api/remote/list?tab=' + tab + '&path=' + encodeURIComponent('/'))).entries;
    if (!source?.some(entry => entry.name === remoteName && entry.size === 67108865)) throw new Error('Over-cap move altered the WebDAV source');
    await expectCap('/api/transfer/upload', {tab, local_dir: dir, remote_dir: '/', names: ['oversize.bin']});
    await expectCap('/api/transfer/upload', {tab: local, local_dir: dir, remote_dir: root, names: ['oversize.bin']});
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'cap-fixture'});
    await invoke('POST', '/api/remote/save', {tab, path: '/cap-fixture/oversize.bin', content: 'small remote fixture'});
    await expectCap('/api/sync/preview', {tab, local_dir: dir, remote_dir: '/cap-fixture', mode: 'remote', criteria: 'checksum'});
    const remote = await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/cap-fixture/oversize.bin'));
    if (remote.content !== 'small remote fixture') throw new Error('Cap refusal changed remote file');
    const after = (await invoke('GET', '/api/local/list?tab=' + local + '&path=' + encodeURIComponent(dir))).entries;
    if (!after?.some(entry => entry.name === 'oversize.bin' && entry.size === 67108865)) throw new Error('Cap refusal changed provider file');
    const rootTab = (await invoke('POST', '/api/tabs/local', {local_dir: root, remote_dir: dir})).tab.id;
    const privateFiles = (await invoke('GET', '/api/local/list?tab=' + rootTab + '&path=' + encodeURIComponent(root))).entries;
    if (privateFiles?.some(entry => entry.name === 'oversize.bin')) throw new Error('Cap refusal left a local destination');
  }
  async function verifyAndroidGrantedSafTreeTransfers(tree, localTab, root, tab, runTask) {
    await invoke('POST', '/api/local/mkdir', {tab: localTab, name: 'transfer-tree-up'});
    const up = tree + '/document/transfer-tree-up';
    const upTab = (await invoke('POST', '/api/tabs/local', {local_dir: up, remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/mkdir', {tab: upTab, name: 'nested'});
    const child = (await invoke('POST', '/api/tabs/local', {local_dir: up + '/document/nested', remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/save', {tab: child, path: 'up.txt', content: 'provider tree upload'});
    const upload = {tab, local_dir: tree, remote_dir: '/', names: ['transfer-tree-up']};
    let refused = false;
    try { await invoke('POST', '/api/transfer/upload', upload); }
    catch (error) { refused = error.status === 409 && error.payload?.directory_copy_risk; }
    if (!refused) throw new Error('WebDAV tree upload did not require risk confirmation');
    await runTask('/api/transfer/upload', {...upload, accept_directory_copy_risk: true});
    if ((await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/transfer-tree-up/nested/up.txt'))).content !== 'provider tree upload') throw new Error('SAF tree upload differs');
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'transfer-tree-down'});
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/transfer-tree-down', name: 'nested'});
    await invoke('POST', '/api/remote/save', {tab, path: '/transfer-tree-down/nested/down.txt', content: 'provider tree download'});
    const download = {tab, local_dir: tree, remote_dir: '/', names: ['transfer-tree-down']};
    refused = false;
    try { await invoke('POST', '/api/transfer/download', download); }
    catch (error) { refused = error.status === 409 && error.payload?.directory_copy_risk; }
    if (!refused) throw new Error('WebDAV tree download did not require risk confirmation');
    await runTask('/api/transfer/download', {...download, accept_directory_copy_risk: true});
    const down = (await invoke('POST', '/api/tabs/local', {local_dir: tree + '/document/transfer-tree-down/document/nested', remote_dir: root})).tab.id;
    if ((await invoke('GET', '/api/local/edit?tab=' + down + '&path=down.txt')).content !== 'provider tree download') throw new Error('SAF tree download differs');
    await invoke('POST', '/api/local/mkdir', {tab: localTab, name: 'transfer-merge'});
    const mergeDir = tree + '/document/transfer-merge';
    const mergeTab = (await invoke('POST', '/api/tabs/local', {local_dir: mergeDir, remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/save', {tab: mergeTab, path: 'keep.txt', content: 'keep provider bytes'});
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'transfer-merge'});
    await invoke('POST', '/api/remote/save', {tab, path: '/transfer-merge/new.txt', content: 'merged server bytes'});
    const merge = {tab, local_dir: tree, remote_dir: '/', names: ['transfer-merge'], accept_directory_copy_risk: true};
    refused = false;
    try { await invoke('POST', '/api/transfer/download', merge); }
    catch (error) { refused = error.status === 409 && error.payload?.directory_conflicts?.includes('transfer-merge'); }
    if (!refused) throw new Error('SAF tree merge did not require confirmation');
    await runTask('/api/transfer/download', {...merge, merge_directories: ['transfer-merge']});
    if ((await invoke('GET', '/api/local/edit?tab=' + mergeTab + '&path=keep.txt')).content !== 'keep provider bytes' ||
        (await invoke('GET', '/api/local/edit?tab=' + mergeTab + '&path=new.txt')).content !== 'merged server bytes') throw new Error('SAF tree merge did not preserve and add files');
    await invoke('POST', '/api/remote/save', {tab, path: '/transfer-merge/keep.txt', content: 'must not overwrite provider'});
    const previous = new Set((await invoke('GET', '/api/transfers')).transfers.map(task => task.id));
    const reply = await invoke('POST', '/api/transfer/download', {...merge, merge_directories: ['transfer-merge']});
    if (!reply.success) throw new Error('SAF conflicting tree merge was not queued');
    let failed = false;
    for (let i = 0; i < 120; i++) {
      const task = (await invoke('GET', '/api/transfers')).transfers.find(item => !previous.has(item.id));
      if (task?.status === 'Failed') { failed = true; break; }
      if (task?.status === 'Completed' || task?.status === 'Cancelled') throw new Error('Conflicting SAF merge unexpectedly finished: ' + JSON.stringify(task));
      await sleep(250);
    }
    if (!failed || (await invoke('GET', '/api/local/edit?tab=' + mergeTab + '&path=keep.txt')).content !== 'keep provider bytes') throw new Error('SAF conflicting tree merge did not preserve destination');
    await invoke('POST', '/api/local/mkdir', {tab: localTab, name: 'transfer-merge-up'});
    const mergeUpDir = tree + '/document/transfer-merge-up';
    const mergeUpTab = (await invoke('POST', '/api/tabs/local', {local_dir: mergeUpDir, remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/save', {tab: mergeUpTab, path: 'new.txt', content: 'merged provider bytes'});
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'transfer-merge-up'});
    await invoke('POST', '/api/remote/save', {tab, path: '/transfer-merge-up/keep.txt', content: 'keep server bytes'});
    const mergeUp = {tab, local_dir: tree, remote_dir: '/', names: ['transfer-merge-up'], accept_directory_copy_risk: true};
    refused = false;
    try { await invoke('POST', '/api/transfer/upload', mergeUp); }
    catch (error) { refused = error.status === 409 && error.payload?.directory_conflicts?.includes('transfer-merge-up'); }
    if (!refused) throw new Error('SAF upload tree merge did not require confirmation');
    await runTask('/api/transfer/upload', {...mergeUp, merge_directories: ['transfer-merge-up']});
    const remoteKeep = '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/transfer-merge-up/keep.txt');
    const remoteNew = '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/transfer-merge-up/new.txt');
    if ((await invoke('GET', remoteKeep)).content !== 'keep server bytes' || (await invoke('GET', remoteNew)).content !== 'merged provider bytes') throw new Error('SAF upload tree merge did not preserve and add files');
    await invoke('POST', '/api/local/save', {tab: mergeUpTab, path: 'keep.txt', content: 'must not overwrite server'});
    const beforeUploadConflict = new Set((await invoke('GET', '/api/transfers')).transfers.map(task => task.id));
    const conflictUpload = await invoke('POST', '/api/transfer/upload', {...mergeUp, merge_directories: ['transfer-merge-up']});
    if (!conflictUpload.success) throw new Error('Conflicting SAF upload merge was not queued');
    failed = false;
    for (let i = 0; i < 120; i++) {
      const task = (await invoke('GET', '/api/transfers')).transfers.find(item => !beforeUploadConflict.has(item.id));
      if (task?.status === 'Failed') { failed = true; break; }
      if (task?.status === 'Completed' || task?.status === 'Cancelled') throw new Error('Conflicting SAF upload merge unexpectedly finished: ' + JSON.stringify(task));
      await sleep(250);
    }
    if (!failed || (await invoke('GET', remoteKeep)).content !== 'keep server bytes') throw new Error('Conflicting SAF upload merge did not preserve destination');
  }
  async function verifyAndroidGrantedSafLocalCopyMove(tree, safTab, root, runTask) {
    const rootTab = (await invoke('POST', '/api/tabs/local', {local_dir: root, remote_dir: tree})).tab.id;
    await invoke('POST', '/api/local/mkdir', {tab: rootTab, name: 'saf-local-copy'});
    const plain = root + '/saf-local-copy';
    const plainTab = (await invoke('POST', '/api/tabs/local', {local_dir: plain, remote_dir: tree})).tab.id;
    await invoke('POST', '/api/local/save', {tab: safTab, path: 'provider-copy.txt', content: 'provider copy bytes'});
    await runTask('/api/transfer/upload', {tab: safTab, local_dir: tree, remote_dir: plain, names: ['provider-copy.txt']});
    if ((await invoke('GET', '/api/local/edit?tab=' + plainTab + '&path=provider-copy.txt')).content !== 'provider copy bytes') throw new Error('SAF to local copy differs');
    await invoke('POST', '/api/local/save', {tab: plainTab, path: 'plain-move.txt', content: 'plain move bytes'});
    await runTask('/api/transfer/move', {tab: plainTab, direction: 'upload', local_dir: plain, remote_dir: tree, names: ['plain-move.txt']});
    if ((await invoke('GET', '/api/local/edit?tab=' + safTab + '&path=plain-move.txt')).content !== 'plain move bytes') throw new Error('Local to SAF move differs');
    const plainList = await invoke('GET', '/api/local/list?tab=' + plainTab + '&path=' + encodeURIComponent(plain));
    if (plainList.entries?.some(entry => entry.name === 'plain-move.txt')) throw new Error('Local move source remains');
    await invoke('POST', '/api/local/save', {tab: plainTab, path: 'provider-copy.txt', content: 'protected destination'});
    let refused = false;
    try { await invoke('POST', '/api/transfer/move', {tab: safTab, direction: 'upload', local_dir: tree, remote_dir: plain, names: ['provider-copy.txt']}); }
    catch (error) { refused = error.status === 409; }
    if (!refused || (await invoke('GET', '/api/local/edit?tab=' + safTab + '&path=provider-copy.txt')).content !== 'provider copy bytes' || (await invoke('GET', '/api/local/edit?tab=' + plainTab + '&path=provider-copy.txt')).content !== 'protected destination') throw new Error('Conflicting SAF move did not preserve both files');
    await runTask('/api/transfer/upload', {tab: safTab, local_dir: tree, remote_dir: plain, names: ['editor-boundary']});
    const nested = (await invoke('POST', '/api/tabs/local', {local_dir: plain + '/editor-boundary', remote_dir: tree})).tab.id;
    if ((await invoke('GET', '/api/local/edit?tab=' + nested + '&path=inside.txt')).content !== 'inside') throw new Error('Nested SAF copy differs');
  }
  async function verifyAndroidGrantedSafNestedSync(tree, localTab, root, tab, runTask) {
    await invoke('POST', '/api/local/mkdir', {tab: localTab, name: 'nested-sync'});
    const localDir = tree + '/document/nested-sync';
    const local = (await invoke('POST', '/api/tabs/local', {local_dir: localDir, remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/mkdir', {tab: local, name: 'from-provider'});
    const localChild = (await invoke('POST', '/api/tabs/local', {local_dir: localDir + '/document/from-provider', remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/mkdir', {tab: localChild, name: 'nested'});
    const localGrandchild = (await invoke('POST', '/api/tabs/local', {local_dir: localDir + '/document/from-provider/document/nested', remote_dir: root})).tab.id;
    await invoke('POST', '/api/local/save', {tab: localGrandchild, path: 'up.txt', content: 'nested provider upload'});
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'nested-sync'});
    const remoteDir = '/nested-sync';
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: remoteDir, name: 'from-server'});
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: remoteDir + '/from-server', name: 'nested'});
    await invoke('POST', '/api/remote/save', {tab, path: remoteDir + '/from-server/nested/down.txt', content: 'nested server download'});
    const sync = {tab, local_dir: localDir, remote_dir: remoteDir};
    await runTask('/api/sync/run', {...sync, mode: 'local'});
    const downloadTab = (await invoke('POST', '/api/tabs/local', {local_dir: localDir + '/document/from-server/document/nested', remote_dir: root})).tab.id;
    if ((await invoke('GET', '/api/local/edit?tab=' + downloadTab + '&path=down.txt')).content !== 'nested server download') throw new Error('Nested provider sync download differs');
    await runTask('/api/sync/run', {...sync, mode: 'remote'});
    if ((await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent(remoteDir + '/from-provider/nested/up.txt'))).content !== 'nested provider upload') throw new Error('Nested provider sync upload differs');
    // A second pass must observe a file created after the first pass began;
    // the external-storage provider has no native watcher and uses polling.
    await invoke('POST', '/api/local/save', {tab: local, path: 'poll-first.txt', content: 'first poll'});
    const result = await invoke('POST', '/api/transfer/keepuptodate', {...sync, count: 2, interval: 10});
    if (!result.success || !result.task_id) throw new Error('Cannot start provider polling');
    let firstSeen = false;
    for (let i = 0; i < 120; i++) {
      const list = await invoke('GET', '/api/remote/list?tab=' + tab + '&path=' + encodeURIComponent(remoteDir));
      if (list.entries?.some(entry => entry.name === 'poll-first.txt')) { firstSeen = true; break; }
      const task = (await invoke('GET', '/api/transfers')).transfers.find(item => item.id === result.task_id);
      if (task?.status === 'Failed' || task?.status === 'Completed' || task?.status === 'Cancelled') throw new Error('Provider polling ended before first file: ' + JSON.stringify(task));
      await sleep(250);
    }
    if (!firstSeen) throw new Error('Initial provider polling pass timed out');
    await invoke('POST', '/api/local/save', {tab: local, path: 'poll-later.txt', content: 'second poll'});
    let completed = false;
    for (let i = 0; i < 180; i++) {
      const task = (await invoke('GET', '/api/transfers')).transfers.find(item => item.id === result.task_id);
      if (task?.status === 'Completed') { completed = true; break; }
      if (task?.status === 'Failed' || task?.status === 'Cancelled') throw new Error('Provider polling failed: ' + JSON.stringify(task));
      await sleep(250);
    }
    if (!completed) throw new Error('Second provider polling pass timed out');
    if ((await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent(remoteDir + '/poll-later.txt'))).content !== 'second poll') throw new Error('Second provider polling pass missed new file');
    await invoke('POST', '/api/local/save', {tab: local, path: 'cancel-first.txt', content: 'before cancellation'});
    const watch = await invoke('POST', '/api/transfer/keepuptodate', {...sync, count: 0, interval: 60});
    if (!watch.success || !watch.task_id) throw new Error('Cannot start cancellable provider polling');
    let cancellationPassSeen = false;
    for (let i = 0; i < 120; i++) {
      const listing = await invoke('GET', '/api/remote/list?tab=' + tab + '&path=' + encodeURIComponent(remoteDir));
      if (listing.entries?.some(entry => entry.name === 'cancel-first.txt')) { cancellationPassSeen = true; break; }
      const task = (await invoke('GET', '/api/transfers')).transfers.find(item => item.id === watch.task_id);
      if (task?.status === 'Failed' || task?.status === 'Completed' || task?.status === 'Cancelled') throw new Error('Cancellable provider polling ended early: ' + JSON.stringify(task));
      await sleep(250);
    }
    if (!cancellationPassSeen) throw new Error('Cancellable provider polling initial pass timed out');
    await invoke('POST', '/api/local/save', {tab: local, path: 'cancel-later.txt', content: 'must remain local'});
    const startedCancel = Date.now();
    const cancelled = await invoke('POST', '/api/queue/cancel', {task_id: watch.task_id});
    if (!cancelled.success) throw new Error('Provider polling cancellation was refused');
    let stopped = false;
    for (let i = 0; i < 40; i++) {
      const task = (await invoke('GET', '/api/transfers')).transfers.find(item => item.id === watch.task_id);
      if (task?.status === 'Cancelled') { stopped = true; break; }
      if (task?.status === 'Failed' || task?.status === 'Completed') throw new Error('Unexpected cancelled polling status: ' + JSON.stringify(task));
      await sleep(250);
    }
    if (!stopped || Date.now() - startedCancel >= 12000) throw new Error('Provider polling did not cancel promptly');
    const finalList = await invoke('GET', '/api/remote/list?tab=' + tab + '&path=' + encodeURIComponent(remoteDir));
    if (finalList.entries?.some(entry => entry.name === 'cancel-later.txt')) throw new Error('Cancelled provider polling uploaded a later file');
  }
  async function verifyAndroidGrantedSafSync(tree, localTab, root, tab, runTask) {
    // Isolate the fixture so the delete test cannot touch the grant marker.
    await invoke('POST', '/api/local/mkdir', {tab: localTab, name: 'sync-fixture'});
    const localDir = tree + '/document/sync-fixture';
    const local = await invoke('POST', '/api/tabs/local', {local_dir: localDir, remote_dir: root});
    const syncTab = local.tab.id;
    await invoke('POST', '/api/remote/mkdir', {tab, remote_dir: '/', name: 'sync-fixture'});
    const remoteDir = '/sync-fixture';
    const sync = {tab, local_dir: localDir, remote_dir: remoteDir};
    await invoke('POST', '/api/local/save', {tab: syncTab, path: 'upload.txt', content: 'from provider'});
    await invoke('POST', '/api/remote/save', {tab, path: remoteDir + '/download.txt', content: 'from webdav'});
    const preview = await invoke('POST', '/api/sync/preview', {...sync, mode: 'local'});
    if (!preview.plan?.items?.some(item => item.action === 'download' && item.path === 'download.txt')) throw new Error('SAF sync preview omitted remote file: ' + JSON.stringify(preview));
    await runTask('/api/sync/run', {...sync, mode: 'local'});
    const downloaded = await invoke('GET', '/api/local/edit?tab=' + syncTab + '&path=download.txt');
    if (downloaded.content !== 'from webdav') throw new Error('SAF synchronization download differs');
    await runTask('/api/sync/run', {...sync, mode: 'remote'});
    const uploaded = await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent(remoteDir + '/upload.txt'));
    if (uploaded.content !== 'from provider') throw new Error('SAF synchronization upload differs');
    await invoke('POST', '/api/local/save', {tab: syncTab, path: 'upload.txt', content: 'new provider!'});
    const checksum = await invoke('POST', '/api/sync/preview', {...sync, mode: 'remote', criteria: 'checksum'});
    if (!checksum.plan?.items?.some(item => item.action === 'upload' && item.path === 'upload.txt')) throw new Error('SAF checksum missed changed bytes: ' + JSON.stringify(checksum));
    await invoke('POST', '/api/local/save', {tab: syncTab, path: 'delete-me.txt', content: 'obsolete'});
    await runTask('/api/sync/run', {...sync, mode: 'local', delete: true});
    const localList = await invoke('GET', '/api/local/list?tab=' + syncTab + '&path=' + encodeURIComponent(localDir));
    if (localList.entries?.some(entry => entry.name === 'delete-me.txt')) throw new Error('SAF synchronization did not delete obsolete local file');
    await invoke('POST', '/api/local/save', {tab: syncTab, path: 'watch.txt', content: 'watched provider file'});
    await runTask('/api/transfer/keepuptodate', {...sync, count: 1});
    const watched = await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent(remoteDir + '/watch.txt'));
    if (watched.content !== 'watched provider file') throw new Error('SAF keep-up-to-date missed the file');
  }
  if (${JSON.stringify(phase)} === 'share-fail') {
    const root = (await invoke('GET', '/api/status')).local_dir;
    let refused = false;
    for (let i = 0; i < 30 && !refused; i++) {
      try { await invoke('GET', '/api/shell/pending'); }
      catch (error) { refused = error.status === 500; }
      if (!refused) await sleep(1000);
    }
    if (!refused) throw new Error('Blocked manifest publication did not report an error');
    // A second poll must retry the same failed publication, not forget it.
    let retried = false;
    try { await invoke('GET', '/api/shell/pending'); }
    catch (error) { retried = error.status === 500; }
    if (!retried) throw new Error('Failed publication was not retried');
    return {root, failedShareRetained: true};
  }
  if (${JSON.stringify(phase)} === 'share-intent') {
    const root = (await invoke('GET', '/api/status')).local_dir;
    let offer;
    for (let i = 0; i < 30 && !offer; i++) {
      const pending = await invoke('GET', '/api/shell/pending');
      offer = pending.pending?.find(item => item.items?.some(file => file.name === 'marker.txt'));
      if (!offer) await sleep(1000);
    }
    if (!offer) throw new Error('Android SEND intent did not produce a pending manifest');
    const item = offer.items.find(file => file.name === 'marker.txt');
    const parent = item.path.slice(0, item.path.lastIndexOf('/'));
    const local = await invoke('POST', '/api/tabs/local', {local_dir: parent, remote_dir: root});
    const read = await invoke('GET', '/api/local/edit?tab=' + local.tab.id + '&path=' + encodeURIComponent(item.name));
    if (read.content !== 'saf-edited') throw new Error('Shared document contents differ');
    await invoke('POST', '/api/shell/dismiss', {id: offer.id});
    return {root, incomingShareIntent: true};
  }
  if (['saf-pick-start', 'saf-pick-finish', 'saf-reopen'].includes(${JSON.stringify(phase)})) return await verifyAndroidGrantedSafEditing();
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
  async function verifyAndroidUngrantedSafRefusals() {
    const tree = 'content://com.android.externalstorage.documents/tree/primary%3ADocuments%2FLinSCP-Ungranted-Smoke';
    const documentUri = tree + '/document/marker.txt';
    const roots = await invoke('GET', '/api/local/roots');
    if (roots.roots?.some(entry => entry.path === tree)) throw new Error('Ungranted folder appeared among persisted roots');
    let registered = false;
    try { await nativeInvoke('linscp_request_saf_tree', {uri: tree}); registered = true; }
    catch (_) { /* The system provider must deny access without a grant. */ }
    if (registered) throw new Error('Ungranted SAF folder registration succeeded');
    async function expectRefusal(method, path, body) {
      let status;
      try { await invoke(method, path, body); } catch (error) { status = error.status; }
      if (status !== 400) throw new Error('Expected ungranted SAF refusal for ' + path + ': ' + status);
    }
    await expectRefusal('GET', '/api/local/list?path=' + encodeURIComponent(tree), {});
    await expectRefusal('POST', '/api/local/save', {path: documentUri, content: 'unexpected overwrite'});
    const after = await invoke('GET', '/api/local/roots');
    if (after.roots?.some(entry => entry.path === tree)) throw new Error('Refused SAF folder was persisted');
  }
  await verifyAndroidUngrantedSafRefusals();
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
    const guiState = state; // DevTools shares the page's global lexical scope; CSP forbids eval.
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
  async function verifyAndroidAgentRefusal() {
    let challenge;
    try {
      await invoke('POST', '/api/tabs/open', {session: {protocol: 'sftp', host: '127.0.0.1', port: ${sshPort}, username: 'testuser', local_dir: root, initial_dir: '/'}});
    } catch (error) {
      if (error.status !== 409 || !error.payload?.challenge) throw error;
      challenge = error.payload.challenge;
    }
    if (!challenge || challenge.host !== '127.0.0.1' || challenge.port !== ${sshPort} || !challenge.fingerprint) throw new Error('Expected SSH fixture host-key challenge');
    let refusal;
    try {
      await invoke('POST', '/api/tabs/verify', {tab: challenge.tab, role: challenge.role, fingerprint: challenge.fingerprint, remember: false});
    } catch (error) { refusal = error; }
    if (refusal?.status !== 400 || !/SSH agent authentication is not available on Android.*private key file/i.test(refusal.message || '')) throw new Error('Expected Android SSH agent refusal: ' + String(refusal?.message));
  }
  await verifyAndroidAgentRefusal();
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
  async function verifyAndroidSftpResume() {
    // The fixture key is accepted for this test only, not saved as trusted.
    let challenge;
    try {
      await invoke('POST', '/api/tabs/open', {session: {protocol: 'sftp', host: '127.0.0.1', port: ${sshPort}, username: 'testuser', password: 'testpass', local_dir: root, initial_dir: '/'}});
    } catch (error) {
      if (error.status !== 409 || !error.payload?.challenge) throw error;
      challenge = error.payload.challenge;
    }
    if (!challenge || challenge.host !== '127.0.0.1' || challenge.port !== ${sshPort}) throw new Error('Expected SFTP fixture host-key challenge');
    const verified = await invoke('POST', '/api/tabs/verify', {tab: challenge.tab, role: challenge.role, fingerprint: challenge.fingerprint, remember: false});
    if (!verified.tab?.connected) throw new Error('SFTP fixture did not authenticate');
    const sftpTab = verified.tab.id;
    await invoke('POST', '/api/remote/save', {tab: sftpTab, path: '/resume-fixture.txt', content: 'Android SFTP resume fixture'});
    async function checkpoint(dir, bytes) {
      await invoke('POST', '/api/local/mkdir', {tab: sftpTab, name: dir});
      await invoke('POST', '/api/local/save', {path: root + '/' + dir + '/resume-fixture.txt.filepart', content: bytes});
      return root + '/' + dir;
    }
    async function waitTask(previous, expected) {
      for (let i = 0; i < 120; i++) {
        const task = (await invoke('GET', '/api/transfers')).transfers.find(item => !previous.has(item.id));
        if (task?.status === expected) return task;
        if (task?.status === 'Failed' || task?.status === 'Completed' || task?.status === 'Cancelled') throw new Error('Unexpected SFTP resume result: ' + JSON.stringify(task));
        await sleep(250);
      }
      throw new Error('SFTP resume timed out');
    }
    const goodDir = await checkpoint('sftp-resume-good', 'Android SFTP');
    const body = {tab: sftpTab, local_dir: goodDir, remote_dir: '/', names: ['resume-fixture.txt'], resume: true};
    let refused = false;
    try { await invoke('POST', '/api/transfer/download', body); }
    catch (error) { refused = error.status === 409 && error.payload?.best_effort_resume_risk === true; }
    if (!refused) throw new Error('SFTP resume did not require explicit best-effort consent');
    const previous = new Set((await invoke('GET', '/api/transfers')).transfers.map(item => item.id));
    await invoke('POST', '/api/transfer/download', {...body, accept_best_effort_resume_risk: true});
    await waitTask(previous, 'Completed');
    const goodTab = (await invoke('POST', '/api/tabs/local', {local_dir: goodDir, remote_dir: root})).tab.id;
    if ((await invoke('GET', '/api/local/edit?tab=' + goodTab + '&path=resume-fixture.txt')).content !== 'Android SFTP resume fixture') throw new Error('SFTP resumed bytes differ');
    const staleDir = await checkpoint('sftp-resume-stale', 'wrong prefix');
    const beforeStale = new Set((await invoke('GET', '/api/transfers')).transfers.map(item => item.id));
    await invoke('POST', '/api/transfer/download', {...body, local_dir: staleDir, accept_best_effort_resume_risk: true});
    await waitTask(beforeStale, 'Failed');
    const listing = await invoke('GET', '/api/local/list?path=' + encodeURIComponent(staleDir));
    if (listing.entries?.some(entry => entry.name === 'resume-fixture.txt')) throw new Error('Rejected SFTP resume published a destination');
    const staleTab = (await invoke('POST', '/api/tabs/local', {local_dir: staleDir, remote_dir: root})).tab.id;
    if ((await invoke('GET', '/api/local/edit?tab=' + staleTab + '&path=resume-fixture.txt.filepart')).content !== 'wrong prefix') throw new Error('Rejected SFTP resume changed the checkpoint');
  }
  await verifyAndroidSftpResume();
  const local = await invoke('POST', '/api/tabs/local', {local_dir: root + '/smoke-download', remote_dir: root});
  const contents = await invoke('GET', '/api/local/edit?tab=' + local.tab.id + '&path=smoke-upload.txt');
  if (contents.content !== 'Android Rust-backed transfer') throw new Error('Downloaded bytes differ');
  await invoke('POST', '/api/local/rename', {tab: local.tab.id, old_name: 'smoke-upload.txt', new_name: 'renamed.txt'});
  async function verifyAndroidTransferPreset() {
    await invoke('POST', '/api/presets/save', {name: 'android-text-only', mask: '*.preset-txt'});
    await invoke('POST', '/api/local/save', {path: root + '/allowed.preset-txt', content: 'preset allowed'});
    await invoke('POST', '/api/local/save', {path: root + '/excluded.preset-bin', content: 'preset excluded'});
    const previous = new Set((await invoke('GET', '/api/transfers')).transfers.map(task => task.id));
    await invoke('POST', '/api/transfer/upload', {tab, local_dir: root, remote_dir: '/', names: ['allowed.preset-txt', 'excluded.preset-bin'], preset: 'android-text-only'});
    let completed = false;
    for (let i = 0; i < 120; i++) {
      const task = (await invoke('GET', '/api/transfers')).transfers.find(item => !previous.has(item.id));
      if (task?.status === 'Completed') { completed = true; break; }
      if (task?.status === 'Failed' || task?.status === 'Cancelled') throw new Error('Preset transfer failed: ' + JSON.stringify(task));
      await sleep(250);
    }
    if (!completed) throw new Error('Preset transfer timed out');
    const listing = await invoke('GET', '/api/remote/list?tab=' + tab + '&path=' + encodeURIComponent('/'));
    if (!listing.entries?.some(entry => entry.name === 'allowed.preset-txt') || listing.entries.some(entry => entry.name === 'excluded.preset-bin')) throw new Error('Preset filter did not control WebDAV upload');
    if ((await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/allowed.preset-txt'))).content !== 'preset allowed') throw new Error('Preset transfer content differs');
    await invoke('POST', '/api/presets/delete', {name: 'android-text-only'});
    let refused = false;
    try { await invoke('POST', '/api/transfer/upload', {tab, local_dir: root, remote_dir: '/', names: ['excluded.preset-bin'], preset: 'android-text-only'}); }
    catch (error) { refused = error.status === 400; }
    if (!refused) throw new Error('Deleted explicit preset silently fell back to defaults');

    // Each member of a mixed selection must choose its own matching preset.
    // A matching filename alone must not bypass an incompatible host rule.
    await invoke('POST', '/api/presets/save', {name: 'android-wrong-host', host: 'wrong.invalid', mask: '*.auto-txt', transfer: 'ascii'});
    await invoke('POST', '/api/presets/save', {name: 'android-auto-text', host: '127.0.0.1', mask: '*.auto-txt', transfer: 'binary'});
    await invoke('POST', '/api/presets/save', {name: 'android-auto-binary', host: '127.0.0.1', mask: '*.auto-bin', transfer: 'binary'});
    await invoke('POST', '/api/local/save', {path: root + '/one.auto-txt', content: 'text auto'});
    await invoke('POST', '/api/local/save', {path: root + '/two.auto-bin', content: 'binary auto'});
    const matched = await invoke('GET', '/api/presets?tab=' + tab + '&filename=' + encodeURIComponent('one.auto-txt'));
    if (matched.matched !== 'android-auto-text') throw new Error('Automatic preset ignored session rule: ' + JSON.stringify(matched));
    const oldTasks = new Set((await invoke('GET', '/api/transfers')).transfers.map(task => task.id));
    await invoke('POST', '/api/transfer/upload', {tab, local_dir: root, remote_dir: '/', names: ['one.auto-txt', 'two.auto-bin']});
    let mixedDone = false;
    for (let i = 0; i < 120; i++) {
      const tasks = (await invoke('GET', '/api/transfers')).transfers.filter(item => !oldTasks.has(item.id));
      if (tasks.some(item => item.status === 'Failed' || item.status === 'Cancelled')) throw new Error('Automatic preset transfer failed: ' + JSON.stringify(tasks));
      if (tasks.length === 2 && tasks.every(item => item.status === 'Completed')) { mixedDone = true; break; }
      await sleep(250);
    }
    if (!mixedDone) throw new Error('Mixed automatic presets did not queue and finish both files');
    for (const [name, content] of [['one.auto-txt', 'text auto'], ['two.auto-bin', 'binary auto']]) {
      if ((await invoke('GET', '/api/remote/edit?tab=' + tab + '&path=' + encodeURIComponent('/' + name))).content !== content) throw new Error('Automatic preset transfer differs: ' + name);
    }
    for (const name of ['android-wrong-host', 'android-auto-text', 'android-auto-binary']) await invoke('POST', '/api/presets/delete', {name});
  }
  await verifyAndroidTransferPreset();
  const vault = await invoke('GET', '/api/vault/status');
  if (vault.vault !== 'setup_required') throw new Error('Expected a fresh emulator vault: ' + JSON.stringify(vault));
  await invoke('POST', '/api/vault/unlock', {password: 'android smoke vault password'});
  const biometricStatus = await window.__TAURI_INTERNALS__.invoke('linscp_biometric_status');
  if (biometricStatus.enabled !== false || typeof biometricStatus.available !== 'boolean') throw new Error('Fresh vault unexpectedly enabled biometrics');
  let wrongEnrollmentRefused = false;
  try { await window.__TAURI_INTERNALS__.invoke('linscp_biometric_enroll', {password: 'wrong vault password'}); }
  catch (_) { wrongEnrollmentRefused = true; }
  if (!wrongEnrollmentRefused || (await window.__TAURI_INTERNALS__.invoke('linscp_biometric_status')).enabled) throw new Error('Wrong password enabled biometrics');
  const savedSite = await invoke('POST', '/api/sessions/save', {name: 'android-smoke-vault-site', session: {protocol: 'dav', host: '127.0.0.1', port: ${port}, username: 'testuser', password: 'testpass', local_dir: root, initial_dir: '/'}});
  if (!savedSite.success) throw new Error('Cannot save Android vault site');
  async function verifyAndroidSiteManager() {
    const session = {protocol: 'dav', host: '127.0.0.1', port: ${port}, username: 'testuser', password: 'testpass', local_dir: root, initial_dir: '/'};
    for (const name of ['android-site-manager/team', 'android-site-manager/team/one', 'android-site-manager/team/nested/two', 'android-site-manager/teamwork/one']) {
      await invoke('POST', '/api/sessions/save', {name, session});
    }
    const names = async () => (await invoke('GET', '/api/sessions')).sessions.map(site => site.name).sort();
    let conflict = false;
    try { await invoke('POST', '/api/sessions/rename', {old_name: 'android-site-manager/team', new_name: 'android-site-manager/teamwork', folder: true}); }
    catch (error) { conflict = error.status === 409; }
    if (!conflict) throw new Error('Conflicting folder rename was not refused');
    const renamed = await invoke('POST', '/api/sessions/rename', {old_name: 'android-site-manager/team', new_name: 'android-site-manager/edge', folder: true});
    if (renamed.renamed !== 2) throw new Error('Unexpected folder rename count: ' + JSON.stringify(renamed));
    await invoke('POST', '/api/sessions/rename', {old_name: 'android-site-manager/edge/one', new_name: 'android-site-manager/edge/primary'});
    const found = await names();
    for (const name of ['android-site-manager/team', 'android-site-manager/edge/primary', 'android-site-manager/edge/nested/two', 'android-site-manager/teamwork/one']) {
      if (!found.includes(name)) throw new Error('Site rename lost ' + name);
    }
    if (found.includes('android-site-manager/team/one') || found.includes('android-site-manager/edge/one')) throw new Error('Old site name survived rename');
    const connected = await invoke('POST', '/api/tabs/open', {site_name: 'android-site-manager/edge/primary'});
    if (!connected.tab?.connected) throw new Error('Renamed site did not retain working credentials');
    await invoke('POST', '/api/tabs/close', {tab: connected.tab.id});
    await invoke('POST', '/api/sessions/delete', {name: 'android-site-manager/edge', folder: true});
    const remaining = await names();
    if (remaining.some(name => name.startsWith('android-site-manager/edge/')) || !remaining.includes('android-site-manager/team') || !remaining.includes('android-site-manager/teamwork/one')) throw new Error('Folder delete affected wrong sites');
    await invoke('POST', '/api/sessions/delete', {name: 'android-site-manager/team'});
    await invoke('POST', '/api/sessions/delete', {name: 'android-site-manager/teamwork', folder: true});
    if ((await names()).some(name => name.startsWith('android-site-manager/'))) throw new Error('Site deletion failed');
  }
  await verifyAndroidSiteManager();
  const locked = await invoke('POST', '/api/vault/lock');
  if (!locked.success || (await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Vault did not lock');
  let biometricRefused = false;
  try { await window.__TAURI_INTERNALS__.invoke('linscp_biometric_unlock'); } catch (_) { biometricRefused = true; }
  if (!biometricRefused || (await invoke('GET', '/api/vault/status')).vault !== 'locked') throw new Error('Unenrolled biometric unlock did not fail closed');
  return {transport: window.LinSCPTransport.mode, root, title: document.title, upload: true, download: true, resume: true, resumeSafetyRefusals: true, conflict: true, externalUriValidation: true, webViewRendering: true, ungrantedSafRefused: true, unenrolledBiometricsRefused: true};
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
if (rootFile && !['damaged-journal', 'saf-pick-start'].includes(phase)) writeFileSync(rootFile, String(reply.result.result.value.root));
console.log('Android WebView and Rust service smoke test passed:', JSON.stringify(reply.result.result.value));
