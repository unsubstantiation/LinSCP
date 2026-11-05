// Runs against the debug WebView through Chrome DevTools. The WebDAV fixture
// is reached through adb reverse; all IPC executes inside the installed APK.
import assert from 'node:assert/strict';
const port = Number(process.argv[2]);
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
  const status = await invoke('GET', '/api/status');
  const root = status.local_dir;
  if (!root || !root.includes('io.linscp.commander')) throw new Error('Not using app-private storage: ' + root);
  const mkdir = await invoke('POST', '/api/local/mkdir', {name: 'smoke-download'});
  if (!mkdir.success) throw new Error('Local mkdir failed: ' + JSON.stringify(mkdir));
  const save = await invoke('POST', '/api/local/save', {path: root + '/smoke-upload.txt', content: 'Android Rust-backed transfer'});
  if (!save.success) throw new Error('Local save failed: ' + JSON.stringify(save));
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
  await invoke('POST', '/api/local/mkdir', {name: 'smoke-resume'});
  await invoke('POST', '/api/local/save', {path: root + '/smoke-resume/smoke-upload.txt.filepart', content: 'Android'});
  await invoke('POST', '/api/transfer/download', {tab, local_dir: root + '/smoke-resume', remote_dir: '/', names: ['smoke-upload.txt'], resume: true});
  await waitTransfer(2);
  const resumedTab = await invoke('POST', '/api/tabs/local', {local_dir: root + '/smoke-resume', remote_dir: root});
  const resumed = await invoke('GET', '/api/local/edit?tab=' + resumedTab.tab.id + '&path=smoke-upload.txt');
  if (resumed.content !== 'Android Rust-backed transfer') throw new Error('Resumed bytes differ');
  const local = await invoke('POST', '/api/tabs/local', {local_dir: root + '/smoke-download', remote_dir: root});
  const contents = await invoke('GET', '/api/local/edit?tab=' + local.tab.id + '&path=smoke-upload.txt');
  if (contents.content !== 'Android Rust-backed transfer') throw new Error('Downloaded bytes differ');
  await invoke('POST', '/api/local/rename', {tab: local.tab.id, old_name: 'smoke-upload.txt', new_name: 'renamed.txt'});
  return {transport: window.LinSCPTransport.mode, root, title: document.title, upload: true, download: true, resume: true, conflict: true};
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
const reply = await evaluate(expression, 120000);
if (reply.error || reply.result?.exceptionDetails) throw new Error(JSON.stringify(reply));
// Reject paths outside private storage before opening any system picker.
const invalidExport = await evaluate(`window.__TAURI_INTERNALS__.invoke('linscp_android_export', {path: '/sdcard/not-private.txt'}).then(() => false, () => true)`, 15000);
assert.equal(invalidExport.result?.result?.value, true, 'Unsafe export path was accepted');
// Launch the actual system document picker, then cancel it from the emulator.
const cancellation = evaluate(`window.__TAURI_INTERNALS__.invoke('linscp_android_import').then(() => false, () => true)`, 30000);
await new Promise(resolve => setTimeout(resolve, 4000));
const { execFileSync } = await import('node:child_process');
execFileSync('adb', ['shell', 'input', 'keyevent', 'BACK']);
const cancelled = await cancellation;
assert.equal(cancelled.result?.result?.value, true, 'Cancelled document picker did not reject');
// Seed a real external file, select it in DocumentsUI and verify the copied bytes.
const { writeFileSync, unlinkSync } = await import('node:fs');
const localFixture = '/tmp/linscp-picker-fixture.txt';
writeFileSync(localFixture, 'Android shared document');
execFileSync('adb', ['push', localFixture, '/sdcard/Download/linscp-picker-fixture.txt']);
unlinkSync(localFixture);
execFileSync('adb', ['shell', 'am', 'broadcast', '-a', 'android.intent.action.MEDIA_SCANNER_SCAN_FILE', '-d', 'file:///sdcard/Download/linscp-picker-fixture.txt']);
const pendingImport = evaluate(`window.__TAURI_INTERNALS__.invoke('linscp_android_import')`, 120000);
async function dumpUi() {
  try {
    execFileSync('adb', ['shell', 'uiautomator', 'dump', '/sdcard/linscp-window.xml'], {timeout: 15000, stdio: 'ignore'});
    return execFileSync('adb', ['shell', 'cat', '/sdcard/linscp-window.xml'], {encoding: 'utf8'});
  } catch (_) { return ''; }
}
function tapNode(xml, pattern) {
  for (const node of xml.match(/<node\b[^>]*>/g) || []) {
    if (!pattern.test(node)) continue;
    const box = node.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
    if (!box) continue;
    const x = Math.floor((Number(box[1]) + Number(box[3])) / 2);
    const y = Math.floor((Number(box[2]) + Number(box[4])) / 2);
    execFileSync('adb', ['shell', 'input', 'tap', String(x), String(y)]);
    return true;
  }
  return false;
}
let selected = false;
for (let i = 0; i < 30 && !selected; i++) {
  const xml = await dumpUi();
  if (tapNode(xml, /(?:text|content-desc)="linscp-picker-fixture\.txt"/i)) { selected = true; break; }
  if (!tapNode(xml, /(?:text|content-desc)="Downloads"/i)) tapNode(xml, /content-desc="(?:Show roots|Open navigation drawer)"/i);
  await new Promise(resolve => setTimeout(resolve, 700));
}
assert.ok(selected, 'Unable to select the fixture in Android DocumentsUI');
await new Promise(resolve => setTimeout(resolve, 1000));
tapNode(await dumpUi(), /(?:text|content-desc)="(?:Open|Select)"/i);
const imported = await pendingImport;
if (imported.error || imported.result?.exceptionDetails) throw new Error('Document import failed: ' + JSON.stringify(imported));
const folder = imported.result.result.value?.directory;
assert.ok(folder && imported.result.result.value.count === 1, 'Import did not return its private directory');
const checkImport = await evaluate(`(async () => {
  const invoke = (method, path, body = {}) => window.LinSCPTransport.request(method, path, body);
  const tab = await invoke('POST', '/api/tabs/local', {local_dir: ${JSON.stringify(folder)}, remote_dir: ${JSON.stringify(folder)}});
  const content = (await invoke('GET', '/api/local/edit?tab=' + tab.tab.id + '&path=linscp-picker-fixture.txt')).content;
  await invoke('POST', '/api/local/rename', {tab: tab.tab.id, old_name: 'linscp-picker-fixture.txt', new_name: 'linscp-export-result.txt'});
  return content;
})()`);
assert.equal(checkImport.result?.result?.value, 'Android shared document', 'Imported bytes differ');
const exportPath = folder + '/linscp-export-result.txt';
const pendingExport = evaluate(`window.__TAURI_INTERNALS__.invoke('linscp_android_export', {path: ${JSON.stringify(exportPath)}})`, 120000);
let saved = false;
for (let i = 0; i < 30 && !saved; i++) {
  const xml = await dumpUi();
  // CREATE_DOCUMENT initially opens the same Downloads directory as import.
  if (tapNode(xml, /(?:text|content-desc)="Save"/i)) { saved = true; break; }
  if (!tapNode(xml, /(?:text|content-desc)="Downloads"/i)) tapNode(xml, /content-desc="(?:Show roots|Open navigation drawer)"/i);
  await new Promise(resolve => setTimeout(resolve, 700));
}
assert.ok(saved, 'Unable to save the exported document in Android DocumentsUI');
const exported = await pendingExport;
if (exported.error || exported.result?.exceptionDetails) throw new Error('Document export failed: ' + JSON.stringify(exported));
const output = execFileSync('adb', ['shell', 'cat', '/sdcard/Download/linscp-export-result.txt'], {encoding: 'utf8'});
assert.equal(output, 'Android shared document', 'Exported bytes differ');
socket.close();
console.log('Android WebView, document picker and Rust service smoke tests passed:', JSON.stringify(reply.result.result.value));
