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
const reply = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('DevTools evaluation timed out')), 120000);
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id !== 1) return;
    clearTimeout(timer);
    resolve(message);
  };
  socket.onerror = reject;
  socket.send(JSON.stringify({id: 1, method: 'Runtime.evaluate', params: {expression, awaitPromise: true, returnByValue: true}}));
});
socket.close();
if (reply.error || reply.result?.exceptionDetails) throw new Error(JSON.stringify(reply));
console.log('Android WebView and Rust service smoke test passed:', JSON.stringify(reply.result.result.value));
