// Prove the SAF bridge against a real DocumentsProvider, not the mock.
//
// The emulator smoke proves the app reaches its own private storage through
// Rust. This proves something different: that a folder granted by Android's
// system picker behaves the way crates/linscp-service's in-memory MockBridge
// says it does. Four `platform.android-saf-*` rows carry the same gap - "no
// suite has touched a real DocumentsProvider" - and this is the suite that
// touches one.
//
// It goes through the same HTTP-API surface the page uses, not the plugin's
// internals. That matters twice: the routes are what the app actually depends
// on, and they are stable in a way that `plugin:linscp-android|...` is not.
//
// Two things it deliberately does not do. It does not click the system
// picker: `pickTree` raises an activity result no DevTools client can answer,
// so the grant is made once by hand and read back here, which also makes the
// run reproducible. And it does not assume the provider is quick or
// well-behaved: every wait is bounded, and a provider that reports a different
// mtime precision fails with the value it reported rather than a vague timeout.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';

const application = process.argv[2];
const reportPath = process.argv[3];
assert.ok(application && application.includes('.'), 'the harness must pass the application ID');

// ---------------------------------------------------------------------------
// DevTools plumbing
// ---------------------------------------------------------------------------
const targets = await (await fetch('http://127.0.0.1:9222/json')).json();
const page = targets.find(target => target.type === 'page' && target.webSocketDebuggerUrl);
assert.ok(page, `No debuggable WebView: ${JSON.stringify(targets)}`);

const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.onopen = resolve;
  socket.onerror = reject;
});

const expression = `
(async () => {
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const fail = message => { throw new Error(message); };
  for (let i = 0; i < 60 && !window.LinSCPTransport; i++) await sleep(1000);
  if (window.LinSCPTransport?.mode !== 'tauri') fail('Tauri frontend transport not initialized');

  const invoke = (method, path, body = {}) => window.LinSCPTransport.request(method, path, body);
  const steps = [];
  const step = name => steps.push(name);

  // A 400 is an answer, not a crash: the transport rejects with a status and
  // the payload, so a refusal can be asserted on instead of aborting the run.
  const attempt = async (method, path, body) => {
    try { return { ok: true, reply: await invoke(method, path, body) }; }
    catch (error) { return { ok: false, status: error?.status, payload: error?.payload, message: String(error?.message ?? error) }; }
  };

  // --- the grant -----------------------------------------------------------
  // The service enumerates granted trees itself (platform::android::list_roots
  // extends the filesystem roots with the bridge's persisted grants), so this
  // one call proves the grant reached the Rust side - which is the part that
  // the mock cannot tell us anything about.
  const listed = await invoke('GET', '/api/local/roots');
  const trees = (listed.roots ?? []).filter(r => r && r.kind === 'saf_tree');
  if (!trees.length) {
    return { skip: 'no granted folder',
             reason: 'grant one in the app with the folder switcher, then re-run',
             seen: (listed.roots ?? []).map(r => r.kind + ':' + r.path) };
  }
  const tree = trees[0];
  const treeUri = tree.path;
  if (!treeUri.startsWith('content://')) fail('granted tree is not a content:// URI: ' + treeUri);
  if (tree.read_only) fail('the granted tree is read-only; the suite needs write access');
  step('the service enumerates a granted folder as a saf_tree root');

  // --- a local tab on the granted tree -------------------------------------
  // Every local route resolves a relative name against the tab's local_dir,
  // so this is what makes the API address a provider-backed folder at all.
  const tab = await attempt('POST', '/api/tabs/local', { local_dir: treeUri, remote_dir: treeUri });
  if (!tab.ok) fail('opening a local tab on the granted tree failed: ' + JSON.stringify(tab));
  const tabId = tab.reply.tab?.id;
  if (typeof tabId !== 'number') fail('no tab id: ' + JSON.stringify(tab.reply));
  step('a local tab opens on a granted folder');

  // The provider is a real filesystem: list it to prove the tab is looking at
  // documents rather than at a pathname that happens to share a name.
  const before = await attempt('GET', '/api/local/list?tab=' + tabId);
  if (!before.ok || !Array.isArray(before.reply.entries)) {
    fail('listing the granted tree failed: ' + JSON.stringify(before));
  }
  step('the granted folder lists through the provider (' + before.reply.entries.length + ' entries)');

  // --- a run-scoped folder, so the user's own files are never touched ------
  const run = 'linscp-saf-' + Date.now();
  const made = await attempt('POST', '/api/local/mkdir', { tab: tabId, name: run });
  if (!made.ok) fail('mkdir in the granted tree failed: ' + JSON.stringify(made));
  step('a folder can be created in a granted tree');

  // --- editing -------------------------------------------------------------
  // platform.android-saf-editing: a document is written, read back byte for
  // byte, and its stat carries the provider's own mtime.
  const text = 'granted text ' + run + '\\n';
  const written = await attempt('POST', '/api/local/save', { tab: tabId, path: run + '/note.txt', content: text });
  if (!written.ok) fail('creating a document failed: ' + JSON.stringify(written));

  const saved = await attempt('GET', '/api/local/edit?tab=' + tabId + '&path=' + encodeURIComponent(run + '/note.txt'));
  if (!saved.ok) fail('reading the document back failed: ' + JSON.stringify(saved));
  if (saved.reply.content !== text) fail('the provider returned different bytes: ' + JSON.stringify(saved.reply.content));
  step('a document round-trips through the provider byte for byte');

  const mtime = saved.reply.info?.mtime;
  if (typeof mtime !== 'number' || !mtime) fail('the provider stat carries no mtime: ' + JSON.stringify(saved.reply.info));
  step('the provider reports an mtime (' + mtime + ')');

  // A save whose base mtime is stale must be refused: this is the conflict
  // guard, and on a provider it depends on the mtime surviving a write.
  const stale = await attempt('POST', '/api/local/save', {
    tab: tabId, path: run + '/note.txt', content: 'lost\\n', base_mtime_ns: mtime - 1000000000,
  });
  if (stale.ok) fail('a stale save was accepted; the conflict guard did not fire');
  if (stale.status !== 400) fail('a stale save failed with status ' + stale.status);
  step('a save against a stale mtime is refused');

  // --- listing sees what the provider now holds ----------------------------
  const after = await attempt('GET', '/api/local/list?tab=' + tabId + '&path=' + encodeURIComponent(run));
  const names = (after.reply?.entries ?? []).map(e => e.name);
  if (!names.includes('note.txt')) fail('the created document is not listed: ' + JSON.stringify(names));
  step('the created document is listed back');

  // --- deleting ------------------------------------------------------------
  const gone = await attempt('POST', '/api/local/delete', { tab: tabId, names: ['note.txt'] });
  if (!gone.ok) fail('deleting a document failed: ' + JSON.stringify(gone));
  const remaining = await attempt('GET', '/api/local/list?tab=' + tabId + '&path=' + encodeURIComponent(run));
  if ((remaining.reply?.entries ?? []).some(e => e.name === 'note.txt')) {
    fail('the deleted document is still listed');
  }
  step('a document can be deleted through the provider');

  return { treeUri, run, tab: tabId, mtime, steps };
})()`;

let nextId = 0;
async function evaluate(source, timeout = 120000) {
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
    socket.send(JSON.stringify({
      id, method: 'Runtime.evaluate',
      params: { expression: source, awaitPromise: true, returnByValue: true },
    }));
  });
}

// Tauri can navigate its initial document while DevTools is already listening,
// so state is only mutated after two stable ready probes.
let stable = 0;
for (let i = 0; i < 60 && stable < 2; i++) {
  const probe = await evaluate("document.readyState === 'complete' && window.LinSCPTransport?.mode === 'tauri'");
  stable = probe.result?.result?.value === true ? stable + 1 : 0;
  if (stable < 2) await new Promise(resolve => setTimeout(resolve, 1000));
}
assert.equal(stable, 2, 'WebView did not become ready');

const reply = await evaluate(expression);
socket.close();
if (reply.error || reply.result?.exceptionDetails) {
  const detail = reply.result?.exceptionDetails;
  throw new Error(detail?.exception?.description ?? detail?.text ?? JSON.stringify(reply.error));
}

const value = reply.result?.result?.value;
if (value?.skip) {
  console.log('Android SAF smoke: skipped - ' + value.skip + ' (' + value.reason + ')');
  console.log('roots seen: ' + JSON.stringify(value.seen));
  process.exit(0);
}

if (reportPath) writeFileSync(reportPath, JSON.stringify(value, null, 2));
for (const name of value.steps ?? []) console.log('  ok  ' + name);
console.log('Android SAF smoke passed on ' + value.treeUri);
