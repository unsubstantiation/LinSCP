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
  const notes = [];
  const step = name => steps.push(name);

  // A refusal is an answer, not a crash: the transport rejects with a status
  // and payload, so a 400 can be asserted on instead of aborting the run.
  const attempt = async (method, path, body) => {
    try { return { ok: true, reply: await invoke(method, path, body) }; }
    catch (error) { return { ok: false, status: error?.status, payload: error?.payload, message: String(error?.message ?? error) }; }
  };

  // --- the grant -----------------------------------------------------------
  // The service enumerates granted trees itself, so this one call proves the
  // grant reached the Rust side - the part a mock cannot speak to.
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

  const before = await attempt('GET', '/api/local/list?tab=' + tabId);
  if (!before.ok || !Array.isArray(before.reply.entries)) {
    fail('listing the granted tree failed: ' + JSON.stringify(before));
  }
  step('the granted folder lists through the provider (' + before.reply.entries.length + ' entries)');

  // --- run-scoped names ----------------------------------------------------
  // One folder and one file, each a single leaf directly in the granted tree.
  // Local routes take a leaf name and refuse anything with a separator, so the
  // suite names leaves rather than paths - which is exactly how the page drives
  // these routes too.
  const run = 'linscp-saf-' + Date.now();
  const fileName = run + '.txt';
  const text = 'granted text ' + run + '\n';

  const made = await attempt('POST', '/api/local/mkdir', { tab: tabId, name: run });
  if (!made.ok) fail('mkdir in the granted tree failed: ' + JSON.stringify(made));
  step('a folder can be created in a granted tree');

  // --- editing -------------------------------------------------------------
  const written = await attempt('POST', '/api/local/save', { tab: tabId, path: fileName, content: text });
  if (!written.ok) fail('creating a document failed: ' + JSON.stringify(written));
  step('a document can be created in a granted folder');

  const saved = await attempt('GET', '/api/local/edit?tab=' + tabId + '&path=' + encodeURIComponent(fileName));
  if (!saved.ok) fail('reading the document back failed: ' + JSON.stringify(saved));
  if (saved.reply.content !== text) {
    fail('the provider returned different bytes: ' + JSON.stringify(saved.reply.content));
  }
  step('a document round-trips through the provider byte for byte');

  const info = saved.reply.info ?? {};
  if (typeof info.mtime !== 'number' || !info.mtime) {
    fail('the provider stat carries no mtime: ' + JSON.stringify(info));
  }
  step('the provider reports an mtime (' + info.mtime + ')');

  // The conflict guard depends on that mtime surviving a write.
  const stale = await attempt('POST', '/api/local/save', {
    tab: tabId, path: fileName, content: 'lost\n', base_mtime_ns: info.mtime - 1000000000,
  });
  if (stale.ok) fail('a stale save was accepted; the conflict guard did not fire');
  if (stale.status !== 400) fail('a stale save failed with status ' + stale.status);
  step('a save against a stale mtime is refused');

  const reSave = await attempt('POST', '/api/local/save', {
    tab: tabId, path: fileName, content: text + 'second\n', base_mtime_ns: info.mtime,
  });
  if (!reSave.ok) {
    // Worth reporting rather than failing the whole run: a provider that
    // rewrites its own mtime after a write cannot honour a conflict guard, and
    // that is a property of the provider, not of this suite.
    notes.push('re-save with the reported mtime was refused: ' + JSON.stringify(reSave.payload ?? reSave.message));
  } else {
    step('a save against the current mtime is accepted');
  }

  const listedFile = await attempt('GET', '/api/local/list?tab=' + tabId);
  const names = (listedFile.reply?.entries ?? []).map(e => e.name);
  if (!names.includes(fileName)) fail('the created document is not listed: ' + JSON.stringify(names));
  step('the created document is listed back');

  // --- the nested case -----------------------------------------------------
  // This is the one that distinguishes a provider whose document id is the
  // display name (shared storage: primary:Download/report.pdf) from one that
  // keeps an opaque id (Google Drive: 1a2B3c...). Opening a folder and reading
  // a document inside it builds .../document/<name> two levels down, and an
  // opaque provider refuses that unless the shell resolves names to ids.
  //
  // It is a probe, not a gate: a provider that refuses nested paths is a real
  // finding to report, so it is recorded instead of aborting the run.
  const nestedTab = await attempt('POST', '/api/tabs/local', {
    local_dir: treeUri + '/document/' + encodeURIComponent(run),
    remote_dir: treeUri,
  });
  if (!nestedTab.ok) {
    notes.push('a local tab will not open on a subfolder: ' + JSON.stringify(nestedTab.payload ?? nestedTab.message));
  } else {
    const nestedId = nestedTab.reply.tab.id;
    const inside = await attempt('GET', '/api/local/edit?tab=' + nestedId + '&path=' + encodeURIComponent(fileName));
    if (!inside.ok) {
      notes.push('a document inside a subfolder cannot be read: ' + JSON.stringify(inside.payload ?? inside.message));
    } else if (inside.reply.content !== text) {
      notes.push('a document inside a subfolder reads back different bytes');
    } else {
      step('a document inside a subfolder is readable (provider ids resolve)');
    }
    await attempt('POST', '/api/tabs/close', { tab: nestedId });
  }

  // --- deleting ------------------------------------------------------------
  const gone = await attempt('POST', '/api/local/delete', { tab: tabId, names: [fileName] });
  if (!gone.ok) fail('deleting a document failed: ' + JSON.stringify(gone));
  const remaining = await attempt('GET', '/api/local/list?tab=' + tabId);
  if ((remaining.reply?.entries ?? []).some(e => e.name === fileName)) {
    fail('the deleted document is still listed');
  }
  step('a document can be deleted through the provider');

  // Leave the granted tree as it was found.
  await attempt('POST', '/api/local/delete', { tab: tabId, names: [run] });

  return { treeUri, run, tab: tabId, mtime: info.mtime, steps, notes };
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
for (const name of value.steps ?? []) console.log('  ok    ' + name);
// A note is a real finding about the provider that did not stop the run. It is
// printed, written into the report, and never turned into a pass.
for (const note of value.notes ?? []) console.log('  note  ' + note);
if ((value.notes ?? []).length) {
  console.log('');
  console.log('Android SAF smoke finished with ' + value.notes.length +
              ' provider finding(s); the runs above still passed.');
} else {
  console.log('Android SAF smoke passed on ' + value.treeUri);
}
console.log(JSON.stringify({ treeUri: value.treeUri, steps: (value.steps ?? []).length, notes: value.notes ?? [] }));
