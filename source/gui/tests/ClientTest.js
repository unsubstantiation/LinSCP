/* Smoke test for the LinSCP Commander web client: boots the real page in
 * jsdom with a stubbed backend and checks that the UI renders and reacts. */
const fs = require('fs');
const path = require('path');

function loadJsdom() {
  const candidates = ['jsdom', path.join(process.cwd(), 'node_modules', 'jsdom')];
  for (const dir of (process.env.NODE_PATH || '').split(path.delimiter)) {
    if (dir) candidates.push(path.join(dir, 'jsdom'));
  }
  for (const candidate of candidates) {
    try { return require(candidate); } catch (error) { /* try the next place */ }
  }
  console.error('This test needs jsdom. Install it with:  npm install jsdom');
  process.exit(2);
}
const { JSDOM } = loadJsdom();

/* Usage: node ClientTest.js [path/to/index.html]
 *
 * Needs jsdom:  npm install jsdom   (in any directory on NODE_PATH or above
 * the page). The backend is stubbed, so no LinSCP build is required. */
const PAGE = process.argv[2] || path.join(__dirname, '..', 'web', 'index.html');
  const html = fs.readFileSync(PAGE, 'utf8');
  const themeCss = fs.readFileSync(path.join(__dirname, '..', 'web', 'theme.css'), 'utf8');
  const iconSvg = fs.readFileSync(path.join(__dirname, '..', 'web', 'icon.svg'), 'utf8');

const LOCAL_ENTRIES = [
  { name: 'a.txt', size: 9, is_dir: false, date: 'Oct 13 07:07', permissions: '-rw-r--r--' },
  { name: 'sub', size: 0, is_dir: true, date: 'Oct 13 07:08', permissions: 'drwxr-xr-x' },
  { name: 'big.bin', size: 1048576, is_dir: false, date: 'Oct 13 07:09', permissions: '-rw-r--r--' }
];
const REMOTE_ENTRIES = [
  { name: 'keep.txt', size: 22, is_dir: false, date: 'Oct 13 07:07', permissions: '-rw-r--r--' },
  { name: 'testdir', size: 60, is_dir: true, date: 'Oct 13 07:08', permissions: 'drwxr-xr-x' }
];

const responses = {
  '/api/status': {
    tabs: [{
      id: 1, name: 'local test', connected: true,
      session: { protocol: 'sftp', host: '127.0.0.1', port: 2222, username: 'user', hostkey: '*' },
      remote_dir: '/tmp/slowremote', local_dir: '/tmp/slowlocal',
      observed_hostkey: 'ssh-ed25519 255 SHA256:abc', error: ''
    }],
    active_tab: 1, paused: false, binary: '/usr/bin/linscp',
    local_dir: '/tmp/slowlocal', remote_dir: '/tmp/slowremote',
    sessions_file: '/tmp/cfg/sessions.ini'
  },
  '/api/local/list': { success: true, path: '/tmp/slowlocal', entries: LOCAL_ENTRIES },
  '/api/remote/list': { success: true, path: '/tmp/slowremote', entries: REMOTE_ENTRIES },
  '/api/transfers': {
    transfers: [
      { id: 1, type: 'Download', status: 'Running', source: '/r/a.txt', destination: '/l/a.txt',
        bytes_done: 5, bytes_total: 10, percent: 50, detail: '' },
      { id: 2, type: 'Synchronize (both)', status: 'Failed', source: '/l', destination: '/r',
        bytes_done: 0, bytes_total: 0, percent: 0, detail: 'boom', error: 'connection lost' }
    ],
    paused: false
  },
  '/api/logs': { logs: [{ time: '07:00', level: 'info', text: 'Connected' }] },
  '/api/sessions': {
    file: '/tmp/cfg/sessions.ini',
    sessions: [{ name: 'GUI/test', protocol: 'sftp', host: '127.0.0.1', port: 2222,
      username: 'user', keyfile: '/tmp/key', hostkey: '*', initial_dir: '/tmp/slowremote',
      local_dir: '/tmp/slowlocal', last_used: 1791876426 }]
  },
  '/api/remote/edit': { success: true, path: '/tmp/slowremote/keep.txt',
    content: 'keep\n', info: { size: 5, mtime: 1791875271, temp: '/tmp/x', path: '/tmp/slowremote/keep.txt' } },
  '/api/local/edit': { success: true, path: '/tmp/slowlocal/a.txt',
    content: 'local text\n', info: { size: 11, mtime: 1791875271, mtime_ns: 1791875271000000000 } },
  '/api/local/save': { success: true,
    info: { size: 12, mtime: 1791875272, mtime_ns: 1791875272000000000 } },
  '/api/transfer/move': { success: true },
  '/api/shell/pending': { success: true, pending: [] },
  '/api/shell/consume': { success: true, queued: ['a.txt', 'folder'],
    missing: [], remote_dir: '/tmp/slowremote' },
  '/api/shell/dismiss': { success: true },
  '/api/sync/preview': { success: true, plan: {
    header: { local: '/tmp/slowlocal', remote: '/tmp/slowremote', mode: 'both', criteria: 'time', mask: '(none)' },
    items: [
      { action: 'download', path: 'keep.txt', reason: 'the remote file is newer' },
      { action: 'delete-remote', path: 'old.bak', reason: 'deleted locally' },
      { action: 'conflict', path: 'a.txt', reason: 'changed on both sides' },
      { action: 'unchanged', path: 'skip.log', reason: 'up to date' }
    ],
    summary: { download: 1, upload: 0, 'delete-local': 0, 'delete-remote': 1, conflict: 1, unchanged: 1 } } },
  '/api/remote/search': { success: true, matches: [
    { path: '/tmp/slowremote/keep.txt', name: 'keep.txt', is_dir: false, size: 22,
      date: 'Oct 13 07:07', permissions: '-rw-r--r--' }], truncated: false },
  '/api/workspaces': { success: true, file: '/tmp/cfg/workspaces.json',
    workspaces: [
      { name: 'stored', tab_count: 2, active: 1, tabs: [
        { name: 'one', kind: 'local', local_dir: '/tmp/slowlocal', remote_dir: '/tmp/slowremote' },
        { name: 'two', kind: 'sftp', site: 'GUI/test' }] }
    ] },
  '/api/command/exec': { success: true, exit_code: 0, stdout: '/tmp/slowremote\n', stderr: '' },
  /* A new site has no host key, so the backend asks instead of connecting. */
  '/api/tabs/open': {
    success: false,
    error: 'The host key is not cached; use -hostkey to accept it',
    challenge: { tab: 7, host: '127.0.0.1', port: 2222,
      fingerprint: 'ssh-ed25519 255 SHA256:2cxQVcO3EC5SbPVedJPA1XHIV2sEvZzPVTIiBgoZaxM' },
    tab: { id: 7, name: 'local test', connected: false, error: '' }
  },
  '/api/tabs/verify': { success: true, tab: {
    id: 7, name: 'local test', connected: true,
    session: { protocol: 'sftp', host: '127.0.0.1', port: 2222, username: 'user',
      hostkey: 'ssh-ed25519 255 SHA256:2cxQVcO3EC5SbPVedJPA1XHIV2sEvZzPVTIiBgoZaxM' },
    remote_dir: '/tmp/slowremote', local_dir: '/tmp/slowlocal',
    observed_hostkey: 'ssh-ed25519 255 SHA256:2cxQVcO3EC5SbPVedJPA1XHIV2sEvZzPVTIiBgoZaxM',
    error: '' } }
};

/* The persisted command templates the custom-commands dialog lists, saves
 * and runs. Both fetch stubs below answer it: the browsing tests replace
 * the first stub, and the dialog tests run after that replacement. */
function customCommandsBody(options) {
  let request = {};
  try { request = JSON.parse((options && options.body) || '{}'); } catch (error) {}
  const stored = [
    { name: 'Checksum', command: 'checksum sha-256 {file}', scope: 'remote' },
    { name: 'Local word count', command: 'wc {file}', scope: 'local' }
  ];
  if (request.action === 'save') {
    stored.push({ name: request.name, command: request.command, scope: request.scope });
    return { success: true, commands: stored };
  }
  if (request.action === 'run') {
    return { success: true, scope: 'remote',
      results: (request.filenames || []).map(name => (
        { file: name, success: true, exit_code: 0, stdout: 'SHA-256 verified', stderr: '' })) };
  }
  return { success: true, commands: stored };
}

const TOKEN = 'test-token-0123456789abcdef';

const calls = [];
const errors = [];
const confirmMessages = [];
let confirmResult = true;

const dom = new JSDOM(html, {
  url: 'http://localhost:8080/',
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  beforeParse(window) {
    // What the backend injects into the page it serves.
    window.LSCP_TOKEN = TOKEN;
    window.fetch = (url, options) => {
      const path = String(url).replace('http://localhost:8080', '').split('?')[0];
      calls.push({ path: path, url: String(url), options: options });
      let body = responses[path];
      if (path === '/api/custom-commands') {
        body = customCommandsBody(options);
      }
      if (path === '/api/workspaces/save') {
        let request = {};
        try { request = JSON.parse(options.body || '{}'); } catch (error) {}
        body = { success: true, workspace: { name: request.name || 'demo', tab_count: 2 } };
      }
      if (path === '/api/workspaces/open') {
        body = { success: true, opened: [3, 4], failed: [], active_tab: 4 };
      }
      if (path === '/api/workspaces/delete') {
        body = { success: true };
      }
      if (path === '/api/remote/search') {
        let request = {};
        try { request = JSON.parse(options.body || '{}'); } catch (error) {}
        if (request.search_contents) {
          body = { success: true, matches: [
            { path: '/tmp/slowremote/keep.txt', name: 'keep.txt', is_dir: false,
              size: 22, permissions: '-rw-r--r--', line: 3,
              snippet: 'Needle <example>' }
          ], truncated: false, scanned: 4, skipped: 1, bytes_scanned: 64 };
        }
      }
      if (path === '/api/custom-commands') {
        let request = {};
        try { request = JSON.parse(options.body || '{}'); } catch (error) {}
        if (request.action === 'list') {
          body = { success: true, commands: [
            { name: 'Checksum', command: 'checksum sha-256 {file}', scope: 'remote' }
          ] };
        } else if (request.action === 'run') {
          body = { success: true, scope: 'remote', results: request.filenames.map(file => ({
            file, success: true, exit_code: 0, stdout: 'SHA-256 verified', stderr: ''
          })) };
        }
      }
      if (body === undefined) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ success: true }) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
    };
    window.prompt = () => 'asked';
    window.confirm = message => { confirmMessages.push(message); return confirmResult; };
    window.alert = () => {};
    window.addEventListener('error', event => errors.push('window error: ' + event.message));
    window.addEventListener('unhandledrejection', event =>
      errors.push('unhandled rejection: ' + event.reason));
  }
});

const { window } = dom;

function check(name, condition, extra) {
  const status = condition ? 'ok  ' : 'FAIL';
  console.log(status + ' ' + name + (condition || !extra ? '' : ' -- ' + extra));
  if (!condition) process.exitCode = 1;
}

function text(id) {
  const node = window.document.getElementById(id);
  return node ? node.textContent.trim() : '<missing #' + id + '>';
}

function value(id) {
  const node = window.document.getElementById(id);
  return node ? node.value : '<missing #' + id + '>';
}

function options(id) {
  const node = window.document.getElementById(id);
  return node ? Array.prototype.slice.call(node.options) : [];
}

(async () => {
  await new Promise(resolve => setTimeout(resolve, 400));

  // Boot fetched what it needs.
  const paths = calls.map(call => call.path);
  check('boot queried the status', paths.includes('/api/status'));
  check('boot listed the local pane', paths.includes('/api/local/list'));
  check('boot listed the remote pane', paths.includes('/api/remote/list'));

  const doc = window.document;
  check('Commander opens with the dark theme',
    doc.documentElement.dataset.theme === 'dark' && themeCss.includes('--bg: #0e131a'));
  check('app icon uses a dark badge', iconSvg.includes('fill="#101821"'));
  check('Commander menu matches the Local / Mark / Files layout',
    ['Local', 'Mark', 'Files', 'Commands', 'Tabs', 'Options', 'Remote', 'Help']
      .every(label => Array.from(doc.querySelectorAll('.menu-item')).some(item => item.textContent.trim() === label)));
  check('function-key strip exposes all ten Commander actions',
    doc.querySelectorAll('.function-keys .fn-key').length === 10 &&
      text('helpModal').indexOf('F5 copy') >= 0);
  check('local pane rendered 3 rows',
    doc.getElementById('localFileList').children.length === 3,
    doc.getElementById('localFileList').children.length);
  check('remote pane rendered 2 rows',
    doc.getElementById('remoteFileList').children.length === 2);
  check('one session tab', doc.getElementById('tabStrip').children.length === 1);
  check('connected badge', text('statusBadge').startsWith('Connected'), text('statusBadge'));
  check('host key notice shown for a wildcard session',
    doc.getElementById('hostKeyBar').style.display === 'flex',
    doc.getElementById('hostKeyBar').style.display);
  check('queue tab counts 2 tasks', text('tabQueueBtn') === 'Transfer Queue (2)', text('tabQueueBtn'));
  check('queue rendered a progress bar',
    doc.getElementById('queueList').innerHTML.indexOf('progress-bar') >= 0);
  check('failed task offers Retry',
    doc.getElementById('queueList').innerHTML.indexOf('Retry') >= 0);
  check('sizes are formatted', text('localFileList').indexOf('1.0 MB') >= 0, text('localFileList'));

  // Selecting a file, then opening the editor on the remote side.
  doc.getElementById('remoteFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  check('clicking a row selects it',
    doc.getElementById('remoteFileList').children[0].className === 'selected',
    doc.getElementById('remoteFileList').children[0].className);
  check('summary counts the selection', text('remoteSummary').indexOf('1 selected') >= 0,
    text('remoteSummary'));

  await window.viewSelected('remote');
  await new Promise(resolve => setTimeout(resolve, 80));
  check('F3 opens the selected remote text file read-only',
    doc.getElementById('editorModal').className.indexOf('open') >= 0 &&
      doc.getElementById('editorText').readOnly &&
      doc.getElementById('editorSaveBtn').style.display === 'none');
  window.closeEditor();
  await window.editSelected('remote');
  await new Promise(resolve => setTimeout(resolve, 100));
  check('F4 opens the selected remote file in the editor', doc.getElementById('editorModal').className.indexOf('open') >= 0);
  check('editor loaded the content', doc.getElementById('editorText').value === 'keep\n',
    JSON.stringify(doc.getElementById('editorText').value));

  // Editing marks it dirty, saving posts the new content.
  const area = doc.getElementById('editorText');
  area.value = 'keep\nmore\n';
  area.dispatchEvent(new window.Event('input', { bubbles: true }));
  check('editing marks the file dirty', text('editorStatus').indexOf('Modified') >= 0,
    text('editorStatus'));
  await window.saveEditorFile();
  await new Promise(resolve => setTimeout(resolve, 100));
  const save = calls.filter(call => call.path === '/api/remote/save').pop();
  check('save posted the new content',
    save && JSON.parse(save.options.body).content === 'keep\nmore\n');
  check('save sent the base modification time',
    save && JSON.parse(save.options.body).base_mtime === 1791875271);

  // Local and remote panels use the same bounded editor workflow.
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await window.editSelected('local');
  await new Promise(resolve => setTimeout(resolve, 80));
  check('F4 edits a local text file too',
    doc.getElementById('editorText').value === 'local text\n' &&
      !doc.getElementById('editorText').readOnly);
  doc.getElementById('editorText').value = 'edited locally\n';
  doc.getElementById('editorText').dispatchEvent(new window.Event('input', { bubbles: true }));
  await window.saveEditorFile();
  await new Promise(resolve => setTimeout(resolve, 80));
  const localSave = calls.filter(call => call.path === '/api/local/save').pop();
  check('local save posts the content and conflict timestamp',
    localSave && JSON.parse(localSave.options.body).content === 'edited locally\n' &&
      JSON.parse(localSave.options.body).base_mtime_ns === 1791875271000000000);
  window.closeEditor();

  // Synchronize: preview renders the plan.
  window.openSynchronize();
  check('sync dialog prefills the panes', doc.getElementById('syncLocal').value === '/tmp/slowlocal');
  await window.previewSynchronization();
  await new Promise(resolve => setTimeout(resolve, 100));
  check('plan listed four items',
    doc.getElementById('syncPreview').children.length === 4,
    doc.getElementById('syncPreview').children.length);
  check('plan summary mentions the conflict',
    text('syncSummary').indexOf('1 conflict') >= 0, text('syncSummary'));
  check('plan items are colour coded by action',
    doc.getElementById('syncPreview').innerHTML.indexOf('plan-item conflict') >= 0);
  doc.getElementById('syncMode').value = 'both';
  await window.runSynchronization();
  await new Promise(resolve => setTimeout(resolve, 100));
  const run = calls.filter(call => call.path === '/api/sync/run').pop();
  check('running the plan posts the settings',
    run && JSON.parse(run.options.body).mode === 'both');
  check('the contents are one of the comparisons offered',
    options('syncCriteria').some(option => option.value === 'checksum') &&
    options('syncCriteria').some(option => option.value === 'time,checksum'),
    options('syncCriteria').map(option => option.value).join('|'));

  // In the 'both' direction the record of the previous synchronization
  // decides, so the dialog stops offering the comparisons the console would
  // refuse there rather than letting a preview fail on one of them.
  doc.getElementById('syncMode').value = 'both';
  doc.getElementById('syncMode').dispatchEvent(new window.Event('change'));
  check('the both direction refuses the comparisons it cannot make',
    options('syncCriteria').filter(option => option.disabled)
      .map(option => option.value).join('|') === 'checksum|time,checksum|none',
    options('syncCriteria').filter(option => option.disabled)
      .map(option => option.value).join('|'));
  check('the both direction keeps a comparison it can make',
    value('syncCriteria') === 'time', value('syncCriteria'));
  check('the both direction says what decides instead',
    text('syncHint').indexOf('previous synchronization') >= 0, text('syncHint'));
  doc.getElementById('syncMode').value = 'local';
  doc.getElementById('syncMode').dispatchEvent(new window.Event('change'));
  check('a one-way direction offers every comparison again',
    options('syncCriteria').every(option => !option.disabled));

  // A list of comparisons reaches the console as the client got it, and the
  // default one is left out of the command line.
  doc.getElementById('syncCriteria').value = 'time,checksum';
  await window.runSynchronization();
  await new Promise(resolve => setTimeout(resolve, 100));
  const listed = calls.filter(call => call.path === '/api/sync/run').pop();
  check('the chosen comparison is posted with the plan',
    listed && JSON.parse(listed.options.body).criteria === 'time,checksum',
    listed && listed.options.body);

  // Filename search remains the default. Content search is opt-in, carries
  // its literal query to the backend, reports its scan budget and escapes
  // matched text before rendering a snippet.
  window.openSearch();
  doc.getElementById('searchPattern').value = '*.txt';
  await window.runSearch();
  await new Promise(resolve => setTimeout(resolve, 100));
  check('filename search lists one match',
    text('searchSummary').indexOf('1 match') >= 0, text('searchSummary'));
  let searchCall = calls.filter(call => call.path === '/api/remote/search').pop();
  check('filename search stays in name-only mode',
    searchCall && JSON.parse(searchCall.options.body).search_contents === false);

  const searchContents = doc.getElementById('searchContents');
  searchContents.checked = true;
  searchContents.dispatchEvent(new window.Event('change'));
  check('content query is revealed when enabled',
    doc.getElementById('searchTextRow').style.display === 'flex');
  doc.getElementById('searchText').value = 'needle';
  await window.runSearch();
  await new Promise(resolve => setTimeout(resolve, 100));
  searchCall = calls.filter(call => call.path === '/api/remote/search').pop();
  check('content search posts its literal query',
    searchCall && JSON.parse(searchCall.options.body).content_query === 'needle' &&
      JSON.parse(searchCall.options.body).search_contents === true);
  check('content search reports scanned and skipped files',
    text('searchSummary').indexOf('4 file(s) scanned, 1 skipped') >= 0,
    text('searchSummary'));
  check('content match snippet is safely escaped',
    doc.getElementById('searchResults').innerHTML.indexOf('Needle &lt;example&gt;') >= 0,
    doc.getElementById('searchResults').innerHTML);

  // Site manager.
  window.openSiteManager();
  await new Promise(resolve => setTimeout(resolve, 150));
  check('site manager lists the stored session',
    doc.getElementById('siteList').children.length === 1 &&
    doc.getElementById('siteList').textContent.indexOf('GUI/test') >= 0);
  doc.getElementById('siteList').children[0].dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  check('clicking a site fills the form', doc.getElementById('siteHost').value === '127.0.0.1',
    doc.getElementById('siteHost').value);
  await window.saveSite();
  await new Promise(resolve => setTimeout(resolve, 100));
  const saved = calls.filter(call => call.path === '/api/sessions/save').pop();
  check('saving posts the name', saved && JSON.parse(saved.options.body).name === 'GUI/test');
  check('saving does not post the password',
    saved && !JSON.parse(saved.options.body).session.password);

  // CLI terminal.
  window.switchTab('cli');
  doc.getElementById('cliInput').value = 'pwd ; ls';
  await window.execCliCommand();
  await new Promise(resolve => setTimeout(resolve, 100));
  check('terminal shows the command output',
    text('cliOutput').indexOf('/tmp/slowremote') >= 0, text('cliOutput').slice(-80));
  window.switchTab('log');
  await new Promise(resolve => setTimeout(resolve, 150));
  check('log tab renders entries', doc.getElementById('logOutput').children.length === 1,
    doc.getElementById('logOutput').children.length);
  window.switchTab('queue');

  // Keyboard shortcuts: Ctrl+A in the focused pane.
  doc.getElementById('localPane').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'a', ctrlKey: true, bubbles: true }));
  check('Ctrl+A selects every entry', text('localSummary').indexOf('3 selected') >= 0,
    text('localSummary'));
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  const uploadsBeforeF5 = calls.filter(call => call.path === '/api/transfer/upload').length;
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F5', bubbles: true }));
  await new Promise(resolve => setTimeout(resolve, 80));
  const f5Upload = calls.filter(call => call.path === '/api/transfer/upload').pop();
  check('F5 copies from the focused local panel',
    calls.filter(call => call.path === '/api/transfer/upload').length === uploadsBeforeF5 + 1 &&
      f5Upload && JSON.parse(f5Upload.options.body).names.join(',') === 'a.txt');
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F6', bubbles: true }));
  await new Promise(resolve => setTimeout(resolve, 100));
  const f6Move = calls.filter(call => call.path === '/api/transfer/move').pop();
  check('F6 queues a move to the opposite panel',
    f6Move && JSON.parse(f6Move.options.body).direction === 'upload' &&
      JSON.parse(f6Move.options.body).names.join(',') === 'a.txt');
  const localChmodBefore = calls.filter(call => call.path === '/api/local/chmod').length;
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F9', bubbles: true }));
  await new Promise(resolve => setTimeout(resolve, 80));
  check('F9 opens properties for the focused panel',
    calls.filter(call => call.path === '/api/local/chmod').length > localChmodBefore);
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F1', bubbles: true }));
  check('F1 opens Help', doc.getElementById('helpModal').className.indexOf('open') >= 0);
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  check('Escape closes the modal', doc.getElementById('helpModal').className.indexOf('open') < 0);

  // ---- Synchronized browsing ------------------------------------------
  // The boot stub answers every list call with one fixed response, which
  // cannot show navigation; switch to a path-aware stub for this section.
  const LOCAL_DIRS = {
    '/tmp/slowlocal': LOCAL_ENTRIES,
    '/tmp/slowlocal/sub': [
      { name: 'inner.txt', size: 3, is_dir: false, date: 'Oct 13 08:00',
        permissions: '-rw-r--r--' }
    ]
  };
  const REMOTE_DIRS = {
    '/tmp/slowremote': REMOTE_ENTRIES,
    '/tmp/slowremote/sub': [
      { name: 'inner-remote.txt', size: 4, is_dir: false, date: 'Oct 13 08:01',
        permissions: '-rw-r--r--' }
    ]
    // Deliberately no '/tmp/slowremote/testdir' -> '/tmp/slowlocal/testdir'
    // mapping: 'testdir' exists only on the remote side.
  };
  const browseCalls = [];
  window.fetch = (url, options) => {
    const raw = String(url).replace('http://localhost:8080', '');
    const parts = raw.split('?');
    const path = parts[0];
    calls.push({ path: path, url: String(url), options: options });
    browseCalls.push(raw);
    const params = new URLSearchParams(parts[1] || '');
    if (path === '/api/local/list' || path === '/api/remote/list') {
      const isLocal = path === '/api/local/list';
      const dir = params.get('path') ||
        (isLocal ? '/tmp/slowlocal' : '/tmp/slowremote');
      const table = isLocal ? LOCAL_DIRS : REMOTE_DIRS;
      const body = table[dir] ?
        { success: true, path: dir, entries: table[dir] } :
        { success: false, error: 'No such directory: ' + dir };
      return Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
    }
    if (path === '/api/custom-commands') {
      return Promise.resolve(
        { ok: true, json: () => Promise.resolve(customCommandsBody(options)) });
    }
    const body = responses[path];
    if (body === undefined) {
      return Promise.resolve(
        { ok: true, json: () => Promise.resolve({ success: true }) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
  };
  const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  window.toggleSyncBrowse();
  check('synchronized browsing lights up when toggled',
    doc.getElementById('syncBrowseBtn').className.indexOf('active') >= 0,
    doc.getElementById('syncBrowseBtn').className);
  await doc.getElementById('localFileList').children[1].ondblclick();
  await wait(80);
  check('entering sub locally moved the local pane',
    value('localPathInput') === '/tmp/slowlocal/sub', value('localPathInput'));
  check('the remote pane followed into its own sub',
    value('remotePathInput') === '/tmp/slowremote/sub', value('remotePathInput'));
  check('the follow asked for the counterpart path',
    browseCalls.some(url =>
      url.indexOf('path=' + encodeURIComponent('/tmp/slowremote/sub')) >= 0),
    browseCalls.slice(-4).join(' | '));
  check('the counterpane lists the sub contents',
    text('remoteFileList').indexOf('inner-remote.txt') >= 0,
    text('remoteFileList'));

  await window.goUp('local');
  await wait(80);
  check('going up carries the pair back to the roots',
    value('localPathInput') === '/tmp/slowlocal' &&
    value('remotePathInput') === '/tmp/slowremote',
    value('localPathInput') + ' / ' + value('remotePathInput'));

  // A directory the other side does not have: neither pane moves.
  await window.openEntry('remote',
    REMOTE_ENTRIES.find(entry => entry.name === 'testdir'));
  await wait(80);
  check('a missing counterpart leaves both panes alone',
    value('localPathInput') === '/tmp/slowlocal' &&
    value('remotePathInput') === '/tmp/slowremote',
    value('localPathInput') + ' / ' + value('remotePathInput'));

  window.toggleSyncBrowse();
  check('toggling synchronized browsing off',
    doc.getElementById('syncBrowseBtn').className.indexOf('active') < 0,
    doc.getElementById('syncBrowseBtn').className);
  await doc.getElementById('localFileList').children[1].ondblclick();
  await wait(80);
  check('with it off the other pane stays put',
    value('localPathInput') === '/tmp/slowlocal/sub' &&
    value('remotePathInput') === '/tmp/slowremote',
    value('localPathInput') + ' / ' + value('remotePathInput'));
  await window.goUp('local');
  await wait(80);

  // ---- Drag and drop between the panes --------------------------------
  function fakeTransfer() {
    const store = {};
    return {
      effectAllowed: '', dropEffect: '',
      setData(kind, value) { store[kind] = value; },
      getData(kind) { return store[kind] || ''; }
    };
  }
  const dragDt = fakeTransfer();
  const dragStart = { dataTransfer: dragDt };
  window.beginDrag('local', LOCAL_ENTRIES[0], dragStart);
  check('the drag payload carries the dragged names',
    JSON.parse(dragDt.getData('text/plain')).names.join(',') === 'a.txt',
    dragDt.getData('text/plain'));
  check('the payload names the source pane',
    JSON.parse(dragDt.getData('text/plain')).side === 'local',
    dragDt.getData('text/plain'));
  check('dragging an unselected entry selects it',
    window.selectedNames('local').join(',') === 'a.txt',
    window.selectedNames('local').join(','));

  const overEvent = {
    dataTransfer: dragDt,
    preventDefault() { this.prevented = true; }
  };
  window.dragOverPane('remote', overEvent);
  check('dragover on the other pane is accepted',
    overEvent.prevented === true, 'preventDefault not called');
  check('the drop target highlights',
    doc.getElementById('remotePane').className.indexOf('drop-target') >= 0,
    doc.getElementById('remotePane').className);

  const uploadsBefore = calls.filter(
    call => call.path === '/api/transfer/upload').length;
  await window.dropOnPane('remote', { dataTransfer: dragDt,
    preventDefault() {} });
  await wait(150);
  const uploadCalls = calls.filter(
    call => call.path === '/api/transfer/upload');
  check('dropping on the other pane queues an upload',
    uploadCalls.length === uploadsBefore + 1,
    uploadsBefore + ' -> ' + uploadCalls.length);
  const uploadBody = uploadCalls.length ?
    JSON.parse(uploadCalls[uploadCalls.length - 1].options.body) : {};
  check('the upload carries exactly the dragged names',
    (uploadBody.names || []).join(',') === 'a.txt',
    JSON.stringify(uploadBody.names));
  check('the upload is rooted in both panes',
    uploadBody.local_dir === '/tmp/slowlocal' &&
    uploadBody.remote_dir === '/tmp/slowremote',
    uploadBody.local_dir + ' / ' + uploadBody.remote_dir);
  check('the highlight cleared after the drop',
    doc.getElementById('remotePane').className.indexOf('drop-target') < 0,
    doc.getElementById('remotePane').className);

  // Files dragged from the operating system have no LinSCP text payload; a
  // drop on the remote pane must post the actual File body to the upload API.
  const desktopFile = new window.File(['desktop upload'], 'desktop.txt',
    { type: 'text/plain' });
  const desktopDt = { files: [desktopFile], types: ['Files'], dropEffect: '' };
  const desktopOver = { dataTransfer: desktopDt,
    preventDefault() { this.prevented = true; } };
  window.dragOverPane('remote', desktopOver);
  check('dragover accepts a file from the desktop',
    desktopOver.prevented === true && desktopDt.dropEffect === 'copy');
  await window.dropOnPane('remote', { dataTransfer: desktopDt,
    preventDefault() {} });
  await wait(100);
  const desktopCalls = calls.filter(call =>
    call.path === '/api/transfer/drop');
  const desktopRequest = desktopCalls[desktopCalls.length - 1];
  const desktopUrl = desktopRequest ? new URL(desktopRequest.url,
    'http://localhost:8080') : null;
  check('desktop file bytes are queued for remote upload',
    !!desktopRequest && desktopRequest.options.body === desktopFile &&
      desktopRequest.options.headers['Content-Type'] === 'application/octet-stream');
  check('desktop upload targets the remote pane directory',
    !!desktopUrl && desktopUrl.searchParams.get('name') === 'desktop.txt' &&
      desktopUrl.searchParams.get('remote_dir') === '/tmp/slowremote' &&
      desktopUrl.searchParams.get('tab') === '1',
    desktopRequest ? desktopRequest.url + ' -> ' +
      JSON.stringify(desktopUrl ? Array.from(desktopUrl.searchParams.entries()) : []) :
      'no upload request');

  // A folder from the Linux file manager exposes FileSystemEntries. Some
  // browsers return directory children in batches, including an empty final
  // batch; nested and empty folders must both survive the drop.
  function fileEntry(name, contents) {
    const file = new window.File([contents], name);
    return { name, isFile: true, file(done) { done(file); } };
  }
  function directoryEntry(name, batches) {
    return { name, isDirectory: true, createReader() {
      let next = 0;
      return { readEntries(done) { done(batches[next++] || []); } };
    } };
  }
  const tree = directoryEntry('project', [
    [directoryEntry('empty', [[]]),
      directoryEntry('src', [
        [fileEntry('read %TIMESTAMP%.txt', 'preserve this literal name')], []])],
    []
  ]);
  const foldersBefore = calls.filter(c => c.path === '/api/transfer/drop-dir').length;
  const filesBefore = calls.filter(c => c.path === '/api/transfer/drop').length;
  await window.dropOnPane('remote', { dataTransfer: {
    items: [{ kind: 'file', webkitGetAsEntry() { return tree; } }],
    files: [], types: ['Files']
  }, preventDefault() {} });
  const folders = calls.filter(c => c.path === '/api/transfer/drop-dir')
    .slice(foldersBefore).map(c => JSON.parse(c.options.body).relative_path);
  check('desktop folders and empty subfolders are queued in order',
    folders.join(',') === 'project,project/empty,project/src', folders.join(','));
  const folderFiles = calls.filter(c => c.path === '/api/transfer/drop')
    .slice(filesBefore);
  const nestedFile = folderFiles.length ?
    new URL(folderFiles[0].url, 'http://localhost:8080') : null;
  check('nested desktop file keeps its relative path and bytes',
    folderFiles.length === 1 && !!nestedFile &&
      nestedFile.searchParams.get('relative_path') ===
        'project/src/read %TIMESTAMP%.txt' &&
      folderFiles[0].options.body.name === 'read %TIMESTAMP%.txt');

  // Enumeration failure is all-or-nothing, not a half-uploaded tree.
  const countBeforeInvalid = calls.filter(c =>
    c.path === '/api/transfer/drop' || c.path === '/api/transfer/drop-dir').length;
  await window.dropOnPane('remote', { dataTransfer: {
    items: [{ kind: 'file', webkitGetAsEntry() {
      return directoryEntry('unsafe', [[fileEntry('..', 'bad')], []]);
    } }], files: [], types: ['Files']
  }, preventDefault() {} });
  check('an unsafe folder entry queues nothing',
    calls.filter(c => c.path === '/api/transfer/drop' ||
      c.path === '/api/transfer/drop-dir').length === countBeforeInvalid);

  // The newer handle API is also usable if the browser has no Entry API.
  const handle = { kind: 'directory', name: 'via-handle',
    async *values() { yield { kind: 'file', name: 'x.txt',
      async getFile() { return new window.File(['handle'], 'x.txt'); } }; }
  };
  await window.dropOnPane('remote', { dataTransfer: {
    items: [{ kind: 'file', getAsFileSystemHandle() { return Promise.resolve(handle); } }],
    files: [], types: ['Files']
  }, preventDefault() {} });
  const handleFile = calls.filter(c => c.path === '/api/transfer/drop').pop();
  check('file system handles retain the directory of their file',
    !!handleFile && new URL(handleFile.url, 'http://localhost:8080')
      .searchParams.get('relative_path') === 'via-handle/x.txt');

  // A drop on the pane the items came from queues nothing.
  const sameDt = fakeTransfer();
  window.beginDrag('local', LOCAL_ENTRIES[0], { dataTransfer: sameDt });
  const sameBefore = calls.filter(
    call => call.path === '/api/transfer/upload').length;
  await window.dropOnPane('local', { dataTransfer: sameDt,
    preventDefault() {} });
  await wait(60);
  check('a same-pane drop does not queue anything',
    calls.filter(call => call.path === '/api/transfer/upload').length ===
      sameBefore);

  // Every API call has to carry this run's token.
  check('every API call carries the token',
    calls.length > 0 && calls.every(call => call.options && call.options.headers &&
      call.options.headers['X-LSCP-Token'] === TOKEN),
    calls.filter(call => !(call.options && call.options.headers &&
      call.options.headers['X-LSCP-Token'] === TOKEN)).map(c => c.path).join(','));

  // Host keys are verified instead of accepted.
  window.openSiteManager();
  await new Promise(resolve => setTimeout(resolve, 100));
  await window.connectFromSiteManager();
  await new Promise(resolve => setTimeout(resolve, 100));
  check('an unknown host key opens the verification dialog',
    doc.getElementById('hostKeyModal').className.indexOf('open') >= 0);
  check('the dialog shows the fingerprint',
    text('hostKeyFingerprint') ===
      'ssh-ed25519 255 SHA256:2cxQVcO3EC5SbPVedJPA1XHIV2sEvZzPVTIiBgoZaxM',
    text('hostKeyFingerprint'));
  check('the dialog names the host',
    text('hostKeyQuestion').indexOf('127.0.0.1 (port 2222)') >= 0, text('hostKeyQuestion'));
  await window.acceptHostKey();
  await new Promise(resolve => setTimeout(resolve, 150));
  const verify = calls.filter(call => call.path === '/api/tabs/verify').pop();
  check('connecting pins the fingerprint that was shown',
    verify && JSON.parse(verify.options.body).fingerprint ===
      'ssh-ed25519 255 SHA256:2cxQVcO3EC5SbPVedJPA1XHIV2sEvZzPVTIiBgoZaxM');
  check('remembering the key is the default',
    verify && JSON.parse(verify.options.body).remember === true);
  check('the pinned connection becomes the active tab',
    text('statusBadge').indexOf('Connected') >= 0, text('statusBadge'));

  window.showHelp();
  check('help shows the token of this run', text('helpToken') === TOKEN, text('helpToken'));
  window.closeModal('helpModal');

  // Local-pane browser drop saves directly to the local panel via /api/local/drop.
  const localDropBefore = calls.filter(c => c.path === '/api/local/drop').length;
  const localDropDirBefore = calls.filter(c => c.path === '/api/local/drop-dir').length;
  const localTree = directoryEntry('local-drop-dir', [
    [fileEntry('dropped-local.txt', 'hello local')],
    []
  ]);
  await window.dropOnPane('local', { dataTransfer: {
    items: [{ kind: 'file', webkitGetAsEntry() { return localTree; } }],
    files: [], types: ['Files']
  }, preventDefault() {} });
  check('dropping a folder on the local pane calls /api/local/drop-dir and /api/local/drop',
    calls.filter(c => c.path === '/api/local/drop-dir').length === localDropDirBefore + 1 &&
      calls.filter(c => c.path === '/api/local/drop').length === localDropBefore + 1);

  // Site manager renders folder hierarchy and supports deleting a folder.
  check('site manager renders folder header for slash-delimited site',
    doc.querySelectorAll('#siteList .site-folder').length === 1);
  await window.deleteSiteFolder('GUI');
  const folderDel = calls.filter(c => c.path === '/api/sessions/delete').pop();
  check('deleting a site folder posts folder:true',
    folderDel && JSON.parse(folderDel.options.body).name === 'GUI' &&
      JSON.parse(folderDel.options.body).folder === true);

  window.fillSiteForm({name: 'jump-site', host: 'destination.example', protocol: 'sftp',
    tunnel: true, tunnel_host: 'jump.example', tunnel_port: 2222,
    tunnel_username: 'jumper', tunnel_password: 'jump-secret',
    tunnel_passphrase: 'phrase', tunnel_hostkey: 'SHA256:jump',
    tunnel_local_port: 22222, auth_gssapi: false, auth_gssapi_kex: true,
    gssapi_fwd_tgt: true, logical_host: 'srv.example.org'});
  check('site manager restores SSH tunnel settings',
    doc.getElementById('siteTunnel').checked &&
    doc.getElementById('siteTunnelHost').value === 'jump.example' &&
    doc.getElementById('siteTunnelPort').value === '2222' &&
    doc.getElementById('siteTunnelHostKey').value === 'SHA256:jump' &&
    !doc.getElementById('siteTunnelFields').disabled);
  check('site manager restores tunnel local port and Kerberos settings',
    doc.getElementById('siteTunnelLocalPort').value === '22222' &&
    !doc.getElementById('siteGssapiAuth').checked &&
    doc.getElementById('siteGssapiKex').checked &&
    doc.getElementById('siteGssapiFwdTgt').checked &&
    doc.getElementById('siteLogicalHost').value === 'srv.example.org');
  doc.getElementById('siteTunnelRemember').checked = false;
  await window.saveSite();
  const tunnelSave = JSON.parse(calls.filter(c => c.path === '/api/sessions/save').pop().options.body);
  check('tunnel credentials are saved only when requested',
    tunnelSave.session.tunnel && tunnelSave.session.tunnel_host === 'jump.example' &&
    tunnelSave.session.tunnel_password === '' && tunnelSave.session.tunnel_passphrase === '');
  check('Kerberos settings and tunnel local port are saved with the site',
    tunnelSave.session.tunnel_local_port === 22222 &&
    tunnelSave.session.auth_gssapi === false &&
    tunnelSave.session.auth_gssapi_kex === true &&
    tunnelSave.session.gssapi_fwd_tgt === true &&
    tunnelSave.session.logical_host === 'srv.example.org',
    JSON.stringify(tunnelSave.session));
  window.showHostKeyChallenge({tab: 1, role: 'tunnel', host: 'jump.example', port: 2222,
    fingerprint: 'SHA256:jump'});
  check('host-key dialog distinguishes the SSH tunnel host',
    text('hostKeyQuestion').includes('SSH tunnel host') && text('hostKeyQuestion').includes('jump.example'));
  await window.acceptHostKey();
  const tunnelVerify = JSON.parse(calls.filter(c => c.path === '/api/tabs/verify').pop().options.body);
  check('host-key confirmation carries the tunnel role', tunnelVerify.role === 'tunnel');
  window.showHostKeyChallenge({tab: 1, role: 'tunnel', host: 'jump.example', port: 2222,
    fingerprint: 'SHA256:changed', changed: true});
  check('changed tunnel keys carry a prominent warning and do not default to remember',
    text('hostKeyTitle') === 'Changed host key' &&
    text('hostKeyQuestion').includes('connection may be intercepted') &&
    !text('hostKeyQuestion').includes('not cached yet') &&
    !doc.getElementById('hostKeyRemember').checked);
  await window.cancelHostKey();
  window.newSite();
  check('a new site resets and disables SSH tunnel fields',
    !doc.getElementById('siteTunnel').checked && doc.getElementById('siteTunnelFields').disabled &&
    doc.getElementById('siteTunnelPass').value === '');
  check('a new site defaults Kerberos on without delegation or key exchange',
    doc.getElementById('siteGssapiAuth').checked &&
    !doc.getElementById('siteGssapiKex').checked &&
    !doc.getElementById('siteGssapiFwdTgt').checked &&
    doc.getElementById('siteTunnelLocalPort').value === '0');

  // The site form's port follows the protocol while it is still a default,
  // and keeps a port the user typed. The form used to leave 22 under every
  // protocol, so an FTP site was stored with the SSH port.
  window.newSite();
  doc.getElementById('siteProtocol').value = 'ftp';
  window.siteProtocolChanged();
  check('choosing FTP in the site form moves the port to 21',
    doc.getElementById('sitePort').value === '21');
  doc.getElementById('siteProtocol').value = 'webdav';
  window.siteProtocolChanged();
  check('the site form offers WebDAV over HTTPS on port 443',
    doc.getElementById('sitePort').value === '443');
  doc.getElementById('sitePort').value = '8443';
  doc.getElementById('siteProtocol').value = 's3';
  window.siteProtocolChanged();
  check('a port the user typed survives a protocol change',
    doc.getElementById('sitePort').value === '8443');
  doc.getElementById('sitePort').value = '';
  doc.getElementById('siteProtocol').value = 'sftp';
  window.siteProtocolChanged();
  check('an empty port takes the default of the new protocol',
    doc.getElementById('sitePort').value === '22');
  window.fillSiteForm({ name: 'legacy', protocol: 'ftps', host: 'h', port: 0 });
  check('a stored site without a port shows the port of its protocol',
    doc.getElementById('sitePort').value === '990' &&
      window.currentSiteForm().port === 990);

  // Synchronize conflict policy selector and resolution bar.
  window.openSynchronize();
  await window.resolveSyncConflictPolicy('newer');
  const syncPrev = calls.filter(c => c.path === '/api/sync/preview').pop();
  check('conflict resolution updates sync preview payload',
    syncPrev && JSON.parse(syncPrev.options.body).conflict === 'newer');
  window.closeModal('syncModal');

  // Queue priority control and ARIA / keyboard navigation.
  await window.prioritizeTask(1, 'top');
  const prioCall = calls.filter(c => c.path === '/api/queue/priority').pop();
  check('prioritizeTask posts to /api/queue/priority',
    prioCall && JSON.parse(prioCall.options.body).task_id === 1 &&
      JSON.parse(prioCall.options.body).position === 'top');
  check('panes and tables expose ARIA roles',
    doc.getElementById('localPane').getAttribute('role') === 'region' &&
      doc.getElementById('remotePane').getAttribute('role') === 'region');
  doc.getElementById('localPane').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
  check('ArrowDown advances selection in the focused pane',
    doc.getElementById('localFileList').children[1].getAttribute('aria-selected') === 'true');

  // Explorer-style single-panel view: the focused pane fills the window,
  // the other is hidden, and the choice survives a reload.
  window.toggleExplorerMode();
  const main = doc.querySelector('.commander-main');
  check('explorer mode marks the layout and hides the unfocused pane',
    main.classList.contains('explorer-mode') &&
      doc.getElementById('remotePane').style.display === 'none' &&
      doc.getElementById('localPane').style.display !== 'none',
    'remote=' + doc.getElementById('remotePane').style.display);
  check('explorer choice is persisted',
    window.localStorage.getItem('lscp-explorer') === '1');
  window.toggleExplorerMode();
  check('leaving explorer mode shows both panes again',
    !main.classList.contains('explorer-mode') &&
      doc.getElementById('remotePane').style.display !== 'none');

  // A local-to-local tab form has two directories and hides every server
  // field; the workspace dialog lists, saves, opens and deletes named groups.
  window.fillSiteForm({ name: 'local pair', protocol: 'local',
    local_dir: '/tmp/slowlocal', other_local_dir: '/tmp/slowremote' });
  window.siteProtocolChanged();
  const localForm = window.currentSiteForm();
  check('the site form offers a two-local-directory mode',
    localForm.protocol === 'local' && localForm.local_dir === '/tmp/slowlocal' &&
      localForm.other_local_dir === '/tmp/slowremote');
  check('local mode hides the server fields and offers Open',
    doc.getElementById('siteHost').closest('.form-row').style.display === 'none' &&
      doc.getElementById('siteOtherLocalDir').closest('.form-row').style.display !== 'none' &&
      text('siteConnectBtn') === 'Open');

  await window.openWorkspaces();
  check('workspace dialog lists stored workspaces',
    doc.getElementById('workspacesModal').className.indexOf('open') >= 0 &&
      doc.getElementById('workspaceList').children.length === 1 &&
      text('workspaceList').indexOf('stored') >= 0, text('workspaceList'));
  doc.getElementById('workspaceName').value = 'demo';
  await window.saveWorkspaceFromModal();
  const wsSave = calls.filter(call => call.path === '/api/workspaces/save').pop();
  check('saving a workspace posts its name',
    wsSave && JSON.parse(wsSave.options.body).name === 'demo');
  confirmResult = true;
  await window.openWorkspace('stored');
  const wsOpen = calls.filter(call => call.path === '/api/workspaces/open').pop();
  check('opening a workspace posts its name and adopts its active tab',
    wsOpen && JSON.parse(wsOpen.options.body).name === 'stored' &&
      calls.some(call => call.path === '/api/status'));
  await window.deleteWorkspace('stored');
  const wsDelete = calls.filter(call => call.path === '/api/workspaces/delete').pop();
  check('deleting a workspace posts its name',
    wsDelete && JSON.parse(wsDelete.options.body).name === 'stored');
  window.closeModal('workspacesModal');

  // Custom commands are persisted, preview their remote target, and run
  // only on the selected entry after confirmation.
  await window.openCustomCommands();
  check('custom commands dialog lists the persisted templates',
    doc.getElementById('customCommandsList').children.length === 2);
  doc.getElementById('customCmdName').value = 'List it';
  doc.getElementById('customCmdCommand').value = 'ls {file}';
  doc.getElementById('customCmdScope').value = 'remote';
  await window.saveCustomCommand();
  const cmdSave = calls.filter(call => call.path === '/api/custom-commands' &&
    JSON.parse(call.options.body || '{}').action === 'save').pop();
  const savePayload = cmdSave ? JSON.parse(cmdSave.options.body) : {};
  check('saving a template posts its name, command and scope',
    savePayload.action === 'save' && savePayload.name === 'List it' &&
      savePayload.command === 'ls {file}' && savePayload.scope === 'remote');
  check('saved template joins the dialog list',
    doc.getElementById('customCommandsList').children.length === 3);

  window.selectCustomCommand(0);
  doc.getElementById('remoteFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  const priorRuns = calls.filter(call => call.path === '/api/custom-commands' &&
    JSON.parse(call.options.body || '{}').action === 'run').length;
  confirmResult = false;
  await window.runCustomCommand();
  const preview = confirmMessages[confirmMessages.length - 1] || '';
  const declinedRuns = calls.filter(call => call.path === '/api/custom-commands' &&
    JSON.parse(call.options.body || '{}').action === 'run').length;
  check('custom command confirmation previews the command and selected name',
    preview.includes('checksum sha-256 keep.txt') && preview.includes('keep.txt') &&
      preview.toLowerCase().includes('remote panel'), preview);
  check('declining a custom command confirmation queues no work',
    declinedRuns === priorRuns);

  confirmResult = true;
  await window.runCustomCommand();
  const customRun = calls.filter(call => call.path === '/api/custom-commands' &&
    JSON.parse(call.options.body || '{}').action === 'run').pop();
  const customPayload = customRun ? JSON.parse(customRun.options.body) : {};
  check('confirmed custom command runs only on the selected remote entry',
    customPayload.action === 'run' && customPayload.tab === 1 &&
      Array.isArray(customPayload.filenames) &&
      customPayload.filenames.length === 1 &&
      customPayload.filenames[0] === 'keep.txt', JSON.stringify(customPayload));
  check('custom command results are rendered as text',
    text('customCommandsResult').includes('keep.txt') &&
      text('customCommandsResult').includes('SHA-256 verified'),
    text('customCommandsResult'));
  window.closeModal('customCommandsModal');

  /* A file-manager selection is offered in a dialog; only confirming
   * it queues anything, and names are shown as text, never markup. */
  responses['/api/shell/pending'] = { success: true, pending: [{
    id: 'a'.repeat(32), created: 1,
    files: [ { name: 'a.txt', path: '/home/u/a.txt', is_dir: false, size: 3 },
             { name: 'folder', path: '/home/u/folder', is_dir: true, size: 0 },
             { name: '<img>.png', path: '/home/u/x.png', is_dir: false, size: 1 } ] }] };
  await window.checkShellPending();
  check('shell offer dialog opened',
    doc.getElementById('shellUploadModal').classList.contains('open'));
  check('shell offer lists the files',
    doc.getElementById('shellUploadList').children.length === 3);
  check('shell offer treats names as text',
    doc.getElementById('shellUploadList').innerHTML.includes('&lt;img&gt;.png'));
  check('shell offer names the target directory',
    text('shellUploadButton').startsWith('Upload to /'), text('shellUploadButton'));
  check('offering queues nothing',
    !calls.some(call => call.path === '/api/shell/consume'));
  responses['/api/shell/pending'] = { success: true, pending: [] };
  await window.shellUploadConfirm();
  const shellConsume = calls.filter(call => call.path === '/api/shell/consume').pop();
  const shellPayload = shellConsume ? JSON.parse(shellConsume.options.body) : {};
  check('confirming posts the selection id against the active tab',
    shellPayload.id === 'a'.repeat(32) && shellPayload.tab === 1,
    JSON.stringify(shellPayload));
  check('confirmed shell upload closes the dialog',
    !doc.getElementById('shellUploadModal').classList.contains('open'));

  check('no script errors', errors.length === 0, errors.join(' | '));
  window.close();
})();
