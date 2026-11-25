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
  '/api/vault/status': { success: true, vault: 'unlocked' },
  '/api/vault/keys': { success: true, keys: [
    { reference: 'vaultkey://0123456789abcdef0123456789abcdef', label: 'work-laptop-key' }
  ] },
  '/api/vault/keys/import': { success: true,
    reference: 'vaultkey://fedcba9876543210fedcba9876543210', label: 'id_ed25519' },
  '/api/monitor/hosts': { success: true, max_hosts: 32, default_interval: 5, default_timeout: 10,
    tabs: [{ tab: 1, name: 'local test', host: '127.0.0.1', port: 2222, protocol: 'sftp', site: null, key: 'ssh:127.0.0.1:2222' }], sites: [] },
  '/api/monitor/settings': { success: true, document: { version: 1, settings: { interval_secs: 5,
    connect_timeout_secs: 10, poll_timeout_secs: 10, outage_threshold: 3, notify_on_outage: true,
    beep_on_outage: false, beep_cooldown_secs: 10 }, hosts: {} } },
  '/api/monitor/sample': { success: true, samples: [{ tab: 1, key: 'ssh:127.0.0.1:2222', name: 'local test', host: '127.0.0.1', port: 2222,
    protocol: 'sftp', status: 'ok', sampled_at: Date.now(), latency_ms: 5, error: '', consecutive_failures: 0,
    outage_since_ms: null, outage: false, outage_started: false, recovered: false, snapshot: {
      hostname: 'worker', primary_ip: '127.0.0.1', uptime_seconds: 10, load_average: [0.1],
      cpu: { model: 'Test CPU', logical_count: 1, percent: 25, cores: [] }, memory: null,
      swap: { total_bytes: 1000, used_bytes: 250, free_bytes: 750, percent: 25 },
      network: { rx_bytes_total: 1000, tx_bytes_total: 2000, rx_bytes_per_sec: 125000, tx_bytes_per_sec: 250000 },
      disks: [], gpus: [], cuda_version: '', custom: [], warnings: [] } }] },
  '/api/session/terminal': { success: true, terminal: 77, cols: 80, rows: 24 },
  '/api/terminal/output': { success: true, data: '', offset: 0, alive: true },
  '/api/terminal/close': { success: true },
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
  '/api/preferences': {
    success: true, file: '/tmp/cfg/preferences.json', defaults: {},
    preferences: { transfer: 'binary', filemask: '*.txt', speed: 0,
      resumesupport: '', resume: true, preserve_time: true, newer_only: false,
      append: false, no_permissions: false, priority: false,
      confirm_overwrite: true, confirm_delete: true }
  },
  '/api/cleanup': {
    success: true, any: true,
    locations: [
      { id: 'sessions', label: 'Stored sessions (sites, user names and host keys)',
        path: '/tmp/cfg/sessions.ini', kind: 'file', exists: true, bytes: 2048 },
      { id: 'bookmarks', label: 'Saved bookmarks',
        path: '/tmp/cfg/bookmarks.json', kind: 'file', exists: false, bytes: 0 }
    ]
  },
  '/api/remote/transfer/targets': {
    success: true,
    targets: [
      { id: 'tab:1', kind: 'tab', tab: 1, label: 'local test', host: '127.0.0.1',
        protocol: 'sftp', current: true, connected: true },
      { id: 'tab:2', kind: 'tab', tab: 2, label: 'mirror', host: 'mirror.test',
        protocol: 'sftp', current: false, connected: true }
    ]
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
    missing: [], refused: [], remote_dir: '/tmp/slowremote' },
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
  '/api/bookmarks': { success: true, file: '/tmp/cfg/bookmarks.json', bookmarks: {
    local: [{ name: 'home', path: '/tmp/slowlocal' },
            { name: 'scratch', path: '/tmp' }],
    remote: [{ name: 'logs', path: '/var/log' }] } },
  '/api/bookmarks/save': { success: true, file: '/tmp/cfg/bookmarks.json' },
  '/api/bookmarks/delete': { success: true, file: '/tmp/cfg/bookmarks.json' },
  '/api/sessions/import': { success: true, sources: [{
    source: 'openssh', path: '/home/user/.ssh/config', exists: true,
    fingerprint: 'fixture-digest', error: '', skipped: [{ name: '*', reason: 'Only a Host line with one plain alias is imported.' }],
    entries: [
      { name: 'prod', host: 'prod.example.test', port: 2222, username: 'deploy',
        protocol: 'sftp', has_password: false, keyfile: '/home/user/.ssh/id_ed25519' },
      { name: 'staging', host: 'staging.example.test', port: 22, username: 'deploy',
        protocol: 'sftp', has_password: false, keyfile: '' }
    ] }] },
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
    /* The backend answers with what each file's run printed, and only the
     * names it actually ran on; the page shows that verbatim. */
    return { success: true, scope: 'remote',
      results: (request.filenames || []).map(name => ({
        file: name, command: 'checksum sha-256 ' + name, success: true,
        exit_code: 0, stdout: 'SHA-256 verified', stderr: '', error: ''
      })) };
  }
  return { success: true, commands: stored };
}

function preferencesBody(options) {
  const stored = responses['/api/preferences'].preferences;
  if ((options.method || 'GET').toUpperCase() !== 'POST') {
    return responses['/api/preferences'];
  }
  let request = {};
  try { request = JSON.parse(options.body || '{}'); } catch (error) {}
  const values = request.action === 'reset' ? stored
    : Object.assign({}, stored, request.preferences || {});
  return { success: true, file: '/tmp/cfg/preferences.json', preferences: values };
}

function cleanupBody(options) {
  if ((options.method || 'GET').toUpperCase() !== 'POST') {
    return responses['/api/cleanup'];
  }
  let request = {};
  try { request = JSON.parse(options.body || '{}'); } catch (error) {}
  const ids = request.ids || [];
  const locations = responses['/api/cleanup'].locations.map(item =>
    Object.assign({}, item, { exists: item.exists && ids.indexOf(item.id) < 0 }));
  return { success: true, removed: ids.map(id => ({ id: id, removed: true, error: '' })),
    locations: locations, any: locations.some(item => item.exists) };
}

function propertiesBody(options) {
  let request = {};
  try { request = JSON.parse(options.body || '{}'); } catch (error) {}
  const names = request.names || (request.name ? [request.name] : []);
  return { success: true, properties: names.map(name => ({
    name: name, path: '/tmp/slowremote/' + name, is_dir: false, is_link: false,
    size: 22, mtime: 1791875271, permissions: '-rw-r--r--', mode: 420,
    owner: '1000', group: '1000' })) };
}

/* Key/Session backups: one answer shape for every phase of the page, so both
 * invoke stubs below can speak it. */
function vaultBackupBody(path, options) {
  let request = {};
  try { request = JSON.parse((options && options.body) || '{}'); } catch (error) {}
  if (path === '/api/backup/export') {
    const out = { success: true, filename: 'backup.lscpbak', data_base64: 'TFNDUEJBSzE=' };
    if (request.save_dir) out.saved_path = request.save_dir.replace(/\/+$/, '') + '/backup.lscpbak';
    return out;
  }
  if (path === '/api/backup/import') return { success: true };
  if (path === '/api/vault/export') {
    const filename = request.plain_text
      ? 'key_session_2026-11-15_00-00-00.json'
      : 'key_session_2026-11-15_00-00-00.json.aes';
    const out = { success: true,
      filename: filename,
      data_base64: 'W10=',
      entry_count: (request.sessions || []).length,
      plain_text: !!request.plain_text };
    if (request.save_dir) out.saved_path = request.save_dir.replace(/\/+$/, '') + '/' + filename;
    return out;
  }
  if (path === '/api/vault/scan') {
    return { success: true, encrypted: false, fingerprint: 'b'.repeat(64), ignored_entries: 1,
      entry_count: 2,
      entries: [
        { name: 'GUI/test', protocol: 'sftp', host: '127.0.0.1', port: 2222,
          username: 'user', has_password: true, has_key_passphrase: true,
          has_ssh_key: false, exists_in_store: true },
        { name: 'backup/restored', protocol: 'webdavs', host: 'dav.example.test', port: 443,
          username: 'build', has_password: false, has_key_passphrase: false,
          has_ssh_key: true, exists_in_store: false }
      ] };
  }
  if (path === '/api/vault/import') {
    return { success: true, imported: (request.sessions || []).length,
      skipped_existing: 0, ignored_entries: 1 };
  }
  return undefined;
}

const calls = [];
const errors = [];
const confirmMessages = [];
let confirmResult = true;
let delayedTabOpen = null;

const dom = new JSDOM(html, {
  url: 'http://localhost:8080/',
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  beforeParse(window) {
    window.TextEncoder = require("util").TextEncoder;
    // The page has one backend: the native shell's in-process IPC. A network
    // request would mean the browser host came back.
    window.fetch = () => {
      throw new Error('the page must not use fetch(): there is no HTTP host');
    };
    /* The build stamps the Alaska Standard Time version (VYYYY-MM-DD-HH-MM)
     * into the page; a page built by ui/scripts/build.mjs overrides this
     * seed with the real stamp. Seeding it keeps this suite runnable against
     * the bare source page as well. */
    window.LinSCPBuildVersion = 'V2000-01-02-03-04';

      // CodeMirror measures text with Range rects and schedules with rAF;
      // jsdom has neither (pretendToBeVisual below only adds rAF). Zero
      // rects are fine headless: nothing depends on the measurements.
      if (typeof window.requestAnimationFrame !== 'function') {
        window.requestAnimationFrame = callback => window.setTimeout(callback, 0);
        window.cancelAnimationFrame = id => window.clearTimeout(id);
      }
      if (window.Range && typeof window.Range.prototype.getClientRects !== 'function') {
        const emptyRect = { x: 0, y: 0, left: 0, top: 0, right: 0, bottom: 0,
          width: 0, height: 0, toJSON: () => ({}) };
        window.Range.prototype.getBoundingClientRect = () => emptyRect;
        window.Range.prototype.getClientRects = () => ({
          length: 0,
          item: () => null,
          [Symbol.iterator]: [][Symbol.iterator],
        });
      }
    /* jsdom has no canvas and says so loudly, but the in-page terminal is a
     * real canvas renderer, so it needs a context to draw into. A recorder is
     * enough: this suite is about the page handing the model's frames to the
     * terminal, not about what the pixels look like - and a terminal that
     * cannot get a context would be a terminal nobody can see, which is a
     * separate thing worth failing on. */
    const drawable = () => {
      const context = {
        font: '', fillStyle: '', textBaseline: '',
        setTransform() {}, fillRect() {}, fillText() {},
        measureText: text => ({ width: String(text).length * 8.8 }),
        getContext() { return context; },
      };
      return context;
    };
    window.HTMLCanvasElement.prototype.getContext = () => drawable();
    /* The export downloads the backup through a temporary object URL; jsdom
     * cannot create one, so a stub keeps the download path testable. */
    window.URL.createObjectURL = () => 'blob:key-session-export';
    window.URL.revokeObjectURL = () => {};
    window.__TAURI_INTERNALS__ = { invoke: async (_cmd, args) => invoke(args.envelope) };
    const invoke = envelope => {
      const method = String(envelope.method || 'GET').toUpperCase();
      const options = { method: method };
      if (envelope.body && Object.keys(envelope.body).length) {
        options.body = JSON.stringify(envelope.body);
      }
      const url = String(envelope.path);
      const path = url.split('?')[0];
      calls.push({ path: path, url: String(url), options: options });
      if (path === '/api/tabs/open' && delayedTabOpen) return delayedTabOpen;
      let body = responses[path];
      if (path === '/api/custom-commands') {
        body = customCommandsBody(options);
      }
      if (path === '/api/preferences') {
        body = preferencesBody(options);
      }
      if (path === '/api/cleanup') {
        body = cleanupBody(options);
      }
      if (path === '/api/remote/properties') {
        body = propertiesBody(options);
      }
      if (path === '/api/remote/rights') {
        body = { success: true, changed: 1, results: [], error: '' };
      }
      if (path === '/api/remote/transfer') {
        body = { success: true, tasks: [{ id: 9, type: 'Copy (remote)', status: 'Queued' }] };
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
      if (path === '/api/bookmarks') {
        const side = /[?&]side=([a-z]+)/.exec(String(url));
        const stored = responses['/api/bookmarks'].bookmarks;
        body = { success: true, file: '/tmp/cfg/bookmarks.json',
          bookmarks: side ? stored[side[1]] : stored };
      }
      if (path === '/api/session/url' && !responses['/api/session/url']) {
        const include = /[?&]password=1(?:&|$)/.test(String(url));
        const mockUrl = include
          ? 'sftp://user:secret%20word@127.0.0.1:2222/tmp/slowremote/'
          : 'sftp://user@127.0.0.1:2222/tmp/slowremote/';
        body = { success: true,
          url: mockUrl,
          open_command: 'open sftp://user@127.0.0.1:2222/tmp/slowremote/',
          script_snippet: 'open "' + mockUrl + '"\ncd "/tmp/slowremote"',
          openssh_command: "sftp -P 2222 user@127.0.0.1:'/tmp/slowremote'",
          path: '/tmp/slowremote', include_password: include,
          has_password: true, protocol: 'sftp', host: '127.0.0.1' };
      }
      if (path === '/api/sessions/import' &&
          (options.method || 'GET').toUpperCase() === 'POST') {
        let request = {};
        try { request = JSON.parse(options.body || '{}'); } catch (error) {}
        body = { success: true, source: request.source, path: '/home/user/.ssh/config',
          imported: request.names || [], skipped: [],
          sessions: (responses['/api/sessions'] || {}).sessions || [],
          file: '/tmp/cfg/sessions.ini' };
      }
      const vaultBody = vaultBackupBody(path, options);
      if (vaultBody !== undefined) { body = vaultBody; }
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
        return Promise.resolve({ status: 200, payload: { success: true } });
      }
      return Promise.resolve({ status: 200, payload: body });
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

/* An error is an entry in the Logs panel, not a popup: a refusal is read back
 * from the panel, and the toast only carries the notices that confirm an
 * action. The panel keeps everything the page logged, so these assertions ask
 * how often a message is in it, not whether it is the only thing there. */
function errorLog() {
  return text('logOutput');
}

/* The entry an action just added, which is what the popup used to show: the
 * panel keeps everything, so a check about one failure reads the last line. */
function lastLogLine() {
  const box = window.document.getElementById('logOutput');
  return box && box.lastElementChild ? box.lastElementChild.textContent : '<no log entry>';
}

function countIn(haystack, needle) {
  return haystack.split(needle).length - 1;
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

  // An FTP/SFTP resume risk requires an affirmative, one-request approval.
  {
    const originalConfirm = window.confirm;
    let prompts = [];
    let requests = [];
    const send = async approval => {
      requests.push(Object.assign({}, approval));
      return {result: approval.accept_best_effort_resume_risk ? {success: true} : {best_effort_resume_risk: true}};
    };
    window.confirm = message => { prompts.push(message); return false; };
    const declined = await window.applyDropApprovals(send);
    check('best-effort resume refusal does not retry', declined.cancelled && requests.length === 1 && prompts[0].includes('corrupt'));
    requests = []; prompts = [];
    window.confirm = message => { prompts.push(message); return true; };
    const accepted = await window.applyDropApprovals(send);
    check('best-effort resume approval is explicit', accepted.result.success && requests.length === 2 && requests[1].accept_best_effort_resume_risk === true);
    window.confirm = originalConfirm;
  }

  // Boot fetched what it needs.
  const doc = window.document;
  const paths = calls.map(call => call.path);
  // Boot the real bundled page as a second native terminal window. Metadata
  // can transiently report the main window; the injected terminal label must
  // still win, and the canvas cannot live under the hidden terminal modal.
  {
    const terminalCalls = [];
    const terminalPage = new JSDOM(html, {
      url: 'http://localhost:8080/', runScripts: 'dangerously', pretendToBeVisual: true,
      beforeParse(host) {
        host.__LINSCP_TERMINAL_LABEL__ = 'terminal-term-separate';
        host.__TAURI_INTERNALS__ = {
          metadata: { currentWindow: { label: 'main' } },
          invoke: async (_command, args) => {
            terminalCalls.push(args.envelope);
            if (String(args.envelope.path).startsWith('/api/terminal/text'))
              return { status: 200, payload: { success: true, text: 'history\ncurrent' } };
            return { status: 200, payload: { success: true, alive: true } };
          }
        };
        host.HTMLCanvasElement.prototype.getContext = () => ({
          font: '', fillStyle: '', textBaseline: '', setTransform() {}, fillRect() {}, fillText() {},
          measureText: value => ({ width: String(value).length * 9 })
        });
        /* Every WebView has TextEncoder and the terminal encodes its shell
         * input with it; jsdom does not, so the window would be one no real
         * host is. */
        host.TextEncoder = require('util').TextEncoder;
      }
    });
    await new Promise(resolve => setTimeout(resolve, 30));
    const child = terminalPage.window.document.getElementById('terminalWindowScreen');
    check('separate terminal canvas is outside all hidden modals',
      !!child && child.parentElement === terminalPage.window.document.body && !child.closest('.modal-overlay'));
    check('the injected terminal label survives unrelated window metadata',
      terminalCalls.some(call => call && call.path === '/api/terminal/input' && call.body.terminal === 'term-separate'),
      JSON.stringify(terminalCalls));

    /* The canvas selection is the model's, so the window's own shortcuts have
     * to reach it: Ctrl+Shift+C reads the selection, Ctrl+Shift+V pastes the
     * clipboard, and a plain Ctrl+C with nothing selected stays the shell's
     * interrupt instead of becoming a copy nobody asked for. */
    const terminalWindow = terminalPage.window;
    Object.defineProperty(terminalWindow.navigator, 'clipboard', {
      configurable: true,
      value: { readText: async () => 'pasted text', writeText: async text => { terminalWindow.copiedTerminalText = text; } }
    });
    const toolbar = terminalWindow.document.querySelector('.terminal-window-toolbar');
    const copyAll = [...toolbar.querySelectorAll('button')].find(button => button.textContent === 'Copy All Text');
    const help = [...toolbar.querySelectorAll('button')].find(button => button.textContent === 'Help');
    check('terminal toolbar below screen offers copy all and help, not copy selected', !!copyAll && !!help && toolbar.previousElementSibling === child && !toolbar.textContent.includes('Copy Selected Text'));
    const smaller = toolbar.querySelector('button[aria-label="Decrease terminal text size"]');
    const larger = toolbar.querySelector('button[aria-label="Increase terminal text size"]');
    check('desktop terminal offers text size buttons below the screen', !!smaller && !!larger);
    larger.click(); smaller.click();
    await new Promise(resolve => setTimeout(resolve, 30));
    const sizes = terminalCalls.filter(call => call && call.path === '/api/terminal/input' && call.body && call.body.cell_height).map(call => call.body.cell_height);
    check('desktop text size buttons update terminal cell metrics by single 1px steps from 11px default',
      sizes[0] === 15 && sizes.includes(16) && sizes.at(-1) === 15, JSON.stringify(sizes));
    larger.click(); larger.click();
    check('desktop terminal remembers adjusted font size in localStorage',
      terminalWindow.localStorage.getItem('lscp-terminal-font-size') === '13',
      terminalWindow.localStorage.getItem('lscp-terminal-font-size'));
    const terminalCanvas = terminalWindow.document.querySelector('#terminalWindowScreen canvas.terminal-canvas');
    check('desktop terminal canvas has tabIndex -1 and retains focus after toolbar clicks',
      !!terminalCanvas && terminalCanvas.tabIndex === -1 &&
      terminalWindow.document.activeElement === terminalCanvas);
    const terminalHelpModal = terminalWindow.document.getElementById('terminalHelpModal');
    help.click();
    const terminalHelpText = terminalHelpModal ? terminalHelpModal.textContent : '';
    check('terminal help opens rich help modal documenting keyboard input, AltGr/Numpad, focus, mouse selection, paste, and scrollback',
      !!terminalHelpModal &&
      terminalHelpModal.classList.contains('open') &&
      terminalHelpText.includes('mouse') &&
      terminalHelpText.includes('Right-click') &&
      terminalHelpText.includes('Ctrl+V') &&
      terminalHelpText.includes('Copy All Text') &&
      terminalHelpText.includes('F1–F12') &&
      terminalHelpText.includes('- and +') &&
      terminalHelpText.includes('AltGr') &&
      terminalHelpText.includes('Numpad'));
    const inputsBeforeHelpEsc = terminalCalls.filter(call => call && call.path === '/api/terminal/input' && call.body && call.body.data).length;
    terminalWindow.document.dispatchEvent(
      new terminalWindow.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await new Promise(resolve => setTimeout(resolve, 20));
    const inputsAfterHelpEsc = terminalCalls.filter(call => call && call.path === '/api/terminal/input' && call.body && call.body.data).length;
    check('Escape closes terminal help modal without sending ESC and returns focus to terminal canvas',
      !terminalHelpModal.classList.contains('open') &&
      inputsAfterHelpEsc === inputsBeforeHelpEsc &&
      terminalWindow.document.activeElement === terminalCanvas);
    copyAll.click();
    await new Promise(resolve => setTimeout(resolve, 30));
    check('desktop copy all reads model text including history', terminalWindow.copiedTerminalText === 'history\ncurrent');
    let unexpectedPrompts = [];
    terminalWindow.prompt = question => { unexpectedPrompts.push(question); return null; };
    const pressPlain = (key, extra = {}) => terminalWindow.document.dispatchEvent(
      new terminalWindow.KeyboardEvent('keydown', Object.assign({ key, bubbles: true, cancelable: true }, extra)));
    pressPlain('-');
    pressPlain('+');
    pressPlain('Subtract');
    pressPlain('Add');
    pressPlain('@', { ctrlKey: true, altKey: true });
    pressPlain('|', { ctrlKey: true, altKey: true });
    pressPlain('€', { ctrlKey: true, altKey: true });
    pressPlain(' ');
    pressPlain('Enter');
    pressPlain('Backspace');
    pressPlain('F1');
    pressPlain('F10');
    pressPlain('n', { ctrlKey: true });
    pressPlain('l', { ctrlKey: true });
    pressPlain('r', { ctrlKey: true });
    pressPlain('a', { ctrlKey: true });
    pressPlain('h', { ctrlKey: true });
    await new Promise(resolve => setTimeout(resolve, 30));
    const typedPayloads = terminalCalls
      .filter(call => call && call.path === '/api/terminal/input' && call.body && call.body.data)
      .map(call => Buffer.from(call.body.data, 'base64').toString('utf8'));
    check('typing -, +, Numpad Subtract/Add, AltGr symbols, Space, Enter, Backspace, F1, F10, and Ctrl+N/L/R/A/H in desktop terminal sends bytes to PTY without triggering Commander popups',
      unexpectedPrompts.length === 0 &&
      typedPayloads.filter(x => x === '-').length >= 2 &&
      typedPayloads.filter(x => x === '+').length >= 2 &&
      typedPayloads.includes('@') &&
      typedPayloads.includes('|') &&
      typedPayloads.includes('€') &&
      typedPayloads.includes(' ') &&
      typedPayloads.includes('\r') &&
      typedPayloads.includes('\x7f') &&
      typedPayloads.includes('\x1b[11~') &&
      typedPayloads.includes('\x1b[21~') &&
      typedPayloads.includes('\x0e') &&
      typedPayloads.includes('\x0c') &&
      typedPayloads.includes('\x12') &&
      typedPayloads.includes('\x01') &&
      typedPayloads.includes('\x08'),
      'prompts=' + JSON.stringify(unexpectedPrompts) + ' typed=' + JSON.stringify(typedPayloads));
    const press = (key, shift) => terminalWindow.document.dispatchEvent(
      new terminalWindow.KeyboardEvent('keydown', { key, ctrlKey: true, shiftKey: !!shift, cancelable: true }));
    press('c', true);
    press('v', true);
    press('v', false);
    press('c', false);
    await new Promise(resolve => setTimeout(resolve, 30));
    const inputs = terminalCalls.filter(call => call && call.path === '/api/terminal/input' && call.body && call.body.data);
    check('Ctrl+Shift+C reads the terminal selection in a desktop window',
      terminalCalls.some(call => call && String(call.path).indexOf('/api/terminal/selection') === 0),
      JSON.stringify(terminalCalls.map(call => call && call.path)));
    check('Ctrl+V and Ctrl+Shift+V each paste once into the shell',
      inputs.filter(call => Buffer.from(call.body.data, 'base64').toString() === 'pasted text').length === 2,
      JSON.stringify(inputs.map(call => call.body.data)));
    check('a plain Ctrl+C still reaches the shell as its interrupt',
      inputs.some(call => call.body.data === Buffer.from('\x03').toString('base64')),
      JSON.stringify(inputs.map(call => call.body.data)));
    const termCanvas = child.querySelector('canvas.terminal-canvas');
    termCanvas.dispatchEvent(new terminalWindow.MouseEvent('mousedown', { button: 0, detail: 1, clientX: 0, clientY: 0, cancelable: true }));
    terminalWindow.document.dispatchEvent(new terminalWindow.MouseEvent('mousemove', { button: 0, clientX: 27, clientY: 0, cancelable: true }));
    terminalWindow.document.dispatchEvent(new terminalWindow.MouseEvent('mouseup', { button: 0, clientX: 27, clientY: 0 }));
    await new Promise(resolve => setTimeout(resolve, 25));
    const rightPasteEvt = new terminalWindow.MouseEvent('contextmenu', { button: 2, cancelable: true });
    termCanvas.dispatchEvent(rightPasteEvt);
    await new Promise(resolve => setTimeout(resolve, 25));
    const afterRightClickInputs = terminalCalls.filter(call => call && call.path === '/api/terminal/input' && call.body && call.body.data);
    check('right-clicking terminal canvas pastes even immediately after selecting text',
      rightPasteEvt.defaultPrevented &&
      afterRightClickInputs.filter(call => Buffer.from(call.body.data, 'base64').toString() === 'pasted text').length === 3,
      JSON.stringify(afterRightClickInputs.map(call => call.body.data)));
    terminalPage.window.close();
  }
  check('boot queried the status', paths.includes('/api/status'));
  check('vault password fields require six characters',
    doc.getElementById('vaultPassword').minLength === 6 &&
      doc.getElementById('vaultPasswordConfirm').minLength === 6);
  check('boot listed the local pane', paths.includes('/api/local/list'));
  check('boot listed the remote pane', paths.includes('/api/remote/list'));

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

  // Android share captures the selected pane and tab before awaiting native
  // staging. No chooser is opened without confirmation or for directories.
  {
    const core = window.LinSCPCore;
    const shares = [];
    let failShare = false;
    window.LinSCPCore = new Proxy(core, { get(target, key) {
      if (key === 'hostCapabilities') return () => ({ ...target.hostCapabilities({ host: window }), platform: 'android', nativeIpc: true });
      if (key === 'shareFiles') return async source => { shares.push(source); if (failShare) throw new Error('provider refused'); };
      return Reflect.get(target, key);
    }});
    window.focusPane('local');
    window.clearFocusedSelection();
    doc.getElementById('localFileList').children[0].click();
    await window.shareSelectedFiles();
    check('Android share sends the selected local file and directory', shares.length === 1 && shares[0].side === 'local' && shares[0].directory === '/tmp/slowlocal' && shares[0].names[0] === 'a.txt');
    confirmResult = false;
    await window.shareSelectedFiles();
    confirmResult = true;
    check('Android share asks for consent before staging', shares.length === 1);
    window.focusPane('remote');
    window.clearFocusedSelection();
    doc.getElementById('remoteFileList').children[0].click();
    await window.shareSelectedFiles();
    check('Android share keeps the selected remote tab and directory', shares.length === 2 && shares[1].side === 'remote' && shares[1].tab === 1 && shares[1].directory === '/tmp/slowremote' && shares[1].names[0] === 'keep.txt');
    failShare = true;
    await window.shareSelectedFiles();
    check('Android share reports provider errors', shares.length === 3 && lastLogLine().includes('provider refused'));
    failShare = false;
    window.clearFocusedSelection();
    doc.getElementById('remoteFileList').children[1].click();
    await window.shareSelectedFiles();
    check('Android share rejects directories before invoking the host', shares.length === 3);
    window.clearFocusedSelection();
    window.LinSCPCore = core;
  }

  // A desktop terminal must use the native invoker object's method, not call
  // the object as a function and silently fall back to the modal.
  {
    const internals = window.__TAURI_INTERNALS__;
    const originalInvoke = internals.invoke;
    const priorTerminal = responses['/api/session/terminal'];
    const windows = [];
    responses['/api/session/terminal'] = { success: true, terminal: 'term-77', cols: 100, rows: 30 };
    internals.invoke = async (command, args) => {
      if (command === 'linscp_open_terminal_window') {
        windows.push(args);
        return { label: 'terminal-term-77' };
      }
      return originalInvoke(command, args);
    };
    const opened = await window.openTerminal();
    check('desktop terminal opens a separate native window', opened && windows.length === 1 &&
      windows[0].terminal === 'term-77' && windows[0].cols === 100 && windows[0].rows === 30 &&
      !doc.getElementById('terminalModal').classList.contains('open'));
    internals.invoke = async (command, args) => {
      if (command === 'linscp_open_terminal_window') throw new Error('window manager refused');
      return originalInvoke(command, args);
    };
    let closedBefore = calls.filter(call => call.path === '/api/terminal/close').length;
    const inputBefore = calls.filter(call => call.path === '/api/terminal/input').length;
    const refused = await window.openTerminal(null, false, 'must-not-run');
    let closes = calls.filter(call => call.path === '/api/terminal/close');
    check('a refused desktop window reports an error, closes its shell and never opens the modal',
      refused === false && lastLogLine().includes('window manager refused') &&
      lastLogLine().includes('Cannot open a separate terminal window.') &&
      !doc.getElementById('terminalModal').classList.contains('open') &&
      closes.length === closedBefore + 1 && JSON.parse(closes.at(-1).options.body).terminal === 'term-77' &&
      calls.filter(call => call.path === '/api/terminal/input').length === inputBefore);
    internals.invoke = async (command, args) => command === 'linscp_open_terminal_window'
      ? {} : originalInvoke(command, args);
    closedBefore = closes.length;
    const missingLabel = await window.openTerminal();
    closes = calls.filter(call => call.path === '/api/terminal/close');
    check('a desktop window with no label closes the shell without opening the modal',
      missingLabel === false && lastLogLine().includes('no window label') &&
      !doc.getElementById('terminalModal').classList.contains('open') && closes.length === closedBefore + 1);
    const priorClose = responses['/api/terminal/close'];
    responses['/api/terminal/close'] = { success: false, error: 'close refused' };
    const failedClose = await window.openTerminal();
    check('a failed terminal cleanup is reported alongside the window failure',
      failedClose === false && lastLogLine().includes('Cannot close the terminal session.') &&
      lastLogLine().includes('close refused') && !doc.getElementById('terminalModal').classList.contains('open'));
    responses['/api/terminal/close'] = priorClose;
    closes = calls.filter(call => call.path === '/api/terminal/close');
    const core = window.LinSCPCore;
    for (const platform of ['linux', 'windows', 'macos', 'unknown']) {
      window.LinSCPCore = new Proxy(core, { get(target, key) {
        if (key === 'nativeInvoker') return () => null;
        if (key === 'hostCapabilities') return () => ({ ...target.hostCapabilities({ host: window }), platform });
        return Reflect.get(target, key);
      }});
      closedBefore = closes.length;
      const noBridge = await window.openTerminal();
      closes = calls.filter(call => call.path === '/api/terminal/close');
      check(`a missing ${platform} window bridge closes the shell without opening the modal`,
        noBridge === false && lastLogLine().includes('bridge is unavailable') &&
        !doc.getElementById('terminalModal').classList.contains('open') && closes.length === closedBefore + 1);
    }
    window.LinSCPCore = core;
    window.LinSCPCore = new Proxy(core, { get(target, key) {
      if (key === 'hostCapabilities') return () => ({ ...target.hostCapabilities({ host: window }), platform: 'android' });
      return Reflect.get(target, key);
    }});
    internals.invoke = async (command, args) => {
      if (command === 'linscp_open_terminal_window') { windows.push(args); throw new Error('not available on Android'); }
      return originalInvoke(command, args);
    };
    await window.openTerminal();
    check('Android opens the in-app terminal without requesting a desktop window',
      windows.length === 1 && doc.getElementById('terminalModal').classList.contains('open'));
    window.closeTerminal();
    window.LinSCPCore = core;
    internals.invoke = originalInvoke;
    responses['/api/session/terminal'] = priorTerminal;
  }

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
      window.isEditorReadOnly() &&
      doc.getElementById('editorSaveBtn').style.display === 'none');
  window.closeEditor();
  await window.editSelected('remote');
  await new Promise(resolve => setTimeout(resolve, 100));
  check('F4 opens the selected remote file in the editor', doc.getElementById('editorModal').className.indexOf('open') >= 0);
  check('editor loaded the content', window.getEditorValue() === 'keep\n',
    JSON.stringify(window.getEditorValue()));

  // Editing marks it dirty, saving posts the new content.
  window.setEditorValue('keep\nmore\n');
  check('editing marks the file dirty', text('editorStatus').indexOf('Modified') >= 0,
    text('editorStatus'));
  await window.saveEditorFile();
  await new Promise(resolve => setTimeout(resolve, 100));
  const save = calls.filter(call => call.path === '/api/remote/save').pop();
  check('save posted the new content',
    save && JSON.parse(save.options.body).content === 'keep\nmore\n');
  check('save sent the base modification time',
    save && JSON.parse(save.options.body).base_mtime === 1791875271);

  // The in-page editor polls for external changes: a clean buffer reloads,
  // a dirty buffer warns instead of losing the edits.
  const originalRemoteEdit = responses['/api/remote/edit'];
  responses['/api/remote/edit'] = { success: true, path: '/tmp/slowremote/keep.txt',
    content: 'keep\n', info: { size: 5, mtime: 1791875272, mtime_ns: '1791875272' } };
  await window.pollEditorFile();
  await new Promise(resolve => setTimeout(resolve, 80));
  check('a clean editor reloads when the file changes on disk',
    window.getEditorValue() === 'keep\n',
    JSON.stringify(window.getEditorValue()));
  window.setEditorValue('dirty edit\n');
  responses['/api/remote/edit'] = { success: true, path: '/tmp/slowremote/keep.txt',
    content: 'keep\n', info: { size: 5, mtime: 1791875273, mtime_ns: '1791875273' } };
  await window.pollEditorFile();
  check('a dirty editor warns instead of reloading',
    text('editorStatus').indexOf('changed on disk') >= 0,
    text('editorStatus'));
  responses['/api/remote/edit'] = originalRemoteEdit;
  window.closeEditor();

  // Local and remote panels use the same bounded editor workflow.
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await window.editSelected('local');
  await new Promise(resolve => setTimeout(resolve, 80));
  check('F4 edits a local text file too',
    window.getEditorValue() === 'local text\n' &&
      !window.isEditorReadOnly());
  window.setEditorValue('edited locally\n');
  await window.saveEditorFile();
  await new Promise(resolve => setTimeout(resolve, 80));
  const localSave = calls.filter(call => call.path === '/api/local/save').pop();
  check('local save posts the content and conflict timestamp',
    localSave && JSON.parse(localSave.options.body).content === 'edited locally\n' &&
      JSON.parse(localSave.options.body).base_mtime_ns === 1791875271000000000);
  window.closeEditor();

  // The built-in editor is a real CodeMirror view, not a textarea: it renders
  // gutters and highlighting, rebuilds cleanly per file, and its view mode
  // makes the document non-editable at the view level, not just in state.
  doc.getElementById('remoteFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await window.editSelected('remote');
  await new Promise(resolve => setTimeout(resolve, 80));
  check('the editor mounts with line numbers and a code surface',
    !!doc.querySelector('#editorHost .cm-gutters .cm-lineNumbers') &&
      !!doc.querySelector('#editorHost .cm-content'),
    doc.getElementById('editorHost').innerHTML.slice(0, 120));
  check('the editor reports the loaded text',
    window.getEditorValue() === 'keep\n');
  check('edit mode keeps the document editable at the view level',
    doc.querySelector('#editorHost .cm-content').getAttribute('contenteditable') ===
      'true');
  window.closeEditor();
  await window.viewSelected('remote');
  await new Promise(resolve => setTimeout(resolve, 80));
  check('view mode makes the document non-editable at the view level',
    doc.querySelector('#editorHost .cm-content').getAttribute('contenteditable') ===
      'false');
  window.closeEditor();

  // While the editor holds the keyboard, the pane shortcuts stay out of the
  // way: CodeMirror's content is a contenteditable div, not a textarea.
  doc.getElementById('remoteFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await window.editSelected('remote');
  await new Promise(resolve => setTimeout(resolve, 80));
  const editorContent = doc.querySelector('#editorHost .cm-content');
  const listCallsBefore = calls.filter(call => call.path === '/api/remote/list').length;
  editorContent.dispatchEvent(new window.KeyboardEvent('keydown', {
    key: 'Backspace', bubbles: true, cancelable: true }));
  await new Promise(resolve => setTimeout(resolve, 80));
  check('Backspace in the editor does not navigate the pane up',
    calls.filter(call => call.path === '/api/remote/list').length === listCallsBefore);
  const remoteSelection = window.selectedNames('remote').join(',');
  editorContent.dispatchEvent(new window.KeyboardEvent('keydown', {
    key: 'a', ctrlKey: true, bubbles: true, cancelable: true }));
  check('Ctrl+A in the editor does not select the whole remote pane',
    window.selectedNames('remote').join(',') === remoteSelection);
  const savesBeforeEditorKeys = calls.filter(call => call.path === '/api/remote/save').length;
  editorContent.dispatchEvent(new window.KeyboardEvent('keydown', {
    key: 's', ctrlKey: true, bubbles: true, cancelable: true }));
  await new Promise(resolve => setTimeout(resolve, 120));
  check('Ctrl+S in the editor saves the file',
    calls.filter(call => call.path === '/api/remote/save').length ===
      savesBeforeEditorKeys + 1);
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
      .map(option => option.value).join('|') === 'checksum|time,checksum|size,checksum|time,size,checksum|none',
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
  check('auto reconnect is off by default with a 30 second interval',
    !doc.getElementById('siteAutoReconnect').checked && doc.getElementById('siteAutoReconnectSeconds').value === '30');
  doc.getElementById('siteAutoReconnect').checked = true;
  doc.getElementById('siteAutoReconnectSeconds').value = '12';
  check('port row sits directly below hostname row and alt port row sits directly below alt hostname row',
    doc.getElementById('siteHost').closest('.form-row').nextElementSibling === doc.getElementById('sitePort').closest('.form-row') &&
    doc.getElementById('siteAltHost').closest('.form-row').nextElementSibling === doc.getElementById('siteAltPort').closest('.form-row'));
  doc.getElementById('siteAltHost').value = 'backup.example.test';
  doc.getElementById('siteAltPort').value = '2222';
  doc.getElementById('siteAltFallback').checked = true;
  await window.saveSite();
  await new Promise(resolve => setTimeout(resolve, 100));
  const saved = calls.filter(call => call.path === '/api/sessions/save').pop();
  check('saved site sends the reconnect toggle and interval',
    JSON.parse(saved.options.body).session.auto_reconnect === true &&
    JSON.parse(saved.options.body).session.auto_reconnect_seconds === 12);
  doc.getElementById('siteAutoReconnectSeconds').value = '0';
  const beforeInvalidReconnect = calls.filter(call => call.path === '/api/sessions/save').length;
  await window.saveSite();
  check('invalid reconnect intervals are rejected before saving',
    calls.filter(call => call.path === '/api/sessions/save').length === beforeInvalidReconnect &&
    lastLogLine().includes('1 to 3600'));
  window.fillSiteForm({name: 'settings', protocol: 'sftp', host: 'test', auto_reconnect: true, auto_reconnect_seconds: 17});
  check('stored auto reconnect settings populate the form',
    doc.getElementById('siteAutoReconnect').checked && doc.getElementById('siteAutoReconnectSeconds').value === '17');
  window.fillSiteForm({name: 'GUI/test', protocol: 'sftp', host: '127.0.0.1', port: 2222, username: 'user'});
  check('saving posts alternate hostname, alternate port and fallback setting',
    JSON.parse(saved.options.body).session.alt_hostname === 'backup.example.test' &&
    JSON.parse(saved.options.body).session.alt_port === 2222 &&
    JSON.parse(saved.options.body).session.alt_fallback === true);
  check('saving posts the name', saved && JSON.parse(saved.options.body).name === 'GUI/test');
  check('saving an existing site without a stored password posts no password',
    saved && !JSON.parse(saved.options.body).session.password);

  const oldPrompt = window.prompt;
  const copyCallsBefore = calls.filter(call => call.path === '/api/sessions/copy').length;
  window.prompt = () => null;
  await window.copySite();
  check('cancelling a site copy does not make a request', calls.filter(call => call.path === '/api/sessions/copy').length === copyCallsBefore);
  window.prompt = () => 'GUI/test copy';
  responses['/api/sessions/copy'] = {success: true};
  await window.copySite();
  const copyCall = calls.filter(call => call.path === '/api/sessions/copy').pop();
  check('copy site copies the selected stored session under the requested name',
    copyCall && JSON.parse(copyCall.options.body).source === 'GUI/test' && JSON.parse(copyCall.options.body).name === 'GUI/test copy');
  delete responses['/api/sessions/copy'];
  window.prompt = oldPrompt;

  window.fillSiteForm({name: 'alt', protocol: 'sftp', host: 'primary.example', port: 22,
    alt_hostname: 'alternate.example', alt_port: 2202, alt_fallback: true});
  check('stored alternate settings populate the form including Alt Port',
    doc.getElementById('siteAltHost').value === 'alternate.example' &&
    doc.getElementById('siteAltPort').value === '2202' &&
    doc.getElementById('siteAltFallback').checked);
  doc.getElementById('siteAltPort').value = '70000';
  const badAltPortBefore = calls.filter(call => call.path === '/api/sessions/save').length;
  await window.saveSite();
  check('invalid Alt Port is rejected before saving',
    calls.filter(call => call.path === '/api/sessions/save').length === badAltPortBefore &&
    lastLogLine().includes('1 to 65535'));
  doc.getElementById('siteAltPort').value = '2202';
  const oldAltOpen = responses['/api/tabs/open'];
  responses['/api/tabs/open'] = {success: false, error: 'Test alternate failure'};
  window.openModal('siteModal');
  await window.connectFromSiteManager(true);
  const altOpen = calls.filter(call => call.path === '/api/tabs/open').pop();
  check('Alt Connect sends the alternate-selection flag and Alt Port without replacing the primary host/port',
    JSON.parse(altOpen.options.body).use_alt_host === true &&
    JSON.parse(altOpen.options.body).session.host === 'primary.example' &&
    JSON.parse(altOpen.options.body).session.port === 22 &&
    JSON.parse(altOpen.options.body).session.alt_hostname === 'alternate.example' &&
    JSON.parse(altOpen.options.body).session.alt_port === 2202);
  responses['/api/tabs/open'] = oldAltOpen;
  window.newSite();
  const missingAltBefore = calls.filter(call => call.path === '/api/tabs/open').length;
  doc.getElementById('siteHost').value = 'primary.example';
  await window.connectFromSiteManager(true);
  check('Alt Connect requires an alternate hostname',
    calls.filter(call => call.path === '/api/tabs/open').length === missingAltBefore &&
    lastLogLine().includes('An alternate hostname is required.'));
  window.newSite();
  check('new SSH sessions default to storing their password',
    doc.getElementById('siteRemember').checked);
  check('automatic sudo password use is off by default',
    !doc.getElementById('siteSudoPassword').checked);
  doc.getElementById('siteSudoPassword').checked = true;
  doc.getElementById('siteName').value = 'new-ssh-site';
  doc.getElementById('siteHost').value = 'new.example.test';
  doc.getElementById('siteUser').value = 'deploy';
  doc.getElementById('sitePass').value = 'ssh-password';
  await window.saveSite();
  const newSiteSave = calls.filter(call => call.path === '/api/sessions/save').pop();
  check('new SSH session saves its password when the default is kept',
    newSiteSave && JSON.parse(newSiteSave.options.body).session.password === 'ssh-password');
  check('automatic sudo password use is saved only when selected',
    newSiteSave && JSON.parse(newSiteSave.options.body).session.sudo_password_auto === true);

  check('private-key controls offer both browse and vault pickers for destination and tunnel keys',
    !!doc.getElementById('siteKeyBrowseBtn') && !!doc.getElementById('siteKeyVaultBtn') &&
      doc.getElementById('siteKeyFileInput').type === 'file' &&
      !!doc.getElementById('siteTunnelKeyBrowseBtn') && !!doc.getElementById('siteTunnelKeyVaultBtn') &&
      doc.getElementById('siteTunnelKeyFileInput').type === 'file');
  await window.openSshKeyVaultPicker();
  await new Promise(resolve => setTimeout(resolve, 20));
  const vaultKeyChoice = doc.querySelector('#sshKeyVaultList button');
  check('vault picker lists saved encrypted keys',
    doc.getElementById('sshKeyVaultModal').classList.contains('open') &&
      vaultKeyChoice && vaultKeyChoice.textContent === 'work-laptop-key');
  if (vaultKeyChoice) vaultKeyChoice.click();
  check('choosing a vault key fills its opaque encrypted reference',
    doc.getElementById('siteKey').value === 'vaultkey://0123456789abcdef0123456789abcdef' &&
      window.currentSiteForm().keyfile === 'vaultkey://0123456789abcdef0123456789abcdef');
  await window.openSshKeyVaultPicker('siteTunnelKey');
  await new Promise(resolve => setTimeout(resolve, 20));
  const tunnelKeyChoice = doc.querySelector('#sshKeyVaultList button');
  if (tunnelKeyChoice) tunnelKeyChoice.click();
  check('vault picker can target the SSH tunnel key field',
    doc.getElementById('siteTunnelKey').value === 'vaultkey://0123456789abcdef0123456789abcdef');
  const originalVaultKeys = responses['/api/vault/keys'];
  responses['/api/vault/keys/delete'] = { success: true, deleted: true };
  await window.openSshKeyVaultPicker();
  const deleteKey = doc.querySelector('#sshKeyVaultList .vault-key-delete');
  const keyDeletesBefore = calls.filter(call => call.path === '/api/vault/keys/delete').length;
  confirmResult = false;
  if (deleteKey) deleteKey.click();
  confirmResult = true;
  const deleteWarning = confirmMessages[confirmMessages.length - 1] || '';
  check('deleting a vault key requires confirmation and explains saved sites and backups',
    !!deleteKey && deleteWarning.includes('work-laptop-key') && deleteWarning.includes('stored sessions') &&
    deleteWarning.includes('backups') && calls.filter(call => call.path === '/api/vault/keys/delete').length === keyDeletesBefore);
  responses['/api/vault/keys'] = { success: true, keys: [] };
  if (deleteKey) deleteKey.click();
  await new Promise(resolve => setTimeout(resolve, 30));
  const deletedKeyCall = calls.filter(call => call.path === '/api/vault/keys/delete').pop();
  check('confirmed deletion sends only the reference and confirmation, clears current fields and refreshes the list',
    deletedKeyCall && JSON.parse(deletedKeyCall.options.body).reference === 'vaultkey://0123456789abcdef0123456789abcdef' &&
      JSON.parse(deletedKeyCall.options.body).confirm === true && !doc.getElementById('siteKey').value &&
      !doc.getElementById('siteTunnelKey').value && text('sshKeyVaultList').includes('No SSH keys'));
  responses['/api/vault/keys'] = originalVaultKeys;
  responses['/api/vault/keys/delete'] = { success: false, error: 'vault delete refused' };
  doc.getElementById('siteKey').value = 'vaultkey://0123456789abcdef0123456789abcdef';
  await window.openSshKeyVaultPicker();
  doc.querySelector('#sshKeyVaultList .vault-key-delete').click();
  await new Promise(resolve => setTimeout(resolve, 30));
  check('failed key deletion leaves the current selection and reports the error',
    doc.getElementById('siteKey').value === 'vaultkey://0123456789abcdef0123456789abcdef' && lastLogLine().includes('vault delete refused'));
  responses['/api/vault/keys/delete'] = { success: false, deleted: true, error: 'metadata cleanup failed' };
  responses['/api/vault/keys'] = { success: true, keys: [] };
  doc.querySelector('#sshKeyVaultList .vault-key-delete').click();
  await new Promise(resolve => setTimeout(resolve, 30));
  check('partial key deletion clears the deleted selection and reports metadata cleanup failure',
    !doc.getElementById('siteKey').value && lastLogLine().includes('metadata cleanup failed') &&
      text('sshKeyVaultList').includes('No SSH keys'));
  responses['/api/vault/keys'] = originalVaultKeys;
  window.closeModal('sshKeyVaultModal');
  delete responses['/api/vault/keys/delete'];
  const keyFileInput = doc.getElementById('siteKeyFileInput');
  Object.defineProperty(keyFileInput, 'files', { configurable: true, value: [{
    name: 'id_ed25519', size: 32, text: async () => '-----BEGIN OPENSSH PRIVATE KEY-----\\nfixture\\n',
  }] });
  await window.importSshKeyFile(keyFileInput);
  const keyImport = calls.filter(call => call.path === '/api/vault/keys/import').pop();
  check('browsed key content is sent to the vault import endpoint',
    keyImport && JSON.parse(keyImport.options.body).name === 'id_ed25519' &&
      JSON.parse(keyImport.options.body).private_key.includes('OPENSSH PRIVATE KEY'));
  check('imported key is used as an encrypted vault reference',
    doc.getElementById('siteKey').value === 'vaultkey://fedcba9876543210fedcba9876543210');

  // CLI terminal.
  window.switchTab('cli');
  doc.getElementById('cliInput').value = 'pwd ; ls';
  await window.execCliCommand();
  await new Promise(resolve => setTimeout(resolve, 100));
  check('terminal shows the command output',
    text('cliOutput').indexOf('/tmp/slowremote') >= 0, text('cliOutput').slice(-80));
  window.switchTab('log');
  await new Promise(resolve => setTimeout(resolve, 150));
  // The panel also holds what the page logged itself, so the backend's entry
  // is asked for by name rather than by a count of the whole panel.
  check('log tab renders entries', text('logOutput').includes('Connected'), text('logOutput'));
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
  check('Help shows the build stamp as the version',
    /^LinSCP V\d{4}-\d{2}-\d{2}-\d{2}-\d{2}$/.test(doc.getElementById('buildVersion').textContent));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  check('Escape closes the modal', doc.getElementById('helpModal').className.indexOf('open') < 0);

  // F8 deletes the selection. The request carries the tab and, for the remote
  // side, the kind of each name as the pane listed it, because a delete of a
  // directory has to remove what is inside it and a rename to a file must not
  // be attempted on a tree.
  const deletesBefore = calls.filter(c => c.path === '/api/local/delete').length;
  const asksBefore = confirmMessages.length;
  // F9 above ran against the local pane, so the focus is already there; the
  // selection may have been consumed by the transfer the key asked for.
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F8', bubbles: true }));
  await new Promise(resolve => setTimeout(resolve, 120));
  const localDelete = calls.filter(c => c.path === '/api/local/delete').pop();
  const localDeleteBody = localDelete ? JSON.parse(localDelete.options.body) : {};
  check('F8 deletes the selected local entry after asking',
    calls.filter(c => c.path === '/api/local/delete').length === deletesBefore + 1 &&
      confirmMessages.length === asksBefore + 1 &&
      localDeleteBody.tab === 1 && (localDeleteBody.names || []).join(',') === 'a.txt',
    localDelete ? localDelete.options.body : 'no delete request');
  doc.getElementById('remotePane').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  doc.getElementById('remoteFileList').children[1]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F8', bubbles: true }));
  await new Promise(resolve => setTimeout(resolve, 120));
  const remoteDelete = calls.filter(c => c.path === '/api/remote/delete').pop();
  const remoteDeleteBody = remoteDelete ? JSON.parse(remoteDelete.options.body) : {};
  check('F8 deletes a remote directory by its listed kind',
    !!remoteDelete && remoteDeleteBody.tab === 1 &&
      (remoteDeleteBody.names || []).length === 1 &&
      remoteDeleteBody.names[0].name === 'testdir' && remoteDeleteBody.names[0].is_dir === true,
    remoteDelete ? remoteDelete.options.body : 'no delete request');
  // A successful batch response may still report a failed, partially removed
  // tree. Its diagnostic must reach the persistent error log.
  const previousDeleteResponse = responses['/api/remote/delete'];
  responses['/api/remote/delete'] = { success: true, deleted: ['another.txt'],
    failed: [{ name: 'testdir', error: 'tree may be partially deleted' }] };
  doc.getElementById('remoteFileList').children[1]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F8', bubbles: true }));
  await new Promise(resolve => setTimeout(resolve, 120));
  check('partial remote deletion is reported in the error log',
    lastLogLine().includes('testdir:') && lastLogLine().includes('tree may be partially deleted'), lastLogLine());
  responses['/api/remote/delete'] = previousDeleteResponse;
  // Declining the question sends nothing at all.
  const declinedBefore = calls.filter(c =>
    c.path === '/api/remote/delete' || c.path === '/api/local/delete').length;
  confirmResult = false;
  doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F8', bubbles: true }));
  await new Promise(resolve => setTimeout(resolve, 80));
  confirmResult = true;
  check('declining the delete question sends nothing',
    calls.filter(c => c.path === '/api/remote/delete' || c.path === '/api/local/delete')
      .length === declinedBefore);
  doc.getElementById('localPane').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

  /* ---- The menu bar --------------------------------------------------- */
  /* A dropdown is an absolutely-positioned panel inside the bar, so it lives
   * in the bar's overflow. Any ancestor that clips its overflow - a scroll
   * container is the usual accident - hides the whole panel, and the menu
   * simply does not exist for the person clicking it. This happened twice: a
   * `overflow-x: auto` on the bar at desktop width and again in the narrow
   * rule, which is why no menu worked anywhere. */
  {
    // `themeCss` is the stylesheet the run was pointed at: the built one when
    // the harness is given `dist/index.html`, which is what CI and the release
    // run pass.
    const stylesheet = themeCss;
    // Every declaration of a selector, so a later rule cannot quietly reinstate
    // what an earlier one stopped doing.
    // The declarations of a selector, found without a regex so the CSS in the
    // test file cannot confuse the test: every `{...}` that follows the name.
    const declarationsOf = (selector, from = stylesheet) => {
      const found = [];
      let at = from.indexOf(selector);
      while (at !== -1) {
        const open = from.indexOf('{', at + selector.length);
        const close = from.indexOf('}', open);
        // Only a rule, not a mention in a comment or a longer selector.
        const before = from.slice(Math.max(0, at - 1), at);
        const after = from.slice(at + selector.length, open).trim();
        if (open !== -1 && close !== -1 && (before === '' || /[\s,}]/.test(before)) && after === '') {
          found.push(from.slice(open + 1, close));
        }
        at = from.indexOf(selector, at + selector.length);
      }
      return found;
    };
    // Which of the given rules make a scroll container, and so clip whatever
    // overflows them - which is where an absolutely-positioned dropdown lives.
    const clippingIn = (blocks) => blocks.flatMap((block) => {
      const entries = block.split(';').map((entry) => entry.trim());
      return ['overflow', 'overflow-x', 'overflow-y']
        .filter((prop) => entries.some((entry) =>
          entry.startsWith(`${prop}:`) && !entry.includes('visible')));
    });
    const wide = declarationsOf('.menu-bar');
    check('the menu bar is styled at all', wide.length > 0, JSON.stringify(wide));
    check('no rule for the menu bar clips the dropdowns it holds',
      clippingIn(wide).length === 0, JSON.stringify(clippingIn(wide)));
    const narrow = declarationsOf(
      '.menu-bar', stylesheet.slice(stylesheet.indexOf('@media (max-width: 720px)')),
    );
    check('the narrow menu bar does not clip them either',
      clippingIn(narrow).length === 0, JSON.stringify(clippingIn(narrow)));
    check('the bar wraps so every group stays reachable',
      wide.some((block) => block.includes('flex-wrap: wrap')), JSON.stringify(wide));

    /* The extra-keys row has two sources of visibility - a `visible` class the
     * shell toggles and a `hidden` attribute the page sets while a selection is
     * open - and the class was the more specific of the two. `hidden` then did
     * nothing at all: the row of Esc/Ctrl/arrow keys stayed on screen under the
     * copy bar. jsdom lays nothing out, so the rule that settles it is asserted
     * here rather than the geometry. */
    const extraKeysHidden = declarationsOf('.terminal-extra-keys.visible[hidden]');
    check('hiding the extra-keys row actually hides it',
      extraKeysHidden.some((block) => block.includes('display: none')),
      JSON.stringify(extraKeysHidden));

    /* ---- The design system ------------------------------------------- */
    /* The stylesheet is now built out of tokens, so the ways it can rot are
     * different from the ways a hand-written stylesheet rots. These four
     * checks each cover a failure this migration actually hit. */
    {
      // 1. A block that closes early leaves the declarations after it outside
      //    any rule. They are parsed, ignored, and every colour they define
      //    silently disappears - while the page still renders and every
      //    geometry test still passes. This is how the base palette died once.
      let depth = 0;
      let orphaned = 0;
      for (const line of stylesheet.split('\n')) {
        const code = line.split('/*')[0];
        const before = depth;
        depth += (code.match(/{/g) || []).length - (code.match(/}/g) || []).length;
        if (before === 0 && /^\s*--[a-z0-9-]+\s*:/.test(code)) orphaned += 1;
      }
      check('every declaration in the stylesheet is inside a rule', orphaned === 0,
        `${orphaned} token declarations sit outside any block`);
      check('the stylesheet braces balance', depth === 0, `unbalanced by ${depth}`);

      // 2. A var() with no definition is not an error in CSS: the property
      //    just does not apply, so a typo in a token name looks like styling
      //    that was never written.
      // Comments are stripped first: prose that names a token - including a
      // note explaining that one was undefined - is not a use of it.
      const code = stylesheet.replace(/\/\*[\s\S]*?\*\//g, '');
      const defined = new Set();
      for (const m of code.matchAll(/(--[a-z0-9-]+)\s*:/g)) defined.add(m[1]);
      const undefinedTokens = [...new Set([...code.matchAll(/var\((--[a-z0-9-]+)/g)]
        .map((m) => m[1]))].filter((name) => !defined.has(name));
      check('every token a rule uses is defined', undefinedTokens.length === 0,
        undefinedTokens.join(', '));

      // 3. The palette is the only source of colour. One-off hex inside a
      //    rule is how the light theme ended up with a dark blue glow.
      //    Comments are stripped first: this file documents the values it
      //    replaced, and quoting one is not painting with it.
      const body = stylesheet
        .slice(stylesheet.indexOf('* { box-sizing'))
        .replace(/\/\*[\s\S]*?\*\//g, '');
      const literals = [...new Set([
        ...(body.match(/#[0-9a-fA-F]{3,8}\b/g) || []),
        ...(body.match(/rgba?\([^)]*\)/g) || []),
      ])].filter((value) => !value.includes('transparent'));
      check('no rule paints a colour the palette does not name',
        literals.length === 0, literals.join(', '));

      // 4. Text has to be readable, and a placeholder is still text. Both
      //    themes are checked against every surface an input can sit on.
      const luminance = (hex) => {
        const value = hex.replace('#', '');
        const channels = [0, 2, 4].map((i) => parseInt(value.slice(i, i + 2), 16) / 255);
        return channels
          .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
          .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);
      };
      const contrast = (a, b) => {
        const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
        return (hi + 0.05) / (lo + 0.05);
      };
      const valueOf = (name, from) => {
        const m = from.match(new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`));
        return m ? m[1] : null;
      };
      const themes = {
        dark: stylesheet.slice(0, stylesheet.indexOf(':root[data-theme="light"]')),
        light: stylesheet.slice(stylesheet.indexOf(':root[data-theme="light"]'),
          stylesheet.indexOf('* { box-sizing')),
      };
      // The terminal is painted by a canvas that brings its own colours, so
      // only the surfaces that actually carry HTML text are checked.
      const textSurfaces = ['--surface', '--surface-raised', '--code-bg', '--surface-input'];
      const unreadable = [];
      for (const [theme, block] of Object.entries(themes)) {
        for (const surface of textSurfaces) {
          for (const ink of ['--text', '--muted', '--subtle']) {
            const fg = valueOf(ink, block);
            const bg = valueOf(surface, block);
            if (!fg || !bg) continue;
            if (contrast(fg, bg) < 4.5) unreadable.push(`${theme}: ${ink} on ${surface}`);
          }
        }
      }
      check('body and placeholder text clear 4.5:1 on every surface',
        unreadable.length === 0, unreadable.join(', '));
    }

    // And the behaviour the stylesheet exists for: a click opens the panel.
    const button = doc.querySelector('[onclick*="localMenu"]');
    const menu = doc.getElementById('localMenu');
    button.click();
    check('clicking a menu opens its panel',
      menu.parentElement.classList.contains('open'), menu.parentElement.className);
    button.click();
    check('clicking again closes it',
      !menu.parentElement.classList.contains('open'), menu.parentElement.className);
  }

  // ---- Synchronized browsing ------------------------------------------
  // The boot stub answers every list call with one fixed response, which
  // cannot show navigation; switch to a path-aware stub for this section.
  const LOCAL_DIRS = {
    '/tmp/slowlocal': LOCAL_ENTRIES,
    '/tmp/slowlocal/sub': [
      { name: 'inner.txt', size: 3, is_dir: false, date: 'Oct 13 08:00',
        permissions: '-rw-r--r--' }
    ],
    // What a listing looks like when the backend could not describe every
    // entry: the page has to draw the ones it can and must not throw.
    '/tmp/slowlocal/partial': [
      null,
      1,
      { name: 'keep.txt', size: 3, is_dir: false, date: 'Oct 13 08:00',
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
  // The page caches the transport it built at boot, so the new browser-phase
  // answers are reached by replacing the bridge method the transport holds,
  // not by installing a second `__TAURI_INTERNALS__`.
  window.__TAURI_INTERNALS__.invoke = async (_cmd, args) => invoke(args.envelope);
  const invoke = envelope => {
    const options = { method: String(envelope.method || 'GET').toUpperCase() };
    if (envelope.body && Object.keys(envelope.body).length) {
      options.body = JSON.stringify(envelope.body);
    }
    const url = String(envelope.path);
    const raw = url;
    const parts = raw.split('?');
    const path = parts[0];
    calls.push({ path: path, url: url, options: options });
    browseCalls.push(raw);
    if (path === '/api/tabs/open' && delayedTabOpen) return delayedTabOpen;
    const params = new URLSearchParams(parts[1] || '');
    if (path === '/api/local/list' || path === '/api/remote/list') {
      const isLocal = path === '/api/local/list';
      const dir = params.get('path') ||
        (isLocal ? '/tmp/slowlocal' : '/tmp/slowremote');
      const table = isLocal ? LOCAL_DIRS : REMOTE_DIRS;
      const body = table[dir] ?
        { success: true, path: dir, entries: table[dir] } :
        { success: false, error: 'No such directory: ' + dir };
      return Promise.resolve({ status: 200, payload: body });
    }
    if (path === '/api/custom-commands') {
      return Promise.resolve(
        { status: 200, payload: customCommandsBody(options) });
    }
    if (path === '/api/preferences') {
      return Promise.resolve(
        { status: 200, payload: preferencesBody(options) });
    }
    if (path === '/api/cleanup') {
      return Promise.resolve(
        { status: 200, payload: cleanupBody(options) });
    }
    if (path === '/api/remote/properties') {
      return Promise.resolve(
        { status: 200, payload: propertiesBody(options) });
    }
    if (path === '/api/remote/rights') {
      return Promise.resolve(
        { status: 200, payload: { success: true, changed: 1, results: [], error: '' } });
    }
    if (path === '/api/remote/transfer') {
      return Promise.resolve(
        { status: 200, payload: { success: true,
          tasks: [{ id: 9, type: 'Copy (remote)', status: 'Queued' }] } });
    }
    if (path === '/api/bookmarks') {
      const stored = responses['/api/bookmarks'].bookmarks;
      const body = { success: true, file: '/tmp/cfg/bookmarks.json',
        bookmarks: params.has('side') ? stored[params.get('side')] : stored };
      return Promise.resolve({ status: 200, payload: body });
    }
    if (path === '/api/session/url' && (options.method || 'GET').toUpperCase() === 'GET') {
      if (responses['/api/session/url']) {
        return Promise.resolve({ status: 200, payload: responses['/api/session/url'] });
      }
      const include = params.get('password') === '1';
      const mockUrl = include
        ? 'sftp://user:secret%20word@127.0.0.1:2222/tmp/slowremote/'
        : 'sftp://user@127.0.0.1:2222/tmp/slowremote/';
      const body = { success: true,
        url: mockUrl,
        open_command: 'open sftp://user@127.0.0.1:2222/tmp/slowremote/',
        script_snippet: 'open "' + mockUrl + '"\ncd "/tmp/slowremote"',
        openssh_command: "sftp -P 2222 user@127.0.0.1:'/tmp/slowremote'",
        path: '/tmp/slowremote', include_password: include,
        has_password: true, protocol: 'sftp', host: '127.0.0.1' };
      return Promise.resolve({ status: 200, payload: body });
    }
    if (path === '/api/sessions/import' &&
        (options.method || 'GET').toUpperCase() === 'POST') {
      let request = {};
      try { request = JSON.parse(options.body || '{}'); } catch (error) {}
      const body = { success: true, source: request.source,
        path: '/home/user/.ssh/config', imported: request.names || [],
        skipped: [], sessions: (responses['/api/sessions'] || {}).sessions || [],
        file: '/tmp/cfg/sessions.ini' };
      return Promise.resolve({ status: 200, payload: body });
    }
    const vaultBody = vaultBackupBody(path, options);
    if (vaultBody !== undefined) {
      return Promise.resolve({ status: 200, payload: vaultBody });
    }
    const body = responses[path];
    if (body === undefined) {
      return Promise.resolve(
        { status: 200, payload: { success: true } });
    }
    return Promise.resolve({ status: 200, payload: body });
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
  const desktopBody = desktopRequest && desktopRequest.options.body
    ? JSON.parse(desktopRequest.options.body) : {};
  /* One request carries the bytes as base64 on every transport, so the same
   * handler serves the browser, the native window and the Android app. */
  check('desktop file bytes are queued for remote upload',
    !!desktopRequest &&
      Buffer.from(desktopBody.data_base64 || '', 'base64').toString() ===
        'desktop upload');
  check('desktop upload targets the remote pane directory',
    desktopBody.name === 'desktop.txt' &&
      desktopBody.remote_dir === '/tmp/slowremote' &&
      desktopBody.tab === 1,
    desktopRequest ? desktopRequest.options.body : 'no upload request');

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
  const nestedBody = folderFiles.length ?
    JSON.parse(folderFiles[0].options.body) : {};
  check('nested desktop file keeps its relative path and bytes',
    folderFiles.length === 1 &&
      nestedBody.relative_path === 'project/src/read %TIMESTAMP%.txt' &&
      nestedBody.name === 'read %TIMESTAMP%.txt' &&
      Buffer.from(nestedBody.data_base64 || '', 'base64').toString() ===
        'preserve this literal name');

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
    !!handleFile && JSON.parse(handleFile.options.body).relative_path ===
      'via-handle/x.txt');

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

  // The packaged window swallows HTML5 drag-and-drop, so dragging a row to
  // the other panel is driven by pointer events everywhere. A press, a small
  // move and a release on the remote pane queues the same upload as F5.
  const pointerRow = doc.getElementById('localFileList').children[0];
  pointerRow.click();
  const pointerBefore = calls.filter(
    call => call.path === '/api/transfer/upload').length;
  pointerRow.dispatchEvent(new window.MouseEvent('pointerdown', {
    bubbles: true, button: 0, clientX: 10, clientY: 10 }));
  doc.dispatchEvent(new window.MouseEvent('pointermove', {
    bubbles: true, clientX: 10, clientY: 11 }));
  check('a sub-threshold move does not start a drag',
    !doc.querySelector('.pane-drag-ghost'));
  doc.dispatchEvent(new window.MouseEvent('pointermove', {
    bubbles: true, clientX: 80, clientY: 120 }));
  check('a pointer move past the threshold shows a drag ghost',
    !!doc.querySelector('.pane-drag-ghost'),
    'no ghost rendered');
  check('the dragged entry is selected for the transfer',
    window.selectedNames('local').join(',') === 'a.txt',
    window.selectedNames('local').join(','));
  doc.getElementById('remotePane').dispatchEvent(new window.MouseEvent('pointerup', {
    bubbles: true, clientX: 700, clientY: 300 }));
  await wait(150);
  const pointerCalls = calls.filter(
    call => call.path === '/api/transfer/upload');
  const pointerBody = pointerCalls.length ?
    JSON.parse(pointerCalls[pointerCalls.length - 1].options.body) : {};
  check('a pointer drag from local to remote queues an upload',
    pointerCalls.length === pointerBefore + 1,
    pointerBefore + ' -> ' + pointerCalls.length);
  check('the pointer drag carries the dragged name and both panes',
    (pointerBody.names || []).join(',') === 'a.txt' &&
      pointerBody.local_dir === '/tmp/slowlocal' &&
      pointerBody.remote_dir === '/tmp/slowremote',
    JSON.stringify(pointerBody));
  check('the drop clears the ghost and the highlight',
    !doc.querySelector('.pane-drag-ghost') &&
      !doc.body.classList.contains('pane-drag-active') &&
      doc.getElementById('remotePane').className.indexOf('drop-target') < 0);

  // Escape aborts the gesture without queueing a transfer or leaving a ghost.
  const escapeBefore = calls.filter(
    call => call.path === '/api/transfer/upload').length;
  pointerRow.dispatchEvent(new window.MouseEvent('pointerdown', {
    bubbles: true, button: 0, clientX: 10, clientY: 10 }));
  doc.dispatchEvent(new window.MouseEvent('pointermove', {
    bubbles: true, clientX: 60, clientY: 80 }));
  doc.dispatchEvent(new window.KeyboardEvent('keydown', {
    key: 'Escape', bubbles: true, cancelable: true }));
  doc.getElementById('remotePane').dispatchEvent(new window.MouseEvent('pointerup', {
    bubbles: true, clientX: 700, clientY: 300 }));
  await wait(80);
  check('Escape cancels the drag and queues nothing',
    calls.filter(call => call.path === '/api/transfer/upload').length === escapeBefore);
  check('the cancelled drag leaves no ghost behind',
    !doc.querySelector('.pane-drag-ghost') &&
      !doc.body.classList.contains('pane-drag-active'));

  // A finger on a row keeps the shell's gestures; only a mouse or pen drags.
  const touchDown = new window.MouseEvent('pointerdown', {
    bubbles: true, button: 0, clientX: 10, clientY: 10 });
  Object.defineProperty(touchDown, 'pointerType', { value: 'touch' });
  pointerRow.dispatchEvent(touchDown);
  doc.dispatchEvent(new window.MouseEvent('pointermove', {
    bubbles: true, clientX: 60, clientY: 80 }));
  check('a touch pointerdown does not start a file drag',
    !doc.querySelector('.pane-drag-ghost'));

  // Every API call goes through the native bridge: one backend, one route.
  check('every API call goes through the native bridge',
    calls.length > 0 && calls.every(call => call.options && call.options.method &&
      call.path.startsWith('/api/')),
    calls.filter(call => !(call.options && call.options.method)).map(c => c.path).join(','));

  // Failures and successes are recorded in the visible log.
  window.openSiteManager();
  await new Promise(resolve => setTimeout(resolve, 100));
  const originalOpen = responses['/api/tabs/open'];
  responses['/api/tabs/open'] = { success: false, error: 'Connection refused' };
  await window.connectFromSiteManager();
  check('a failed connection is visible in the log and permits another try',
    doc.getElementById('tabLogBtn').classList.contains('active') &&
    !doc.getElementById('siteConnectBtn').disabled &&
    lastLogLine().includes('Connection refused'));
  window.openSiteManager();
  responses['/api/tabs/open'] = { success: true, tab: {
    id: 1, session: { protocol: 'sftp' }
  } };
  await window.connectFromSiteManager();
  check('a successful connection clears progress and closes the site form',
    !doc.getElementById('siteModal').classList.contains('open') &&
    !doc.getElementById('siteConnectBtn').disabled && text('logOutput').includes('Connection established.'));
  responses['/api/tabs/open'] = originalOpen;

  // Automatic attempts must still ask for a host-key decision.
  responses['/api/auto-reconnect/tick'] = { success: true, attempted: 'restored', result: {
    success: false, challenge: { tab: 31, host: 'restored.example', port: 22, fingerprint: 'ssh-ed25519 SHA256:restore' }
  } };
  await window.pollAutoReconnect();
  check('automatic reconnect presents the host-key challenge without accepting it',
    doc.getElementById('hostKeyModal').classList.contains('open') &&
    text('hostKeyFingerprint') === 'ssh-ed25519 SHA256:restore');
  await window.cancelHostKey();
  responses['/api/auto-reconnect/tick'] = { success: true, attempted: 'restored', result: {
    success: false, error: 'Server rejected password authentication.'
  } };
  await window.pollAutoReconnect();
  check('automatic reconnect failures are visible in the log',
    lastLogLine().includes('Automatic reconnection failed for restored.') &&
    lastLogLine().includes('Server rejected password authentication.'));
  delete responses['/api/auto-reconnect/tick'];

  // Host keys are verified instead of accepted.
  window.openSiteManager();
  await new Promise(resolve => setTimeout(resolve, 100));
  let finishOpen;
  delayedTabOpen = new Promise(resolve => { finishOpen = resolve; });
  const beforeOpen = calls.filter(call => call.path === '/api/tabs/open').length;
  doc.getElementById('sitePass').value = 'secret-connection-test';
  const connecting = window.connectFromSiteManager();
  check('connection opens the log with details and disables duplicate attempts',
    !doc.getElementById('siteModal').classList.contains('open') &&
    doc.getElementById('tabLogBtn').classList.contains('active') &&
    doc.getElementById('siteConnectBtn').disabled &&
    text('logOutput').includes(doc.getElementById('siteHost').value) &&
    text('logOutput').includes('Waiting for the connection') &&
    !text('logOutput').includes('secret-connection-test'));
  const oldLogs = responses['/api/logs'];
  responses['/api/logs'] = { logs: [{ timestamp_ms: Date.now(), level: 'info',
    text: '[Connection 7] SSH handshake and host-key verification completed; starting authentication.' }] };
  await window.refreshLogs();
  check('backend connection stages appear in the log while the request is pending',
    text('logOutput').includes('SSH handshake and host-key verification completed'));
  responses['/api/logs'] = oldLogs;
  await window.connectFromSiteManager();
  check('repeated connection requests do not start another attempt',
    calls.filter(call => call.path === '/api/tabs/open').length === beforeOpen + 1);
  finishOpen({ status: 200, payload: responses['/api/tabs/open'] });
  await connecting;
  delayedTabOpen = null;
  await new Promise(resolve => setTimeout(resolve, 100));
  check('connection progress clears for a host-key challenge',
    !doc.getElementById('siteConnectBtn').disabled &&
    text('logOutput').includes('Host-key verification is required') &&
    !doc.getElementById('siteModal').classList.contains('open'));
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
  const savedVerify = responses['/api/tabs/verify'];
  const failedKey = 'Failed to load PPK private key: PPK integrity check failed';
  responses['/api/tabs/verify'] = { success: false, error: failedKey };
  window.showHostKeyChallenge({ tab: 7, host: '127.0.0.1', port: 2222, role: 'destination', fingerprint: 'ssh-ed25519 SHA256:example' });
  await window.acceptHostKey();
  check('a private-key failure after verification does not blame the host key',
    lastLogLine().includes('Connection failed after host-key verification.') && lastLogLine().includes(failedKey) &&
      !lastLogLine().includes('Cannot connect with that host key.'));
  responses['/api/tabs/verify'] = { success: false, error: 'unknown destination key', challenge: {
    tab: 7, host: 'destination', port: 22, role: 'destination', fingerprint: 'ssh-ed25519 SHA256:destination' } };
  const beforeNextChallenge = doc.querySelectorAll('#logOutput .log-error').length;
  window.showHostKeyChallenge({ tab: 7, host: 'jump', port: 22, role: 'tunnel', fingerprint: 'ssh-ed25519 SHA256:jump' });
  await window.acceptHostKey();
  check('a second host-key challenge opens without logging a connection failure',
    doc.getElementById('hostKeyModal').classList.contains('open') &&
    text('hostKeyFingerprint') === 'ssh-ed25519 SHA256:destination' &&
    doc.querySelectorAll('#logOutput .log-error').length === beforeNextChallenge &&
    lastLogLine().includes('Host-key verification is required'));
  window.closeModal('hostKeyModal');
  responses['/api/tabs/verify'] = savedVerify;

  window.showHelp();
  check('help opens the shortcut reference',
    doc.getElementById('helpModal').classList.contains('open'));
  window.closeModal('helpModal');

  // A byte drop saves directly to the local panel via /api/local/drop.
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
  const localDropBody = JSON.parse(
    calls.filter(c => c.path === '/api/local/drop').pop().options.body);
  check('dropping a folder on the local pane calls /api/local/drop-dir and /api/local/drop',
    calls.filter(c => c.path === '/api/local/drop-dir').length === localDropDirBefore + 1 &&
      calls.filter(c => c.path === '/api/local/drop').length === localDropBefore + 1 &&
      localDropBody.local_dir === '/tmp/slowlocal' &&
      localDropBody.relative_path === 'local-drop-dir/dropped-local.txt' &&
      Buffer.from(localDropBody.data_base64, 'base64').toString() === 'hello local',
    JSON.stringify({ ...localDropBody, data_base64: '...' }));

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
  check('choosing FTP in the site form moves both Port and Alt Port to 21',
    doc.getElementById('sitePort').value === '21' &&
    doc.getElementById('siteAltPort').value === '21');
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
  // Upstream keeps explicit TLS ('ftpes://') and implicit TLS ('ftps://')
  // apart, so a site says which one it uses instead of a bare 'FTP'.
  const protocolOptions = Array.from(doc.getElementById('siteProtocol').options)
    .map(option => option.value);
  check('the site form offers both TLS schemes',
    protocolOptions.includes('ftpes') && protocolOptions.includes('ftps'));
  window.fillSiteForm({ name: 'explicit', protocol: 'ftpes', host: 'h', port: 0 });
  window.siteProtocolChanged();
  check('a stored explicit-TLS site opens on FTP port 21',
    doc.getElementById('sitePort').value === '21' &&
      window.currentSiteForm().protocol === 'ftpes');

  // A mirror deletes at the target, so the dialogue says so and is one-way.
  window.openSynchronize();
  check('the sync dialog is not still mirroring from a previous visit',
    doc.getElementById('syncMirror').checked === false);
  doc.getElementById('syncMode').value = 'both';
  doc.getElementById('syncMirror').checked = true;
  window.syncMirrorChanged();
  check('a mirror is one-way', doc.getElementById('syncMode').value === 'remote',
    doc.getElementById('syncMode').value);
  check('a mirror deletes obsolete files', doc.getElementById('syncDelete').checked === true);
  check('a mirror says that it deletes',
    doc.getElementById('syncHint').textContent.indexOf('deletes') >= 0,
    doc.getElementById('syncHint').textContent);
  await window.previewSynchronization();
  const mirrorPreview = calls.filter(c => c.path === '/api/sync/preview').pop();
  check('the mirror choice reaches the backend',
    mirrorPreview && JSON.parse(mirrorPreview.options.body).mirror === true);
  window.closeModal('syncModal');

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

  /* A template saved for one side must not run on the other side's names:
   * remote `checksum sha-256 keep.txt` against the local pane would check a
   * different file. The page refuses it by name instead of posting it. */
  const beforeMismatch = calls.filter(call => call.path === '/api/custom-commands' &&
    JSON.parse(call.options.body || '{}').action === 'run').length;
  window.selectCustomCommand(0);
  doc.getElementById('localPane')
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await window.runCustomCommand();
  const refusals = lastLogLine();
  const afterMismatch = calls.filter(call => call.path === '/api/custom-commands' &&
    JSON.parse(call.options.body || '{}').action === 'run').length;
  check('a template saved for one side is refused on the other side by name',
    afterMismatch === beforeMismatch && refusals.includes('Checksum') &&
      refusals.toLowerCase().includes('remote'), refusals);
  window.selectCustomCommand(0);
  window.focusPane('remote');
  doc.getElementById('remoteFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

  confirmResult = true;
  await window.runCustomCommand();
  const customRun = calls.filter(call => call.path === '/api/custom-commands' &&
    JSON.parse(call.options.body || '{}').action === 'run').pop();
  const customPayload = customRun ? JSON.parse(customRun.options.body) : {};
  check('confirmed custom command runs only on the selected remote entry',
    customPayload.action === 'run' && customPayload.tab === 1 &&
      customPayload.pane === 'remote' &&
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
    items: [ { name: 'a.txt', path: '/home/u/a.txt', is_dir: false, size: 3 },
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

  // A file that is still there but cannot be queued is reported with the
  // reason, not described as missing.
  responses['/api/shell/pending'] = { success: true, pending: [{
    id: 'b'.repeat(32), created: 1,
    items: [ { name: 'locked.txt', path: '/home/u/locked.txt', is_dir: false, size: 3 }] }] };
  await window.checkShellPending();
  responses['/api/shell/consume'] = { success: true, queued: [], missing: [],
    refused: [{ name: 'locked.txt', error: 'The destination already exists.' }] };
  await window.shellUploadConfirm();
  check('a refused file is reported with its reason',
    lastLogLine().includes('locked.txt: The destination already exists.'),
    lastLogLine());
  responses['/api/shell/consume'] = { success: true, queued: ['a.txt', 'folder'],
    missing: [], refused: [], remote_dir: '/tmp/slowremote' };
  responses['/api/shell/pending'] = { success: true, pending: [] };

  /* Directory bookmarks: one list per panel, stored by the backend; the
   * dialog jumps to a saved directory and never treats a name as markup. */
  await window.openBookmarks('remote');
  check('bookmark dialog lists the selected panel bookmarks',
    doc.getElementById('bookmarksModal').classList.contains('open') &&
      doc.getElementById('bookmarkList').children.length === 1 &&
      text('bookmarkList').includes('logs') &&
      text('bookmarkStatus').includes('1 bookmark in the Remote panel'),
    text('bookmarkList') + ' / ' + text('bookmarkStatus'));
  const localListBefore = calls.filter(call => call.path === '/api/local/list').length;
  await window.goBookmark('local', '/tmp/slowlocal');
  check('a local bookmark loads its directory in the local panel',
    calls.filter(call => call.path === '/api/local/list').length ===
      localListBefore + 1 &&
      !doc.getElementById('bookmarksModal').classList.contains('open'));
  window.prompt = () => 'work';
  await window.addBookmark('local');
  const bookmarkSave = calls.filter(call => call.path === '/api/bookmarks/save').pop();
  const bookmarkPayload = bookmarkSave ? JSON.parse(bookmarkSave.options.body) : {};
  check('adding a bookmark posts the panel, name and directory',
    bookmarkPayload.side === 'local' && bookmarkPayload.name === 'work' &&
      bookmarkPayload.path === '/tmp/slowlocal',
    JSON.stringify(bookmarkPayload));
  await window.deleteBookmark('local', 'home');
  const bookmarkDelete = calls.filter(call => call.path === '/api/bookmarks/delete').pop();
  check('deleting a bookmark posts its panel and name',
    bookmarkDelete && JSON.parse(bookmarkDelete.options.body).side === 'local' &&
      JSON.parse(bookmarkDelete.options.body).name === 'home');
  check('bookmark names are inserted as text, not markup',
    doc.getElementById('bookmarkList').innerHTML.includes('home') &&
      !doc.getElementById('bookmarkList').innerHTML.includes('<script'));
  check('a bookmark list is rendered from the panel the request named',
    !doc.getElementById('bookmarkList').innerHTML.includes('logs'));
  window.closeModal('bookmarksModal');

  /* Generate URL: password omitted by default, included only on request. */
  await window.openSessionUrl();
  check('the session URL dialog shows a URL without the password',
    doc.getElementById('sessionUrlModal').classList.contains('open') &&
      value('sessionUrlText') === 'sftp://user@127.0.0.1:2222/tmp/slowremote/' &&
      !doc.getElementById('urlIncludePassword').checked,
    value('sessionUrlText'));
  check('the dialog offers the stored password explicitly',
    text('sessionUrlStatus').includes('Tick the box'));
  doc.getElementById('urlIncludePassword').checked = true;
  await window.loadSessionUrl();
  const urlCall = calls.filter(call => call.path === '/api/session/url').pop();
  check('asking for the password asks the backend for it',
    urlCall && urlCall.url.includes('password=1') &&
      value('sessionUrlText').includes('secret%20word') &&
      text('sessionUrlStatus').includes('Treat it as a secret'),
    urlCall && urlCall.url);
  window.closeModal('sessionUrlModal');

  /* Import sessions: the scan lists names without passwords; only ticked
   * sites are posted, and the site list is reloaded afterwards. */
  await window.openImportSessions();
  check('import dialog scans the chosen source',
    doc.getElementById('importSessionsModal').classList.contains('open') &&
      doc.getElementById('importList').children.length === 2 &&
      text('importList').includes('prod') && text('importList').includes('staging'),
    text('importList'));
  check('a skipped import entry says why',
    text('importStatus').includes('Only a Host line with one plain alias'),
    text('importStatus'));
  check('the import scan never lists a password',
    !text('importList').includes('secret') &&
      !text('importStatus').includes('secret'));
  const importPostsBefore = calls.filter(call => call.path === '/api/sessions/import' &&
    (call.options.method || 'GET').toUpperCase() === 'POST').length;
  doc.getElementById('importPath').value = '/changed/source';
  await window.runSessionImport();
  check('changing the import path requires a fresh scan before importing',
    calls.filter(call => call.path === '/api/sessions/import' &&
      (call.options.method || 'GET').toUpperCase() === 'POST').length === importPostsBefore);
  doc.getElementById('importPath').value = '';
  doc.querySelectorAll('#importList input[type="checkbox"]')[1].checked = false;
  const sessionsBefore = calls.filter(call => call.path === '/api/sessions').length;
  doc.getElementById('importOverwrite').checked = true;
  await window.runSessionImport();
  const importCall = calls.filter(call => call.path === '/api/sessions/import' &&
    (call.options.method || 'GET').toUpperCase() === 'POST').pop();
  const importPayload = importCall ? JSON.parse(importCall.options.body) : {};
  check('importing posts only the ticked sites and the overwrite choice',
    importPayload.source === 'openssh' &&
      JSON.stringify(importPayload.names) === JSON.stringify(['prod']) &&
      importPayload.overwrite === true && importPayload.fingerprint === 'fixture-digest', JSON.stringify(importPayload));
  check('a finished import reloads the stored site list',
    calls.filter(call => call.path === '/api/sessions').length > sessionsBefore);
  window.closeModal('importSessionsModal');

  const previousVaultStatus = responses['/api/vault/status'];
  responses['/api/vault/status'] = { success: false, error: 'Configuration is locked by another instance.' };
  const gated = await window.requireLocalVaultUnlock();
  check('configuration startup errors remain visible and block vault setup',
    gated === false && doc.getElementById('vaultGate').style.display === 'flex' &&
      doc.getElementById('vaultUnlockButton').disabled && text('vaultGateError').includes('another instance') &&
      doc.getElementById('vaultPasswordFields').style.display === 'none' &&
      doc.getElementById('vaultRetryButton').style.display === '');
  responses['/api/vault/retry-lock'] = { success: false, error: 'Still locked.' };
  const retryFailed = await window.retryVaultConfigurationLock();
  check('retrying configuration lock while still held surfaces the error and keeps Retry active',
    retryFailed === false && text('vaultGateError').includes('Still locked.') &&
      !doc.getElementById('vaultRetryButton').disabled);
  responses['/api/vault/retry-lock'] = { success: true };
  responses['/api/vault/status'] = previousVaultStatus;
  const retrySucceeded = await window.retryVaultConfigurationLock();
  check('retrying configuration lock after release recovers and closes vaultGate',
    retrySucceeded === true &&
      calls.some(call => call.path === '/api/vault/retry-lock') &&
      doc.getElementById('vaultGate').style.display === 'none' &&
      doc.getElementById('vaultPasswordFields').style.display === '');
  delete responses['/api/vault/retry-lock'];
  doc.getElementById('vaultUnlockButton').disabled = false;
  doc.getElementById('vaultGateError').textContent = '';

  window.openFullBackup();
  check('full backup dialog opens', doc.getElementById('fullBackupModal').classList.contains('open'));
  doc.getElementById('fullBackupPassword').value = 'long-backup-password';
  doc.getElementById('fullBackupConfirm').value = 'mismatch';
  await window.exportFullBackup();
  check('full backup rejects mismatched passwords', !calls.some(call => call.path === '/api/backup/export'));
  doc.getElementById('fullBackupConfirm').value = 'long-backup-password';
  await window.exportFullBackup();
  const fullExport = calls.filter(call => call.path === '/api/backup/export').pop();
  check('full backup exports with an independent password and clears it',
    fullExport && JSON.parse(fullExport.options.body).password === 'long-backup-password' && value('fullBackupPassword') === '');
  check('full backup restore requires choosing a backup file first',
    !doc.getElementById('fullBackupImport').disabled);
  await window.importFullBackup();
  check('full backup restore without file sends nothing',
    !calls.some(call => call.path === '/api/backup/import') &&
      text('fullBackupStatus').includes('Choose a full backup file first.'));
  const fullBackupFile = new window.File([new Uint8Array([76, 83, 67, 80, 66, 65, 75, 49, 1])], 'backup.lscpbak');
  Object.defineProperty(doc.getElementById('fullBackupFile'), 'files',
    { value: [fullBackupFile], configurable: true });
  doc.getElementById('fullBackupPassword').value = 'long-backup-password';
  await window.importFullBackup();
  check('full backup restore requires explicit replace confirmation',
    !calls.some(call => call.path === '/api/backup/import') &&
      text('fullBackupStatus').includes('Confirm replacing current configuration'));
  doc.getElementById('fullBackupPassword').value = 'long-backup-password';
  doc.getElementById('fullBackupConfirmReplace').checked = true;
  await window.importFullBackup();
  const fullImport = calls.filter(call => call.path === '/api/backup/import').pop();
  const fullImportBody = fullImport ? JSON.parse(fullImport.options.body) : {};
  check('full backup restore posts base64 backup with confirmation and clears secrets',
    fullImportBody.password === 'long-backup-password' &&
      fullImportBody.confirm_replace === true &&
      fullImportBody.data_base64 === 'TFNDUEJBSzEB' &&
      value('fullBackupPassword') === '' &&
      !doc.getElementById('fullBackupConfirmReplace').checked &&
      text('fullBackupStatus').includes('Full backup restored.'));
  window.closeFullBackup();

  /* Key/Session Export: the list comes from saved sessions (reloaded on open),
   * the password must match, tunnel-only keys show the SSH key badge, and
   * only the ticked sessions are sent. */
  const origSessionsList = responses['/api/sessions'].sessions;
  responses['/api/sessions'].sessions = [
    Object.assign({}, origSessionsList[0], {
      has_password: false,
      has_proxy_password: true,
      has_key_passphrase: false,
      has_tunnel_passphrase: true,
      linscp_public_key_file: 'vaultpub://0123456789abcdef0123456789abcdef',
    }),
    {
      name: 'Workspaces/DualLocal',
      protocol: 'local',
      host: '',
      port: 0,
      username: '',
      local_dir: '/srv/left',
      other_local_dir: '/srv/right',
    },
  ];
  await window.openKeySessionExport();
  check('the export dialog flags proxy/tunnel secrets, public SSH keys, and dual-local directories',
    text('keyExportList').includes('Password') &&
      text('keyExportList').includes('Key password') &&
      text('keyExportList').includes('SSH key') &&
      text('keyExportList').includes('/srv/left ↔ /srv/right'),
    text('keyExportList'));
  responses['/api/sessions'].sessions = [
    Object.assign({}, origSessionsList[0], { tunnel_private_key: 'vaultkey://fedcba9876543210fedcba9876543210' })
  ];
  await window.openKeySessionExport();
  check('the export dialog reloads saved sessions and flags tunnel SSH keys',
    doc.getElementById('keySessionExportModal').classList.contains('open') &&
      doc.getElementById('keyExportList').children.length === 1 &&
      text('keyExportList').includes('GUI/test') &&
      text('keyExportList').includes('SSH key'),
    text('keyExportList'));
  responses['/api/sessions'].sessions = origSessionsList;
  check('the export dialog does not offer plaintext backups',
    !doc.getElementById('keyExportPlainText') && !doc.getElementById('keyExportPassword').disabled);
  doc.getElementById('keyExportPassword').value = 'backup-password';
  doc.getElementById('keyExportPasswordConfirm').value = 'backup-password';
  const exportCalls = () => calls.filter(call => call.path === '/api/vault/export');
  const exportBaseline = exportCalls().length;
  doc.querySelector('#keyExportList input[type="checkbox"]').checked = false;
  await window.exportKeySession();
  check('an empty selection exports nothing',
    exportCalls().length === exportBaseline &&
      text('keyExportStatus').includes('Select at least one session to export.'),
    text('keyExportStatus'));
  doc.querySelector('#keyExportList input[type="checkbox"]').checked = true;
  doc.getElementById('keyExportPassword').value = 'backup-password';
  doc.getElementById('keyExportPasswordConfirm').value = 'different-password';
  const mismatchBaseline = exportCalls().length;
  await window.exportKeySession();
  check('mismatched passwords refuse to export',
    exportCalls().length === mismatchBaseline &&
      text('keyExportStatus').includes('The backup passwords do not match.'),
    text('keyExportStatus'));
  doc.getElementById('keyExportPasswordConfirm').value = 'backup-password';
  await window.exportKeySession();
  const exportCall = exportCalls().pop();
  const exportPayload = exportCall ? JSON.parse(exportCall.options.body) : {};
  check('a matching export posts the ticked sessions',
    exportPayload.plain_text === false &&
      exportPayload.password === 'backup-password' &&
      JSON.stringify(exportPayload.sessions) === JSON.stringify(['GUI/test']),
    JSON.stringify(exportPayload));
  check('a finished export names the file and clears the password fields',
    text('keyExportStatus').includes('key_session_2026-11-15_00-00-00.json.aes') &&
      value('keyExportPassword') === '' && value('keyExportPasswordConfirm') === '',
    text('keyExportStatus'));
  window.closeModal('keySessionExportModal');

  /* Key/Session Import: the file is read before anything is listed, the
   * magic bytes tell encrypted from plain without trusting the extension,
   * scan fingerprints prevent stale imports, and ticked sessions (with their
   * merged SSH keys) are imported. */
  await window.openKeySessionImport();
  check('the import dialog opens with everything reset',
    doc.getElementById('keySessionImportModal').classList.contains('open') &&
      value('keyImportPassword') === '' && value('keyImportFile') === '' &&
      doc.getElementById('keyImportList').children.length === 0);
  const scanCalls = () => calls.filter(call => call.path === '/api/vault/scan');
  const sealedFile = new window.File([new Uint8Array([76, 83, 67, 80, 86, 76, 84, 50, 1, 2])], 'backup.json.aes');
  Object.defineProperty(doc.getElementById('keyImportFile'), 'files',
    { value: [sealedFile], configurable: true });
  await window.scanKeySessionBackup();
  check('an encrypted backup without a password explains itself and scans nothing',
    scanCalls().length === 0 &&
      text('keyImportStatus').includes('encrypted backup'),
    text('keyImportStatus'));
  const plainFile = new window.File(['[{"type":"PASSWORD"}]'], 'backup.json',
    { type: 'application/json' });
  Object.defineProperty(doc.getElementById('keyImportFile'), 'files',
    { value: [plainFile], configurable: true });
  await window.scanKeySessionBackup();
  check('the scan lists what the backup holds',
    doc.getElementById('keyImportList').children.length === 2 &&
      text('keyImportList').includes('GUI/test') &&
      text('keyImportList').includes('backup/restored'),
    text('keyImportList'));
  check('the scan flags sessions that already exist',
    text('keyImportList').includes('Already saved'));
  check('the scan reports ignored entries',
    text('keyImportStatus').includes('1'), text('keyImportStatus'));
  const scanCall = scanCalls().pop();
  const scanPayload = scanCall ? JSON.parse(scanCall.options.body) : {};
  check('the scan posts the file and the password it was given',
    typeof scanPayload.data_base64 === 'string' && scanPayload.data_base64.length > 0 &&
      scanPayload.password === '',
    JSON.stringify(scanPayload));
  const importCalls = () => calls.filter(call => call.path === '/api/vault/import');
  const importBaseline = importCalls().length;
  const boxes = doc.querySelectorAll('#keyImportList input[type="checkbox"]');
  boxes[0].checked = false; // skip the one that is already saved
  confirmResult = false;
  doc.getElementById('keyImportReplace').checked = true;
  await window.importKeySession();
  check('a declined overwrite warning imports nothing',
    importCalls().length === importBaseline &&
      confirmMessages[confirmMessages.length - 1].includes('overwritten'),
    confirmMessages[confirmMessages.length - 1]);
  confirmResult = true;
  doc.getElementById('keyImportReplace').checked = false;
  const mutatedFile = new window.File(['[{"type":"PASSWORD","changed":1}]'], 'backup.json',
    { type: 'application/json' });
  Object.defineProperty(doc.getElementById('keyImportFile'), 'files',
    { value: [mutatedFile], configurable: true });
  await window.importKeySession();
  check('changing the backup file after scan refuses import until re-read',
    importCalls().length === importBaseline &&
      text('keyImportStatus').includes('changed since it was read'),
    text('keyImportStatus'));
  Object.defineProperty(doc.getElementById('keyImportFile'), 'files',
    { value: [plainFile], configurable: true });
  doc.getElementById('sshKeyVaultModal').classList.add('open');
  const keyPickerCallsBefore = calls.filter(call => call.path === '/api/vault/keys').length;
  await window.importKeySession();
  const keyPickerCallsAfter = calls.filter(call => call.path === '/api/vault/keys').length;
  doc.getElementById('sshKeyVaultModal').classList.remove('open');
  const keyImportCall = importCalls().pop();
  const keyImportPayload = keyImportCall ? JSON.parse(keyImportCall.options.body) : {};
  check('importing posts only the ticked sessions and the scan fingerprint',
    JSON.stringify(keyImportPayload.sessions) === JSON.stringify(['backup/restored']) &&
      keyImportPayload.fingerprint === 'b'.repeat(64) &&
      keyImportPayload.replace === false,
    JSON.stringify(keyImportPayload));
  check('a finished import reports what happened, reloads saved sessions, and refreshes open key pickers',
    text('keyImportStatus').includes('Imported 1 session(s)') &&
      calls.filter(call => call.path === '/api/sessions').length > 0 &&
      keyPickerCallsAfter > keyPickerCallsBefore,
    text('keyImportStatus'));
  window.closeModal('keySessionImportModal');

  /* Preferences: the defaults come from the backend, a save posts the whole
   * document, and the confirmation switches reach the copy and delete paths. */
  await window.openPreferences();
  check('the preferences dialog opens with the stored values',
    doc.getElementById('preferencesModal').classList.contains('open') &&
      value('prefTransfer') === 'binary' && value('prefFilemask') === '*.txt',
    value('prefTransfer') + ' / ' + value('prefFilemask'));
  doc.getElementById('prefConfirmOverwrite').checked = false;
  doc.getElementById('prefSpeed').value = '128';
  await window.savePreferences();
  const prefSave = calls.filter(call => call.path === '/api/preferences' &&
    (call.options.method || 'GET').toUpperCase() === 'POST').pop();
  const prefPayload = prefSave ? JSON.parse(prefSave.options.body) : {};
  check('saving preferences posts the whole document',
    prefPayload.action === 'save' &&
      prefPayload.preferences.confirm_overwrite === false &&
      prefPayload.preferences.speed === 128 &&
      prefPayload.preferences.transfer === 'binary',
    JSON.stringify(prefPayload));
  check('a saved preference is the default the transfer dialog shows',
    (window.openTransferSettings(), value('transferSpeed') === '128'),
    value('transferSpeed'));
  window.closeModal('transferModal');

  /* A resume threshold is stored as a number of KiB, which is not one of the
   * select's own values: opening the dialog has to show it as "resume above
   * a size" with the number in the field, and saving must keep it rather
   * than write the empty option back over it. */
  const storedPreferences = responses['/api/preferences'].preferences;
  responses['/api/preferences'].preferences =
    Object.assign({}, storedPreferences, { resumesupport: '2048' });
  await window.loadTransferSettings();
  window.openTransferSettings();
  check('a numeric resume threshold opens as the size option',
    value('transferResumeSupport') === 'size' && value('transferResumeSize') === '2048',
    value('transferResumeSupport') + ' / ' + value('transferResumeSize'));
  check('the resume size field is shown for a stored threshold',
    window.document.getElementById('transferResumeSizeRow').style.display === 'flex',
    window.document.getElementById('transferResumeSizeRow').style.display);
  await window.saveTransferSettings();
  const thresholdSave = calls.filter(call => call.path === '/api/preferences' &&
    (call.options.method || 'GET').toUpperCase() === 'POST').pop();
  const thresholdPayload = thresholdSave ? JSON.parse(thresholdSave.options.body) : {};
  check('saving the dialog keeps the resume threshold',
    thresholdPayload.preferences &&
      thresholdPayload.preferences.resumesupport === '2048',
    JSON.stringify(thresholdPayload.preferences));
  responses['/api/preferences'].preferences = storedPreferences;
  await window.loadTransferSettings();
  window.closeModal('transferModal');
  await window.resetPreferences();
  const prefReset = calls.filter(call => call.path === '/api/preferences' &&
    (call.options.method || 'GET').toUpperCase() === 'POST').pop();
  check('restoring the defaults asks the backend to reset them',
    prefReset && JSON.parse(prefReset.options.body).action === 'reset');

  /* Cleanup: the list is the data this client stores, only ticked entries
   * are removed, and a location that is gone cannot be ticked or removed. */
  await window.openCleanup();
  const cleanupBoxes = () =>
    Array.from(doc.querySelectorAll('#cleanupList input[type="checkbox"]'));
  check('the cleanup dialog lists every stored location',
    doc.getElementById('cleanupModal').classList.contains('open') &&
      cleanupBoxes().length === 2 &&
      text('cleanupList').includes('/tmp/cfg/sessions.ini') &&
      text('cleanupList').includes('Stored sessions') &&
      !text('cleanupList').includes('undefined'),
    text('cleanupList'));
  check('a location that is not there cannot be ticked',
    cleanupBoxes()[0].checked === true && cleanupBoxes()[1].disabled === true);
  window.toggleCleanupAll();
  check('check all clears the ticked locations first',
    cleanupBoxes()[0].checked === false);
  window.toggleCleanupAll();
  confirmResult = true;
  await window.runCleanup();
  const cleanupCall = calls.filter(call => call.path === '/api/cleanup' &&
    (call.options.method || 'GET').toUpperCase() === 'POST').pop();
  const cleanupPayload = cleanupCall ? JSON.parse(cleanupCall.options.body) : {};
  check('removing stored data posts the ticked ids and a confirmation',
    cleanupPayload.confirm === true &&
      JSON.stringify(cleanupPayload.ids) === JSON.stringify(['sessions']),
    JSON.stringify(cleanupPayload));
  check('a removed location stays listed but can no longer be ticked',
    cleanupBoxes()[0].disabled === true && text('cleanupStatus').length > 0,
    text('cleanupStatus'));
  window.closeModal('cleanupModal');

  /* Copy between two servers: the dialog lists the other sessions, a copy
   * inside the current session is direct, and any other target is a local
   * copy that is queued as a job. */
  window.focusPane('remote');
  doc.getElementById('remoteFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await window.openRemoteTransfer();
  check('the copy dialog lists the other sessions as targets',
    doc.getElementById('remoteTransferModal').classList.contains('open') &&
      doc.getElementById('remoteTransferTarget').options.length === 2 &&
      text('remoteTransferTarget').includes('(this session)'),
    text('remoteTransferTarget'));
  check('the copy dialog starts at the current directory and mask',
    value('remoteTransferDirectory') === '/tmp/slowremote' &&
      value('remoteTransferMask') === '*.txt',
    value('remoteTransferDirectory') + ' / ' + value('remoteTransferMask'));
  check('a copy inside the current session is done by the server',
    text('remoteTransferHint').includes('done by the server') &&
      !text('remoteTransferHint').includes('temporary local download'),
    text('remoteTransferHint'));
  doc.getElementById('remoteTransferTarget').value = 'tab:2';
  window.remoteTransferTargetChanged();
  check('another session is copied through a temporary directory',
    text('remoteTransferHint').includes('temporary local download'),
    text('remoteTransferHint'));
  await window.runRemoteTransfer();
  const remoteCopy = calls.filter(call => call.path === '/api/remote/transfer').pop();
  const remoteCopyPayload = remoteCopy ? JSON.parse(remoteCopy.options.body) : {};
  check('the copy posts the target, the directory and the mask',
    remoteCopyPayload.tab === 1 && remoteCopyPayload.target === 'tab:2' &&
      remoteCopyPayload.directory === '/tmp/slowremote' &&
      remoteCopyPayload.filemask === '*.txt' &&
      JSON.stringify(remoteCopyPayload.names) === JSON.stringify(['keep.txt']),
    JSON.stringify(remoteCopyPayload));

  /* Properties: every selected entry is read at once, and the dialog can
   * change the rights of the whole selection from the same place. */
  await window.openProperties();
  check('the properties dialog names every selected entry',
    doc.getElementById('propertiesModal').classList.contains('open') &&
      text('propertiesBody').includes('/tmp/slowremote/keep.txt') &&
      text('propertiesBody').includes('Owner'),
    text('propertiesBody'));
  check('the properties dialog offers a rights editor',
    doc.getElementById('propertiesMode') !== null);
  doc.getElementById('propertiesMode').value = '640';
  await window.applyPropertiesRights('remote', ['keep.txt']);
  const rightsCall = calls.filter(call => call.path === '/api/remote/rights').pop();
  const rightsPayload = rightsCall ? JSON.parse(rightsCall.options.body) : {};
  check('changing the rights posts the mode for the entry',
    rightsPayload.mode === '640' &&
      JSON.stringify(rightsPayload.names) === JSON.stringify(['keep.txt']),
    JSON.stringify(rightsPayload));
  window.closeModal('propertiesModal');

  /* Regression checks: desktop dragover on local pane, opening a local file
   * entry in the editor, and Save As refreshing baseMtime. */
  const localDesktopDt = { files: [desktopFile], types: ['Files'], dropEffect: '' };
  const localDesktopOver = { dataTransfer: localDesktopDt,
    preventDefault() { this.prevented = true; } };
  window.dragOverPane('local', localDesktopOver);
  check('dragover accepts a desktop file on the local pane too',
    localDesktopOver.prevented === true && localDesktopDt.dropEffect === 'copy');
  await window.openEntry('local', { name: 'a.txt', is_dir: false });
  check('opening a local file entry loads it in the editor',
    doc.getElementById('editorModal').classList.contains('open'));
  window.closeModal('editorModal');

  /* Payload shapes. The backend is the only source of these objects, so a
   * field that is missing or of the wrong type has to be survivable: each
   * of these used to throw out of a render or a poll, which left the page
   * silently stale - no tabs, no queue, no logs - with the error only in
   * the browser console. */
  check('a message that is not a string is translated to nothing',
    window.t(undefined) === '' && window.t(null) === '');

  const savedStatus = responses['/api/status'];
  responses['/api/status'] = { tabs: { not: 'a list' }, active_tab: 1 };
  await window.refreshStatus();
  check('a status answer whose tabs are not a list draws no rows',
    doc.getElementById('tabStrip').children.length === 0,
    String(doc.getElementById('tabStrip').children.length));

  responses['/api/status'] = { tabs: [null, 1, { id: 1, name: 'kept' }],
    active_tab: 1 };
  await window.refreshStatus();
  check('a status answer with unusable tab entries keeps the usable one',
    doc.getElementById('tabStrip').children.length === 1 &&
      text('tabStrip').includes('kept'),
    text('tabStrip'));

  responses['/api/status'] = savedStatus;
  await window.refreshStatus();
  check('the tab strip comes back when the answer does',
    doc.getElementById('tabStrip').children.length === savedStatus.tabs.length,
    String(doc.getElementById('tabStrip').children.length));

  /* A request that got no answer is not a status. The transport hands back
   * `{success:false, error}` for one, and drawing that emptied the tab strip
   * and put "Disconnected" on the badge - a backend that could not be reached
   * is not a server that went away, and this is asked on a timer and whenever
   * the window is looked at again. */
  responses['/api/status'] = { success: false, error: 'Cannot reach the LinSCP backend.' };
  await window.refreshStatus();
  check('a status answer that failed the request leaves the tabs it last drew',
    doc.getElementById('tabStrip').children.length === savedStatus.tabs.length,
    String(doc.getElementById('tabStrip').children.length));
  responses['/api/status'] = savedStatus;
  await window.refreshStatus();

  /* A session can end while this window is not the one being looked at: on a
   * desktop the shell that says so runs in a window of its own. The status is
   * asked again when this window is looked at again instead of only by the
   * fifteen-second poll, so the badge has caught up by the time the panes are
   * being used. */
  {
    const statuses = () => calls.filter(call => call.path === '/api/status').length;
    const before = statuses();
    window.dispatchEvent(new window.Event('focus'));
    await new Promise(resolve => setTimeout(resolve, 40));
    check('looking at the window again asks what became of its tabs',
      statuses() > before, 'status calls before=' + before + ' after=' + statuses());
  }

  // Late replies must not replace the newest navigation.
  {
    const transport = window.LinSCPTransport;
    const original = transport.request;
    let release;
    transport.request = async function(method, url, body) {
      if (url.includes('path=' + encodeURIComponent('/race/slow'))) {
        return await new Promise(resolve => { release = () => resolve({ success: true, path: '/race/slow', entries: [{name:'old', is_dir:false}] }); });
      }
      if (url.includes('path=' + encodeURIComponent('/race/new'))) {
        return { success: true, path: '/race/new', entries: [{name:'new', is_dir:false}] };
      }
      return original.call(this, method, url, body);
    };
    const first = window.loadLocal('/race/slow');
    await wait(10);
    const second = window.loadLocal('/race/new');
    check('pending pane navigation does not leave rows selectable', doc.getElementById('localFileList').children.length === 0);
    release(); await first; await second;
    check('a stale listing cannot replace a newer navigation', value('localPathInput') === '/race/new' && text('localFileList').includes('new') && !text('localFileList').includes('old'));
    transport.request = original;
    await window.loadLocal('/tmp/slowlocal');
  }

  await window.loadLocal('/tmp/slowlocal/partial');
  check('a listing with unusable entries still shows the usable ones',
    text('localFileList').includes('keep.txt') &&
      doc.getElementById('localFileList').children.length === 1,
    text('localFileList'));
  await window.loadLocal('/tmp/slowlocal');
  check('the local pane comes back to the whole directory',
    text('localFileList').includes('a.txt'), text('localFileList'));

  const savedTransfers = responses['/api/transfers'];
  responses['/api/transfers'] = { transfers: [null, { id: 1 },
    { id: 2, type: 'Copy', status: 'Running' }], paused: false };
  await window.refreshQueue();
  check('a task with no type or status does not empty the queue',
    doc.getElementById('queueList').children.length === 2,
    String(doc.getElementById('queueList').children.length));
  responses['/api/transfers'] = savedTransfers;
  await window.refreshQueue();

  const savedLogs = responses['/api/logs'];
  // The panel holds the page's own entries too, so the backend's answer is
  // counted against a fetch that returned nothing usable at all.
  responses['/api/logs'] = { logs: [] };
  await window.refreshLogs();
  const ownEntries = doc.getElementById('logOutput').children.length;
  responses['/api/logs'] = { logs: [null, { level: 'error', text: 'kept line' }] };
  await window.refreshLogs();
  check('a log answer with an unusable entry keeps the usable one',
    doc.getElementById('logOutput').children.length === ownEntries + 1 &&
      text('logOutput').includes('kept line'),
    text('logOutput'));
  // Logs are selectable across refreshes, and right-click copies either the
  // selected text or the clicked entry without exposing HTML as markup.
  window.switchTab('log');
  responses['/api/logs'] = { logs: [
    { time: '12:34:56', level: 'info', text: 'first <entry> here' },
    { time: '12:34:57', level: 'error', text: 'second entry' }
  ] };
  await window.refreshLogs();
  const logOutput = doc.getElementById('logOutput');
  const logScroller = doc.getElementById('tabLog');
  const contextMenu = doc.getElementById('logContextMenu');
  const firstLog = logOutput.querySelector('.log-line');
  const firstText = firstLog.lastElementChild.firstChild;
  const selection = window.getSelection();
  const range = doc.createRange();
  range.setStart(firstText, 0); range.setEnd(firstText, 5);
  firstLog.dispatchEvent(new window.MouseEvent('mousedown', { bubbles: true, button: 0 }));
  responses['/api/logs'].logs.push({ time: '12:34:58', level: 'info', text: 'new entry' });
  await window.refreshLogs();
  check('a refresh does not replace logs while a text drag is starting', logOutput.firstElementChild === firstLog);
  selection.removeAllRanges(); selection.addRange(range);
  doc.dispatchEvent(new window.MouseEvent('mouseup', { bubbles: true, button: 0 }));
  await window.refreshLogs();
  check('a selected log survives a refresh until selection is cleared',
    logOutput.firstElementChild === firstLog && selection.toString() === 'first' && !text('logOutput').includes('new entry'));
  check('logs explicitly enable mouse text selection', /#logOutput\s*\{[^}]*user-select:\s*text/.test(themeCss));

  const clipboardDescriptor = Object.getOwnPropertyDescriptor(window.navigator, 'clipboard');
  const copiedLogs = [];
  Object.defineProperty(window.navigator, 'clipboard', { configurable: true, value: { writeText: async value => copiedLogs.push(value) } });
  firstLog.dispatchEvent(new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 20, clientY: 30 }));
  check('right-click offers Copy for log text', !contextMenu.hidden && contextMenu.textContent.includes('Copy'));
  await window.copyLogContext();
  check('right-click on selected log text copies the selection', copiedLogs.pop() === 'first');
  const across = doc.createRange();
  across.setStart(firstText, 0);
  across.setEnd(logOutput.children[1].lastElementChild.firstChild, 6);
  selection.removeAllRanges(); selection.addRange(across);
  const acrossText = selection.toString();
  logOutput.children[1].dispatchEvent(new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  await window.copyLogContext();
  check('a selection spanning log entries is copied intact', acrossText.includes('first') && acrossText.includes('second') && copiedLogs.pop() === acrossText);
  selection.removeAllRanges(); selection.addRange(range);
  // Some native WebViews do not expose navigator.clipboard: the fallback must
  // check execCommand's return value and leave the user's selection intact.
  Object.defineProperty(window.navigator, 'clipboard', { configurable: true, value: { writeText: async () => { throw new Error('denied'); } } });
  const savedExecCommand = doc.execCommand;
  let fallbackText = '';
  doc.execCommand = command => {
    if (command !== 'copy') return false;
    fallbackText = doc.activeElement.value;
    return true;
  };
  firstLog.dispatchEvent(new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  await window.copyLogContext();
  check('clipboard fallback copies and preserves the log selection', fallbackText === 'first' && selection.toString() === 'first', JSON.stringify({ fallbackText, selected: selection.toString(), rangeCount: selection.rangeCount }));
  doc.execCommand = savedExecCommand;
  Object.defineProperty(window.navigator, 'clipboard', { configurable: true, value: { writeText: async value => copiedLogs.push(value) } });
  logOutput.children[1].dispatchEvent(new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  await window.copyLogContext();
  check('right-click on a different log copies its timestamp and complete message', copiedLogs.pop() === '12:34:57 second entry');
  firstLog.dispatchEvent(new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  contextMenu.querySelector('button').dispatchEvent(new window.KeyboardEvent('keydown', { bubbles: true, key: 'Escape' }));
  check('Escape dismisses the log context menu', contextMenu.hidden);
  Object.defineProperty(window.navigator, 'clipboard', { configurable: true, value: { writeText: async () => { throw new Error('denied'); } } });
  doc.execCommand = () => false;
  firstLog.dispatchEvent(new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  await window.copyLogContext();
  doc.execCommand = savedExecCommand;
  selection.removeAllRanges();
  doc.dispatchEvent(new window.Event('selectionchange'));
  check('the latest logs appear after the selection is cleared', text('logOutput').includes('new entry'));
  check('clipboard failure is reported instead of claiming success', text('logOutput').includes('Copy failed — select the log text and copy it manually.'));
  // Touch long-press on Android must NOT preventDefault or steal focus with #logContextMenu,
  // so native draggable teardrop selection handles stay adjustable.
  {
    const freshFirstLog = logOutput.querySelector('.log-line');
    const freshRange = doc.createRange();
    freshRange.setStart(freshFirstLog.lastElementChild.firstChild, 0);
    freshRange.setEnd(freshFirstLog.lastElementChild.firstChild, 5);
    selection.removeAllRanges();
    selection.addRange(freshRange);
    freshFirstLog.dispatchEvent(new window.Event('touchstart', { bubbles: true }));
    const touchCtx = new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 20, clientY: 30 });
    freshFirstLog.dispatchEvent(touchCtx);
    doc.dispatchEvent(new window.Event('touchend', { bubbles: true }));
    check('touch long-press on log leaves native selection handles unblocked',
      touchCtx.defaultPrevented === false && contextMenu.hidden === true && selection.toString() === 'first');
    selection.removeAllRanges();
    doc.dispatchEvent(new window.Event('selectionchange'));
  }
  Object.defineProperty(logScroller, 'scrollHeight', { configurable: true, value: 1000 });
  Object.defineProperty(logScroller, 'clientHeight', { configurable: true, value: 100 });
  logScroller.scrollTop = 20;
  await window.refreshLogs();
  check('refresh keeps the scroll position when reading older logs', logScroller.scrollTop === 20);
  delete logScroller.scrollHeight; delete logScroller.clientHeight;
  if (clipboardDescriptor) Object.defineProperty(window.navigator, 'clipboard', clipboardDescriptor);
  else delete window.navigator.clipboard;
  responses['/api/logs'] = savedLogs;
  await window.refreshLogs();

  // ---- Errors are log entries, not popups -------------------------------
  /* A failure used to be a toast: gone after four seconds, and nothing to read
   * back for anyone who was not looking at that moment. Every failure the page
   * reports goes through toast(message, true), so the backend is made
   * unreachable here - the one failure that reaches every caller - and the
   * message has to end up in the Logs panel with the popup left alone. */
  const logTab = doc.getElementById('tabLogBtn');
  const popup = doc.getElementById('toast');
  const realRequest = window.LinSCPTransport.request;
  const unreachable = 'Cannot reach the LinSCP backend';
  popup.textContent = '';
  popup.className = 'toast';
  // The checks before this one logged refusals of their own. Opening the
  // panel clears that count, so the one this block causes can be counted.
  window.switchTab('log');
  await window.refreshLogs();
  window.switchTab('queue');
  window.LinSCPTransport.request = async () => { throw new Error('the stub backend is not there'); };
  await window.refreshQueue();
  check('an error is written into the Logs panel instead of a popup',
    countIn(errorLog(), unreachable) === 1 &&
      lastLogLine().includes('the stub backend is not there') &&
      !text('toast').includes(unreachable),
    errorLog() + ' | popup=' + text('toast'));
  check('the Logs tab counts an error that arrived behind another panel',
    logTab.getAttribute('data-count') === '1', String(logTab.getAttribute('data-count')));
  /* The queue is polled every two seconds and the log every four, so an
   * unreachable backend fails again on a timer. The repeat replaces its own
   * entry: a panel full of one sentence is not a log. */
  await window.refreshQueue();
  await window.refreshLogs();
  check('a repeating error replaces its own entry instead of stacking up',
    countIn(errorLog(), unreachable) === 1 && logTab.getAttribute('data-count') === '1',
    countIn(errorLog(), unreachable) + ' | ' + logTab.getAttribute('data-count'));
  window.LinSCPTransport.request = realRequest;
  await window.refreshQueue();
  window.switchTab('log');
  await window.refreshLogs();
  check('opening the Logs panel clears the error count',
    logTab.getAttribute('data-count') === null && errorLog().includes(unreachable),
    String(logTab.getAttribute('data-count')));
  // A notice is still a popup: it confirms an action just taken, and there is
  // nothing about it to read back later.
  window.toast('The stub backend renamed the file.');
  check('a notice is still a popup and not a log entry',
    text('toast').includes('The stub backend renamed the file.') &&
      !errorLog().includes('The stub backend renamed the file.'),
    text('toast'));
  popup.textContent = '';
  popup.className = 'toast';

  // ---- Granted Android folders ------------------------------------------
  // A granted folder browses, edits, copies and moves, but cannot sync,
  // watch, transfer to a session, or chmod. The page asks the shared bundle
  // for the reason and offers nothing that could only fail; the backend
  // refuses the same way when called.
  const SAF_DIR = 'content://mock.tree/tree/primary%3ADownload';
  LOCAL_DIRS[SAF_DIR] = [
    { name: 'note.txt', size: 4, is_dir: false, date: 'Oct 13 08:00', permissions: '' }
  ];
  await window.loadLocal(SAF_DIR);
  check('the local pane navigated into the granted folder',
    text('localFileList').includes('note.txt'), text('localFileList'));
  // dist/index.html inlines the real bundle; the source page has none, so a
  // stub standing in for its contract proves the wiring in both runs.
  let safStubInstalled = false;
  if (!window.LinSCPCore || typeof window.LinSCPCore.safLimitationReason !== 'function') {
    window.LinSCPCore = window.LinSCPCore || {};
    window.LinSCPCore.safLimitationReason = (action, path) =>
      (typeof path === 'string' && path.startsWith('content://') ? 'stub refuses ' + action : null);
    safStubInstalled = true;
  }
  const safReason = action => window.LinSCPCore.safLimitationReason(action, SAF_DIR);
  const posted = path => calls.filter(call => call.path === path).length;

  const editsBefore = posted('/api/local/edit');
  await window.openEditor(SAF_DIR + '/document/primary%3ADownload%2Fnote.txt', 'local');
  check('a granted folder offers the editor',
    doc.getElementById('editorModal').className.indexOf('open') >= 0 &&
      posted('/api/local/edit') === editsBefore + 1,
    lastLogLine());
  window.closeModal('editorModal');

  window.openSynchronize();
  check('a granted folder is offered synchronization',
    doc.getElementById('syncModal').className.indexOf('open') >= 0,
    lastLogLine());
  window.closeModal('syncModal');

  window.openKeepUpToDate();
  check('a granted folder is offered keep-up-to-date',
    doc.getElementById('keepUpToDateModal').className.indexOf('open') >= 0,
    lastLogLine());
  window.closeModal('keepUpToDateModal');

  window.focusPane('local');
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  const safUploadsBefore = posted('/api/transfer/upload');
  await window.transfer('upload');
  check('a granted folder is offered transfers',
    posted('/api/transfer/upload') === safUploadsBefore + 1,
    lastLogLine());

  const confirmsBefore = confirmMessages.length;
  const movesBefore = posted('/api/transfer/move');
  await window.moveToOtherPane();
  check('a granted folder is offered moves',
    confirmMessages.length === confirmsBefore + 1 &&
      posted('/api/transfer/move') === movesBefore + 1,
    lastLogLine());

  const chmodsBefore = posted('/api/local/chmod');
  await window.permissionsPrompt('local');
  check('a granted folder is not offered chmod',
    lastLogLine().includes(safReason('permissions')) &&
      posted('/api/local/chmod') === chmodsBefore,
    lastLogLine());

  await window.openProperties();
  check('properties on a granted folder explain the missing rights editor',
    doc.getElementById('propertiesModal').className.indexOf('open') >= 0 &&
      !doc.getElementById('propertiesMode') &&
      text('propertiesBody').includes(safReason('permissions')),
    text('propertiesBody'));
  window.closeModal('propertiesModal');

  await window.loadLocal('/tmp/slowlocal');
  window.openSynchronize();
  check('leaving the granted folder offers the actions again',
    doc.getElementById('syncModal').className.indexOf('open') >= 0);
  window.closeModal('syncModal');

  // Both tab kinds offer transfers and moves now; the local tab below
  // proves the same granted folder is served there too.
  const savedStatusForLocalTab = responses['/api/status'];
  responses['/api/status'] = {
    tabs: [{ id: 1, name: 'local tab', connected: true, is_local: true,
      local_dir: SAF_DIR, remote_dir: '/tmp/slowlocal', error: '' }],
    active_tab: 1, paused: false, binary: '/usr/bin/linscp',
    local_dir: SAF_DIR, remote_dir: '/tmp/slowlocal',
    sessions_file: '/tmp/cfg/sessions.ini'
  };
  await window.refreshStatus();
  await window.loadLocal(SAF_DIR);
  await window.loadRemote('/tmp/slowlocal');
  window.focusPane('local');
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  const localUploadsBefore = posted('/api/transfer/upload');
  await window.transfer('upload');
  check('a local tab offers transfers out of a granted folder',
    posted('/api/transfer/upload') === localUploadsBefore + 1,
    lastLogLine());
  const localConfirmsBefore = confirmMessages.length;
  const localMovesBefore = posted('/api/transfer/move');
  await window.moveToOtherPane();
  check('a local tab offers moves out of a granted folder',
    confirmMessages.length === localConfirmsBefore + 1 &&
      posted('/api/transfer/move') === localMovesBefore + 1,
    lastLogLine());
  responses['/api/status'] = savedStatusForLocalTab;
  await window.refreshStatus();
  await window.loadLocal('/tmp/slowlocal');
  if (safStubInstalled) window.LinSCPCore.safLimitationReason = undefined;

  // ---- Local symbolic links ---------------------------------------------
  // The link dialog works on the local pane through /api/local/link and is
  // not offered for a granted folder, where links cannot exist.
  window.prompt = () => 'asked';
  window.focusPane('local');
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await window.promptLink('local');
  const linkCall = calls.filter(call => call.path === '/api/local/link').pop();
  check('the local pane offers symbolic links',
    linkCall && JSON.parse(linkCall.options.body).target === 'a.txt' &&
      JSON.parse(linkCall.options.body).name === 'asked' &&
      text('toast').includes('Created the symbolic link'),
    text('toast'));

  if (!window.LinSCPCore || typeof window.LinSCPCore.safLimitationReason !== 'function') {
    window.LinSCPCore = window.LinSCPCore || {};
    window.LinSCPCore.safLimitationReason = (action, path) =>
      (typeof path === 'string' && path.startsWith('content://') ? 'stub refuses ' + action : null);
    safStubInstalled = true;
  }
  await window.loadLocal(SAF_DIR);
  window.focusPane('local');
  doc.getElementById('localFileList').children[0]
    .dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  const linksBefore = posted('/api/local/link');
  await window.promptLink('local');
  check('a granted folder is not offered symbolic links',
    lastLogLine().includes(safReason('symlink')) &&
      posted('/api/local/link') === linksBefore,
    lastLogLine());
  await window.loadLocal('/tmp/slowlocal');
  if (safStubInstalled) window.LinSCPCore.safLimitationReason = undefined;

  // ---- Missing SSH agent ------------------------------------------------
  // The site dialog names the reason agent login is not offered instead of
  // failing the connection later; the wording comes from the shared bundle.
  window.updateAgentHint('stub no agent');
  check('the site dialog explains a missing SSH agent',
    doc.getElementById('siteAgentHint').hidden === false &&
      text('siteAgentHint') === 'stub no agent',
    text('siteAgentHint'));
  window.updateAgentHint(null);
  check('the agent hint hides when the host has an agent',
    doc.getElementById('siteAgentHint').hidden === true,
    String(doc.getElementById('siteAgentHint').hidden));

  let agentStubInstalled = false;
  if (!window.LinSCPCore || typeof window.LinSCPCore.hostDifferenceReason !== 'function') {
    window.LinSCPCore = window.LinSCPCore || {};
    window.LinSCPCore.hostDifferenceReason = () => 'stub no agent';
    agentStubInstalled = true;
  }
  const agentReason = window.sshAgentGap({ sshAgent: false });
  check('the agent gap asks the bundle for the reason',
    (agentStubInstalled ? agentReason === 'stub no agent' : agentReason.includes('private key')) &&
      window.sshAgentGap({ sshAgent: true }) === null,
    String(agentReason));
  if (agentStubInstalled) window.LinSCPCore.hostDifferenceReason = undefined;

  // ---- Kerberos limits --------------------------------------------------
  // The Kerberos section names its Linux-only limit, and key exchange — the
  // one setting no build honors — is noted where the Linux-only note is not.
  let gssapiStubInstalled = false;
  if (!window.LinSCPCore || typeof window.LinSCPCore.hostDifferenceReason !== 'function') {
    window.LinSCPCore = window.LinSCPCore || {};
    window.LinSCPCore.hostDifferenceReason = (capability) => 'stub no ' + capability;
    gssapiStubInstalled = true;
  }
  const kerberosReason = window.gssapiGap({ gssapi: false });
  check('the Kerberos gap names Linux-only builds',
    (gssapiStubInstalled ? kerberosReason === 'stub no gssapi' : kerberosReason.includes('Linux')) &&
      window.gssapiGap({ gssapi: true }) === null,
    String(kerberosReason));
  const kexReason = window.gssapiKexGap({ gssapi: true });
  check('the key-exchange gap applies on every build',
    (gssapiStubInstalled ? kexReason === 'stub no gssapiKex' : kexReason.includes('key exchange')) &&
      window.gssapiKexGap({ gssapi: false }) === null,
    String(kexReason));
  window.updateGssapiHint();
  const gssapiHintHidden = doc.getElementById('siteGssapiHint').hidden;
  // Which note this host shows depends on the host: where Kerberos is
  // unavailable the note is the Linux-only limit, and where it is available
  // the note is the unwired key exchange. Asserting one sentence made this
  // pass on Linux and fail on Windows, where the other is correct.
  const gssapiHostMissing = !gssapiStubInstalled &&
    window.LinSCPCore.hostCapabilities({ host: window }).gssapi === false;
  check('the Kerberos hint shows the gap reason',
    gssapiStubInstalled ? gssapiHintHidden === true :
      (gssapiHintHidden === false && text('siteGssapiHint').includes(
        gssapiHostMissing ? 'Linux' : 'key exchange')),
    JSON.stringify({ stub: gssapiStubInstalled, missing: gssapiHostMissing,
      hidden: gssapiHintHidden, hint: text('siteGssapiHint') }));
  if (gssapiStubInstalled) window.LinSCPCore.hostDifferenceReason = undefined;

  // ---- Shared multi-server monitor --------------------------------------
  // Exercise both the Android in-page shell and the independent desktop
  // window. The renderer itself is covered by TerminalRenderer.test.mjs.
  await window.openServerMonitor();
  await new Promise(resolve => setTimeout(resolve, 80));
  check('monitor opens its shared component', doc.getElementById('serverMonitorModal').classList.contains('open') &&
    doc.querySelectorAll('#serverMonitorScreen .monitor-picker-item').length === 1);
  doc.querySelector('#serverMonitorScreen .monitor-picker-item input').click();
  [...doc.querySelectorAll('#serverMonitorScreen button')].find(b => b.textContent === 'Monitor selected servers').click();
  await new Promise(resolve => setTimeout(resolve, 80)); await new Promise(resolve => setTimeout(resolve, 80));
  check('monitor samples the selected session', calls.some(call => call.path === '/api/monitor/sample' &&
    JSON.parse(call.options.body).tabs.join() === '1'));
  check('monitor renders telemetry', text('serverMonitorScreen').includes('25.0%'));
  check('monitor loads persisted settings and network rates', calls.some(call => call.path === '/api/monitor/settings') &&
    text('serverMonitorScreen').includes('1.00 Mbps') && text('serverMonitorScreen').includes('2.00 Mbps'));
  const monitorCore = window.LinSCPCore;
  window.LinSCPCore = new Proxy(monitorCore, { get(target, key) {
    if (key === 'hostCapabilities') return () => ({ ...target.hostCapabilities({ host: window }), platform: 'android' });
    return Reflect.get(target, key);
  }});
  [...doc.querySelectorAll('#serverMonitorScreen button')].find(b => b.textContent === 'SSH shell').click();
  await new Promise(resolve => setTimeout(resolve, 80));
  check('monitor shell reuses the terminal endpoint', calls.some(call => call.path === '/api/session/terminal' &&
    JSON.parse(call.options.body).tab === 1) && doc.getElementById('terminalModal').classList.contains('open'));
  window.closeTerminal();
  await new Promise(resolve => setTimeout(resolve, 80));
  check('closing the monitor shell resumes monitoring', text('serverMonitorScreen').includes('Sampling selected servers') ||
    text('serverMonitorScreen').includes('servers selected'));
  window.LinSCPCore = monitorCore;
  {
    const internals = window.__TAURI_INTERNALS__;
    const originalInvoke = internals.invoke;
    internals.invoke = async (command, args) => command === 'linscp_open_terminal_window'
      ? { label: 'terminal-monitor' } : originalInvoke(command, args);
    [...doc.querySelectorAll('#serverMonitorScreen button')].find(b => b.textContent === 'SSH shell').click();
    await new Promise(resolve => setTimeout(resolve, 80));
    check('opening a separate monitor shell resumes monitoring without closing the monitor',
      doc.getElementById('serverMonitorModal').classList.contains('open') &&
      [...doc.querySelectorAll('#serverMonitorScreen button')].some(b => b.textContent === 'Pause') &&
      !doc.getElementById('terminalModal').classList.contains('open'));
    const closedBefore = calls.filter(call => call.path === '/api/terminal/close').length;
    internals.invoke = async (command, args) => {
      if (command === 'linscp_open_terminal_window') throw new Error('cannot create monitor window');
      return originalInvoke(command, args);
    };
    [...doc.querySelectorAll('#serverMonitorScreen button')].find(b => b.textContent === 'SSH shell').click();
    await new Promise(resolve => setTimeout(resolve, 80));
    check('a failed monitor shell resumes monitoring, closes its PTY and shows no in-app terminal',
      [...doc.querySelectorAll('#serverMonitorScreen button')].some(b => b.textContent === 'Pause') &&
      !doc.getElementById('terminalModal').classList.contains('open') &&
      calls.filter(call => call.path === '/api/terminal/close').length === closedBefore + 1 &&
      lastLogLine().includes('cannot create monitor window'));
    internals.invoke = originalInvoke;
  }
  window.closeServerMonitor();
  check('closing the monitor keeps the session tab', !doc.getElementById('serverMonitorModal').classList.contains('open') &&
    doc.getElementById('tabStrip').children.length === 1);

  // ---- Embedded remote terminal -----------------------------------------
  /* Android uses an in-page terminal. What the page is answerable for is
   * the transplant: the modal is on screen before the
   * renderer measures its font (a terminal measured inside a display:none box
   * has no cell at all), the frames the model produces are painted, and a
   * backend that refuses to answer ends the session instead of leaving a black
   * box that never changes.
   *
   * The renderer is driven here by a recording stand-in, because a canvas in
   * jsdom draws nothing; the real one is covered by the bundle's own suite. */
  {
    const painted = [];
    let openedVisible = null;
    const frames = [];
    let lastWindow = null;
    window.LinSCPCore.terminalWindow = function (options) {
      /* The real window attaches a keyboard to the canvas when the host asks
       * for one; a stand-in without it would let the page ship a terminal
       * nobody can type into and still pass. */
      let keyboard = null;
      /* Typed text goes to the shell the way the real terminal sends it: a
       * base64 body on `/api/terminal/input`. */
      const send = data => {
        painted.push(data);
        void window.LinSCPTransport.request('POST', '/api/terminal/input', {
          terminal: options.terminal,
          data: window.btoa(unescape(encodeURIComponent(data))),
          cols: 80,
          rows: 24
        });
      };
      if (options.keyboard) {
        const field = doc.createElement('textarea');
        field.setAttribute('aria-label', 'Terminal input');
        field.addEventListener('input', () => {
          const text = field.value;
          field.value = '';
          if (text) send(text);
        });
        options.container.appendChild(field);
        keyboard = { element: field };
      }
      /* The real window exposes the open selection and can copy it from the
       * model; the page's copy bar is driven by both. */
      let selection = null;
      let currentFontSize = typeof options.fontSize === 'number' ? options.fontSize : 11;
      painted.push('initialSize:' + currentFontSize);
      lastWindow = {
        get selection() { return selection; },
        copyAllText: async () => 'all terminal text',
        changeTextSize: delta => {
          currentFontSize = Math.max(8, Math.min(32, currentFontSize + delta));
          painted.push('size:' + delta + '->' + currentFontSize);
          return currentFontSize;
        },
        copySelection: async () => {
          if (!selection) return null;
          selection = null;
          options.onSelection && options.onSelection(false);
          return 'copied text';
        },
        clearSelection: async () => {
          selection = null;
          options.onSelection && options.onSelection(false);
        },
        start: async () => {
          const modal = options.container.closest('.modal-overlay');
          openedVisible = !!modal && modal.classList.contains('open');
          // The session asks the model for a frame, which is where the output
          // is: the bytes of /api/terminal/output are history, not a screen.
          // The page's own transport is the only door to the backend, so the
          // stand-in goes through it exactly as the real session does.
          try {
            const frame = await window.LinSCPTransport.request('GET',
              '/api/terminal/frame?terminal=' + encodeURIComponent(options.terminal), {});
            if (!frame || !frame.success) {
              // An answer that is not a frame is the session ending: the page
              // has to say so, not leave a black box behind.
              options.onEnded && options.onEnded(frame && frame.error ? frame.error : null);
              return true;
            }
            if (frame.frame) {
              frames.push(frame.frame);
              painted.push(frame.frame.cells.map(cell => String.fromCodePoint(...cell.text)).join('').trimEnd());
              if (frame.frame.title) options.onTitle && options.onTitle(frame.frame.title);
            }
            if (frame && frame.alive === false) {
              options.onEnded && options.onEnded(frame.error || null);
            }
          } catch (error) {
            options.onEnded && options.onEnded(String(error));
          }
          return true;
        },
        write: data => send(data),
        // A long press in the real terminal opens a selection; the harness opens
        // one on demand so the page's copy bar can be checked.
        selectAll: () => {
          selection = { start: { row: 0, column: 0 }, end: { row: 0, column: 10 } };
          options.onSelection && options.onSelection(true);
        },
        stop: () => { keyboard = null; },
        /* Closing a terminal closes its shell: the real window sends
         * `/api/terminal/close` and then stops. A stand-in without `close`
         * would let the page leak a remote PTY on every close and still pass,
         * which is exactly what it did. */
        close: async () => {
          keyboard = null;
          await window.LinSCPTransport.request('POST', '/api/terminal/close',
            { terminal: options.terminal });
        },
        paste: () => {},
        handleKey: () => false,
        input: () => keyboard
      };
      return lastWindow;
    };
    /* A frame as the model produces it: the shell's own line on the first row
     * of a 4-column screen, and a title. */
    const frameOf = (text, title) => ({
      columns: 24, lines: 3,
      cells: Array.from({ length: 72 }, (_, index) => ({
        text: index < text.length ? [text.codePointAt(index)] : [32],
        fg: { named: 256, indexed: -1, rgb: null },
        bg: { named: 257, indexed: -1, rgb: null },
        attrs: 0
      })),
      cursor: { column: text.length, line: 0, shape: 'block' },
      display_offset: 0, total_lines: 3, title: title || null,
      modes: { alternate_screen: false, app_cursor: false, bracketed_paste: false, mouse_reporting: false, show_cursor: true }
    });
    responses['/api/terminal/frame'] = {
      success: true, dirty: true, alive: true, error: null,
      frame: frameOf('user@host:~$ ls', 'web-1 — Terminal') };

    /* The bundle's exports are getter-only, so the platform cannot be
     * stubbed by assignment; wrapping the whole namespace in a Proxy is the
     * only door from the outside, and it is scoped to this block. */
    const realCore = window.LinSCPCore;
    const asPlatform = platform => new Proxy(realCore, {
      get(target, key) {
        if (key === 'hostCapabilities') {
          return () => Object.assign(
            target.hostCapabilities({ host: window }), { platform });
        }
        const value = Reflect.get(target, key);
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });
    // X2Go uses a desktop terminal window; fake the OS window bridge while
    // testing that installation scripts reach the selected remote shell.
    const internals = window.__TAURI_INTERNALS__;
    const originalInvoke = internals.invoke;
    internals.invoke = async (command, args) => command === 'linscp_open_terminal_window'
      ? { label: 'terminal-installer' } : originalInvoke(command, args);
    // A missing X2Go server is offered for installation on the selected
    // authenticated host, never run until the user presses Install.
    responses['/api/desktop/check'] = { success: true, available: false, checked: true,
      via_ssh: true, can_install: true, desktop_checked: true, desktop: 'MATE',
      reason: 'x2goserver not found on 127.0.0.1',
      install_script: '#!/bin/bash\necho install-x2go\n',
      xfce_install_script: '#!/bin/bash\necho install-xfce\n' };
    responses['/api/terminal/input'] = { success: true };
    const desktopTestStatus = responses['/api/status'];
    responses['/api/status'] = { ...desktopTestStatus, tabs: [{
      id: 1, name: 'X2Go server', connected: true,
      session: { protocol: 'x2go', host: '127.0.0.1', port: 2222, username: 'user' },
      local_dir: '/tmp/slowlocal', remote_dir: '/'
    }], active_tab: 1 };
    await window.refreshStatus();
    window.openRemoteDesktop(1);
    await new Promise(resolve => setTimeout(resolve, 50));
    const directCheck = calls.filter(call => call.path === '/api/desktop/check').pop();
    const directBody = directCheck && JSON.parse(directCheck.options.body);
    check('an X2Go tab automatically checks its actual SSH port',
      directBody && directBody.kind === 'x2go' && directBody.tab === 1 && directBody.port === 2222 &&
      !doc.getElementById('remoteDesktopInstallBtn').disabled);
    window.closeModal('remoteDesktopModal');
    responses['/api/status'] = desktopTestStatus;
    await window.refreshStatus();
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    check('missing X2Go offers an explicit installation on the selected server',
      doc.getElementById('remoteDesktopPrompt').style.display === 'block' &&
      !doc.getElementById('remoteDesktopInstallBtn').disabled &&
      doc.getElementById('remoteDesktopXfceChoice').hidden);
    check('the X2Go installer is expanded and shown before installation',
      doc.getElementById('remoteDesktopScriptDetails').open &&
      doc.getElementById('remoteDesktopScript').textContent === responses['/api/desktop/check'].install_script);
    const inputBeforeInstall = calls.filter(call => call.path === '/api/terminal/input').length;
    doc.getElementById('remoteDesktopScriptDetails').open = false;
    await window.installRemoteDesktop();
    check('a collapsed installer preview is reopened without starting the installer',
      doc.getElementById('remoteDesktopScriptDetails').open &&
      calls.filter(call => call.path === '/api/terminal/input').length === inputBeforeInstall);
    await window.installRemoteDesktop();
    const installInput = calls.filter(call => call.path === '/api/terminal/input').pop();
    const installBody = installInput && JSON.parse(installInput.options.body);
    const installCommand = installBody && Buffer.from(installBody.data, 'base64').toString();
    check('X2Go install opens a terminal and sends the reviewed script after approval',
      calls.filter(call => call.path === '/api/terminal/input').length === inputBeforeInstall + 1 &&
      installCommand && installCommand.includes('base64 -d | bash') &&
      Buffer.from(installCommand.match(/'([^']+)'/)[1], 'base64').toString().includes('install-x2go'));
    check('an existing MATE desktop does not install XFCE',
      installCommand && !installCommand.includes(' && ') &&
      doc.getElementById('remoteDesktopXfceChoice').hidden);
    window.closeTerminal();
    // Neither X2Go nor a known desktop: the extra XFCE install is opt-in.
    responses['/api/desktop/check'].desktop = null;
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    check('no detected desktop offers XFCE unchecked',
      !doc.getElementById('remoteDesktopXfceChoice').hidden &&
      !doc.getElementById('remoteDesktopXfce').checked &&
      !text('remoteDesktopScript').includes('install-xfce'));
    await window.installRemoteDesktop();
    let lastInput = calls.filter(call => call.path === '/api/terminal/input').pop();
    let command = Buffer.from(JSON.parse(lastInput.options.body).data, 'base64').toString();
    check('leaving XFCE unchecked installs only X2Go', !command.includes(' && '));
    window.closeTerminal();
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    doc.getElementById('remoteDesktopXfce').checked = true;
    window.updateRemoteDesktopScript();
    check('opting in includes the XFCE installer in the expanded preview',
      doc.getElementById('remoteDesktopScriptDetails').open &&
      doc.getElementById('remoteDesktopScript').textContent === responses['/api/desktop/check'].install_script + '\n\n' + responses['/api/desktop/check'].xfce_install_script);
    await window.installRemoteDesktop();
    lastInput = calls.filter(call => call.path === '/api/terminal/input').pop();
    command = Buffer.from(JSON.parse(lastInput.options.body).data, 'base64').toString();
    let scripts = Array.from(command.matchAll(/'([^']+)'/g), match => Buffer.from(match[1], 'base64').toString());
    check('XFCE is installed only after explicit opt-in',
      scripts.length === 2 && scripts[0].includes('install-x2go') && scripts[1].includes('install-xfce'));
    window.closeTerminal();
    // If the server is already installed, offer XFCE by itself.
    responses['/api/desktop/check'].available = true;
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    check('an installed server without a known desktop offers only XFCE',
      doc.getElementById('remoteDesktopInstallBtn').textContent === 'Install XFCE' &&
      text('remoteDesktopScript').includes('install-xfce') && !text('remoteDesktopScript').includes('install-x2go'));
    await window.installRemoteDesktop();
    lastInput = calls.filter(call => call.path === '/api/terminal/input').pop();
    command = Buffer.from(JSON.parse(lastInput.options.body).data, 'base64').toString();
    scripts = Array.from(command.matchAll(/'([^']+)'/g), match => Buffer.from(match[1], 'base64').toString());
    check('the desktop-only action does not reinstall X2Go',
      scripts.length === 1 && scripts[0].includes('install-xfce'));
    window.closeTerminal();
    // A failed environment probe is unknown, not an invitation to install.
    responses['/api/desktop/check'].desktop_checked = false;
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    check('an inconclusive desktop check does not offer XFCE installation',
      doc.getElementById('remoteDesktopInstallBtn').disabled && doc.getElementById('remoteDesktopXfceChoice').hidden);
    responses['/api/desktop/check'].available = false;
    responses['/api/desktop/check'].desktop_checked = true;
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    doc.getElementById('remoteDesktopHost').value = 'other.example';
    window.remoteDesktopSelectionChanged();
    check('changing the target invalidates the previous install approval',
      doc.getElementById('remoteDesktopInstallBtn').disabled);
    const beforeStaleInstall = calls.filter(call => call.path === '/api/terminal/input').length;
    await window.installRemoteDesktop();
    check('a stale X2Go check cannot run an installer',
      calls.filter(call => call.path === '/api/terminal/input').length === beforeStaleInstall);
    window.closeModal('remoteDesktopModal');
    // Other remote desktop installers also show their script before use.
    const savedCheck = responses['/api/desktop/check'];
    responses['/api/desktop/check'] = { success: true, available: false, checked: true,
      via_ssh: true, can_install: true, reason: 'xrdp missing', install_script: '#!/bin/bash\necho install-xrdp\n' };
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'rdp';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    check('other desktop installers are expanded and visible before installation',
      doc.getElementById('remoteDesktopScriptDetails').open &&
      doc.getElementById('remoteDesktopScript').textContent === responses['/api/desktop/check'].install_script &&
      !doc.getElementById('remoteDesktopInstallBtn').disabled);
    responses['/api/desktop/check'].install_script = '';
    await window.checkRemoteDesktop();
    check('installation is unavailable when the script cannot be shown',
      doc.getElementById('remoteDesktopInstallBtn').disabled && !text('remoteDesktopScript'));
    window.closeModal('remoteDesktopModal');
    responses['/api/desktop/check'] = savedCheck;
    // A detected desktop can now open the experimental built-in viewer.
    responses['/api/desktop/check'].available = true;
    responses['/api/desktop/check'].desktop = 'MATE';
    responses['/api/x2go/open'] = { success: true, generation: '1' };
    responses['/api/x2go/input'] = { success: true };
    responses['/api/x2go/close'] = { success: true };
    const pngHeader = Buffer.from([137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,2,0,0,0,1]).toString('base64');
    responses['/api/x2go/poll'] = { success: true, message: { type: 'frame', frame: {
      width: 2, height: 1, x: -1, y: -1, cacheId: 0, windowId: 0,
      regions: [{ sourceId: 0, sourceX: 0, sourceY: 0, x: 0, y: 0, width: 2, height: 1, data: pngHeader }] } } };
    const savedContext = window.HTMLCanvasElement.prototype.getContext;
    const savedBitmap = window.createImageBitmap;
    window.HTMLCanvasElement.prototype.getContext = () => ({
      createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }),
      putImageData() {}, drawImage() {},
      getImageData: (_x, _y, w, h) => ({ data: new Uint8ClampedArray(w * h * 4).fill(42) })
    });
    window.createImageBitmap = async () => ({ width: 2, height: 1, close() {} });
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    check('KDrive detection describes the viewer as experimental',
      text('remoteDesktopStatus').includes('experimental'));
    await window.launchRemoteDesktop();
    await new Promise(resolve => setTimeout(resolve, 60));
    const openedX2Go = calls.filter(call => call.path === '/api/x2go/open').pop();
    const openedX2GoBody = openedX2Go && JSON.parse(openedX2Go.options.body);
    check('X2Go launch opens the tab-bound experimental viewer',
      openedX2GoBody && openedX2GoBody.desktop === 'MATE' && openedX2GoBody.tab === 1 &&
      doc.getElementById('x2goViewerModal').classList.contains('open') &&
      !!doc.querySelector('#x2goSurface canvas'));
    check('the viewer polls and paints the backend main frame',
      calls.some(call => call.path === '/api/x2go/poll') && text('x2goViewerStatus') === 'X2Go desktop');
    responses['/api/x2go/poll'] = { success: true, message: null };
    const xcanvas = doc.querySelector('#x2goSurface canvas');
    if (xcanvas) {
      xcanvas.focus();
      xcanvas.dispatchEvent(new window.KeyboardEvent('keydown', { bubbles: true, cancelable: true, code: 'KeyA', key: 'a' }));
      xcanvas.dispatchEvent(new window.KeyboardEvent('keyup', { bubbles: true, cancelable: true, code: 'KeyA', key: 'a' }));
    }
    await new Promise(resolve => setTimeout(resolve, 40));
    check('viewer keyboard input reaches the tab-bound bridge',
      calls.filter(call => call.path === '/api/x2go/input').length >= 2 &&
      JSON.parse(calls.filter(call => call.path === '/api/x2go/input').pop().options.body).generation === '1');
    if (xcanvas) xcanvas.dispatchEvent(new window.KeyboardEvent('keydown', { bubbles: true, cancelable: true, code: 'Escape', key: 'Escape' }));
    check('Escape in the focused desktop is sent to the server instead of closing it',
      doc.getElementById('x2goViewerModal').classList.contains('open'));
    window.closeX2GoViewer();
    await new Promise(resolve => setTimeout(resolve, 20));
    check('closing the viewer requests agent cleanup', calls.some(call => call.path === '/api/x2go/close' && JSON.parse(call.options.body).generation === '1'));
    // If the user closes while startup is still in flight, a later successful
    // answer must not leak the newly started remote agent.
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    const realX2GoRequest = window.LinSCPTransport.request;
    let finishX2GoOpen;
    window.LinSCPTransport.request = (method, path, body) => path === '/api/x2go/open'
      ? new Promise(resolve => { finishX2GoOpen = resolve; }) : realX2GoRequest.call(window.LinSCPTransport, method, path, body);
    const closesBeforeCancel = calls.filter(call => call.path === '/api/x2go/close').length;
    const pendingX2Go = window.launchRemoteDesktop();
    await new Promise(resolve => setTimeout(resolve, 20));
    window.closeX2GoViewer();
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 50));
    const firstFinishX2GoOpen = finishX2GoOpen;
    await window.launchRemoteDesktop();
    check('a new viewer cannot replace one whose startup is being cancelled',
      finishX2GoOpen === firstFinishX2GoOpen && !doc.getElementById('x2goViewerModal').classList.contains('open'));
    window.closeModal('remoteDesktopModal');
    if (finishX2GoOpen) finishX2GoOpen({success: true, generation: '2'});
    await pendingX2Go;
    await new Promise(resolve => setTimeout(resolve, 20));
    check('cancelling startup closes a session that opens afterwards',
      !!finishX2GoOpen && calls.filter(call => call.path === '/api/x2go/close').length === closesBeforeCancel + 1 &&
      JSON.parse(calls.filter(call => call.path === '/api/x2go/close').pop().options.body).generation === '2' &&
      !doc.getElementById('x2goViewerModal').classList.contains('open'));
    window.LinSCPTransport.request = realX2GoRequest;
    window.HTMLCanvasElement.prototype.getContext = savedContext;
    window.createImageBitmap = savedBitmap;
    delete responses['/api/x2go/open']; delete responses['/api/x2go/input'];
    delete responses['/api/x2go/poll']; delete responses['/api/x2go/close'];

    // Mosh option in Site Manager and inspectable Mosh server installer modal.
    window.fillSiteForm({
      name: 'Mosh site', protocol: 'sftp', host: 'mosh.example.test', port: 22,
      username: 'ops', mosh: true, mosh_port: '60010:60020'
    });
    const moshForm = window.currentSiteForm();
    check('site form round-trips Mosh option and UDP port range',
      moshForm.mosh === true && moshForm.mosh_port === '60010:60020' &&
      doc.getElementById('siteMoshSettings').open === true);
    window.newSite();
    check('new site defaults Mosh off with collapsed settings',
      window.currentSiteForm().mosh === false &&
      window.currentSiteForm().mosh_port === '' &&
      doc.getElementById('siteMoshSettings').open === false);

    {
      const savedTermResp = responses['/api/session/terminal'];
      const moshWindows = [];
      internals.invoke = async (command, args) => {
        if (command === 'linscp_open_terminal_window') {
          moshWindows.push(args);
          return { label: 'terminal-mosh-test' };
        }
        return originalInvoke(command, args);
      };
      const fakeMoshScript = '#!/bin/bash\necho install-mosh-server\n';
      const realMoshTransport = window.LinSCPTransport.request;
      window.LinSCPTransport.request = async (method, path, body) => {
        if (path === '/api/session/terminal' && body && body.mosh && !body.force_ssh && !window.__moshInstalledTest) {
          return {
            success: false,
            mosh_missing: true,
            available: false,
            checked: true,
            via_ssh: true,
            can_install: true,
            host: '127.0.0.1',
            port: 22,
            mosh_port: '60010:60020',
            reason: 'Mosh server (mosh-server) was not found on 127.0.0.1.',
            install_script: fakeMoshScript,
          };
        }
        if (path === '/api/session/terminal' && body && body.mosh && window.__moshInstalledTest) {
          calls.push({ path, url: path, options: { method, body: JSON.stringify(body) } });
          return { success: true, terminal: 'term-mosh-1', transport: 'mosh', udp_port: 60011, cols: 100, rows: 30 };
        }
        return realMoshTransport.call(window.LinSCPTransport, method, path, body);
      };
      window.__moshInstalledTest = false;
      const moshMissingOpened = await window.openTerminal(null, false, null, { mosh: true });
      check('missing mosh-server opens the inspectable Mosh setup modal instead of a broken shell',
        moshMissingOpened === false &&
        doc.getElementById('moshSetupModal').classList.contains('open') &&
        doc.getElementById('moshSetupPrompt').style.display === 'block' &&
        !doc.getElementById('moshInstallBtn').disabled &&
        doc.getElementById('moshOpenBtn').disabled &&
        doc.getElementById('moshScriptDetails').open &&
        doc.getElementById('moshScript').textContent === fakeMoshScript);

      const moshInputsBefore = calls.filter(call => call.path === '/api/terminal/input').length;
      doc.getElementById('moshScriptDetails').open = false;
      await window.installMoshOnServer();
      check('a collapsed Mosh installer preview is reopened without executing the script',
        doc.getElementById('moshScriptDetails').open &&
        calls.filter(call => call.path === '/api/terminal/input').length === moshInputsBefore);

      await window.installMoshOnServer();
      const moshTermCalls = calls.filter(call => call.path === '/api/session/terminal');
      const lastTermOpenBody = JSON.parse(moshTermCalls.at(-1).options.body);
      const lastMoshInput = JSON.parse(calls.filter(call => call.path === '/api/terminal/input').at(-1).options.body);
      const decodedMoshCmd = Buffer.from(lastMoshInput.data, 'base64').toString();
      check('approving Mosh install opens a standard SSH terminal (force_ssh) and runs the reviewed script',
        lastTermOpenBody.force_ssh === true &&
        decodedMoshCmd.includes('base64 -d | bash') &&
        Buffer.from(decodedMoshCmd.match(/'([^']+)'/)[1], 'base64').toString().includes('install-mosh-server'));

      // Re-open Mosh setup, verify Check enables Open Mosh terminal, and launch Mosh window.
      await window.openTerminal(null, false, null, { mosh: true });
      responses['/api/mosh/check'] = {
        success: true, available: true, checked: true, via_ssh: true,
        host: '127.0.0.1', port: 22, mosh_port: '60010:60020',
        can_install: true, install_script: fakeMoshScript,
      };
      await window.checkMoshServer();
      check('checking Mosh after installation enables Open Mosh terminal',
        !doc.getElementById('moshOpenBtn').disabled &&
        doc.getElementById('moshSetupPrompt').style.display === 'none');
      window.__moshInstalledTest = true;
      const retriedMosh = await window.retryOpenMoshTerminal();
      check('retrying Mosh opens a Mosh-titled terminal window',
        retriedMosh === true &&
        moshWindows.some(w => w.terminal === 'term-mosh-1' && String(w.title).includes('Mosh')));

      // Fallback button opens standard SSH terminal with force_ssh: true.
      window.__moshInstalledTest = false;
      await window.openTerminal(null, false, null, { mosh: true });
      const fbOpened = await window.fallbackMoshToSshTerminal();
      const fbBody = JSON.parse(calls.filter(call => call.path === '/api/session/terminal').at(-1).options.body);
      check('Open SSH terminal instead bypasses Mosh via force_ssh',
        fbOpened === true && fbBody.force_ssh === true);

      delete window.__moshInstalledTest;
      delete responses['/api/mosh/check'];
      window.LinSCPTransport.request = realMoshTransport;
      responses['/api/session/terminal'] = savedTermResp;
    }

    internals.invoke = originalInvoke;
    /* The Android path starts here: a touch host, no OS windows. */
    window.LinSCPCore = asPlatform('android');

    await window.openTerminal();
    await new Promise(resolve => setTimeout(resolve, 120));
    check('the terminal is only opened once its modal is on screen',
      openedVisible === true, String(openedVisible));
    check('the shell output reaches the terminal',
      painted.join('').indexOf('user@host:~$ ls') >= 0, JSON.stringify(painted.slice(0, 3)));
    check('the terminal asks for the frame of the id the backend answered with',
      calls.some(call => call.path === '/api/terminal/frame' && call.url.indexOf('terminal=77') >= 0),
      JSON.stringify(calls.filter(call => call.path === '/api/terminal/frame').map(call => call.url)));
    /* The Android path has no OS window, so the terminal is the in-page one -
     * and a canvas cannot raise a soft keyboard. Without the attachment the
     * pane is a picture of a shell nobody can type into, which is exactly what
     * it was. */
    const terminalInput = doc.querySelector('#terminalScreen textarea');
    check('the in-page terminal carries an element that can raise a keyboard',
      !!terminalInput, String(!!terminalInput));
    if (terminalInput) {
      terminalInput.value = 'l';
      terminalInput.dispatchEvent(new window.Event('input'));
      await new Promise(resolve => setTimeout(resolve, 60));
      const typed = calls.filter(call => call.path === '/api/terminal/input')
        .map(call => JSON.parse(call.options.body));
      check('a character typed on a phone reaches the shell',
        typed.some(body => window.atob(body.data) === 'l'),
        JSON.stringify(typed.map(body => window.atob(body.data))));
      check('the typed character does not stay in the field',
        terminalInput.value === '', JSON.stringify(terminalInput.value));
    }

    /* A long press selects text, and a phone has no Ctrl+Shift+C: the bar is
     * the only way that selection becomes usable in another app. */
    const selectionBar = doc.getElementById('terminalSelectionBar');
    check('the copy bar is out of the way until something is selected',
      !!selectionBar && selectionBar.hidden === true, String(selectionBar && selectionBar.hidden));
    check('terminal footer exposes copy all and help without a copy selected button', !!doc.querySelector('#terminalModal button[onclick="copyTerminalAllText()"]') && !!doc.querySelector('#terminalModal button[onclick="showTerminalCopyHelp()"]') && !doc.getElementById('terminalCopySelected'));
    const shrink = doc.querySelector('#terminalModal button[aria-label="Decrease terminal text size"]');
    const grow = doc.querySelector('#terminalModal button[aria-label="Increase terminal text size"]');
    const terminalModalEl = doc.getElementById('terminalModal');
    const terminalModalBox = terminalModalEl && terminalModalEl.querySelector('.modal-box');
    check('Android terminal modal spans full display width without inline max-width or horizontal padding',
      !!terminalModalEl && terminalModalEl.classList.contains('terminal-fullscreen') &&
      !!terminalModalBox && !terminalModalBox.getAttribute('style') &&
      themeCss.includes('#terminalModal.terminal-fullscreen') &&
      themeCss.includes('padding: env(safe-area-inset-top, 0) 0 0 0;'));
    check('embedded terminal exposes both text size buttons', !!shrink && !!grow);
    check('embedded terminal opens at 11px default font size', painted.includes('initialSize:11'), JSON.stringify(painted));
    shrink.click(); grow.click(); grow.click();
    check('embedded terminal size buttons adjust by a single step and persist font size',
      painted.includes('size:-1->10') && painted.includes('size:1->11') && painted.includes('size:1->12') &&
      window.localStorage.getItem('lscp-terminal-font-size') === '12',
      JSON.stringify(painted) + ' | saved=' + window.localStorage.getItem('lscp-terminal-font-size'));
    await window.copyTerminalAllText();
    lastWindow.selectAll();
    check('selecting text offers to copy it',
      selectionBar.hidden === false && !!selectionBar.querySelector('button[onclick="copyTerminalSelection()"]'),
      String(selectionBar.hidden));
    await window.copyTerminalSelection();
    check('copying from the terminal selection bar closes the bar',
      selectionBar.hidden === true, String(selectionBar.hidden));
    lastWindow.selectAll();
    await window.clearTerminalSelection();
    await new Promise(resolve => setTimeout(resolve, 20));
    check('clearing the selection puts the bar away',
      selectionBar.hidden === true, String(selectionBar.hidden));

    check('the screen title follows the model',
      doc.getElementById('terminalModal').querySelector('.modal-header span').textContent.includes('web-1'),
      doc.getElementById('terminalModal').querySelector('.modal-header span').textContent);
    window.closeTerminal();
    await new Promise(resolve => setTimeout(resolve, 60));

    /* A backend that refuses the frame. The page has to say so: a silent
     * retry loop is indistinguishable from a shell that has not woken up. */
    responses['/api/terminal/frame'] = {
      success: false, error: 'This terminal is no longer open.' };
    await window.openTerminal();
    check('reopening embedded terminal restores the remembered font size',
      painted.includes('initialSize:12'), JSON.stringify(painted));
    await new Promise(resolve => setTimeout(resolve, 500));
    check('a terminal the backend refuses is reported, not left black',
      lastLogLine().indexOf('The terminal session ended.') >= 0 ||
      !doc.getElementById('terminalModal').classList.contains('open'),
      lastLogLine() + ' | open=' + doc.getElementById('terminalModal').classList.contains('open'));
    window.closeTerminal();
    await new Promise(resolve => setTimeout(resolve, 60));

    /* The other silence: the channel is open and the shell never starts,
     * because the server refused the pty or the shell. It is only
     * distinguishable from a slow prompt by the reason the server gave, so
     * the page has to show that reason and not just "the session ended". */
    responses['/api/terminal/frame'] = {
      success: true, dirty: true, alive: false,
      error: 'The server refused to start an interactive shell on this connection.',
      frame: frameOf('') };
    await window.openTerminal();
    await new Promise(resolve => setTimeout(resolve, 200));
    check('a shell the server refused names the reason, not just the ending',
      lastLogLine().indexOf('refused to start an interactive shell') >= 0, lastLogLine());
    window.closeTerminal();
    await new Promise(resolve => setTimeout(resolve, 60));

    /* The shell and the tab's session run over one connection, so a server
     * that was told to shut down ends both. The backend says so while
     * answering the frame that reported the ending, and the page has to ask
     * for the status again at that moment: the badge is otherwise drawn from a
     * poll that runs every fifteen seconds, and a tab still saying
     * "connected" beside a terminal that says the session ended is the thing
     * the person looking at both windows sees first. */
    {
      responses['/api/terminal/frame'] = {
        success: true, dirty: true, alive: false,
        error: 'The connection to the server ended.', frame: frameOf('') };
      const statuses = () => calls.filter(call => call.path === '/api/status').length;
      const before = statuses();
      await window.openTerminal();
      await new Promise(resolve => setTimeout(resolve, 200));
      check('an ended shell asks what became of its tab',
        statuses() > before, 'status calls before=' + before + ' after=' + statuses());
      window.closeTerminal();
      await new Promise(resolve => setTimeout(resolve, 60));
      responses['/api/terminal/frame'] = {
        success: true, dirty: true, alive: true, error: null,
        frame: frameOf('user@host:~$ ', 'web-1 — Terminal') };
    }

    /* Closing a terminal closes the shell, not just the picture of it.
     *
     * The window is the only thing that knows the session exists, and the
     * remote PTY lives on the server until something tells it to stop. Every
     * close used to leave that shell running on the far side, holding its
     * channel and a process, for as long as the app was open. */
    {
      // The checks above deliberately left a refusing frame in place; a
      // terminal that cannot paint would fail for the wrong reason here.
      responses['/api/terminal/frame'] = {
        success: true, dirty: true, alive: true, error: null,
        frame: frameOf('user@host:~$ ', 'web-1 — Terminal') };
      const closings = calls.filter(call => call.path === '/api/terminal/close');
      const before = closings.length;
      await window.openTerminal();
      await new Promise(resolve => setTimeout(resolve, 120));
      window.closeTerminal();
      await new Promise(resolve => setTimeout(resolve, 120));
      const after = calls.filter(call => call.path === '/api/terminal/close').length;
      check('closing a terminal ends the shell it was showing',
        after > before, 'close calls before=' + before + ' after=' + after);
    }

    /* The Terminal tab on a phone is a button, not a panel.
     *
     * There is no Terminal *pane* in the page - the modal is the terminal - so
     * tapping the tab has to open it. Acting only on a change of pane made the
     * tab work once: closing the modal leaves the tab selected, so the next tap
     * changed nothing and opened nothing. That is the "I can't open the
     * terminal" report, and it is what this check is for. */
    {
      const navTerminal = doc.querySelector('#mobileBottomNav [data-pane="terminal"]');
      check('the touch shell offers a Terminal tab', !!navTerminal,
        String(!!navTerminal));
      if (navTerminal) {
        // Leave the shell on another pane, open the terminal, close it, and tap
        // the very same tab again while it is still the selected pane.
        doc.querySelector('#mobileBottomNav [data-pane="local"]').click();
        await new Promise(resolve => setTimeout(resolve, 40));
        navTerminal.click();
        await new Promise(resolve => setTimeout(resolve, 200));
        const openedByTab = doc.getElementById('terminalModal').classList.contains('open');
        window.closeTerminal();
        await new Promise(resolve => setTimeout(resolve, 120));
        const closedByButton = !doc.getElementById('terminalModal').classList.contains('open');
        navTerminal.click();
        await new Promise(resolve => setTimeout(resolve, 200));
        check('the Terminal tab opens the terminal', openedByTab, 'open=' + openedByTab);
        check('closing it leaves the tab selected so it can be tapped again', closedByButton,
          'modal open=' + doc.getElementById('terminalModal').classList.contains('open'));
        check('a second tap on the already-selected Terminal tab opens it again',
          doc.getElementById('terminalModal').classList.contains('open'),
          'pane=' + (doc.getElementById('appShell') || doc.body).dataset.mobilePane +
          ' open=' + doc.getElementById('terminalModal').classList.contains('open'));
        window.closeTerminal();
        await new Promise(resolve => setTimeout(resolve, 120));
      }
    }

    /* Closing a terminal while a selection is open must not leave the next one
     * without its keys.
     *
     * The Esc/Ctrl/arrow row is hidden while a selection is open, and the code
     * that hid it only ran when a terminal existed. Closing mid-selection
     * therefore skipped the update and left the attribute set, so the row was
     * still hidden the next time a terminal opened - and a phone has no other
     * source for Esc, Ctrl or the cursor keys.
     */
    {
      const keysRow = doc.getElementById('terminalExtraKeys');
      const navLocal = doc.querySelector('#mobileBottomNav [data-pane="local"]');
      const navTerminal2 = doc.querySelector('#mobileBottomNav [data-pane="terminal"]');
      if (navLocal) navLocal.click();
      await new Promise(resolve => setTimeout(resolve, 40));
      navTerminal2.click();
      await new Promise(resolve => setTimeout(resolve, 200));
      check('the extra-keys row is on screen for an open terminal',
        keysRow.hidden === false, String(keysRow.hidden));
      // Open a selection the way the page sees one, then close under it.
      lastWindow.selectAll();
      await new Promise(resolve => setTimeout(resolve, 40));
      check('a selection hides the key row it would type through',
        keysRow.hidden === true, String(keysRow.hidden));
      window.closeTerminal();
      await new Promise(resolve => setTimeout(resolve, 120));
      navTerminal2.click();
      await new Promise(resolve => setTimeout(resolve, 250));
      check('the next terminal still has its keys after a close mid-selection',
        keysRow.hidden === false && doc.getElementById('terminalModal').classList.contains('open'),
        'hidden=' + keysRow.hidden +
        ' open=' + doc.getElementById('terminalModal').classList.contains('open'));
      window.closeTerminal();
      await new Promise(resolve => setTimeout(resolve, 120));
    }

    // Android mobile terminal survival across app switches + WebView reload reattachment.
    {
      const savedCoreTermBg = window.LinSCPCore;
      const savedTransfersBg = responses['/api/transfers'];
      const savedTermListBg = responses['/api/terminal/list'];
      let termFgStarts = [];
      let termFgStops = 0;

      responses['/api/transfers'] = { transfers: [], paused: false };
      await window.refreshQueue();
      const FakeForegroundBridge = function () {
        this.available = true;
        this.isRunning = false;
        this.start = async (title, ongoing) => {
          termFgStarts.push([title, ongoing]);
          this.isRunning = true;
          return true;
        };
        this.update = async () => true;
        this.stop = async () => {
          termFgStops += 1;
          this.isRunning = false;
          return true;
        };
      };
      window.LinSCPCore = new Proxy(realCore, {
        get(target, key) {
          if (key === 'hostCapabilities') {
            return () => Object.assign(target.hostCapabilities({ host: window }), {
              platform: 'android',
              foregroundTransfers: true,
              separateWindows: false
            });
          }
          if (key === 'ForegroundTransferBridge') {
            return FakeForegroundBridge;
          }
          const value = Reflect.get(target, key);
          return typeof value === 'function' ? value.bind(target) : value;
        }
      });

      await window.openTerminal();
      await new Promise(resolve => setTimeout(resolve, 120));
      check('opening an Android terminal starts the foreground service keepalive immediately',
        termFgStarts.length >= 1 && termFgStarts[0][1] === 1 && termFgStops === 0,
        JSON.stringify({ starts: termFgStarts, stops: termFgStops }));

      await window.refreshQueue();
      check('empty transfer queue poll keeps Android foreground service running while terminal is open',
        termFgStops === 0 && doc.getElementById('terminalModal').classList.contains('open'),
        'stops=' + termFgStops);

      let fakeVisibility = 'hidden';
      Object.defineProperty(doc, 'visibilityState', {
        configurable: true,
        get: () => fakeVisibility
      });
      doc.dispatchEvent(new window.Event('visibilitychange'));
      await new Promise(resolve => setTimeout(resolve, 100));
      fakeVisibility = 'visible';
      doc.dispatchEvent(new window.Event('visibilitychange'));
      await new Promise(resolve => setTimeout(resolve, 80));
      check('Android terminal modal stays open and alive across app-switch visibility transitions',
        doc.getElementById('terminalModal').classList.contains('open') && termFgStops === 0,
        'open=' + doc.getElementById('terminalModal').classList.contains('open') + ' stops=' + termFgStops);

      window.closeTerminal();
      await new Promise(resolve => setTimeout(resolve, 80));
      check('closing the Android terminal stops the foreground service when no transfers are active',
        termFgStops === 1 && !doc.getElementById('terminalModal').classList.contains('open'),
        'stops=' + termFgStops);

      termFgStarts = [];
      termFgStops = 0;
      responses['/api/terminal/list'] = {
        success: true,
        terminals: [{ terminal: 'term-surviving-42', tab: 1, transport: 'mosh', cols: 80, rows: 24, alive: true, title: 'mosh@prod' }]
      };
      const reattached = await window.restoreOpenInPageTerminal();
      await new Promise(resolve => setTimeout(resolve, 100));
      check('restoreOpenInPageTerminal reattaches a surviving backend terminal and restarts foreground keepalive',
        reattached === true &&
        doc.getElementById('terminalModal').classList.contains('open') &&
        termFgStarts.length >= 1,
        JSON.stringify({ reattached, starts: termFgStarts }));
      responses['/api/terminal/list'] = { success: true, terminals: [] };
      window.closeTerminal();
      await new Promise(resolve => setTimeout(resolve, 80));

      delete doc.visibilityState;
      window.LinSCPCore = savedCoreTermBg;
      responses['/api/transfers'] = savedTransfersBg;
      if (savedTermListBg === undefined) delete responses['/api/terminal/list'];
      else responses['/api/terminal/list'] = savedTermListBg;
    }

    window.LinSCPCore = realCore;
    delete window.LinSCPCore.terminalWindow;
  }

  /* Transfer default resume alignment, S3 object versions, WebDAV locks/properties,
   * X2Go session resume/suspend/terminate, and Android tunneled desktop launch. */
  {
    const savedPrefDoc = responses['/api/preferences'].preferences;
    responses['/api/preferences'].preferences = Object.assign({}, savedPrefDoc, { resume: false });
    await window.resetTransferSettings();
    check('resetting transfer settings defaults resume to false',
      doc.getElementById('transferResume').checked === false &&
      window.transferOptions().resume === false);
    window.closeModal('transferModal');
    responses['/api/preferences'].preferences = savedPrefDoc;
    await window.loadTransferSettings();

    responses['/api/s3/versions'] = {
      success: true,
      versions: [
        { key: '/Remote/report.csv', version_id: 'ver-2', is_latest: true, is_delete_marker: false, size: 128, mtime: 1700000100 },
        { key: '/Remote/report.csv', version_id: 'ver-1', is_latest: false, is_delete_marker: false, size: 64, mtime: 1700000000 }
      ]
    };
    responses['/api/s3/version-download'] = { success: true, task_id: 99 };
    responses['/api/s3/version-delete'] = { success: true };
    doc.getElementById('s3VersionsName').value = 'report.csv';
    await window.openS3Versions();
    check('S3 object versions modal lists returned versions',
      doc.getElementById('s3VersionsModal').classList.contains('open') &&
      doc.querySelectorAll('#s3VersionsList tr').length === 2 &&
      text('s3VersionsList').includes('ver-2'));
    await window.downloadS3Version('report.csv', 'ver-1');
    const s3DlCall = calls.filter(call => call.path === '/api/s3/version-download').pop();
    check('S3 version download queues the selected version_id',
      !!s3DlCall && JSON.parse(s3DlCall.options.body).version_id === 'ver-1');
    check('S3 version resume is opt-in by default', !doc.getElementById('s3VersionResume').checked && JSON.parse(s3DlCall.options.body).resume === false);
    doc.getElementById('s3VersionResume').checked = true;
    await window.downloadS3Version('report.csv', 'ver-1');
    const resumedVersion = JSON.parse(calls.filter(call => call.path === '/api/s3/version-download').pop().options.body);
    check('S3 version resume sends the selected version and explicit flag', resumedVersion.resume === true && resumedVersion.version_id === 'ver-1');
    await window.openS3Versions();
    check('S3 version resume approval is not persisted across dialogs', !doc.getElementById('s3VersionResume').checked);
    await window.deleteS3Version('report.csv', 'ver-1');
    const s3DelCall = calls.filter(call => call.path === '/api/s3/version-delete').pop();
    check('S3 version delete posts the selected version_id',
      !!s3DelCall && JSON.parse(s3DelCall.options.body).version_id === 'ver-1');
    window.closeModal('s3VersionsModal');
    delete responses['/api/s3/versions'];
    delete responses['/api/s3/version-download'];
    delete responses['/api/s3/version-delete'];

    responses['/api/dav/lock'] = { success: true, path: '/Remote/report.csv', token: 'opaquelocktoken:test-123' };
    responses['/api/dav/unlock'] = { success: true, path: '/Remote/report.csv' };
    responses['/api/dav/property'] = { success: true, path: '/Remote/report.csv', property: 'tag', value: 'approved' };
    doc.getElementById('davResourceName').value = 'report.csv';
    window.openDavTools();
    await window.lockDavResource();
    check('WebDAV lock populates the returned lock token',
      doc.getElementById('davLockToken').value === 'opaquelocktoken:test-123');
    await window.unlockDavResource();
    const davUnlockCall = calls.filter(call => call.path === '/api/dav/unlock').pop();
    check('WebDAV unlock posts the lock token and clears it',
      !!davUnlockCall &&
      JSON.parse(davUnlockCall.options.body).token === 'opaquelocktoken:test-123' &&
      doc.getElementById('davLockToken').value === '');
    doc.getElementById('davPropName').value = 'tag';
    await window.getDavProperty();
    check('WebDAV get property populates the value field',
      doc.getElementById('davPropValue').value === 'approved');
    doc.getElementById('davPropValue').value = 'updated';
    await window.saveDavProperty();
    const davSetCall = calls.filter(call => call.path === '/api/dav/property').pop();
    check('WebDAV set property posts action set and value',
      !!davSetCall &&
      JSON.parse(davSetCall.options.body).action === 'set' &&
      JSON.parse(davSetCall.options.body).value === 'updated');
    window.closeModal('davToolsModal');
    delete responses['/api/dav/lock'];
    delete responses['/api/dav/unlock'];
    delete responses['/api/dav/property'];

    const savedCtx2 = window.HTMLCanvasElement.prototype.getContext;
    const savedBmp2 = window.createImageBitmap;
    window.HTMLCanvasElement.prototype.getContext = () => ({
      imageSmoothingEnabled: true, clearRect() {}, drawImage() {},
      getImageData: (_x, _y, w, h) => ({ data: new Uint8ClampedArray(w * h * 4), width: w, height: h }),
      putImageData() {}
    });
    window.createImageBitmap = async () => ({ width: 1024, height: 768, close() {} });
    responses['/api/desktop/check'] = {
      success: true, checked: true, available: true, via_ssh: true,
      desktop_checked: true, desktop: 'XFCE'
    };
    responses['/api/x2go/sessions'] = {
      success: true,
      sessions: [{ session_id: 'alice-50-1700000000_stDXFCE_dp24', display: 50, status: 'S', desktop: 'XFCE' }]
    };
    responses['/api/x2go/terminate'] = { success: true };
    responses['/api/x2go/open'] = { success: true, generation: '9' };
    responses['/api/x2go/poll'] = { success: true, message: null };
    responses['/api/x2go/input'] = { success: true };
    responses['/api/x2go/suspend'] = { success: true };
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 40));
    await window.refreshX2GoSessions();
    check('X2Go session picker lists resumable sessions without cookies',
      doc.querySelectorAll('#x2goSessionSelect option').length === 2);
    doc.getElementById('x2goSessionSelect').value = 'alice-50-1700000000_stDXFCE_dp24';
    doc.getElementById('x2goClipboardOptIn').checked = true;
    await window.launchRemoteDesktop();
    await new Promise(resolve => setTimeout(resolve, 40));
    const resumedOpen = calls.filter(call => call.path === '/api/x2go/open').pop();
    const resumedBody = resumedOpen ? JSON.parse(resumedOpen.options.body) : {};
    check('X2Go launch forwards resume_session_id and allow_clipboard',
      resumedBody.resume_session_id === 'alice-50-1700000000_stDXFCE_dp24' &&
      resumedBody.allow_clipboard === true);
    await window.suspendX2GoViewer();
    const suspendCall = calls.filter(call => call.path === '/api/x2go/suspend').pop();
    check('Suspending the X2Go viewer calls /api/x2go/suspend without /api/x2go/close',
      !!suspendCall && JSON.parse(suspendCall.options.body).generation === '9' &&
      !doc.getElementById('x2goViewerModal').classList.contains('open'));
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await window.refreshX2GoSessions();
    doc.getElementById('x2goSessionSelect').value = 'alice-50-1700000000_stDXFCE_dp24';
    await window.terminateSelectedX2GoSession();
    const termCall = calls.filter(call => call.path === '/api/x2go/terminate').pop();
    check('Terminating a listed X2Go session posts session_id to /api/x2go/terminate',
      !!termCall && JSON.parse(termCall.options.body).session_id === 'alice-50-1700000000_stDXFCE_dp24');
    window.closeModal('remoteDesktopModal');
    window.HTMLCanvasElement.prototype.getContext = savedCtx2;
    window.createImageBitmap = savedBmp2;
    delete responses['/api/x2go/sessions'];
    delete responses['/api/x2go/terminate'];
    delete responses['/api/x2go/open'];
    delete responses['/api/x2go/poll'];
    delete responses['/api/x2go/input'];
    delete responses['/api/x2go/suspend'];

    const savedCoreForAndroid = window.LinSCPCore;
    let openedExternalUri = null;
    let fgStarted = false;
    let fgStartArgs = null;
    let fgStopped = false;
    let allowOpenExternal = true;
    window.LinSCPCore = Object.assign({}, savedCoreForAndroid, {
      hostCapabilities: () => ({
        platform: 'android', desktopLaunchers: true, saf: true, share: true, separateWindows: false
      }),
      openExternalUri: async uri => { openedExternalUri = uri; return allowOpenExternal; },
      ForegroundTransferBridge: function () {
        this.isRunning = false;
        this.start = async (title, ongoing) => {
          fgStarted = true;
          fgStartArgs = [title, ongoing];
          this.isRunning = true;
        };
        this.stop = async () => {
          fgStopped = true;
          this.isRunning = false;
        };
      }
    });
    responses['/api/desktop/launch'] = {
      success: true, kind: 'rdp', tunneled: true, local_endpoint: '127.0.0.1:43389'
    };
    responses['/api/desktop/tunnel-close'] = { success: true, closed: true };
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'rdp';
    window.remoteDesktopKindChanged();
    doc.getElementById('remoteDesktopTunnel').checked = true;
    await window.launchRemoteDesktop();
    const launchTunCall = calls.filter(call => call.path === '/api/desktop/launch').pop();
    check('Android tunneled desktop launch forwards tunnel_via_ssh, starts keepalive and opens loopback URI',
      !!launchTunCall &&
      JSON.parse(launchTunCall.options.body).tunnel_via_ssh === true &&
      fgStarted === true &&
      Array.isArray(fgStartArgs) &&
      typeof fgStartArgs[0] === 'string' && fgStartArgs[0].length > 0 &&
      fgStartArgs[1] === 1 &&
      openedExternalUri === 'rdp://127.0.0.1:43389');
    await window.closeRemoteDesktopTunnel();
    const closeTunCall = calls.filter(call => call.path === '/api/desktop/tunnel-close').pop();
    check('Closing the desktop tunnel stops keepalive and posts /api/desktop/tunnel-close',
      !!closeTunCall && fgStopped === true && JSON.parse(closeTunCall.options.body).kind === 'rdp');

    fgStarted = false;
    fgStopped = false;
    allowOpenExternal = false;
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'rdp';
    window.remoteDesktopKindChanged();
    doc.getElementById('remoteDesktopTunnel').checked = true;
    await window.launchRemoteDesktop();
    check('Failed Android viewer intent stops tunneled foreground keepalive immediately',
      fgStarted === true && fgStopped === true);
    window.closeModal('remoteDesktopModal');
    window.LinSCPCore = savedCoreForAndroid;
    delete responses['/api/desktop/launch'];
    delete responses['/api/desktop/tunnel-close'];

    // Editable & customizable installer scripts (Mosh, Remote Desktop, Preferences).
    const internals = window.__TAURI_INTERNALS__;
    const prevInvokeForScripts = internals.invoke;
    internals.invoke = async (command, args) => {
      if (command === 'linscp_open_terminal_window') return { label: 'terminal-script-test' };
      return prevInvokeForScripts(command, args);
    };
    check('installer script views are editable textareas',
      doc.getElementById('moshScript').tagName === 'TEXTAREA' &&
      doc.getElementById('remoteDesktopScript').tagName === 'TEXTAREA' &&
      doc.getElementById('prefInstallScriptEditor').tagName === 'TEXTAREA');

    // 1. Mosh inline edit + UTF-8 base64 execution + save/reset custom script.
    responses['/api/session/terminal'] = {
      success: false, mosh_missing: true, via_ssh: true, can_install: true,
      host: '127.0.0.1', port: 2222,
      install_script: '#!/bin/bash\necho default-mosh\n',
      default_install_script: '#!/bin/bash\necho default-mosh\n',
      is_custom: false,
      reason: 'Mosh server (mosh-server) was not found on 127.0.0.1.'
    };
    await window.openTerminal(null, false, null, { mosh: true });
    const moshEditor = doc.getElementById('moshScript');
    moshEditor.value = '#!/bin/bash\n# édité\nsudo apt-get install -y mosh\n';
    window.onMoshScriptInput();
    check('editing Mosh installer marks toolbar state as unsaved',
      text('moshScriptState').includes('Edited'));
    responses['/api/mosh/install-script'] = {
      success: true,
      install_script: moshEditor.value,
      default_install_script: '#!/bin/bash\necho default-mosh\n',
      is_custom: true
    };
    await window.saveCustomMoshScript();
    const saveMoshCall = calls.filter(call => call.path === '/api/mosh/install-script' && call.options && call.options.method === 'POST').pop();
    check('saving custom Mosh script posts script to /api/mosh/install-script',
      !!saveMoshCall &&
      JSON.parse(saveMoshCall.options.body).script.includes('# édité') &&
      text('moshScriptState').includes('Custom saved script'));
    responses['/api/session/terminal'] = { success: true, terminal: 88, cols: 80, rows: 24 };
    await window.installMoshOnServer();
    const editedMoshInput = JSON.parse(calls.filter(call => call.path === '/api/terminal/input').pop().options.body);
    const editedMoshCmd = Buffer.from(editedMoshInput.data, 'base64').toString();
    const editedMoshB64 = (editedMoshCmd.match(/printf %s '([^']+)' \| base64 -d \| bash/) || [])[1] || '';
    check('installing edited Mosh script executes the exact UTF-8 edited script',
      Buffer.from(editedMoshB64, 'base64').toString('utf8') === '#!/bin/bash\n# édité\nsudo apt-get install -y mosh\n');
    window.closeTerminal();
    responses['/api/mosh/install-script'] = {
      success: true,
      install_script: '#!/bin/bash\necho default-mosh\n',
      default_install_script: '#!/bin/bash\necho default-mosh\n',
      is_custom: false
    };
    await window.resetCustomMoshScript();
    const resetMoshCall = calls.filter(call => call.path === '/api/mosh/install-script' && call.options && call.options.method === 'POST').pop();
    check('resetting custom Mosh script posts reset and restores default script',
      !!resetMoshCall &&
      JSON.parse(resetMoshCall.options.body).reset === true &&
      moshEditor.value === '#!/bin/bash\necho default-mosh\n');
    delete responses['/api/mosh/install-script'];

    // 2. Remote Desktop (RDP) inline edit + /api/desktop/install script forwarding + Load/Save/Reset.
    responses['/api/desktop/check'] = {
      success: true, checked: true, available: false, via_ssh: true, can_install: true,
      kind: 'rdp', host: '127.0.0.1', port: 3389,
      install_script: '#!/bin/bash\necho default-rdp\n',
      default_install_script: '#!/bin/bash\necho default-rdp\n',
      is_custom: false,
      reason: 'RDP not listening'
    };
    responses['/api/desktop/install'] = {
      success: true, host: '127.0.0.1', kind: 'rdp', package: 'xrdp',
      exit_code: 0, stdout: 'ok', stderr: '', now_available: true,
      install_script: '#!/bin/bash\necho custom-inline-rdp\n', message: 'Installed'
    };
    window.openRemoteDesktop();
    doc.getElementById('remoteDesktopKind').value = 'rdp';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 40));
    const rdEditor = doc.getElementById('remoteDesktopScript');
    rdEditor.value = '#!/bin/bash\necho custom-inline-rdp\n';
    window.onRemoteDesktopScriptInput();
    responses['/api/desktop/check'] = {
      success: true, checked: true, available: true, via_ssh: true, can_install: false,
      kind: 'rdp', host: '127.0.0.1', port: 3389,
      install_script: '#!/bin/bash\necho default-rdp\n',
      default_install_script: '#!/bin/bash\necho default-rdp\n',
      is_custom: false,
      reason: ''
    };
    await window.installRemoteDesktop();
    const rdpInstallCall = calls.filter(call => call.path === '/api/desktop/install').pop();
    check('installing edited RDP script forwards edited script in /api/desktop/install',
      !!rdpInstallCall &&
      JSON.parse(rdpInstallCall.options.body).script === '#!/bin/bash\necho custom-inline-rdp\n');
    responses['/api/desktop/install-script'] = {
      success: true, kind: 'rdp', target: 'rdp',
      install_script: '#!/bin/bash\necho loaded-rdp\n',
      default_install_script: '#!/bin/bash\necho default-rdp\n',
      is_custom: false
    };
    await window.loadRemoteDesktopScriptForEdit();
    check('Load script button populates Remote Desktop script editor even when already installed',
      rdEditor.value === '#!/bin/bash\necho loaded-rdp\n');
    rdEditor.value = '#!/bin/bash\necho saved-rdp\n';
    window.onRemoteDesktopScriptInput();
    responses['/api/desktop/install-script'] = {
      success: true, kind: 'rdp', target: 'rdp',
      install_script: '#!/bin/bash\necho saved-rdp\n',
      default_install_script: '#!/bin/bash\necho default-rdp\n',
      is_custom: true
    };
    await window.saveCustomRemoteDesktopScript();
    const saveRdpCall = calls.filter(call => call.path === '/api/desktop/install-script' && call.options && call.options.method === 'POST').pop();
    check('Save custom script in Remote Desktop posts target and script',
      !!saveRdpCall &&
      JSON.parse(saveRdpCall.options.body).kind === 'rdp' &&
      JSON.parse(saveRdpCall.options.body).script === '#!/bin/bash\necho saved-rdp\n');

    // 3. Edited X2Go script runs exact edited script in SSH terminal.
    responses['/api/desktop/check'] = {
      success: true, checked: true, available: false, via_ssh: true, can_install: true,
      kind: 'x2go', host: '127.0.0.1', port: 2222,
      desktop_checked: true, desktop: 'XFCE',
      install_script: '#!/bin/bash\necho default-x2go\n',
      default_install_script: '#!/bin/bash\necho default-x2go\n',
      reason: 'x2goserver missing'
    };
    doc.getElementById('remoteDesktopKind').value = 'x2go';
    window.remoteDesktopKindChanged();
    await new Promise(resolve => setTimeout(resolve, 40));
    rdEditor.value = '#!/bin/bash\necho edited-x2go-custom\n';
    window.onRemoteDesktopScriptInput();
    await window.installRemoteDesktop();
    const x2goEditedInput = JSON.parse(calls.filter(call => call.path === '/api/terminal/input').pop().options.body);
    const x2goEditedCmd = Buffer.from(x2goEditedInput.data, 'base64').toString();
    const x2goEditedB64 = (x2goEditedCmd.match(/printf %s '([^']+)' \| base64 -d \| bash/) || [])[1] || '';
    check('installing edited X2Go script executes the edited script instead of reverting to default',
      Buffer.from(x2goEditedB64, 'base64').toString('utf8') === '#!/bin/bash\necho edited-x2go-custom\n');
    window.closeTerminal();
    window.closeModal('remoteDesktopModal');
    delete responses['/api/desktop/install'];
    delete responses['/api/desktop/install-script'];

    // 4. Preferences modal customizable installer scripts editor.
    responses['/api/mosh/install-script'] = {
      success: true,
      install_script: '#!/bin/bash\necho pref-default-mosh\n',
      default_install_script: '#!/bin/bash\necho pref-default-mosh\n',
      is_custom: false
    };
    responses['/api/desktop/install-script'] = {
      success: true, kind: 'x2go_xfce', target: 'x2go_xfce',
      install_script: '#!/bin/bash\necho pref-default-xfce\n',
      default_install_script: '#!/bin/bash\necho pref-default-xfce\n',
      is_custom: false
    };
    await window.openPreferences();
    check('opening Preferences loads selected installer script target',
      doc.getElementById('prefInstallScriptEditor').value === '#!/bin/bash\necho pref-default-mosh\n');
    doc.getElementById('prefInstallScriptTarget').value = 'x2go_xfce';
    await window.loadPrefInstallScriptTarget();
    check('switching Preferences installer target loads that target script',
      doc.getElementById('prefInstallScriptEditor').value === '#!/bin/bash\necho pref-default-xfce\n');
    doc.getElementById('prefInstallScriptEditor').value = '#!/bin/bash\necho pref-custom-xfce\n';
    window.onPrefInstallScriptInput();
    responses['/api/desktop/install-script'] = {
      success: true, kind: 'x2go_xfce', target: 'x2go_xfce',
      install_script: '#!/bin/bash\necho pref-custom-xfce\n',
      default_install_script: '#!/bin/bash\necho pref-default-xfce\n',
      is_custom: true
    };
    await window.savePrefInstallScript();
    const prefSaveCall = calls.filter(call => call.path === '/api/desktop/install-script' && call.options && call.options.method === 'POST').pop();
    check('saving custom script in Preferences posts target and script',
      !!prefSaveCall &&
      JSON.parse(prefSaveCall.options.body).kind === 'x2go_xfce' &&
      JSON.parse(prefSaveCall.options.body).script === '#!/bin/bash\necho pref-custom-xfce\n');
    responses['/api/desktop/install-script'] = {
      success: true, kind: 'x2go_xfce', target: 'x2go_xfce',
      install_script: '#!/bin/bash\necho pref-default-xfce\n',
      default_install_script: '#!/bin/bash\necho pref-default-xfce\n',
      is_custom: false
    };
    await window.resetPrefInstallScript();
    const prefResetCall = calls.filter(call => call.path === '/api/desktop/install-script' && call.options && call.options.method === 'POST').pop();
    check('resetting custom script in Preferences posts reset and restores default',
      !!prefResetCall &&
      JSON.parse(prefResetCall.options.body).reset === true &&
      doc.getElementById('prefInstallScriptEditor').value === '#!/bin/bash\necho pref-default-xfce\n');
    window.closeModal('preferencesModal');
    delete responses['/api/mosh/install-script'];
    delete responses['/api/desktop/install-script'];
    internals.invoke = prevInvokeForScripts;
  }

  // ---- S3 options, transfer presets, encodings, external editor, XML logs, share cancel & workspace challenge ----
  {
    // 1. S3 advanced options & preset round-trip in Site Manager.
    window.openSiteManager();
    window.newSite();
    doc.getElementById('siteName').value = 's3-prod';
    doc.getElementById('siteProtocol').value = 's3';
    window.siteProtocolChanged();
    doc.getElementById('siteHost').value = 's3.amazonaws.com';
    doc.getElementById('siteUser').value = 'AKIAEXAMPLE';
    doc.getElementById('siteS3Region').value = 'eu-west-1';
    doc.getElementById('siteS3UrlStyle').value = 'path';
    doc.getElementById('siteS3StorageClass').value = 'STANDARD_IA';
    doc.getElementById('siteS3Acl').value = 'bucket-owner-full-control';
    doc.getElementById('siteS3Sse').value = 'aws:kms';
    doc.getElementById('siteS3KmsKey').value = 'alias/prod-key';
    doc.getElementById('siteS3Metadata').value = 'env=prod,team=ops';
    doc.getElementById('sitePreset').value = 'TextLogs';
    await window.saveSite();
    const s3Save = JSON.parse(calls.filter(c => c.path === '/api/sessions/save').pop().options.body);
    check('S3 advanced options and site preset are posted when saving a site',
      s3Save.session.protocol === 's3' &&
      s3Save.session.s3_region === 'eu-west-1' &&
      s3Save.session.s3_url_style === 'path' &&
      s3Save.session.s3_storage_class === 'STANDARD_IA' &&
      s3Save.session.s3_acl === 'bucket-owner-full-control' &&
      s3Save.session.s3_sse === 'aws:kms' &&
      s3Save.session.s3_kms_key === 'alias/prod-key' &&
      s3Save.session.s3_metadata === 'env=prod,team=ops' &&
      s3Save.session.preset === 'TextLogs');
    window.closeModal('siteModal');

    // 2. Transfer presets load, apply, save and delete.
    responses['/api/presets'] = {
      success: true,
      presets: [{ name: 'TextLogs', transfer: 'ascii', filemask: '*.log', speed: 256, preserve_time: true, newer_only: true }]
    };
    responses['/api/presets/save'] = { success: true, preset: { name: 'TextLogs' } };
    responses['/api/presets/delete'] = { success: true };
    window.openTransferSettings();
    await window.loadTransferPresets();
    doc.getElementById('transferPresetSelect').value = 'TextLogs';
    window.selectTransferPreset();
    check('selecting a transfer preset populates transfer form fields',
      doc.getElementById('transferMode').value === 'ascii' &&
      doc.getElementById('transferMask').value === '*.log' &&
      doc.getElementById('transferSpeed').value === '256' &&
      doc.getElementById('transferNewerOnly').checked === true &&
      window.transferOptions().preset === 'TextLogs');
    doc.getElementById('transferPresetName').value = 'FastBin';
    doc.getElementById('transferMode').value = 'binary';
    await window.saveCurrentTransferPreset();
    const presetSaveCall = calls.filter(c => c.path === '/api/presets/save').pop();
    check('saving a transfer preset posts settings to /api/presets/save',
      !!presetSaveCall && JSON.parse(presetSaveCall.options.body).name === 'FastBin' &&
      JSON.parse(presetSaveCall.options.body).transfer === 'binary');
    await window.deleteSelectedTransferPreset();
    const presetDeleteCall = calls.filter(c => c.path === '/api/presets/delete').pop();
    check('deleting a transfer preset posts name to /api/presets/delete',
      !!presetDeleteCall && JSON.parse(presetDeleteCall.options.body).name === 'FastBin');
    await window.resetTransferSettings();
    window.closeModal('transferModal');
    delete responses['/api/presets'];
    delete responses['/api/presets/save'];
    delete responses['/api/presets/delete'];

    // 3. Editor encoding/EOL/BOM + External desktop editor + Search encoding.
    const prevStatus = responses['/api/status'];
    responses['/api/status'] = Object.assign({}, prevStatus, {
      gssapi_available: true,
      supported_encodings: ['UTF-8', 'UTF-16LE', 'Windows-1252', 'Shift_JIS'],
      external_editor_supported: true
    });
    await window.refreshStatus();
    const prevRemoteEdit = responses['/api/remote/edit'];
    responses['/api/remote/edit'] = {
      success: true, path: '/tmp/slowremote/keep.txt', content: 'encoded\n',
      info: { size: 8, mtime: 1791875271, mtime_ns: '1791875271', encoding: 'Windows-1252', eol: 'crlf', bom: false }
    };
    await window.openEditor('/tmp/slowremote/keep.txt', 'remote', false);
    check('editor reflects encoding, line endings and external editor support',
      doc.getElementById('editorEncoding').value === 'Windows-1252' &&
      doc.getElementById('editorEol').value === 'crlf' &&
      doc.getElementById('editorExternalBtn').hidden === false);
    doc.getElementById('editorBom').checked = true;
    window.markDirty();
    await window.saveEditorFile();
    const encSaveCall = calls.filter(c => c.path === '/api/remote/save').pop();
    const encSaveBody = JSON.parse(encSaveCall.options.body);
    check('editor save forwards encoding, eol and bom metadata',
      encSaveBody.encoding === 'Windows-1252' && encSaveBody.eol === 'crlf' && encSaveBody.bom === true);
    responses['/api/editor/external'] = { success: true, id: 'ext-42', editor: 'code', is_remote: true };
    responses['/api/editor/external/close'] = { success: true };
    await window.openInExternalEditor();
    const extOpenCall = calls.filter(c => c.path === '/api/editor/external' && (c.options.method || 'GET').toUpperCase() === 'POST').pop();
    check('external editor button posts file to /api/editor/external and reveals stop button',
      !!extOpenCall && JSON.parse(extOpenCall.options.body).path === '/tmp/slowremote/keep.txt' &&
      doc.getElementById('editorExternalCloseBtn').hidden === false);
    await window.closeExternalEditorSession();
    const extCloseCall = calls.filter(c => c.path === '/api/editor/external/close').pop();
    check('closing external editor session posts id to /api/editor/external/close',
      !!extCloseCall && JSON.parse(extCloseCall.options.body).id === 'ext-42');
    window.closeEditor();
    responses['/api/remote/edit'] = prevRemoteEdit;
    responses['/api/status'] = prevStatus;
    delete responses['/api/editor/external'];
    delete responses['/api/editor/external/close'];

    window.openSearch();
    doc.getElementById('searchContents').checked = true;
    window.toggleSearchContents();
    doc.getElementById('searchText').value = 'latin';
    doc.getElementById('searchEncoding').value = 'Windows-1252';
    await window.runSearch();
    const encSearchCall = calls.filter(c => c.path === '/api/remote/search').pop();
    check('content search forwards selected text encoding',
      !!encSearchCall && JSON.parse(encSearchCall.options.body).encoding === 'Windows-1252');
    window.closeModal('searchModal');

    // 4. Preferences XML log settings & XML log viewer/clear.
    await window.openPreferences();
    doc.getElementById('prefXmlLogEnabled').checked = true;
    doc.getElementById('prefXmlLogPath').value = 'audit-actions.xml';
    await window.savePreferences();
    const xmlPrefCall = calls.filter(c => c.path === '/api/preferences' && (c.options.method || 'GET').toUpperCase() === 'POST').pop();
    const xmlPrefBody = JSON.parse(xmlPrefCall.options.body);
    check('saving Preferences includes xml_log_enabled and xml_log_path',
      xmlPrefBody.preferences.xml_log_enabled === true &&
      xmlPrefBody.preferences.xml_log_path === 'audit-actions.xml');
    responses['/api/logs/xml'] = {
      success: true, enabled: true, exists: true, size: 64,
      path: '/tmp/cfg/audit-actions.xml', content: '<session><upload filename="/a"/></session>'
    };
    responses['/api/logs/xml/clear'] = { success: true };
    await window.openXmlLogViewer();
    check('XML log viewer renders XML log content and path',
      doc.getElementById('xmlLogModal').classList.contains('open') &&
      text('xmlLogContent').includes('<upload filename="/a"/>'));
    await window.clearXmlLogFile();
    check('clearing XML log posts /api/logs/xml/clear',
      calls.some(c => c.path === '/api/logs/xml/clear'));
    window.closeModal('xmlLogModal');
    delete responses['/api/logs/xml'];
    delete responses['/api/logs/xml/clear'];

    // 5. Android remote share staging progress & cancel.
    const origCore = window.LinSCPCore;
    let releaseShare = null;
    responses['/api/android/share/status'] = {
      success: true, active: true, cancelled: false, files_done: 0, files_total: 1, bytes_done: 4096, bytes_total: 8192
    };
    responses['/api/android/share/cancel'] = { success: true };
    window.LinSCPCore = new Proxy(origCore, { get(target, key) {
      if (key === 'hostCapabilities') return () => ({ ...target.hostCapabilities({ host: window }), platform: 'android', nativeIpc: true });
      if (key === 'shareFiles') return () => new Promise(resolve => { releaseShare = resolve; });
      return Reflect.get(target, key);
    }});
    window.focusPane('remote');
    window.clearFocusedSelection();
    doc.getElementById('remoteFileList').children[0].click();
    const pendingShare = window.shareSelectedFiles();
    await new Promise(resolve => setTimeout(resolve, 20));
    await window.pollAndroidShareStatus();
    check('Android remote share opens progress modal and displays staged byte status',
      doc.getElementById('androidShareModal').classList.contains('open') &&
      text('androidShareProgressText').includes('1'));
    await window.cancelAndroidShare();
    check('cancelling Android share posts /api/android/share/cancel',
      calls.some(c => c.path === '/api/android/share/cancel'));
    if (releaseShare) releaseShare();
    await pendingShare;
    window.clearFocusedSelection();
    window.LinSCPCore = origCore;
    delete responses['/api/android/share/status'];
    delete responses['/api/android/share/cancel'];

    // 6. Workspace open surfaces pending SSH host-key challenge.
    const prevWsOpen = responses['/api/workspaces/open'];
    responses['/api/workspaces/open'] = {
      success: true, name: 'ops', opened: [], failed: [], active_tab: null,
      challenges: [{ tab: 88, host: 'ws-host.example', port: 22, role: 'destination', fingerprint: 'ssh-ed25519 SHA256:wschal' }]
    };
    await window.openWorkspace('ops');
    check('workspace open surfaces pending SSH host-key challenge modal',
      doc.getElementById('hostKeyModal').classList.contains('open') &&
      text('hostKeyFingerprint') === 'ssh-ed25519 SHA256:wschal');
    await window.cancelHostKey();
    responses['/api/workspaces/open'] = prevWsOpen;

    // 7. SAF joinPath escapes URI-reserved characters (`%`, `?`, `#`, `/`).
    const safJoined = window.joinPath(
      'content://com.android.externalstorage.documents/tree/primary%3ADownload',
      'budget_50%#1?.csv'
    );
    check('joinPath escapes reserved URI characters inside SAF document segments',
      safJoined === 'content://com.android.externalstorage.documents/tree/primary%3ADownload/document/budget_50%25%231%3F.csv');

    // 8. Native backup export with `saved_path` refreshes local pane without blob navigation.
    const prevBackupExport = responses['/api/backup/export'];
    responses['/api/backup/export'] = {
      success: true,
      filename: 'linscp-full-backup-direct.lscpbak',
      saved_path: '/tmp/slowlocal/linscp-full-backup-direct.lscpbak',
      data_base64: 'TFNDUEJBSzE='
    };
    const listsBeforeExport = calls.filter(c => c.path && c.path.startsWith('/api/local/list')).length;
    window.openFullBackup();
    doc.getElementById('fullBackupPassword').value = 'direct-save-password';
    doc.getElementById('fullBackupConfirm').value = 'direct-save-password';
    await window.exportFullBackup();
    const directExportCall = calls.filter(c => c.path === '/api/backup/export').pop();
    const listsAfterExport = calls.filter(c => c.path && c.path.startsWith('/api/local/list')).length;
    check('full backup passes save_dir and refreshes local pane when saved_path is returned',
      directExportCall &&
      typeof JSON.parse(directExportCall.options.body).save_dir === 'string' &&
      listsAfterExport > listsBeforeExport &&
      text('fullBackupStatus').includes('Encrypted backup download started.'));
    window.closeFullBackup();
    responses['/api/backup/export'] = prevBackupExport;

    // 9. Local checksum modal posts /api/local/checksum with local_dir, algorithm, and names.
    const prevPromptForCs = window.prompt;
    window.prompt = () => 'sha-256';
    responses['/api/local/checksum'] = {
      success: true,
      algorithm: 'sha-256',
      results: [{ name: 'local-a.txt', checksum: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }]
    };
    window.focusPane('local');
    window.clearFocusedSelection();
    const localFileRow = Array.from(doc.getElementById('localFileList').children)
      .find(el => el.dataset && el.dataset.name && el.dataset.name !== '..' && el.dataset.dir !== '1');
    if (localFileRow) localFileRow.click();
    await window.openChecksum();
    const localCsCall = calls.filter(c => c.path === '/api/local/checksum').pop();
    check('local checksum posts /api/local/checksum and opens checksum modal',
      localCsCall &&
      JSON.parse(localCsCall.options.body).algorithm === 'sha-256' &&
      Array.isArray(JSON.parse(localCsCall.options.body).names) &&
      JSON.parse(localCsCall.options.body).names.length === 1 &&
      doc.getElementById('propertiesModal').classList.contains('open') &&
      text('propertiesBody').includes('0123456789abcdef'));
    window.closeModal('propertiesModal');
    window.clearFocusedSelection();
    window.prompt = prevPromptForCs;
    delete responses['/api/local/checksum'];

    // 10. Byte-drop conflict on /api/local/drop asks for overwrite approval and retries with overwrite='overwrite'.
    const origTauriInvoke = window.__TAURI_INTERNALS__.invoke;
    const localDropBodies = [];
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      const envelope = args && args.envelope;
      if (envelope && envelope.path === '/api/local/drop') {
        localDropBodies.push(envelope.body);
        if (!envelope.body.overwrite) {
          return {
            status: 409,
            payload: {
              success: false,
              conflicts: ['dup.txt']
            }
          };
        }
        return { status: 200, payload: { success: true } };
      }
      return origTauriInvoke(cmd, args);
    };
    const prevConfirm = confirmResult;
    confirmResult = true;
    await window.saveLocalDesktopFile(new window.File(['hello'], 'dup.txt'), 'dup.txt');
    check('local byte-drop 409 conflict retries with overwrite approval',
      localDropBodies.length === 2 &&
      !localDropBodies[0].overwrite &&
      localDropBodies[1].overwrite === 'overwrite');
    confirmResult = prevConfirm;
    window.__TAURI_INTERNALS__.invoke = origTauriInvoke;

    // 11. External editor close conflict prompts before retrying with force=true.
    let closeCalls = [];
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      const envelope = args && args.envelope;
      if (envelope && envelope.path === '/api/editor/external/close') {
        closeCalls.push(envelope.body);
        if (!envelope.body.force) {
          return {
            status: 400,
            payload: { success: false, error: 'Remote file changed while open.' }
          };
        }
        return { status: 200, payload: { success: true } };
      }
      return origTauriInvoke(cmd, args);
    };
    await window.openEditor('/tmp/slowremote/keep.txt', 'remote', false);
    responses['/api/editor/external'] = { success: true, id: 404, editor: 'nvim', staged_path: '/tmp/ext-404/keep.txt' };
    await window.openInExternalEditor();
    confirmResult = true;
    await window.closeExternalEditorSession();
    check('external editor close conflict confirms and retries with force=true',
      closeCalls.length === 2 &&
      closeCalls[0].id === 404 && !closeCalls[0].force &&
      closeCalls[1].id === 404 && closeCalls[1].force === true);
    confirmResult = prevConfirm;
    window.__TAURI_INTERNALS__.invoke = origTauriInvoke;
    window.closeEditor();
    delete responses['/api/editor/external'];

    // 12. Native desktop drop onto right pane of a dual-local tab routes target='local' to state.remote.path.
    const prevDropCore = window.LinSCPCore;
    let capturedDropTarget = null;
    window.LinSCPCore = new Proxy(prevDropCore, { get(target, key) {
      if (key === 'dropPaths') {
        return async (_transport, _items, opts) => {
          capturedDropTarget = opts;
          return { queued: 1, failed: [] };
        };
      }
      return Reflect.get(target, key);
    }});
    const prevTabs = JSON.parse(JSON.stringify(window.__testTabsSnapshot ? window.__testTabsSnapshot() : null));
    const prevStatusResp = responses['/api/status'];
    responses['/api/status'] = Object.assign({}, prevStatusResp, {
      connected: true,
      active_tab: 99,
      tabs: [{ id: 99, name: 'Local', connected: true, is_local: true, local_dir: '/tmp/slowlocal', remote_dir: '/tmp/otherlocal', protocol: 'local' }]
    });
    const prevRemoteListResp = responses['/api/remote/list'];
    responses['/api/remote/list'] = { path: '/tmp/otherlocal', entries: [] };
    await window.refreshStatus();
    await window.loadRemote('/tmp/otherlocal');
    await window.handleNativeDrop({ paths: ['/tmp/desktop-note.txt'], side: 'remote' });
    check('dual-local native drop onto right pane uses target=local and right-pane directory',
      capturedDropTarget &&
      capturedDropTarget.target === 'local' &&
      capturedDropTarget.directory === '/tmp/otherlocal' &&
      capturedDropTarget.tab === 99);
    window.LinSCPCore = prevDropCore;
    responses['/api/status'] = prevStatusResp;
    responses['/api/remote/list'] = prevRemoteListResp;
    await window.refreshStatus();

    // 13. Windows & SAF parent-path navigation + local directory search (`/api/local/search`).
    check('localParentPath navigates Windows drive paths without corrupting to /',
      window.localParentPath('C:\\Users\\alice\\Documents') === 'C:\\Users\\alice' &&
      window.localParentPath('C:\\Users') === 'C:\\' &&
      window.localParentPath('C:\\') === 'C:\\');
    check('localParentPath preserves encoded Android SAF document URIs',
      window.localParentPath('content://com.android.externalstorage.documents/tree/primary%3ADownload/document/primary%3ADownload%2Fnotes%2Ftodo.txt') ===
      'content://com.android.externalstorage.documents/tree/primary%3ADownload');

    const prevLocalList = responses['/api/local/list'];
    let lastLocalListPath = null;
    responses['/api/local/search'] = {
      success: true,
      matches: [{
        path: 'C:\\Users\\alice\\Documents\\todo.txt',
        name: 'todo.txt',
        is_dir: false,
        size: 42,
        line: 3,
        snippet: 'ship release'
      }],
      scanned: 2,
      skipped: 0,
      bytes_scanned: 128,
      truncated: false
    };
    const origInvokeSearch = window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope && args.envelope.path.startsWith('/api/local/list')) {
        const q = args.envelope.path.split('?')[1] || '';
        const params = new URLSearchParams(q);
        lastLocalListPath = params.get('path');
        return {
          status: 200,
          payload: { path: lastLocalListPath, entries: [{ name: 'todo.txt', is_dir: false, size: 42, permissions: '-rw-r--r--', date: '2026-11-20' }] }
        };
      }
      return origInvokeSearch(cmd, args);
    };
    window.openSearch('local');
    check('openSearch("local") selects local target and populates local path',
      doc.getElementById('searchTarget').value === 'local' &&
      doc.getElementById('searchModalTitle').textContent.indexOf('local') >= 0);
    doc.getElementById('searchPath').value = 'C:\\Users\\alice';
    doc.getElementById('searchPattern').value = '*.txt|node_modules/';
    doc.getElementById('searchContents').checked = true;
    window.toggleSearchContents();
    doc.getElementById('searchText').value = 'ship';
    await window.runSearch();
    const localSearchCall = calls.filter(c => c.path === '/api/local/search').pop();
    check('local search posts to /api/local/search with pattern and content query',
      !!localSearchCall &&
      JSON.parse(localSearchCall.options.body).path === 'C:\\Users\\alice' &&
      JSON.parse(localSearchCall.options.body).pattern === '*.txt|node_modules/' &&
      JSON.parse(localSearchCall.options.body).content_query === 'ship');
    const firstMatchRow = doc.getElementById('searchResults').children[0];
    await firstMatchRow.ondblclick();
    check('double-clicking a Windows local search result navigates local pane to Windows parent directory',
      lastLocalListPath === 'C:\\Users\\alice\\Documents');
    window.__TAURI_INTERNALS__.invoke = origInvokeSearch;
    responses['/api/local/list'] = prevLocalList;
    delete responses['/api/local/search'];
    await window.loadLocal('/tmp/slowlocal');

    // 14. Symlinks (`is_symlink` / `broken_link`), mtime date fallback, offline local chmod/link,
    // Windows `joinPath` + `navigateSync`, `transportShim`, Site Manager secret placeholders,
    // modal shortcut isolation, and embedded terminal Escape / selection copy / UTF-8 command.
    const pageState = window.eval('state');
    check('joinPath formats Windows drive roots and subdirectories cleanly',
      window.joinPath('C:\\', 'Users') === 'C:\\Users' &&
      window.joinPath('C:\\Users\\', 'alice') === 'C:\\Users\\alice' &&
      window.joinPath('C:/Users', 'alice') === 'C:/Users/alice');

    const shimReply = await window.transportShim().post('/api/local/mkdir', { name: 'shim_test' });
    check('transportShim preserves parsed JSON reply objects on POST',
      !!shimReply && shimReply.success === true);

    // Render `is_symlink` + `broken_link` + `mtime` (with empty `date`) in local pane.
    const savedLocalEntries = pageState.local.entries.slice();
    pageState.local.entries = [
      { name: 'dangling.lnk', size: 0, is_dir: false, is_symlink: true, broken_link: true, date: '', mtime: 1700000000, permissions: 'lrwxrwxrwx', owner: '1000', group: '1000' },
      { name: 'dir_alias', size: 0, is_dir: true, is_symlink: true, broken_link: false, date: '2026-11-20 12:00', mtime: 1700000000, permissions: 'lrwxrwxrwx', owner: '1000', group: '1000' },
      ...savedLocalEntries
    ];
    window.renderPane('local');
    const danglingRow = Array.from(doc.querySelectorAll('#localFileList tr')).find(r => r.dataset.name === 'dangling.lnk');
    const dirAliasRow = Array.from(doc.querySelectorAll('#localFileList tr')).find(r => r.dataset.name === 'dir_alias');
    check('local broken symlink renders link icon, broken-link class and mtime fallback date',
      !!danglingRow &&
      danglingRow.classList.contains('broken-link') &&
      danglingRow.children[0].textContent.includes('🔗') &&
      danglingRow.children[0].textContent.includes('(broken link)') &&
      danglingRow.children[2].textContent.trim().length > 0);
    check('directory symlink renders symlink icon instead of plain folder icon',
      !!dirAliasRow && dirAliasRow.children[0].textContent.includes('🔗'));

    window.focusPane('local');
    pageState.local.selection = new Set(['dangling.lnk']);
    await window.openProperties();
    const propHtml = doc.getElementById('propertiesBody').textContent;
    check('local Properties identifies broken symlink, owner:group and missing-target hint',
      propHtml.includes('Symbolic link') &&
      propHtml.includes('The file this link points at does not exist.'));
    window.closeModal('propertiesModal');

    // Delete a remote directory symlink (`is_dir: true, is_symlink: true`): payload must send `is_dir: false`.
    const savedRemoteEntries = pageState.remote.entries.slice();
    pageState.remote.entries = [
      { name: 'remote_dir_link', size: 0, is_dir: true, is_symlink: true, broken_link: false, date: '2026-11-20 12:00', mtime: 1700000000, permissions: 'lrwxrwxrwx' }
    ];
    pageState.remote.selection = new Set(['remote_dir_link']);
    const prevDelConfirm = confirmResult;
    confirmResult = true;
    responses['/api/remote/delete'] = { success: true };
    await window.deletePrompt('remote');
    const remoteDelCall = calls.filter(c => c.path === '/api/remote/delete').pop();
    const remoteDelBody = remoteDelCall ? JSON.parse(remoteDelCall.options.body) : {};
    check('deleting a remote directory symlink sends is_dir=false so only the link is unlinked',
      Array.isArray(remoteDelBody.names) &&
      remoteDelBody.names.length === 1 &&
      remoteDelBody.names[0].name === 'remote_dir_link' &&
      remoteDelBody.names[0].is_dir === false);
    confirmResult = prevDelConfirm;
    pageState.remote.entries = savedRemoteEntries;

    // Offline local `applyPropertiesRights` and `promptLink` work without an active remote tab.
    const savedTabs = pageState.tabs.slice();
    const savedActiveTab = pageState.activeTab;
    pageState.tabs = [];
    pageState.activeTab = null;
    await window.openProperties();
    doc.getElementById('propertiesMode').value = '0640';
    responses['/api/local/chmod'] = { success: true };
    await window.applyPropertiesRights('local', ['a.txt']);
    const offlineChmodCall = calls.filter(c => c.path === '/api/local/chmod').pop();
    check('local applyPropertiesRights works offline when no remote tab is open',
      !!offlineChmodCall && JSON.parse(offlineChmodCall.options.body).permissions === '0640');
    window.closeModal('propertiesModal');

    const prevPromptAnswer = window.prompt;
    window.prompt = () => 'a_offline.lnk';
    pageState.local.entries = savedLocalEntries;
    pageState.local.selection = new Set(['a.txt']);
    responses['/api/local/link'] = { success: true };
    await window.promptLink('local');
    const offlineLinkCall = calls.filter(c => c.path === '/api/local/link').pop();
    check('local promptLink works offline when no remote tab is open',
      !!offlineLinkCall && JSON.parse(offlineLinkCall.options.body).name === 'a_offline.lnk');
    window.prompt = prevPromptAnswer;
    pageState.tabs = savedTabs;
    pageState.activeTab = savedActiveTab;

    // Windows synchronized browsing (`navigateSync` with `..` on remote side navigates Windows local parent).
    const prevSyncLocalPath = pageState.local.path;
    const prevSyncRemotePath = pageState.remote.path;
    pageState.local.path = 'C:\\Users\\alice\\project';
    pageState.remote.path = '/srv/alice/project';
    let syncedLocalTarget = null;
    const origSyncInvoke = window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope && args.envelope.path.startsWith('/api/local/list')) {
        const params = new URLSearchParams(args.envelope.path.split('?')[1] || '');
        syncedLocalTarget = params.get('path');
        return { status: 200, payload: { path: syncedLocalTarget, entries: [] } };
      }
      return origSyncInvoke(cmd, args);
    };
    await window.navigateSync('remote', { name: '..', path: '/srv/alice' });
    check('navigateSync uses localParentPath on Windows local counterpart instead of corrupting to /',
      syncedLocalTarget === 'C:\\Users\\alice');
    window.__TAURI_INTERNALS__.invoke = origSyncInvoke;
    pageState.local.path = prevSyncLocalPath;
    pageState.remote.path = prevSyncRemotePath;
    await window.loadLocal('/tmp/slowlocal');
    await window.loadRemote('/tmp/slowremote');

    // Site Manager stored secret placeholders for tunnel password, tunnel passphrase, and proxy password.
    window.fillSiteForm({
      name: 'tunneled-site',
      protocol: 'sftp',
      host: 'example.com',
      port: 22,
      tunnel: true,
      has_tunnel_password: true,
      has_tunnel_passphrase: true,
      has_proxy_password: true
    });
    check('fillSiteForm sets stored-secret placeholders for tunnel and proxy credentials',
      doc.getElementById('siteTunnelPass').placeholder.includes('stored') &&
      doc.getElementById('siteTunnelPassphrase').placeholder.includes('stored') &&
      doc.getElementById('siteProxyPassword').placeholder.includes('stored'));

    // Modal shortcut isolation: openModal moves focus into the modal, and Backspace / F8 on activeElement do not mutate background panes.
    doc.getElementById('localPane').focus();
    window.openModal('siteModal');
    check('openModal moves activeElement inside the opened modal dialog',
      doc.getElementById('siteModal').contains(doc.activeElement));
    const localPathBeforeModalKey = pageState.local.path;
    const deleteCallsBeforeModalKey = calls.filter(c => c.path === '/api/local/delete' || c.path === '/api/remote/delete').length;
    doc.activeElement.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Backspace', bubbles: true, cancelable: true }));
    doc.activeElement.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F8', bubbles: true, cancelable: true }));
    await wait(30);
    check('background Commander shortcuts do not fire while a modal dialog holds focus',
      pageState.local.path === localPathBeforeModalKey &&
      calls.filter(c => c.path === '/api/local/delete' || c.path === '/api/remote/delete').length === deleteCallsBeforeModalKey);
    window.closeModal('siteModal');

    // Embedded terminal UTF-8 initialCommand + Escape forwarded to PTY + Ctrl+C copies canvas selection.
    const prevTermCore = window.LinSCPCore;
    const prevSessionTerm = responses['/api/session/terminal'];
    const prevTermInput = responses['/api/terminal/input'];
    const prevTermFrame = responses['/api/terminal/frame'];
    const prevTermClose = responses['/api/terminal/close'];
    let copiedEmbeddedText = '';
    let mockEmbeddedSelection = null;
    window.LinSCPCore = new Proxy(prevTermCore, {
      get(target, key) {
        if (key === 'hostCapabilities') {
          return () => Object.assign(target.hostCapabilities({ host: window }), { platform: 'android' });
        }
        if (key === 'terminalWindow') {
          return (opts) => ({
            get selection() { return mockEmbeddedSelection; },
            handleKey(ev) {
              if (ev.key === 'Escape') {
                ev.preventDefault();
                void window.LinSCPTransport.request('POST', '/api/terminal/input', {
                  terminal: opts.terminal, data: window.btoa('\x1b'), cols: 80, rows: 24
                });
                return true;
              }
              return false;
            },
            async copySelection() {
              copiedEmbeddedText = String(mockEmbeddedSelection || '');
              mockEmbeddedSelection = null;
              return copiedEmbeddedText;
            },
            async clearSelection() { mockEmbeddedSelection = null; },
            start() { return Promise.resolve(true); },
            write() {},
            stop() {},
            async close() {},
          });
        }
        const value = Reflect.get(target, key);
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });
    responses['/api/session/terminal'] = { success: true, terminal: 777, transport: 'ssh' };
    responses['/api/terminal/input'] = { success: true };
    responses['/api/terminal/frame'] = { success: true, dirty: false, alive: true };
    responses['/api/terminal/close'] = { success: true };
    const termInputCountBefore = calls.filter(c => c.path === '/api/terminal/input').length;
    const openedUtf8Term = await window.openTerminal(null, false, 'echo "สวัสดี"');
    const termInputsAfterOpen = calls.filter(c => c.path === '/api/terminal/input');
    const initialCmdDecoded = termInputsAfterOpen.length > termInputCountBefore
      ? Buffer.from(JSON.parse(termInputsAfterOpen[termInputsAfterOpen.length - 1].options.body).data, 'base64').toString('utf8')
      : '';
    check('openTerminal encodes UTF-8 initialCommand safely via utf8ToBase64',
      openedUtf8Term === true && initialCmdDecoded === 'echo "สวัสดี"\n');
    const termInputCountBeforeEsc = calls.filter(c => c.path === '/api/terminal/input').length;
    doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await wait(40);
    const termInputsAfterEsc = calls.filter(c => c.path === '/api/terminal/input');
    const escDecoded = termInputsAfterEsc.length > termInputCountBeforeEsc
      ? Buffer.from(JSON.parse(termInputsAfterEsc[termInputsAfterEsc.length - 1].options.body).data, 'base64').toString('utf8')
      : '';
    check('Escape inside active embedded terminal sends ESC to PTY without closing terminalModal',
      doc.getElementById('terminalModal').classList.contains('open') && escDecoded === '\x1b');
    mockEmbeddedSelection = 'selected canvas output';
    doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'c', ctrlKey: true, bubbles: true, cancelable: true }));
    await wait(30);
    check('Ctrl+C inside embedded terminal copies active canvas selection instead of sending SIGINT',
      copiedEmbeddedText === 'selected canvas output');
    const prevPromptEmbedded = window.prompt;
    const embeddedPrompts = [];
    window.prompt = question => { embeddedPrompts.push(question); return null; };
    const disconnectsBeforeEmbeddedF10 = calls.filter(c => c.path === '/api/session/disconnect').length;
    if (doc.activeElement && doc.activeElement !== doc.body && typeof doc.activeElement.blur === 'function') {
      doc.activeElement.blur();
    }
    doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: '-', bubbles: true, cancelable: true }));
    doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: '+', bubbles: true, cancelable: true }));
    doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'F10', bubbles: true, cancelable: true }));
    await wait(30);
    window.prompt = prevPromptEmbedded;
    check('Commander shortcuts (-, +, F10) never fire behind an open terminal modal even when body holds focus',
      embeddedPrompts.length === 0 &&
      calls.filter(c => c.path === '/api/session/disconnect').length === disconnectsBeforeEmbeddedF10);
    window.showTerminalCopyHelp();
    check('showTerminalCopyHelp opens #terminalHelpModal above #terminalModal',
      doc.getElementById('terminalHelpModal').classList.contains('open') &&
      doc.getElementById('terminalModal').classList.contains('open'));
    doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    await wait(20);
    check('Escape closes #terminalHelpModal while keeping #terminalModal open',
      !doc.getElementById('terminalHelpModal').classList.contains('open') &&
      doc.getElementById('terminalModal').classList.contains('open'));
    window.closeTerminal();
    await wait(40);
    window.LinSCPCore = prevTermCore;
    responses['/api/session/terminal'] = prevSessionTerm;
    responses['/api/terminal/input'] = prevTermInput;
    responses['/api/terminal/frame'] = prevTermFrame;
    responses['/api/terminal/close'] = prevTermClose;
  }

  // ---- Completed features: WebDAV ETag preconditions, external editor live sync, local tabs, desktop tunnels/tickets, Mark menu & site warnings ----
  {
    // Ensure a connected active remote tab is present for these checks.
    responses['/api/status'] = {
      external_editor_supported: true,
      tabs: [{
        id: 1,
        name: 'dav-main',
        connected: true,
        is_local: false,
        local_dir: '/work/local',
        remote_dir: '/remote/dav',
        session: { protocol: 'sftp', host: 'srv.example.test', port: 22 }
      }],
      active_tab: 1,
    };
    await window.eval('refreshStatus()');
    window.eval('state.externalEditorSupported = true');

    // 1. WebDAV ETag preconditions in #davToolsModal.
    window.openDavTools();
    doc.getElementById('davResourceName').value = 'report.xml';
    responses['/api/dav/etag'] = { success: true, path: '/remote/dav/report.xml', etag: '"v42"', missing: false };
    await window.getDavEtag();
    check('WebDAV Get ETag populates #davEtagValue and status',
      doc.getElementById('davEtagValue').value === '"v42"' &&
      doc.getElementById('davToolsStatus').textContent.includes('"v42"'));

    responses['/api/dav/etag'] = { success: true, path: '/remote/dav/report.xml', action: 'match', etag: '"v42"' };
    await window.setDavEtagPrecondition('match');
    const davMatchBody = JSON.parse(calls.filter(c => c.path === '/api/dav/etag').pop().options.body);
    check('WebDAV Require If-Match posts action=match and etag',
      davMatchBody.action === 'match' && davMatchBody.etag === '"v42"' && davMatchBody.name === 'report.xml');

    responses['/api/dav/etag'] = { success: true, path: '/remote/dav/report.xml', action: 'nomatch', etag: '"v42"' };
    await window.setDavEtagPrecondition('nomatch');
    const davNoMatchBody = JSON.parse(calls.filter(c => c.path === '/api/dav/etag').pop().options.body);
    check('WebDAV Require If-None-Match posts action=nomatch and etag',
      davNoMatchBody.action === 'nomatch' && davNoMatchBody.etag === '"v42"');

    responses['/api/dav/etag'] = { success: true, path: '/remote/dav/report.xml', action: 'clear' };
    await window.clearDavEtagPrecondition();
    const davClearBody = JSON.parse(calls.filter(c => c.path === '/api/dav/etag').pop().options.body);
    check('WebDAV Clear ETag rule posts action=clear',
      davClearBody.action === 'clear' && doc.getElementById('davToolsStatus').textContent.includes('Cleared'));
    window.closeModal('davToolsModal');
    delete responses['/api/dav/etag'];

    // 2. External editor Sync now & live reload when upload_count increments.
    responses['/api/remote/edit'] = {
      success: true,
      content: 'initial line\n',
      info: { size: 13, mtime: 1700000000, encoding: 'UTF-8', eol: 'lf', bom: false }
    };
    responses['/api/editor/external'] = { success: true, id: 'ext-99', editor: 'nvim', sessions: [{ id: 'ext-99', editor: 'nvim', upload_count: 0 }] };
    await window.openEditor('/remote/dav/notes.txt', 'remote', false);
    await window.openInExternalEditor();
    check('opening external editor reveals Sync now button',
      doc.getElementById('editorExternalSyncBtn').hidden === false &&
      doc.getElementById('editorExternalCloseBtn').hidden === false);

    responses['/api/remote/edit'] = {
      success: true,
      content: 'updated from external sync\n',
      info: { size: 27, mtime: 1700000005, encoding: 'UTF-8', eol: 'lf', bom: false }
    };
    responses['/api/editor/external/sync'] = { success: true, uploaded: true };
    responses['/api/editor/external'] = { success: true, sessions: [{ id: 'ext-99', editor: 'nvim', upload_count: 1 }] };
    await window.syncExternalEditorNow();
    const extSyncCall = calls.filter(c => c.path === '/api/editor/external/sync').pop();
    check('Sync now posts /api/editor/external/sync, reloads clean buffer and preserves externalId',
      !!extSyncCall &&
      JSON.parse(extSyncCall.options.body).id === 'ext-99' &&
      window.getEditorValue() === 'updated from external sync\n' &&
      window.eval('state.editor.externalId') === 'ext-99');

    responses['/api/remote/edit'] = {
      success: true,
      content: 'background watcher save\n',
      info: { size: 24, mtime: 1700000010, encoding: 'UTF-8', eol: 'lf', bom: false }
    };
    responses['/api/editor/external'] = { success: true, sessions: [{ id: 'ext-99', editor: 'nvim', upload_count: 2 }] };
    await window.pollExternalEditorSessions();
    check('pollExternalEditorSessions reloads clean editor buffer when upload_count increments',
      window.getEditorValue() === 'background watcher save\n' &&
      window.eval('state.editor.externalId') === 'ext-99');
    responses['/api/editor/external/close'] = { success: true };
    await window.closeEditor();
    delete responses['/api/editor/external/sync'];

    // 3. New local-to-local tab quick action (/api/tabs/local).
    const prevPrompt = window.prompt;
    window.prompt = () => '/var/backups';
    responses['/api/tabs/local'] = {
      success: true,
      tab: { id: 42, name: 'local ↔ backups', is_local: true, connected: true, local_dir: '/work/local', remote_dir: '/var/backups' }
    };
    responses['/api/status'] = {
      external_editor_supported: true,
      tabs: [
        { id: 1, name: 'dav-main', connected: true, is_local: false, local_dir: '/work/local', remote_dir: '/remote/dav', session: { protocol: 'sftp', host: 'srv.example.test', port: 22 } },
        { id: 42, name: 'local ↔ backups', connected: true, is_local: true, local_dir: '/work/local', remote_dir: '/var/backups', session: { protocol: 'local', local_dir: '/work/local', other_local_dir: '/var/backups' } }
      ],
      active_tab: 42,
    };
    await window.openNewLocalTabPrompt();
    const localTabCall = calls.filter(c => c.path === '/api/tabs/local').pop();
    check('openNewLocalTabPrompt posts /api/tabs/local and activates the new dual-local tab',
      !!localTabCall &&
      JSON.parse(localTabCall.options.body).other_local_dir === '/var/backups' &&
      window.eval('state.activeTab') === 42);
    // Switch active tab back to SSH tab 1 for Remote Desktop tests.
    responses['/api/status'].active_tab = 1;
    await window.eval('refreshStatus()');
    delete responses['/api/tabs/local'];

    // 4. Remote Desktop active tunnels, recommendations & SPICE .vv ticket download.
    responses['/api/desktop/tunnels'] = {
      success: true,
      active: 1,
      tunnels: [{ tunnel_id: 7, tab: 1, local_endpoint: '127.0.0.1:45900' }]
    };
    responses['/api/desktop/recommendations'] = {
      success: true,
      recommendations: 'RDP: xfreerdp3\nSPICE: virt-viewer (remote-viewer)\n'
    };
    responses['/api/desktop/check'] = { success: true, available: true, checked: true, via_ssh: true };
    responses['/api/desktop/ticket'] = {
      success: true,
      tab: 1,
      ticket: {
        kind: 'spice',
        target: 'srv.example.test:5900',
        file_extension: '.vv',
        file_content: '[virt-viewer]\ntype=spice\nhost=srv.example.test\nport=5900\n',
        has_file: true
      }
    };
    let createdBlobUrl = false;
    const prevCreateObjectUrl = window.URL && window.URL.createObjectURL;
    const prevRevokeObjectUrl = window.URL && window.URL.revokeObjectURL;
    if (window.URL) {
      window.URL.createObjectURL = () => { createdBlobUrl = true; return 'blob:linscp-spice-test'; };
      window.URL.revokeObjectURL = () => {};
    }
    window.openRemoteDesktop(1);
    await wait(40);
    doc.getElementById('remoteDesktopKind').value = 'spice';
    window.remoteDesktopKindChanged();
    await wait(40);
    check('Remote Desktop modal loads active tunnel Close button and SPICE viewer recommendation',
      doc.getElementById('remoteDesktopCloseTunnelBtn').style.display === 'inline-block' &&
      doc.getElementById('remoteDesktopViewerHint').textContent.includes('SPICE: virt-viewer'));
    await window.downloadRemoteDesktopTicket();
    const ticketCall = calls.filter(c => c.path === '/api/desktop/ticket').pop();
    check('Download ticket posts /api/desktop/ticket with kind=spice and triggers .vv blob download',
      !!ticketCall &&
      JSON.parse(ticketCall.options.body).kind === 'spice' &&
      createdBlobUrl === true);
    if (window.URL) {
      window.URL.createObjectURL = prevCreateObjectUrl;
      window.URL.revokeObjectURL = prevRevokeObjectUrl;
    }
    window.closeModal('remoteDesktopModal');
    delete responses['/api/desktop/tunnels'];
    delete responses['/api/desktop/recommendations'];
    delete responses['/api/desktop/ticket'];

    // 5. Commander Mark menu: select/unselect by mask & compareDirectories.
    window.eval(`
      state.focusPane = 'local';
      state.local.entries = [
        { name: 'app.log', size: 120, mtime: 200, is_dir: false, permissions: '-rw-r--r--' },
        { name: 'debug.log', size: 80, mtime: 100, is_dir: false, permissions: '-rw-r--r--' },
        { name: 'same.txt', size: 50, mtime: 150, is_dir: false, permissions: '-rw-r--r--' }
      ];
      state.remote.entries = [
        { name: 'app.log', size: 100, mtime: 150, is_dir: false, permissions: '-rw-r--r--' },
        { name: 'same.txt', size: 50, mtime: 150, is_dir: false, permissions: '-rw-r--r--' },
        { name: 'remote-only.conf', size: 30, mtime: 180, is_dir: false, permissions: '-rw-r--r--' }
      ];
      state.local.selection.clear();
      state.remote.selection.clear();
    `);
    window.prompt = () => '*.log|debug.log';
    window.selectByMaskPrompt(true);
    check('selectByMaskPrompt honors include and |exclude wildcard masks',
      window.eval('state.local.selection.has("app.log") && !state.local.selection.has("debug.log") && !state.local.selection.has("same.txt")'));
    window.prompt = () => '*.log';
    window.selectByMaskPrompt(false);
    check('selectByMaskPrompt(false) unselects matching entries',
      window.eval('state.local.selection.size === 0'));
    window.compareDirectories();
    check('compareDirectories selects missing and newer entries on both panes',
      window.eval('state.local.selection.has("app.log") && state.local.selection.has("debug.log") && !state.local.selection.has("same.txt")') &&
      window.eval('state.remote.selection.has("remote-only.conf") && !state.remote.selection.has("same.txt") && !state.remote.selection.has("app.log")'));
    window.prompt = prevPrompt;

    // 6. Unreadable stored secret warning in Site Manager & session import directory preview.
    const brokenSite = {
      name: 'broken-vault-site',
      protocol: 'sftp',
      host: 'vault.example.test',
      port: 22,
      username: 'ops',
      has_password: true,
      has_unreadable_credential: true
    };
    window.eval(`state.sessions = [${JSON.stringify(brokenSite)}]; renderSites();`);
    window.fillSiteForm(brokenSite);
    check('Site Manager marks unreadable stored secrets in site list and password placeholder',
      doc.getElementById('siteList').textContent.includes('⚠') &&
      doc.getElementById('sitePass').placeholder.includes('unreadable'));

    window.renderImportSource({
      exists: true,
      path: '/home/ops/.config/filezilla/sitemanager.xml',
      entries: [{
        name: 'prod-web',
        protocol: 'sftp',
        host: 'web.example.test',
        port: 22,
        username: 'deploy',
        remote_dir: '/srv/www',
        local_dir: '/home/ops/www'
      }],
      skipped: []
    });
    check('renderImportSource displays imported remote_dir and local_dir paths',
      doc.getElementById('importList').textContent.includes('/srv/www') &&
      doc.getElementById('importList').textContent.includes('(/home/ops/www)'));

    // --- Batch 2 feature completion tests ---
    // 1. Sortable file table columns + hidden files toggle + quick filter.
    window.eval(`
      state.showHidden = true;
      state.local.sortKey = null;
      state.local.sortDir = 'asc';
      state.local.filter = '';
      state.local.entries = [
        { name: '.env', is_dir: false, size: 120, mtime: 100, permissions: 'rw-------' },
        { name: 'zeta.rs', is_dir: false, size: 900, mtime: 300, permissions: 'rw-r--r--' },
        { name: 'alpha.txt', is_dir: false, size: 200, mtime: 500, permissions: 'rwxr-xr-x' },
        { name: 'docs', is_dir: true, size: 0, mtime: 50, permissions: 'rwxr-xr-x' }
      ];
      state.local.selection.clear();
      state.local.selection.add('.env');
      renderPane('local');
    `);
    window.togglePaneSort('local', 'size');
    const localSizeAscNames = Array.from(doc.querySelectorAll('#localFileList tr')).map(r => r.dataset.name);
    const sizeHeader = doc.querySelector('#localPane thead th[data-sort-col="size"]');
    check('Clicking Size header sorts directories first then files ascending with aria-sort',
      JSON.stringify(localSizeAscNames) === JSON.stringify(['docs', '.env', 'alpha.txt', 'zeta.rs']) &&
      sizeHeader.getAttribute('aria-sort') === 'ascending' &&
      sizeHeader.dataset.sortIndicator === '▲');
    window.togglePaneSort('local', 'size');
    const localSizeDescNames = Array.from(doc.querySelectorAll('#localFileList tr')).map(r => r.dataset.name);
    check('Clicking Size header again flips sort descending while keeping directories first',
      JSON.stringify(localSizeDescNames) === JSON.stringify(['docs', 'zeta.rs', 'alpha.txt', '.env']) &&
      sizeHeader.getAttribute('aria-sort') === 'descending' &&
      sizeHeader.dataset.sortIndicator === '▼');

    window.toggleHiddenFiles();
    const afterHideNames = Array.from(doc.querySelectorAll('#localFileList tr')).map(r => r.dataset.name);
    check('toggleHiddenFiles hides dotfiles, updates menu label, and prunes hidden selection',
      !afterHideNames.includes('.env') &&
      doc.getElementById('hiddenFilesMenuLabel').textContent === 'Show hidden files' &&
      !window.eval('state.local.selection.has(".env")'));
    window.toggleHiddenFiles();

    window.setPaneFilter('local', '*.rs');
    const filteredWildcard = Array.from(doc.querySelectorAll('#localFileList tr')).map(r => r.dataset.name);
    check('setPaneFilter supports wildcard masks in the pane quick filter',
      JSON.stringify(filteredWildcard) === JSON.stringify(['zeta.rs']));
    window.setPaneFilter('local', '');
    window.eval('state.local.sortKey = null; state.local.sortDir = "asc"; renderPane("local");');

    // 2. Right-click file pane context menu.
    const alphaRow = doc.querySelector('#localFileList tr[data-name="alpha.txt"]');
    const ctxEvt = new window.MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 80, clientY: 90 });
    alphaRow.dispatchEvent(ctxEvt);
    check('Right-clicking a file row selects it and opens #paneContextMenu with enabled file actions',
      !doc.getElementById('paneContextMenu').hidden &&
      window.eval('state.local.selection.has("alpha.txt")') &&
      !doc.getElementById('paneCtxEditBtn').disabled &&
      !doc.getElementById('paneCtxCopyPathBtn').disabled);
    doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
    check('Pressing Escape closes #paneContextMenu',
      doc.getElementById('paneContextMenu').hidden);

    // 3. Site Manager Remote Desktop options + Session color & notes + RDP connect opens launcher.
    responses['/api/sessions/save'] = { success: true };
    responses['/api/sessions'] = {
      success: true,
      sessions: [{
        name: 'corp-rdp',
        protocol: 'rdp',
        host: 'win.example.test',
        port: 3389,
        username: 'alice',
        color: '#3b82f6',
        note: 'Primary Windows jump host',
        rdp_domain: 'CORP',
        rdp_security: 'nla',
        rdp_color_depth: '32',
        rdp_width: '1920',
        rdp_height: '1080',
        rdp_fullscreen: '1',
        has_password: true
      }]
    };
    window.newSite();
    doc.getElementById('siteName').value = 'corp-rdp';
    doc.getElementById('siteProtocol').value = 'rdp';
    window.siteProtocolChanged();
    check('Selecting RDP in Site Manager reveals #siteDesktopSettings and RDP-specific controls',
      doc.getElementById('siteDesktopSettings').style.display !== 'none' &&
      doc.querySelector('#siteDesktopSettings .desktop-opt-rdp').style.display !== 'none' &&
      doc.querySelector('#siteDesktopSettings .desktop-opt-vnc').style.display === 'none');
    doc.getElementById('siteHost').value = 'win.example.test';
    doc.getElementById('siteColor').value = '#3b82f6';
    doc.getElementById('siteNote').value = 'Primary Windows jump host';
    doc.getElementById('siteRdpDomain').value = 'CORP';
    doc.getElementById('siteRdpSecurity').value = 'nla';
    doc.getElementById('siteRdpColorDepth').value = '32';
    doc.getElementById('siteRdpWidth').value = '1920';
    doc.getElementById('siteRdpHeight').value = '1080';
    doc.getElementById('siteRdpFullscreen').checked = true;
    await window.saveSite();
    const savedRdpCall = calls.filter(c => c.path === '/api/sessions/save').pop();
    const savedRdpBody = savedRdpCall ? JSON.parse(savedRdpCall.options.body) : {};
    check('Saving an RDP site persists DesktopOptions, color swatch, and session note',
      savedRdpBody.session &&
      savedRdpBody.session.color === '#3b82f6' &&
      savedRdpBody.session.note === 'Primary Windows jump host' &&
      savedRdpBody.session.rdp_domain === 'CORP' &&
      savedRdpBody.session.rdp_security === 'nla' &&
      savedRdpBody.session.rdp_color_depth === '32' &&
      savedRdpBody.session.rdp_width === '1920' &&
      savedRdpBody.session.rdp_fullscreen === true &&
      !!doc.querySelector('#siteList .site-color-swatch'));

    const prevOpenResp = responses['/api/tabs/open'];
    const prevStatusResp = responses['/api/status'];
    responses['/api/tabs/open'] = {
      success: true,
      tab: { id: 9, name: 'corp-rdp', connected: true, protocol: 'rdp', session: { protocol: 'rdp', host: 'win.example.test', port: 3389, color: '#3b82f6' } }
    };
    responses['/api/status'] = Object.assign({}, prevStatusResp, {
      active_tab: 9,
      tabs: [{ id: 9, name: 'corp-rdp', connected: true, protocol: 'rdp', site: 'corp-rdp', session: { protocol: 'rdp', host: 'win.example.test', port: 3389, color: '#3b82f6' }, local_dir: '/tmp/slowlocal', remote_dir: '/' }]
    });
    doc.getElementById('siteRemember').checked = false;
    doc.getElementById('sitePass').value = '';
    await window.connectFromSiteManager();
    const rdpOpenCall = calls.filter(c => c.path === '/api/tabs/open').pop();
    const rdpOpenBody = rdpOpenCall ? JSON.parse(rdpOpenCall.options.body) : {};
    check('Connecting an RDP site sends clear_password when Remember is unticked, colors the tab, and opens #remoteDesktopModal',
      rdpOpenBody.session && rdpOpenBody.session.clear_password === true &&
      doc.getElementById('remoteDesktopModal').classList.contains('open') &&
      doc.getElementById('remoteDesktopKind').value === 'rdp' &&
      doc.getElementById('remoteDesktopHost').value === 'win.example.test' &&
      doc.querySelector('#tabStrip .session-tab').dataset.color === '#3b82f6');
    window.closeModal('remoteDesktopModal');
    responses['/api/tabs/open'] = prevOpenResp;
    responses['/api/status'] = prevStatusResp;
    await window.refreshStatus();

    // 4. Built-in CLI command console history, Tab completion, and clear.
    responses['/api/command/exec'] = { success: true, stdout: 'ok\n', stderr: '', exit_code: 0 };
    const cliInput = doc.getElementById('cliInput');
    cliInput.value = 'pwd';
    await window.execCliCommand();
    cliInput.value = 'stat alpha.txt';
    await window.execCliCommand();
    cliInput.value = 'draft';
    window.handleCliInputKeydown(new window.KeyboardEvent('keydown', { key: 'ArrowUp', cancelable: true }));
    const up1 = cliInput.value;
    window.handleCliInputKeydown(new window.KeyboardEvent('keydown', { key: 'ArrowUp', cancelable: true }));
    const up2 = cliInput.value;
    window.handleCliInputKeydown(new window.KeyboardEvent('keydown', { key: 'ArrowDown', cancelable: true }));
    window.handleCliInputKeydown(new window.KeyboardEvent('keydown', { key: 'ArrowDown', cancelable: true }));
    const restoredDraft = cliInput.value;
    cliInput.value = 'syn';
    window.handleCliInputKeydown(new window.KeyboardEvent('keydown', { key: 'Tab', cancelable: true }));
    const tabCompleted = cliInput.value;
    cliInput.value = 'clear';
    await window.execCliCommand();
    check('CLI console supports ArrowUp/ArrowDown history with draft preservation, Tab completion, and clear',
      up1 === 'stat alpha.txt' &&
      up2 === 'pwd' &&
      restoredDraft === 'draft' &&
      tabCompleted === 'synchronize ' &&
      doc.getElementById('cliOutput').textContent === '');

    // --- Batch 3 feature completion tests ---
    // 1. Transfer Presets: auto-matched banner, string preserve_time/permissions/eol/rules round-trip, and fill-from-tab.
    responses['/api/presets'] = {
      success: true,
      matched: { name: 'ProdWeb' },
      presets: [{
        name: 'ProdWeb',
        description: 'transfer=ascii preservetime=all permissions=644 for host=*.prod.example.com',
        transfer: 'ascii',
        preserve_time: 'all',
        newer_only: true,
        speed: 512,
        resumesupport: '256',
        permissions: '644',
        eol: 'crlf',
        filemask: '*.html;*.css',
        host: '*.prod.example.com',
        username: 'deploy',
        remote_dir: '/var/www/*',
        local_dir: '/srv/releases/*'
      }]
    };
    responses['/api/presets/save'] = { success: true, preset: { name: 'ProdWeb' } };
    window.openTransferSettings();
    await window.loadTransferPresets();
    check('loadTransferPresets renders auto-matched preset banner for current tab',
      doc.getElementById('transferPresetMatchedHint').style.display === 'flex' &&
      doc.getElementById('transferPresetMatchedHint').textContent.includes('ProdWeb'));
    window.applyMatchedTransferPreset();
    check('applyMatchedTransferPreset populates permissions, octal mode, EOL, preserve_time=all, and auto-selection rules',
      doc.getElementById('transferPresetSelect').value === 'ProdWeb' &&
      doc.getElementById('transferPreserveTime').checked === true &&
      doc.getElementById('transferPresetPermissions').value === 'mode' &&
      doc.getElementById('transferPresetModeOctal').value === '644' &&
      doc.getElementById('transferPresetEol').value === 'crlf' &&
      doc.getElementById('transferPresetHost').value === '*.prod.example.com' &&
      doc.getElementById('transferPresetUser').value === 'deploy' &&
      doc.getElementById('transferPresetRemoteDir').value === '/var/www/*' &&
      doc.getElementById('transferPresetLocalDir').value === '/srv/releases/*' &&
      doc.getElementById('transferPresetSummary').textContent.includes('permissions=644'));
    await window.saveCurrentTransferPreset();
    const fullPresetSaveBody = JSON.parse(calls.filter(c => c.path === '/api/presets/save').pop().options.body);
    check('saveCurrentTransferPreset preserves permissions, eol, preserve_time=all, and auto-selection rules without data loss',
      fullPresetSaveBody.name === 'ProdWeb' &&
      fullPresetSaveBody.preserve_time === 'all' &&
      fullPresetSaveBody.permissions === '644' &&
      fullPresetSaveBody.eol === 'crlf' &&
      fullPresetSaveBody.host === '*.prod.example.com' &&
      fullPresetSaveBody.username === 'deploy' &&
      fullPresetSaveBody.remote_dir === '/var/www/*' &&
      fullPresetSaveBody.local_dir === '/srv/releases/*');
    doc.getElementById('transferPresetHost').value = '';
    doc.getElementById('transferPresetLocalDir').value = '';
    window.fillPresetRulesFromActiveTab();
    check('fillPresetRulesFromActiveTab populates host and local/remote paths from the active tab',
      doc.getElementById('transferPresetHost').value === 'srv.example.test' &&
      Boolean(doc.getElementById('transferPresetLocalDir').value));
    await window.resetTransferSettings();
    window.closeModal('transferModal');
    delete responses['/api/presets'];
    delete responses['/api/presets/save'];

    // 2. S3 Object Versions: side-by-side target_name download + overwrite confirmation prompt on 409 conflicts.
    responses['/api/s3/version-download'] = { success: true, task_id: 301 };
    await window.downloadS3VersionCopy('reports/monthly.csv', 'v12345');
    const s3CopyBody = JSON.parse(calls.filter(c => c.path === '/api/s3/version-download').pop().options.body);
    check('downloadS3VersionCopy suggests a versioned leaf filename and posts target_name',
      s3CopyBody.target_name === 'monthly.v-v12345.csv' &&
      doc.getElementById('s3VersionsTargetName').value === 'monthly.v-v12345.csv');
    doc.getElementById('s3VersionsTargetName').value = '';
    const prevConfirm = window.confirm;
    let s3DownloadAttempts = 0;
    const origInvokeS3 = window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope && args.envelope.path === '/api/s3/version-download') {
        s3DownloadAttempts++;
        const body = args.envelope.body || {};
        calls.push({ path: '/api/s3/version-download', options: { method: 'POST', body: JSON.stringify(body) } });
        if (body.overwrite !== 'overwrite') {
          return { status: 409, payload: { success: false, error: 'Destination exists', conflicts: ['monthly.csv'] } };
        }
        return { status: 200, payload: { success: true, task_id: 302 } };
      }
      return origInvokeS3(cmd, args);
    };
    window.confirm = () => false;
    await window.downloadS3Version('monthly.csv', 'v12345');
    check('downloadS3Version aborts overwrite when user declines overwrite confirmation',
      s3DownloadAttempts === 1);
    s3DownloadAttempts = 0;
    let confirmPromptText = '';
    window.confirm = (msg) => { confirmPromptText = String(msg || ''); return true; };
    await window.downloadS3Version('monthly.csv', 'v12345');
    check('downloadS3Version prompts with conflict filename and retries with overwrite when confirmed',
      s3DownloadAttempts === 2 && confirmPromptText.includes('monthly.csv'));
    window.confirm = prevConfirm;
    window.__TAURI_INTERNALS__.invoke = origInvokeS3;
    delete responses['/api/s3/version-download'];

    // 3. Session Import File Picker: content-based scan + import + omitted external key notice.
    const origInvokeImport = window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope && args.envelope.path === '/api/sessions/import' && args.envelope.method === 'POST') {
        const body = args.envelope.body || {};
        calls.push({ path: '/api/sessions/import', options: { method: 'POST', body: JSON.stringify(body) } });
        if (body.scan_only) {
          return {
            status: 200,
            payload: {
              success: true,
              sources: [{
                source: body.source,
                path: body.file_name,
                exists: true,
                fingerprint: 'fp-picked-xml',
                entries: [{
                  name: 'fz-mobile',
                  protocol: 'sftp',
                  host: 'fz.example.test',
                  port: 22,
                  username: 'alice',
                  has_external_key: true
                }],
                skipped: []
              }]
            }
          };
        }
        return {
          status: 200,
          payload: {
            success: true,
            path: body.file_name,
            imported: ['fz-mobile'],
            skipped: [],
            omitted_keys: ['fz-mobile']
          }
        };
      }
      return origInvokeImport(cmd, args);
    };
    doc.getElementById('importSource').value = 'openssh';
    await window.handleImportFilePicked({
      target: {
        value: 'sitemanager.xml',
        files: [{
          name: 'sitemanager.xml',
          size: 180,
          text: async () => '<FileZilla3><Servers></Servers></FileZilla3>'
        }]
      }
    });
    check('Picking an XML file in #importSessionsModal auto-selects FileZilla, scans content, and flags external keys',
      doc.getElementById('importSource').value === 'filezilla' &&
      doc.getElementById('importPath').value === 'sitemanager.xml' &&
      doc.getElementById('importList').textContent.includes('fz-mobile') &&
      doc.getElementById('importList').textContent.includes('external key omitted'));
    await window.runSessionImport();
    const pickedImportPost = JSON.parse(calls.filter(c => c.path === '/api/sessions/import').pop().options.body);
    check('runSessionImport posts picked file content + fingerprint and surfaces omitted external key notice',
      pickedImportPost.file_name === 'sitemanager.xml' &&
      pickedImportPost.fingerprint === 'fp-picked-xml' &&
      typeof pickedImportPost.content === 'string' &&
      doc.getElementById('importStatus').textContent.includes('fz-mobile'));
    window.__TAURI_INTERNALS__.invoke = origInvokeImport;

    // 4. Transfer Queue full reordering controls (Top, Up, Down, Bottom).
    const prevTransfers = responses['/api/transfers'];
    responses['/api/transfers'] = {
      paused: false,
      transfers: [
        { id: 41, type: 'Download', source: '/a', destination: '/b', status: 'Running', percent: 50, bytes_done: 50, bytes_total: 100 },
        { id: 42, type: 'Download', source: '/c', destination: '/d', status: 'Queued', percent: 0 },
        { id: 43, type: 'Upload', source: '/e', destination: '/f', status: 'Queued', percent: 0 }
      ]
    };
    await window.refreshQueue();
    const queueRows = doc.querySelectorAll('#queueList tr');
    const firstQueuedBtns = Array.from(queueRows[1].querySelectorAll('button'));
    const lastQueuedBtns = Array.from(queueRows[2].querySelectorAll('button'));
    check('Queued tasks expose Top/Up/Down/Bottom controls with boundary buttons disabled appropriately',
      firstQueuedBtns.some(b => b.textContent === 'Top' && b.disabled) &&
      firstQueuedBtns.some(b => b.textContent === 'Up' && b.disabled) &&
      firstQueuedBtns.some(b => b.textContent === 'Down' && !b.disabled) &&
      firstQueuedBtns.some(b => b.textContent === 'Bottom' && !b.disabled) &&
      lastQueuedBtns.some(b => b.textContent === 'Up' && !b.disabled) &&
      lastQueuedBtns.some(b => b.textContent === 'Down' && b.disabled));
    await window.prioritizeTask(42, 'down');
    const downCall = JSON.parse(calls.filter(c => c.path === '/api/queue/priority').pop().options.body);
    check('prioritizeTask supports down/up/bottom queue ordering',
      downCall.task_id === 42 && downCall.position === 'down');
    responses['/api/transfers'] = prevTransfers;
    await window.refreshQueue();

    // 5. Synchronize criteria parity + 6. Search result direct Go/View/Edit buttons.
    const syncCriteriaValues = Array.from(doc.getElementById('syncCriteria').options).map(o => o.value);
    check('#syncCriteria includes size,checksum and time,size,checksum options',
      syncCriteriaValues.includes('size,checksum') &&
      syncCriteriaValues.includes('time,size,checksum'));

    responses['/api/remote/search'] = {
      success: true,
      matches: [
        { name: 'notes.txt', path: '/tmp/slowremote/notes.txt', is_dir: false, size: 42, line: 3, snippet: 'hello' },
        { name: 'subdir', path: '/tmp/slowremote/subdir', is_dir: true, size: 0 }
      ]
    };
    responses['/api/remote/edit'] = {
      success: true,
      path: '/tmp/slowremote/notes.txt',
      content: 'hello\n',
      info: { size: 6, mtime: 1791875271, mtime_ns: '1791875271', encoding: 'UTF-8', eol: 'lf', bom: false }
    };
    doc.getElementById('searchTarget').value = 'remote';
    doc.getElementById('searchContents').checked = false;
    window.toggleSearchContents();
    await window.runSearch();
    const searchRows = doc.querySelectorAll('#searchResults .plan-item');
    const fileMatchBtns = Array.from(searchRows[0].querySelectorAll('.search-match-actions button')).map(b => b.textContent);
    const dirMatchBtns = Array.from(searchRows[1].querySelectorAll('.search-match-actions button')).map(b => b.textContent);
    check('Search results render Go/View/Edit buttons for files and Go for directories',
      JSON.stringify(fileMatchBtns) === JSON.stringify(['Go', 'View', 'Edit']) &&
      JSON.stringify(dirMatchBtns) === JSON.stringify(['Go']));
    searchRows[0].querySelectorAll('.search-match-actions button')[2].click();
    await new Promise(resolve => setTimeout(resolve, 60));
    check('Clicking Edit on a search result opens #editorModal in editable mode',
      doc.getElementById('editorModal').classList.contains('open') &&
      doc.getElementById('editorSaveBtn').style.display !== 'none');
    window.closeEditor();

    // 7. Properties visual POSIX permissions matrix, recursive chmod, and directory size calculation.
    const origInvokeProps = window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope && args.envelope.path === '/api/remote/properties') {
        const bodyObj = typeof args.envelope.body === 'string' ? JSON.parse(args.envelope.body) : (args.envelope.body || {});
        calls.push({ path: args.envelope.path, options: { method: 'POST', body: JSON.stringify(bodyObj) } });
        if (bodyObj.calculate_size) {
          return {
            status: 200,
            payload: {
              success: true,
              properties: [{
                name: 'subdir', path: '/tmp/slowremote/subdir', is_dir: true,
                size: 0, mode: 0o755, permissions: 'drwxr-xr-x',
                total_size: 20480, file_count: 5, dir_count: 2, truncated: false
              }]
            }
          };
        }
        return {
          status: 200,
          payload: {
            success: true,
            properties: [{
              name: 'subdir', path: '/tmp/slowremote/subdir', is_dir: true,
              size: 0, mode: 0o755, permissions: 'drwxr-xr-x', owner: '1000', group: '1000'
            }]
          }
        };
      }
      return origInvokeProps(cmd, args);
    };
    const wfState = window.eval('state');
    const savedWfRemoteEntries = wfState.remote.entries.slice();
    const savedWfRemoteSel = new Set(wfState.remote.selection);
    const savedWfTabs = wfState.tabs.slice();
    const savedWfActiveTab = wfState.activeTab;
    wfState.tabs = [{ id: 'tab-wf-remote', name: 'wf-sftp', protocol: 'sftp', connected: true, is_local: false }];
    wfState.activeTab = 'tab-wf-remote';
    wfState.remote.path = '/tmp/slowremote';
    wfState.remote.entries = [
      { name: 'subdir', is_dir: true, size: 0, permissions: 'drwxr-xr-x', mtime: 1791875271 },
      { name: 'notes.txt', is_dir: false, size: 42, permissions: '-rw-r--r--', mtime: 1791875271 }
    ];
    wfState.remote.selection = new Set(['subdir']);
    window.focusPane('remote');
    await window.openProperties();
    check('Properties dialog renders POSIX rights matrix and recursive checkbox for directories',
      !!doc.getElementById('propertiesRightsMatrix') &&
      !!doc.getElementById('propertiesRecursive') &&
      doc.getElementById('propertiesMode').value === '755' &&
      doc.getElementById('propRight_ur').checked &&
      !doc.getElementById('propRight_gw').checked);
    doc.getElementById('propRight_gw').checked = true;
    doc.getElementById('propRight_gw').onchange();
    doc.getElementById('propRight_suid').checked = true;
    doc.getElementById('propRight_suid').onchange();
    check('Toggling permission checkboxes updates #propertiesMode octal value including special bits',
      doc.getElementById('propertiesMode').value === '4775');
    doc.getElementById('propertiesMode').value = '0750';
    doc.getElementById('propertiesMode').oninput();
    check('Typing octal mode into #propertiesMode syncs checkboxes two-way',
      !doc.getElementById('propRight_suid').checked &&
      !doc.getElementById('propRight_gw').checked &&
      !doc.getElementById('propRight_or').checked &&
      doc.getElementById('propRight_gr').checked);
    const calcBtn = doc.querySelector('#propertiesBody .prop-calc-size-btn');
    calcBtn.click();
    await new Promise(resolve => setTimeout(resolve, 40));
    check('Calculate size button fetches recursive directory totals and updates Properties table',
      doc.querySelector('#propertiesBody .prop-size-text').textContent.includes('5 files, 2 folders') &&
      doc.getElementById('propBytes_0').textContent === '20480');
    responses['/api/remote/rights'] = { success: true };
    doc.getElementById('propertiesRecursive').checked = true;
    await window.applyPropertiesRights('remote', ['subdir']);
    const recRightsBody = JSON.parse(calls.filter(c => c.path === '/api/remote/rights').pop().options.body);
    check('applyPropertiesRights forwards recursive=true when #propertiesRecursive is checked',
      recRightsBody.recursive === true && recRightsBody.mode === '0750');
    window.closeModal('propertiesModal');
    window.__TAURI_INTERNALS__.invoke = origInvokeProps;

    // 8. Selective Synchronize preview checkboxes + transfer options.
    const prevSyncPreview = responses['/api/sync/preview'];
    const prevSyncRun = responses['/api/sync/run'];
    responses['/api/sync/preview'] = {
      success: true,
      plan: {
        summary: { upload: 1, 'delete-remote': 2 },
        items: [
          { action: 'upload', path: 'fresh.txt', is_dir: false, size: 10, reason: 'New local file' },
          { action: 'delete-remote', path: 'obsolete_dir', is_dir: true, size: 0, reason: 'Deleted locally' },
          { action: 'delete-remote', path: 'obsolete_dir/keep.txt', is_dir: false, size: 5, reason: 'Deleted locally' }
        ]
      }
    };
    responses['/api/sync/run'] = { success: true, task_id: 99 };
    window.openSynchronize();
    doc.getElementById('syncTransferMode').value = 'ascii';
    doc.getElementById('syncSpeed').value = '256';
    doc.getElementById('syncPreserveTime').checked = false;
    await window.previewSynchronization();
    const syncBoxes = doc.querySelectorAll('#syncPreview .sync-item-check');
    check('Synchronize preview renders per-item checkboxes and Select all / Clear all bar',
      syncBoxes.length === 3 && !!doc.querySelector('#syncSummary .plan-select-bar'));
    // Uncheck obsolete_dir/keep.txt -> parent obsolete_dir delete-remote must also be excluded.
    syncBoxes[2].checked = false;
    syncBoxes[2].onchange();
    check('Unchecking a child item also prevents deleting its parent directory in sync preview',
      !syncBoxes[1].checked && syncBoxes[0].checked &&
      doc.querySelectorAll('#syncPreview .plan-item.excluded').length === 2);
    const origConfirmSync = window.confirm;
    window.confirm = () => true;
    await window.runSynchronization();
    window.confirm = origConfirmSync;
    const syncRunBody = JSON.parse(calls.filter(c => c.path === '/api/sync/run').pop().options.body);
    check('runSynchronization forwards transfer options and excluded_paths',
      syncRunBody.transfer === 'ascii' &&
      syncRunBody.speed === 256 &&
      syncRunBody.preserve_time === false &&
      Array.isArray(syncRunBody.excluded_paths) &&
      syncRunBody.excluded_paths.includes('obsolete_dir/keep.txt') &&
      syncRunBody.excluded_paths.includes('obsolete_dir'));
    responses['/api/sync/preview'] = prevSyncPreview;
    responses['/api/sync/run'] = prevSyncRun;

    // 9. Keep Up to Date extended options.
    responses['/api/transfer/keepuptodate'] = { success: true, task_id: 100 };
    window.openKeepUpToDate();
    doc.getElementById('kudTransferMode').value = 'ascii';
    doc.getElementById('kudSpeed').value = '512';
    doc.getElementById('kudPreserveTime').checked = false;
    doc.getElementById('kudDelete').checked = true;
    doc.getElementById('kudContinueOnError').checked = true;
    await window.startKeepUpToDate();
    const kudBody = JSON.parse(calls.filter(c => c.path === '/api/transfer/keepuptodate').pop().options.body);
    check('startKeepUpToDate forwards transfer, speed, preserve_time, delete, and continue_on_error',
      kudBody.transfer === 'ascii' &&
      kudBody.speed === 512 &&
      kudBody.preserve_time === false &&
      kudBody.delete === true &&
      kudBody.continue_on_error === true);

    // 10. Site Manager extended S3, FTP, and TLS controls.
    window.fillSiteForm({
      name: 'MinIO Internal',
      protocol: 's3',
      host: 'minio.internal',
      port: 80,
      s3_protocol: '0',
      s3_multipart_threshold: '33554432',
      s3_min_part_size: '8388608',
      s3_request_payer: '1',
      ftp_force_pasv_ip: '2',
      ftp_use_mlsd: '2',
      ftp_account: 'billing',
      tls_certificate_key_file: '/etc/ssl/private/client.key',
      ca_certificate_dir: '/etc/ssl/certs'
    });
    check('fillSiteForm populates S3 HTTP, human-formatted multipart sizes, FTP PASV IP/3-state MLSD/ACCT, and TLS paths',
      doc.getElementById('siteS3Protocol').value === '0' &&
      doc.getElementById('sitePort').value === '80' &&
      doc.getElementById('siteS3MultipartThreshold').value === '32M' &&
      doc.getElementById('siteS3MinPartSize').value === '8M' &&
      doc.getElementById('siteS3RequestPayer').checked === true &&
      doc.getElementById('siteFtpPasvIp').value === '2' &&
      doc.getElementById('siteFtpMlsd').value === '2' &&
      doc.getElementById('siteFtpAccount').value === 'billing' &&
      doc.getElementById('siteTlsKey').value === '/etc/ssl/private/client.key' &&
      doc.getElementById('siteCaCertDir').value === '/etc/ssl/certs');
    doc.getElementById('siteS3Protocol').value = '1';
    window.siteS3ProtocolChanged();
    const s3FormOut = window.currentSiteForm();
    check('siteS3ProtocolChanged switches default port 80->443 and currentSiteForm serializes all extended fields',
      s3FormOut.port === 443 &&
      s3FormOut.s3_protocol === '1' &&
      s3FormOut.s3_multipart_threshold === '32M' &&
      s3FormOut.s3_min_part_size === '8M' &&
      s3FormOut.s3_request_payer === true &&
      s3FormOut.ftp_force_pasv_ip === '2' &&
      s3FormOut.ftp_use_mlsd === '2' &&
      s3FormOut.ftp_account === 'billing' &&
      s3FormOut.tls_certificate_key_file === '/etc/ssl/private/client.key' &&
      s3FormOut.ca_certificate_dir === '/etc/ssl/certs');

    // 11. Custom Commands description, apply_to_directories, fileless run, and pane context menu button.
    check('#paneContextMenu includes #paneCtxCustomCmdBtn', !!doc.getElementById('paneCtxCustomCmdBtn'));
    const origInvokeCmd = window.__TAURI_INTERNALS__.invoke;
    let savedCmdList = [
      { name: 'PrintPWD', command: 'pwd', description: 'Show remote working dir', scope: 'remote', apply_to_directories: false },
      { name: 'HashFiles', command: 'sha256sum {file}', description: 'Digest files only', scope: 'remote', apply_to_directories: false }
    ];
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope && args.envelope.path === '/api/custom-commands') {
        const b = typeof args.envelope.body === 'string' ? JSON.parse(args.envelope.body) : (args.envelope.body || {});
        calls.push({ path: args.envelope.path, options: { method: 'POST', body: JSON.stringify(b) } });
        if (b.action === 'list') {
          return { status: 200, payload: { success: true, commands: savedCmdList } };
        }
        if (b.action === 'save') {
          savedCmdList = [{ name: b.name, command: b.command, description: b.description, scope: b.scope, apply_to_directories: b.apply_to_directories }];
          return { status: 200, payload: { success: true, commands: savedCmdList } };
        }
        if (b.action === 'run') {
          return { status: 200, payload: { success: true, output: '/tmp/slowremote\n' } };
        }
      }
      return origInvokeCmd(cmd, args);
    };
    window.focusPane('remote');
    wfState.remote.entries = [
      { name: 'subdir', is_dir: true, size: 0, permissions: 'drwxr-xr-x', mtime: 1791875271 },
      { name: 'notes.txt', is_dir: false, size: 42, permissions: '-rw-r--r--', mtime: 1791875271 }
    ];
    wfState.remote.selection = new Set();
    await window.openCustomCommands();
    check('Custom commands list renders command descriptions',
      doc.getElementById('customCommandsList').textContent.includes('Show remote working dir'));
    window.selectCustomCommand(0);
    const origConfirmCmd = window.confirm;
    window.confirm = () => true;
    await window.runCustomCommand();
    const pwdRunCall = JSON.parse(calls.filter(c => c.path === '/api/custom-commands').pop().options.body);
    check('Fileless custom command runs even with empty selection',
      pwdRunCall.action === 'run' && pwdRunCall.name === 'PrintPWD' && Array.isArray(pwdRunCall.filenames) && pwdRunCall.filenames.length === 0);
    // Select both 'subdir' and 'notes.txt' and run 'HashFiles' (apply_to_directories=false).
    wfState.remote.entries = [
      { name: 'subdir', is_dir: true, size: 0, permissions: 'drwxr-xr-x', mtime: 1791875271 },
      { name: 'notes.txt', is_dir: false, size: 42, permissions: '-rw-r--r--', mtime: 1791875271 }
    ];
    wfState.remote.selection = new Set(['subdir', 'notes.txt']);
    window.selectCustomCommand(1);
    await window.runCustomCommand();
    window.confirm = origConfirmCmd;
    const hashRunCall = JSON.parse(calls.filter(c => c.path === '/api/custom-commands').pop().options.body);
    check('Custom command with apply_to_directories=false filters out directories from selection',
      hashRunCall.action === 'run' && hashRunCall.name === 'HashFiles' && JSON.stringify(hashRunCall.filenames) === JSON.stringify(['notes.txt']));
    doc.getElementById('customCmdDescription').value = 'Updated desc';
    doc.getElementById('customCmdDirs').checked = true;
    await window.saveCustomCommand();
    const saveCmdCall = JSON.parse(calls.filter(c => c.path === '/api/custom-commands').pop().options.body);
    check('saveCustomCommand persists description and apply_to_directories',
      saveCmdCall.description === 'Updated desc' && saveCmdCall.apply_to_directories === true);
    window.closeModal('customCommandsModal');
    window.__TAURI_INTERNALS__.invoke = origInvokeCmd;
    wfState.remote.entries = savedWfRemoteEntries;
    wfState.remote.selection = savedWfRemoteSel;
    wfState.tabs = savedWfTabs;
    wfState.activeTab = savedWfActiveTab;

    // 12. SSH Host Keys Manager (`/api/hostkeys` list, add, delete).
    const origInvokeHk = window.__TAURI_INTERNALS__.invoke;
    let mockHostKeys = [{
      host_port: 'bastion.example.test@22',
      host: 'bastion.example.test',
      port: 22,
      key_type: 'ssh-ed25519',
      fingerprint: 'SHA256:BastionKey1',
      pin: 'ssh-ed25519 SHA256:BastionKey1'
    }];
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope) {
        const p = args.envelope.path || '';
        const m = String(args.envelope.method || 'GET').toUpperCase();
        const b = typeof args.envelope.body === 'string' ? JSON.parse(args.envelope.body) : (args.envelope.body || {});
        if (p === '/api/hostkeys') {
          calls.push({ path: p, options: { method: m, body: JSON.stringify(b) } });
          if (m === 'GET') {
            return { status: 200, payload: { success: true, entries: mockHostKeys } };
          }
          if (b.action === 'add') {
            mockHostKeys.push({
              host_port: b.host.toLowerCase() + '@' + b.port,
              host: b.host.toLowerCase(),
              port: b.port,
              key_type: b.key_type,
              fingerprint: b.fingerprint,
              pin: b.key_type + ' ' + b.fingerprint
            });
            return { status: 200, payload: { success: true, entries: mockHostKeys } };
          }
          if (b.action === 'delete') {
            mockHostKeys = mockHostKeys.filter(e => !(e.host_port === b.host_port && e.key_type === b.key_type));
            return { status: 200, payload: { success: true, entries: mockHostKeys } };
          }
        }
        if (p === '/api/session/url' && m === 'POST') {
          calls.push({ path: p, options: { method: m, body: JSON.stringify(b) } });
          return {
            status: 200,
            payload: {
              success: true,
              session: {
                name: 'app.example.test',
                protocol: 'ftpes',
                host: 'app.example.test',
                port: 2121,
                username: 'deploy',
                password: 'url-secret',
                has_password: true,
                initial_dir: '/var/www',
                ftps: 'explicit'
              }
            }
          };
        }
      }
      return origInvokeHk(cmd, args);
    };
    await window.openHostKeysManager();
    check('SSH Host Keys modal renders cached host keys',
      doc.getElementById('hostKeysModal').classList.contains('open') &&
      doc.getElementById('hostKeysList').textContent.includes('bastion.example.test:22') &&
      doc.getElementById('hostKeysList').textContent.includes('SHA256:BastionKey1'));
    doc.getElementById('hostKeyAddHost').value = 'Web.Example.Test';
    doc.getElementById('hostKeyAddPort').value = '2222';
    doc.getElementById('hostKeyAddType').value = 'ecdsa-sha2-nistp256';
    doc.getElementById('hostKeyAddFingerprint').value = 'SHA256:WebFp99';
    await window.addCachedHostKey();
    check('Adding a cached SSH host key updates the rendered list',
      doc.getElementById('hostKeysList').children.length === 2 &&
      doc.getElementById('hostKeysList').textContent.includes('web.example.test:2222'));
    const origConfirmHk = window.confirm;
    window.confirm = () => true;
    await window.deleteCachedHostKey(mockHostKeys[0]);
    window.confirm = origConfirmHk;
    check('Deleting a cached SSH host key removes it from the list',
      doc.getElementById('hostKeysList').children.length === 1 &&
      !doc.getElementById('hostKeysList').textContent.includes('bastion.example.test'));
    window.closeModal('hostKeysModal');

    // 13. Paste / Open Session URL loads parsed settings into Site Manager.
    window.openPasteSessionUrl();
    doc.getElementById('pasteSessionUrlInput').value = 'ftpes://deploy:url-secret@app.example.test:2121/var/www';
    await window.loadPastedUrlIntoSiteManager();
    check('loadPastedUrlIntoSiteManager populates Site Manager from POST /api/session/url',
      doc.getElementById('siteModal').classList.contains('open') &&
      doc.getElementById('siteProtocol').value === 'ftpes' &&
      doc.getElementById('siteHost').value === 'app.example.test' &&
      doc.getElementById('sitePort').value === '2121' &&
      doc.getElementById('siteUser').value === 'deploy' &&
      doc.getElementById('sitePass').value === 'url-secret' &&
      doc.getElementById('siteRemoteDir').value === '/var/www');
    window.closeModal('siteModal');
    window.__TAURI_INTERNALS__.invoke = origInvokeHk;

    // 14. New file (`newFilePrompt`) with `create_only: true` + Local `Save as` (`saveEditorFileAs`).
    const origInvokeEdit = window.__TAURI_INTERNALS__.invoke;
    let localSaveCalls = [];
    let simulateExistsOnce = true;
    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === 'linscp_invoke' && args && args.envelope && args.envelope.path === '/api/local/save') {
        const b = typeof args.envelope.body === 'string' ? JSON.parse(args.envelope.body) : (args.envelope.body || {});
        localSaveCalls.push(b);
        if (b.create_only && simulateExistsOnce) {
          simulateExistsOnce = false;
          return { status: 409, payload: { success: false, exists: true, error: 'A file with that name already exists.' } };
        }
        return { status: 200, payload: { success: true, info: { size: (b.content || '').length, mtime: 1791875300, mtime_ns: '1791875300000000000' } } };
      }
      return origInvokeEdit(cmd, args);
    };
    const origPromptEdit = window.prompt;
    const origConfirmEdit = window.confirm;
    wfState.local.path = '/tmp/slowlocal';
    window.prompt = () => 'fresh_note.txt';
    await window.newFilePrompt('local');
    check('newFilePrompt opens editor in new-file mode with Reload hidden and Save As visible',
      doc.getElementById('editorModal').classList.contains('open') &&
      wfState.editor.isNew === true &&
      wfState.editor.path === '/tmp/slowlocal/fresh_note.txt' &&
      doc.getElementById('editorReloadBtn').style.display === 'none' &&
      doc.getElementById('editorSaveAsBtn').style.display === '');
    window.setEditorValue('hello world\n');
    window.confirm = () => true;
    await window.saveEditorFile();
    check('Saving a new file sends create_only first, confirms overwrite on 409 exists, and transitions out of isNew',
      localSaveCalls.length === 2 &&
      localSaveCalls[0].create_only === true &&
      localSaveCalls[1].create_only === undefined &&
      wfState.editor.isNew === false &&
      doc.getElementById('editorReloadBtn').style.display === '');
    window.prompt = () => 'copied_note.txt';
    await window.saveEditorFileAs();
    check('saveEditorFileAs works on local files and resolves relative leaf names in the parent directory',
      localSaveCalls.length === 3 &&
      localSaveCalls[2].path === '/tmp/slowlocal/copied_note.txt' &&
      localSaveCalls[2].create_only === true &&
      wfState.editor.path === '/tmp/slowlocal/copied_note.txt');
    window.closeModal('editorModal');
    window.prompt = origPromptEdit;
    window.confirm = origConfirmEdit;
    window.__TAURI_INTERNALS__.invoke = origInvokeEdit;

    // 15. Paired Bookmarks (`side: 'both'` add, rename with `old_name`, and dual-panel `goBookmark`).
    responses['/api/bookmarks'].bookmarks.both = [
      { name: 'pair-1', local_path: '/tmp/pair-local', remote_path: '/tmp/pair-remote' }
    ];
    await window.openBookmarks('both');
    check('Paired bookmarks render local and remote paths in bookmarksModal',
      doc.getElementById('bookmarkScopeSelect').value === 'both' &&
      doc.getElementById('bookmarkList').textContent.includes('/tmp/pair-local') &&
      doc.getElementById('bookmarkList').textContent.includes('/tmp/pair-remote'));
    const origPromptBm = window.prompt;
    window.prompt = () => 'pair-renamed';
    await window.renameBookmark('both', { name: 'pair-1', local_path: '/tmp/pair-local', remote_path: '/tmp/pair-remote' });
    window.prompt = origPromptBm;
    const bmRenameBody = JSON.parse(calls.filter(c => c.path === '/api/bookmarks/save').pop().options.body);
    check('renameBookmark posts old_name, new name, local_path and remote_path',
      bmRenameBody.side === 'both' &&
      bmRenameBody.old_name === 'pair-1' &&
      bmRenameBody.name === 'pair-renamed' &&
      bmRenameBody.local_path === '/tmp/pair-local' &&
      bmRenameBody.remote_path === '/tmp/pair-remote');
    const localBeforePair = calls.filter(c => c.path === '/api/local/list').length;
    const remoteBeforePair = calls.filter(c => c.path === '/api/remote/list').length;
    wfState.tabs = [{ id: 1, name: 'box', connected: true, is_local: false }];
    wfState.activeTab = 1;
    await window.goBookmark('both', { local_path: '/tmp/pair-local', remote_path: '/tmp/pair-remote' });
    check('goBookmark("both") navigates both local and remote panels',
      calls.filter(c => c.path === '/api/local/list').length === localBeforePair + 1 &&
      calls.filter(c => c.path === '/api/remote/list').length === remoteBeforePair + 1);
    wfState.tabs = savedWfTabs;
    wfState.activeTab = savedWfActiveTab;

    // 16. Preferences Modal `resumesupport` (`#prefResumeSupport` + `#prefResumeSize`).
    responses['/api/preferences'].preferences.resumesupport = '4096';
    await window.loadTransferSettings();
    await window.openPreferences();
    check('Preferences modal loads numeric resumesupport into #prefResumeSupport="size" and #prefResumeSize',
      doc.getElementById('prefResumeSupport').value === 'size' &&
      doc.getElementById('prefResumeSize').value === '4096' &&
      doc.getElementById('prefResumeSizeRow').style.display === 'flex');
    doc.getElementById('prefResumeSize').value = '8192';
    await window.savePreferences();
    const prefRsCall = JSON.parse(calls.filter(c => c.path === '/api/preferences' && (c.options.method || 'GET').toUpperCase() === 'POST').pop().options.body);
    check('Saving Preferences persists updated resumesupport threshold',
      prefRsCall.preferences.resumesupport === '8192');
    window.closeModal('preferencesModal');

    // 17. Properties Modification Timestamp (`appendMtimeEditor` + `applyPropertiesMtime` on local & remote).
    const prevWfLocalEntries = wfState.local.entries.slice();
    const prevWfFocus = wfState.focusPane;
    wfState.focusPane = 'local';
    wfState.local.entries = [
      { name: 'stamp.txt', is_dir: false, size: 128, mtime: 1700000000, permissions: '-rw-r--r--' },
      { name: 'stamp_dir', is_dir: true, size: 0, mtime: 1700000100, permissions: 'drwxr-xr-x' }
    ];
    wfState.local.selection = new Set(['stamp_dir']);
    responses['/api/local/touch'] = { success: true, changed: 3 };
    await window.openProperties();
    check('Properties modal renders #propertiesMtimeInput, #propertiesMtimeNowBtn and #propertiesMtimeRecursive for directory',
      !!doc.getElementById('propertiesMtimeInput') &&
      !!doc.getElementById('propertiesMtimeNowBtn') &&
      !!doc.getElementById('propertiesMtimeRecursive') &&
      doc.getElementById('propertiesMtimeInput').value.length >= 16);
    doc.getElementById('propertiesMtimeNowBtn').click();
    doc.getElementById('propertiesMtimeRecursive').checked = true;
    await window.applyPropertiesMtime('local', ['stamp_dir']);
    const localTouchBody = JSON.parse(calls.filter(c => c.path === '/api/local/touch').pop().options.body);
    check('applyPropertiesMtime posts mtime and recursive=true to /api/local/touch',
      typeof localTouchBody.mtime === 'number' &&
      localTouchBody.mtime > 1700000000 &&
      localTouchBody.recursive === true &&
      Array.isArray(localTouchBody.names) &&
      localTouchBody.names[0] === 'stamp_dir');
    window.closeModal('propertiesModal');

    // 18. Local File Duplicate (`promptDuplicate('local')` -> `/api/local/copy` & `#paneCtxDuplicateBtn`).
    wfState.local.selection = new Set(['stamp.txt']);
    responses['/api/local/copy'] = { success: true, destination: '/tmp/stamp.txt.copy' };
    const origPromptDup = window.prompt;
    window.prompt = () => 'stamp.txt.bak';
    await window.promptDuplicate('local');
    window.prompt = origPromptDup;
    const localCopyBody = JSON.parse(calls.filter(c => c.path === '/api/local/copy').pop().options.body);
    check('promptDuplicate("local") posts source and destination to /api/local/copy',
      localCopyBody.source === 'stamp.txt' &&
      localCopyBody.destination === 'stamp.txt.bak');
    wfState.local.entries = [
      { name: 'stamp.txt', is_dir: false, size: 128, mtime: 1700000000, permissions: '-rw-r--r--' },
      { name: 'stamp_dir', is_dir: true, size: 0, mtime: 1700000100, permissions: 'drwxr-xr-x' }
    ];
    wfState.local.selection = new Set(['stamp.txt']);
    window.openPaneContextMenu('local', { preventDefault() {}, clientX: 20, clientY: 20 });
    check('#paneCtxDuplicateBtn is enabled for a single selected file',
      doc.getElementById('paneCtxDuplicateBtn').disabled === false);
    wfState.local.selection = new Set(['stamp_dir']);
    window.openPaneContextMenu('local', { preventDefault() {}, clientX: 20, clientY: 20 });
    check('#paneCtxDuplicateBtn is disabled when a directory is selected',
      doc.getElementById('paneCtxDuplicateBtn').disabled === true);
    window.closePaneContextMenu();
    wfState.local.entries = prevWfLocalEntries;
    wfState.focusPane = prevWfFocus;

    // 19. Site & Folder Rename (`renameSite` & `renameSiteFolder` -> `/api/sessions/rename`).
    const prevSessions = wfState.sessions.slice();
    wfState.sessions = [
      { name: 'Prod/web1', protocol: 'sftp', host: '10.0.0.5', port: 22, username: 'deploy' }
    ];
    wfState.selectedSite = 'Prod/web1';
    window.renderSites();
    check('renderSites renders folder rename button without breaking .site-folder delete count',
      doc.querySelectorAll('#siteList .site-folder-rename').length === 1 &&
      doc.querySelectorAll('#siteList .site-folder').length === 1);
    responses['/api/sessions/rename'] = { success: true, name: 'Prod/web-primary', renamed: 1 };
    const origPromptRen = window.prompt;
    window.prompt = () => 'Prod/web-primary';
    await window.renameSite();
    const siteRenBody = JSON.parse(calls.filter(c => c.path === '/api/sessions/rename').pop().options.body);
    check('renameSite posts old_name and new_name to /api/sessions/rename',
      siteRenBody.old_name === 'Prod/web1' &&
      siteRenBody.new_name === 'Prod/web-primary' &&
      !siteRenBody.folder);
    responses['/api/sessions/rename'] = { success: true, name: 'Staging', renamed: 1 };
    window.prompt = () => 'Staging';
    await window.renameSiteFolder('Prod');
    window.prompt = origPromptRen;
    const folderRenBody = JSON.parse(calls.filter(c => c.path === '/api/sessions/rename').pop().options.body);
    check('renameSiteFolder posts folder=true to /api/sessions/rename',
      folderRenBody.old_name === 'Prod' &&
      folderRenBody.new_name === 'Staging' &&
      folderRenBody.folder === true);
    wfState.sessions = prevSessions;

    // 20. Workspaces Rename (`renameWorkspace`) & `close_existing` (`#workspaceCloseExisting`).
    responses['/api/workspaces'] = {
      success: true,
      file: '/tmp/workspaces.json',
      workspaces: [{ name: 'ops', tab_count: 2, updated: 1700000500, tabs: [{ name: 'web1', site: 'Prod/web1' }] }]
    };
    responses['/api/workspaces/rename'] = { success: true, workspace: { name: 'ops-renamed', updated: 1700000600 } };
    await window.openWorkspaces();
    check('Workspaces modal keeps 1 row per workspace and renders Rename button + tab summary tooltip',
      doc.getElementById('workspaceList').children.length === 1 &&
      doc.getElementById('workspaceList').textContent.includes('Rename') &&
      doc.querySelector('#workspaceList .site-item span').title.includes('Prod/web1'));
    const origPromptWs = window.prompt;
    window.prompt = () => 'ops-renamed';
    await window.renameWorkspace('ops');
    window.prompt = origPromptWs;
    const wsRenBody = JSON.parse(calls.filter(c => c.path === '/api/workspaces/rename').pop().options.body);
    check('renameWorkspace posts old_name and new_name to /api/workspaces/rename',
      wsRenBody.old_name === 'ops' && wsRenBody.new_name === 'ops-renamed');
    doc.getElementById('workspaceCloseExisting').checked = true;
    responses['/api/workspaces/open'] = { success: true, opened: [{ name: 'web1', id: 9 }], failed: [] };
    const origConfirmWs = window.confirm;
    window.confirm = () => true;
    await window.openWorkspace('ops');
    await new Promise(resolve => setTimeout(resolve, 20));
    window.confirm = origConfirmWs;
    doc.getElementById('workspaceCloseExisting').checked = false;
    const wsOpenCloseBody = JSON.parse(calls.filter(c => c.path === '/api/workspaces/open').pop().options.body);
    check('openWorkspace forwards close_existing=true when #workspaceCloseExisting is checked',
      wsOpenCloseBody.name === 'ops' && wsOpenCloseBody.close_existing === true);
    window.closeModal('workspacesModal');

    // 21. Synchronize Permissions (`#syncPermissions` + `#syncPermissionsOctal`).
    wfState.tabs = [{ id: 1, name: 'box', connected: true, is_local: false }];
    wfState.activeTab = 1;
    window.openSynchronize();
    doc.getElementById('syncPermissions').value = 'mode';
    window.syncPermissionsChanged();
    doc.getElementById('syncPermissionsOctal').value = '0750';
    check('Selecting Custom octal mode in Synchronize reveals #syncPermissionsOctal',
      doc.getElementById('syncPermissionsOctal').style.display !== 'none');
    const syncPermSettings = window.syncSettings();
    check('syncSettings includes octal permissions when #syncPermissions is "mode"',
      syncPermSettings.permissions === '0750');
    doc.getElementById('syncPermissions').value = '';
    window.syncPermissionsChanged();
    window.closeModal('syncModal');

    // 22. S3 object version restore (`restoreS3Version` + `.s3-version-restore` button).
    wfState.tabs = [{ id: 1, name: 's3-box', connected: true, is_local: false, remote_dir: '/bucket' }];
    wfState.activeTab = 1;
    responses['/api/s3/versions'] = {
      success: true,
      versions: [
        { key: '/bucket/config.json', version_id: 'v-cur', is_latest: true, is_delete_marker: false, size: 100, mtime: 1700000200 },
        { key: '/bucket/config.json', version_id: 'v-old', is_latest: false, is_delete_marker: false, size: 80, mtime: 1700000100 }
      ]
    };
    responses['/api/s3/version-restore'] = { success: true, version_id: 'v-old' };
    doc.getElementById('s3VersionsName').value = 'config.json';
    await window.openS3Versions();
    check('S3 versions modal renders Restore button only for non-latest object versions',
      doc.querySelectorAll('#s3VersionsList .s3-version-restore').length === 1);
    await window.restoreS3Version('config.json', 'v-old');
    const s3RestoreCall = calls.filter(c => c.path === '/api/s3/version-restore').pop();
    check('restoreS3Version posts name and version_id to /api/s3/version-restore',
      !!s3RestoreCall &&
      JSON.parse(s3RestoreCall.options.body).name === 'config.json' &&
      JSON.parse(s3RestoreCall.options.body).version_id === 'v-old');
    window.closeModal('s3VersionsModal');
    delete responses['/api/s3/versions'];
    delete responses['/api/s3/version-restore'];

    // 23. WebDAV dead property removal (`removeDavProperty`) & active lock token query (`loadDavLockToken`).
    wfState.tabs = [{ id: 1, name: 'dav-box', connected: true, is_local: false, remote_dir: '/dav' }];
    wfState.activeTab = 1;
    responses['/api/dav/lock'] = { success: true, path: '/dav/doc.xml', token: 'opaquelocktoken:loaded-77' };
    responses['/api/dav/property'] = { success: true, path: '/dav/doc.xml', property: 'owner_tag', removed: true };
    doc.getElementById('davResourceName').value = 'doc.xml';
    window.openDavTools();
    await window.loadDavLockToken();
    const davLoadLockBody = JSON.parse(calls.filter(c => c.path === '/api/dav/lock').pop().options.body);
    check('loadDavLockToken posts action=get and populates #davLockToken',
      davLoadLockBody.action === 'get' &&
      doc.getElementById('davLockToken').value === 'opaquelocktoken:loaded-77');
    doc.getElementById('davLockToken').value = '';
    window.openDavTools();
    check('openDavTools restores cached session lock token synchronously for same resource',
      doc.getElementById('davLockToken').value === 'opaquelocktoken:loaded-77');
    doc.getElementById('davPropName').value = 'owner_tag';
    doc.getElementById('davPropValue').value = 'stale';
    await window.removeDavProperty();
    const davRmPropBody = JSON.parse(calls.filter(c => c.path === '/api/dav/property').pop().options.body);
    check('removeDavProperty posts action=remove and clears #davPropValue',
      davRmPropBody.action === 'remove' &&
      davRmPropBody.property === 'owner_tag' &&
      doc.getElementById('davPropValue').value === '');
    window.closeModal('davToolsModal');
    delete responses['/api/dav/lock'];
    delete responses['/api/dav/property'];

    // 24. Interactive Checksum Verification, Algorithm Recalculation, & Manifest Export.
    const savedLocalPath = wfState.local.path;
    const savedLocalEntries = wfState.local.entries;
    wfState.focusPane = 'local';
    wfState.local.path = '/tmp/cs';
    wfState.local.entries = [{ name: 'release.tar.gz', size: 512, is_dir: false, mtime: 1700000000 }];
    wfState.local.selection.clear();
    window.renderPane('local');
    const csRow = Array.from(doc.getElementById('localFileList').children)
      .find(el => el.dataset && el.dataset.name === 'release.tar.gz');
    if (csRow) csRow.click();
    responses['/api/local/checksum'] = {
      success: true,
      algorithm: 'sha-256',
      results: [{ name: 'release.tar.gz', checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }]
    };
    await window.openChecksum('sha-256');
    doc.getElementById('checksumVerifyInput').value = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  release.tar.gz';
    window.verifyChecksumsInModal();
    check('verifyChecksumsInModal verifies matching sha256sum manifest line',
      doc.getElementById('checksumVerifyStatus').textContent.includes('1/1'));
    doc.getElementById('checksumVerifyInput').value = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    window.verifyChecksumsInModal();
    check('verifyChecksumsInModal flags digest mismatch',
      doc.getElementById('checksumVerifyStatus').textContent.toLowerCase().includes('mismatch'));
    responses['/api/local/save'] = { success: true };
    const origPromptCsSave = window.prompt;
    window.prompt = () => 'release.tar.gz.sha256';
    await window.saveChecksumManifestFile();
    window.prompt = origPromptCsSave;
    const csSaveCall = calls.filter(c => c.path === '/api/local/save').pop();
    check('saveChecksumManifestFile writes GNU-formatted checksum file via /api/local/save',
      !!csSaveCall &&
      JSON.parse(csSaveCall.options.body).path === '/tmp/cs/release.tar.gz.sha256' &&
      JSON.parse(csSaveCall.options.body).create_only === true &&
      JSON.parse(csSaveCall.options.body).content.includes('  release.tar.gz\n'));
    window.closeModal('propertiesModal');
    wfState.local.path = savedLocalPath;
    wfState.local.entries = savedLocalEntries;
    wfState.local.selection.clear();
    window.renderPane('local');
    delete responses['/api/local/checksum'];
    delete responses['/api/local/save'];

    // 25. Site Manager search filter, Recent sort (`last_used`), & `#siteLastUsedHint`.
    const prevSitesForFilter = wfState.sessions;
    wfState.sessions = [
      { name: 'Alpha/one', protocol: 'sftp', host: 'alpha.example', port: 22, last_used: 1700000100 },
      { name: 'Beta/two', protocol: 'sftp', host: 'beta.example', port: 22, last_used: 1700000900 }
    ];
    doc.getElementById('siteSortSelect').value = 'recent';
    window.renderSites();
    check('Site Manager Recent sort orders most recently connected site first',
      doc.querySelector('#siteList .site-item span').textContent.includes('Beta/two'));
    doc.getElementById('siteSearchInput').value = 'alpha.example';
    window.renderSites();
    check('Site Manager filter narrows #siteList by host/name',
      doc.querySelectorAll('#siteList .site-item').length === 1 &&
      doc.querySelector('#siteList .site-item span').textContent.includes('Alpha/one'));
    window.fillSiteForm(wfState.sessions[1]);
    check('fillSiteForm displays Last connected timestamp when last_used is present',
      doc.getElementById('siteLastUsedHint').style.display !== 'none' &&
      doc.getElementById('siteLastUsedHint').textContent.includes('2023-11-14'));
    doc.getElementById('siteSearchInput').value = '';
    doc.getElementById('siteSortSelect').value = 'name';
    wfState.sessions = prevSitesForFilter;
    window.renderSites();

    // 26. Built-in Editor Find / Replace toolbar button (`openEditorFind`).
    responses['/api/local/edit'] = {
      success: true,
      content: 'line one\nline two\n',
      encoding: 'UTF-8',
      eol: 'lf',
      bom: false,
      info: { size: 18, mtime: 1700000000 }
    };
    await window.openEditor('/tmp/cs/sample.txt', 'local', false);
    window.openEditorFind();
    check('openEditorFind opens CodeMirror search panel inside #editorHost',
      !!doc.querySelector('#editorHost .cm-search'));
    await window.closeEditor();
    delete responses['/api/local/edit'];

    // 27. Session URL format switcher (Session URL / LinSCP script / OpenSSH command).
    wfState.tabs = [{ id: 1, name: 'sftp-box', connected: true, is_local: false, remote_dir: '/srv/app' }];
    wfState.activeTab = 1;
    responses['/api/session/url'] = {
      success: true,
      url: 'sftp://alice@host.example.test:2222/srv/app',
      open_command: 'open sftp://alice@host.example.test:2222/srv/app',
      script_snippet: 'open "sftp://alice@host.example.test:2222/srv/app" -hostkey="ssh-ed25519 SHA256:Pin1"\ncd "/srv/app"',
      openssh_command: "sftp -P 2222 alice@host.example.test:'/srv/app'",
      include_password: false,
      has_password: false,
      protocol: 'sftp',
      host: 'host.example.test'
    };
    await window.openSessionUrl();
    doc.getElementById('sessionUrlFormat').value = 'script';
    window.updateSessionUrlDisplay();
    check('Session URL format=script displays script_snippet with hostkey and cd',
      doc.getElementById('sessionUrlText').value.includes('-hostkey="ssh-ed25519 SHA256:Pin1"') &&
      doc.getElementById('sessionUrlText').value.includes('\ncd "/srv/app"'));
    doc.getElementById('sessionUrlFormat').value = 'openssh';
    window.updateSessionUrlDisplay();
    check('Session URL format=openssh displays OpenSSH CLI command',
      doc.getElementById('sessionUrlText').value === "sftp -P 2222 alice@host.example.test:'/srv/app'");
    window.closeModal('sessionUrlModal');
    delete responses['/api/session/url'];

    // 28. SSH Host Keys search filter & OpenSSH known_hosts import.
    responses['/api/hostkeys'] = {
      success: true,
      imported: 2,
      skipped: 1,
      entries: [
        { host: 'git.example.test', port: 22, host_port: 'git.example.test@22', key_type: 'ssh-ed25519', fingerprint: 'SHA256:GitFp1', pin: 'ssh-ed25519 SHA256:GitFp1' },
        { host: 'db.example.test', port: 2222, host_port: 'db.example.test@2222', key_type: 'ecdsa-sha2-nistp256', fingerprint: 'SHA256:DbFp2', pin: 'ecdsa-sha2-nistp256 SHA256:DbFp2' }
      ]
    };
    await window.openHostKeysManager();
    await window.importDefaultKnownHosts();
    const khImportCall = calls.filter(c => c.path === '/api/hostkeys' && c.options && c.options.method === 'POST').pop();
    check('importDefaultKnownHosts posts action=import_known_hosts and updates status',
      !!khImportCall &&
      JSON.parse(khImportCall.options.body).action === 'import_known_hosts' &&
      doc.getElementById('hostKeysStatus').textContent.includes('2'));
    doc.getElementById('hostKeysSearchInput').value = 'db.example.test';
    window.filterCachedHostKeys();
    check('filterCachedHostKeys narrows #hostKeysList by query',
      doc.getElementById('hostKeysList').children.length === 1 &&
      doc.getElementById('hostKeysList').textContent.includes('db.example.test:2222'));
    doc.getElementById('hostKeysSearchInput').value = '';
    window.filterCachedHostKeys();
    window.closeModal('hostKeysModal');
    delete responses['/api/hostkeys'];

    // 29. Keep Up to Date dual-local & custom octal permissions.
    wfState.tabs = [{ id: 2, name: 'local-pair', connected: true, is_local: true, remote_dir: '/tmp/right' }];
    wfState.activeTab = 2;
    responses['/api/transfer/keepuptodate'] = { success: true, task_id: 201 };
    window.openKeepUpToDate();
    doc.getElementById('kudPermissions').value = 'mode';
    window.kudPermissionsChanged();
    doc.getElementById('kudPermissionsOctal').value = '0640';
    await window.startKeepUpToDate();
    const kudPermCall = calls.filter(c => c.path === '/api/transfer/keepuptodate').pop();
    check('startKeepUpToDate supports dual-local tabs and forwards custom octal permissions',
      !!kudPermCall &&
      JSON.parse(kudPermCall.options.body).tab === 2 &&
      JSON.parse(kudPermCall.options.body).permissions === '0640');
    delete responses['/api/transfer/keepuptodate'];

    // 30. Batch Retry failed transfers (`retryAllFailedTasks`).
    responses['/api/queue/retry'] = { success: true, retried: 3 };
    await window.retryAllFailedTasks();
    const retryAllCall = calls.filter(c => c.path === '/api/queue/retry').pop();
    check('retryAllFailedTasks posts all=true to /api/queue/retry',
      !!retryAllCall &&
      JSON.parse(retryAllCall.options.body).all === true);
    delete responses['/api/queue/retry'];

    // 31. Search result direct Download action via `.search-match-extra-actions`.
    wfState.tabs = [{ id: 1, name: 'sftp-box', connected: true, is_local: false, remote_dir: '/srv/app' }];
    wfState.activeTab = 1;
    responses['/api/remote/search'] = {
      success: true,
      matches: [
        { name: 'deep.log', path: '/srv/app/logs/deep.log', is_dir: false, size: 128 }
      ]
    };
    responses['/api/transfer/download'] = { success: true };
    doc.getElementById('searchTarget').value = 'remote';
    doc.getElementById('searchContents').checked = false;
    window.toggleSearchContents();
    await window.runSearch();
    const dlSearchBtn = doc.querySelector('#searchResults .search-match-extra-actions button');
    check('Search file match renders Download action in .search-match-extra-actions',
      !!dlSearchBtn && dlSearchBtn.textContent === 'Download');
    dlSearchBtn.click();
    await new Promise(resolve => setTimeout(resolve, 60));
    const searchDlCall = calls.filter(c => c.path === '/api/transfer/download').pop();
    check('Clicking Download on a search match queues /api/transfer/download with parent remote_dir',
      !!searchDlCall &&
      JSON.parse(searchDlCall.options.body).remote_dir === '/srv/app/logs' &&
      JSON.parse(searchDlCall.options.body).names[0] === 'deep.log');
    delete responses['/api/remote/search'];
    delete responses['/api/transfer/download'];

    // 32. Search dialog size (`min_size`/`max_size`) & modified date (`modified_after`/`modified_before`) bounds.
    responses['/api/remote/search'] = { success: true, matches: [] };
    window.openSearch('remote');
    doc.getElementById('searchMinSize').value = '4';
    doc.getElementById('searchMinSizeUnit').value = '1024';
    doc.getElementById('searchMaxSize').value = '2';
    doc.getElementById('searchMaxSizeUnit').value = '1024';
    const beforeInvalidSearchCount = calls.filter(c => c.path === '/api/remote/search').length;
    await window.runSearch();
    check('runSearch rejects min_size > max_size before dispatching a search request',
      calls.filter(c => c.path === '/api/remote/search').length === beforeInvalidSearchCount);
    doc.getElementById('searchMaxSize').value = '1';
    doc.getElementById('searchMaxSizeUnit').value = '1048576';
    doc.getElementById('searchModifiedAfter').value = '2026-02-01';
    doc.getElementById('searchModifiedBefore').value = '2026-02-10';
    await window.runSearch();
    const boundedSearchCall = calls.filter(c => c.path === '/api/remote/search').pop();
    const boundedSearchBody = boundedSearchCall ? JSON.parse(boundedSearchCall.options.body) : {};
    check('runSearch forwards scaled min_size, max_size, modified_after, and modified_before bounds',
      boundedSearchBody.min_size === 4096 &&
      boundedSearchBody.max_size === 1048576 &&
      typeof boundedSearchBody.modified_after === 'number' &&
      typeof boundedSearchBody.modified_before === 'number' &&
      boundedSearchBody.modified_after < boundedSearchBody.modified_before);
    window.closeModal('searchModal');
    delete responses['/api/remote/search'];

    // 33. Custom Commands interactive `!?prompt?default!` parameters, `!*`, `!.`, and token insertion.
    check('customTemplateNamesFile distinguishes interactive prompts from !* and !. file tokens',
      window.customTemplateNamesFile('mkdir !?Folder name?work!') === false &&
      window.customTemplateNamesFile('chmod 600 !*') === true &&
      window.customTemplateNamesFile('call mv ! !.') === true);
    doc.getElementById('customCmdCommand').value = 'chmod 600';
    window.insertCustomCommandToken('!*');
    check('insertCustomCommandToken appends placeholder with spacing into #customCmdCommand',
      doc.getElementById('customCmdCommand').value === 'chmod 600 !*');
    await window.openCustomCommands();
    doc.getElementById('customCmdName').value = 'Prompt Mkdir';
    doc.getElementById('customCmdCommand').value = 'mkdir !?Folder label?default-dir!';
    doc.getElementById('customCmdScope').value = 'remote';
    await window.saveCustomCommand();
    window.focusPane('remote');
    const origPromptCc = window.prompt;
    const origConfirmCc = window.confirm;
    let seenPromptArgs = null;
    window.prompt = (label, defVal) => {
      seenPromptArgs = [label, defVal];
      return 'release-2026';
    };
    window.confirm = () => true;
    await window.runCustomCommand();
    window.prompt = origPromptCc;
    window.confirm = origConfirmCc;
    const ccPromptRun = calls.filter(c => c.path === '/api/custom-commands' && JSON.parse(c.options.body || '{}').action === 'run').pop();
    const ccPromptBody = ccPromptRun ? JSON.parse(ccPromptRun.options.body) : {};
    check('runCustomCommand prompts for !?label?default! and posts prompt_values without requiring file selection',
      !!seenPromptArgs &&
      seenPromptArgs[0] === 'Folder label' &&
      seenPromptArgs[1] === 'default-dir' &&
      Array.isArray(ccPromptBody.prompt_values) &&
      ccPromptBody.prompt_values[0] === 'release-2026' &&
      Array.isArray(ccPromptBody.filenames) &&
      ccPromptBody.filenames.length === 0);
    window.closeModal('customCommandsModal');
    delete responses['/api/custom-commands'];

    // 34. Bookmarks filter (`#bookmarkSearchInput`) and reordering (`POST /api/bookmarks/reorder`).
    responses['/api/bookmarks'].bookmarks.local = [
      { name: 'alpha', path: '/srv/alpha' },
      { name: 'beta', path: '/srv/beta' }
    ];
    responses['/api/bookmarks/reorder'] = {
      success: true,
      bookmarks: [
        { name: 'beta', path: '/srv/beta' },
        { name: 'alpha', path: '/srv/alpha' }
      ]
    };
    await window.openBookmarks('local');
    doc.getElementById('bookmarkSearchInput').value = 'beta';
    window.filterBookmarksView();
    check('bookmarkSearchInput filters visible bookmark rows without mutating total count',
      doc.getElementById('bookmarkList').children.length === 1 &&
      doc.getElementById('bookmarkList').textContent.includes('beta'));
    doc.getElementById('bookmarkSearchInput').value = '';
    window.filterBookmarksView();
    await window.reorderBookmark('local', 'beta', 'up');
    const bmReorderCall = calls.filter(c => c.path === '/api/bookmarks/reorder').pop();
    check('reorderBookmark posts side, name, and direction to /api/bookmarks/reorder and updates order',
      !!bmReorderCall &&
      JSON.parse(bmReorderCall.options.body).name === 'beta' &&
      JSON.parse(bmReorderCall.options.body).direction === 'up' &&
      doc.getElementById('bookmarkList').children[0].textContent.includes('beta'));
    window.closeModal('bookmarksModal');
    delete responses['/api/bookmarks/reorder'];

    // 35. Configurable Compare Directories modes (`#compareDirsModal`).
    wfState.local.entries = [
      { name: 'newer_same_size.txt', size: 100, mtime: 500, is_dir: false, permissions: '-rw-r--r--' },
      { name: 'older_diff_size.txt', size: 250, mtime: 100, is_dir: false, permissions: '-rw-r--r--' },
      { name: 'only_local_dir', size: 0, mtime: 300, is_dir: true, permissions: 'drwxr-xr-x' }
    ];
    wfState.remote.entries = [
      { name: 'newer_same_size.txt', size: 100, mtime: 200, is_dir: false, permissions: '-rw-r--r--' },
      { name: 'older_diff_size.txt', size: 100, mtime: 400, is_dir: false, permissions: '-rw-r--r--' }
    ];
    window.openCompareDirectoriesModal();
    doc.getElementById('compareCriteriaSelect').value = 'size';
    doc.getElementById('compareIncludeDirs').checked = false;
    window.applyCompareDirectoriesModal();
    check('Compare directories size-only mode with includeDirs=false selects size differences and skips missing folders',
      wfState.local.selection.has('older_diff_size.txt') &&
      !wfState.local.selection.has('newer_same_size.txt') &&
      !wfState.local.selection.has('only_local_dir'));
    window.compareDirectories('time_or_size', true);
    wfState.compareCriteria = 'time_or_size';
    wfState.compareIncludeDirs = true;

    // 36. High-density Commander shell: central transfer spine, protocol-contextual
    // remote header pills, explorer-mode toolbar toggle, and collapsible/tall bottom dock.
    const mainChildren = Array.from(doc.querySelector('.commander-main').children).map(el => el.id || el.className);
    check('commander-main arranges localPane, central commander-actions spine, and remotePane in order',
      mainChildren[0] === 'localPane' &&
      mainChildren[1].includes('commander-actions') &&
      mainChildren[2] === 'remotePane');
    check('menu-bar-right hosts statusBadge, themeToggleBtn, and languageSelect without duplicate toolbar brand',
      !!doc.querySelector('.menu-bar-right #statusBadge') &&
      !!doc.querySelector('.menu-bar-right #themeToggleBtn') &&
      !!doc.querySelector('.menu-bar-right #languageSelect') &&
      doc.querySelectorAll('.app-toolbar .toolbar-cluster').length === 4);

    window.toggleExplorerMode();
    check('explorerModeBtn reflects active single-panel state and clears when exiting explorer mode',
      doc.getElementById('explorerModeBtn').classList.contains('active') &&
      doc.querySelector('.commander-main').classList.contains('explorer-mode'));
    window.toggleExplorerMode();
    check('exiting explorerModeBtn clears active class',
      !doc.getElementById('explorerModeBtn').classList.contains('active'));

    wfState.tabs = [{ id: 1, protocol: 's3', session: { protocol: 's3' }, connected: true, label: 's3://bucket', remote_dir: '/' }];
    wfState.activeTab = 1;
    window.updateRemoteDesktopButton();
    check('remote header exposes S3 versions shortcut only on S3 tabs and WebDAV shortcut only on WebDAV tabs',
      !doc.getElementById('remoteS3Btn').hidden &&
      doc.getElementById('remoteDavBtn').hidden);
    wfState.tabs = [{ id: 1, protocol: 'webdav', session: { protocol: 'webdav' }, connected: true, label: 'davs://cloud', remote_dir: '/' }];
    window.updateRemoteDesktopButton();
    check('remote header switches to DAV shortcut on WebDAV tabs',
      !doc.getElementById('remoteDavBtn').hidden &&
      doc.getElementById('remoteS3Btn').hidden);

    const lowerPanelEl = doc.getElementById('lowerPanel');
    window.switchTab('queue');
    await new Promise(resolve => setTimeout(resolve, 25));
    check('Transfer Queue tab shows queueControlsGroup and hides log/cli dock controls',
      !doc.getElementById('queueControlsGroup').hidden &&
      doc.getElementById('logControlsGroup').hidden &&
      doc.getElementById('cliControlsGroup').hidden);
    window.toggleLowerPanel();
    check('toggleLowerPanel collapses lowerPanel and updates aria-expanded',
      lowerPanelEl.classList.contains('collapsed') &&
      doc.getElementById('toggleLowerPanelBtn').getAttribute('aria-expanded') === 'false');
    window.switchTab('log');
    await new Promise(resolve => setTimeout(resolve, 25));
    check('selecting Log tab un-collapses lowerPanel and switches contextual controls to logControlsGroup',
      !lowerPanelEl.classList.contains('collapsed') &&
      doc.getElementById('queueControlsGroup').hidden &&
      !doc.getElementById('logControlsGroup').hidden &&
      doc.getElementById('cliControlsGroup').hidden);
    window.switchTab('cli');
    check('selecting CLI Console tab switches contextual controls to cliControlsGroup',
      !doc.getElementById('cliControlsGroup').hidden &&
      doc.getElementById('logControlsGroup').hidden);
    window.toggleLowerPanelTall();
    check('toggleLowerPanelTall expands lowerPanel height and marks expandLowerPanelBtn active',
      lowerPanelEl.classList.contains('tall') &&
      doc.getElementById('expandLowerPanelBtn').classList.contains('active'));
    window.toggleLowerPanelTall();
    window.switchTab('queue');
    await new Promise(resolve => setTimeout(resolve, 25));

    wfState.tabs = savedWfTabs;
    wfState.activeTab = savedWfActiveTab;
    window.updateRemoteDesktopButton();

    // 37. Unified workspace-bar, logical pane-header order, cross-pane spine,
    // categorized menu dropdowns, and 3-tab Site Manager sub-tabs.
    check('workspace-bar combines session tabs-bar and app-toolbar on a single unified strip',
      !!doc.querySelector('.workspace-bar > .tabs-bar') &&
      !!doc.querySelector('.workspace-bar > .app-toolbar') &&
      doc.querySelectorAll('.menu-bar .menu-item').length === 8 &&
      doc.querySelectorAll('.menu-dropdown .menu-section-title').length >= 15);
    const localHeaderGroups = Array.from(doc.querySelector('#localPane .pane-header').children).map(el => el.className);
    check('pane-header orders pane-title, pane-nav-group, path-input-group, and pane-create-group left to right',
      localHeaderGroups[0] === 'pane-title' &&
      localHeaderGroups[1] === 'pane-nav-group' &&
      localHeaderGroups[2] === 'path-input-group' &&
      localHeaderGroups[3] === 'pane-create-group');
    const spineLabels = Array.from(doc.querySelectorAll('.commander-actions .action-label')).map(el => el.textContent.trim());
    check('commander-actions spine contains exclusively cross-pane transfer and directory comparison actions',
      JSON.stringify(spineLabels) === JSON.stringify(['Upload', 'Download', 'Copy', 'Move', 'Compare', 'Synchronize']));

    window.switchSiteFormTab('network');
    check('switchSiteFormTab("network") activates Tunnel & Proxy pane and hides Connection pane',
      doc.getElementById('siteTabNetwork').classList.contains('active') &&
      !doc.getElementById('siteTabGeneral').classList.contains('active') &&
      doc.getElementById('siteTabNetworkBtn').getAttribute('aria-selected') === 'true');
    doc.getElementById('siteProtocol').value = 'local';
    window.siteProtocolChanged();
    check('switching Site Manager protocol to local while on network tab returns to general tab',
      doc.getElementById('siteTabGeneral').classList.contains('active') &&
      !doc.getElementById('siteTabProtocolBtn').classList.contains('has-proto-opts'));
    doc.getElementById('siteProtocol').value = 's3';
    window.siteProtocolChanged();
    check('selecting S3 protocol marks Protocol & Options sub-tab with has-proto-opts indicator',
      doc.getElementById('siteTabProtocolBtn').classList.contains('has-proto-opts'));
    doc.getElementById('siteProtocol').value = 'sftp';
    window.siteProtocolChanged();
    window.switchSiteFormTab('general');

    // 38. Disconnected Remote Quick-Connect Hub, empty-filter clear action,
    // toolbar hidden-files toggle, dock click-to-collapse, and 3-tab Preferences.
    const prevTabs38 = wfState.tabs;
    const prevActive38 = wfState.activeTab;
    const prevSessions38 = wfState.sessions;
    wfState.sessions = [
      { name: 'Prod/api', protocol: 'sftp', host: 'api.example.internal', port: 22, username: 'deploy', color: '#3b82f6', last_used: 200 },
      { name: 'Backups/s3', protocol: 's3', host: 's3.amazonaws.com', port: 443, username: 'AKIA', last_used: 100 }
    ];
    wfState.tabs = [];
    wfState.activeTab = null;
    window.renderTabs();
    window.updateRemoteDesktopButton();
    window.renderPane('remote');
    check('disconnected remote pane shows Quick-Connect Hub, saved sites grid, and empty-tab hint instead of blank void',
      !doc.getElementById('remoteEmptyHub').hidden &&
      doc.getElementById('remoteFileTable').hidden &&
      !doc.getElementById('emptyTabHint').hidden &&
      doc.querySelectorAll('#quickConnectSites .quick-site-card').length === 2);
    doc.getElementById('quickProtocol').value = 's3';
    window.quickProtocolChanged();
    check('quickProtocolChanged updates quickPort default from 22 to 443 for S3',
      doc.getElementById('quickPort').value === '443');
    doc.getElementById('quickProtocol').value = 'sftp';
    window.quickProtocolChanged();

    wfState.tabs = prevTabs38;
    wfState.activeTab = prevActive38;
    wfState.sessions = prevSessions38;
    window.renderTabs();
    window.updateRemoteDesktopButton();
    window.renderPane('remote');
    check('reconnected remote pane hides Quick-Connect Hub and shows uppercase protocol badge',
      doc.getElementById('remoteEmptyHub').hidden &&
      !doc.getElementById('remoteFileTable').hidden &&
      doc.getElementById('emptyTabHint').hidden &&
      !doc.getElementById('remoteProtoBadge').hidden);

    doc.getElementById('localFilterInput').value = '__no_such_item_xyz__';
    window.setPaneFilter('local', '__no_such_item_xyz__');
    check('unmatched pane filter reveals empty-state message and Clear filter button',
      !doc.getElementById('localEmptyState').hidden &&
      !doc.getElementById('localClearFilterBtn').hidden);
    window.clearPaneFilter('local');
    check('clearPaneFilter resets filter input and hides empty-state notice',
      doc.getElementById('localFilterInput').value === '' &&
      doc.getElementById('localEmptyState').hidden);

    const wasShowingHidden = Boolean(wfState.showHidden);
    window.toggleHiddenFiles();
    check('hiddenFilesToolbarBtn syncs active state and aria-pressed with toggleHiddenFiles',
      doc.getElementById('hiddenFilesToolbarBtn').classList.contains('active') === !wasShowingHidden &&
      doc.getElementById('hiddenFilesToolbarBtn').getAttribute('aria-pressed') === String(!wasShowingHidden));
    window.toggleHiddenFiles();

    window.switchTab('queue');
    window.dockTabClick('queue');
    check('clicking already-active dock tab collapses lowerPanel',
      doc.getElementById('lowerPanel').classList.contains('collapsed'));
    window.dockTabClick('queue');
    await new Promise(resolve => setTimeout(resolve, 25));
    check('clicking collapsed dock tab re-expands lowerPanel',
      !doc.getElementById('lowerPanel').classList.contains('collapsed'));

    window.switchPrefTab('safety');
    check('Preferences 3-tab navigation switches cleanly between Transfers, Safety, and Scripts',
      doc.getElementById('prefTabSafety').classList.contains('active') &&
      !doc.getElementById('prefTabTransfers').classList.contains('active') &&
      doc.getElementById('prefTabSafetyBtn').getAttribute('aria-selected') === 'true');
    window.switchPrefTab('scripts');
    check('Preferences Scripts sub-tab activates installer scripts section',
      doc.getElementById('prefTabScripts').classList.contains('active') &&
      !!doc.querySelector('#fullBackupModal .dialog-grid-2') &&
      !!doc.querySelector('#davToolsModal .dialog-grid-2'));
    window.switchPrefTab('transfers');

    // CLI Console focus & shortcut isolation + Help menu Terminal Help entry.
    {
      const savedPromptCli = window.prompt;
      const cliMaskPrompts = [];
      window.prompt = question => { cliMaskPrompts.push(question); return null; };
      doc.getElementById('tabCliBtn').focus();
      window.dockTabClick('cli');
      check('clicking CLI Console tab focuses #cliInput immediately',
        doc.activeElement === doc.getElementById('cliInput'));
      doc.activeElement.dispatchEvent(new window.KeyboardEvent('keydown', { key: '-', bubbles: true, cancelable: true }));
      doc.activeElement.dispatchEvent(new window.KeyboardEvent('keydown', { key: '+', bubbles: true, cancelable: true }));
      doc.getElementById('cliOutput').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
      check('clicking #cliOutput with no selection keeps #cliInput focused',
        doc.activeElement === doc.getElementById('cliInput'));
      doc.getElementById('tabCli').dispatchEvent(new window.KeyboardEvent('keydown', { key: '-', bubbles: true, cancelable: true }));
      doc.getElementById('tabCli').dispatchEvent(new window.KeyboardEvent('keydown', { key: '+', bubbles: true, cancelable: true }));
      window.clearCliConsole();
      check('clearCliConsole returns focus to #cliInput and typing - or + in CLI Console never opens Commander mask popup',
        doc.activeElement === doc.getElementById('cliInput') && cliMaskPrompts.length === 0,
        JSON.stringify(cliMaskPrompts));
      window.switchTab('queue');
      await new Promise(resolve => setTimeout(resolve, 25));
      check('switching away from CLI Console blurs #cliInput so file-pane shortcuts work normally',
        doc.activeElement !== doc.getElementById('cliInput'));

      check('Help menu and LinSCP Help modal both expose Terminal Help',
        !!doc.querySelector('#helpMenu button[onclick*="showTerminalCopyHelp"]') &&
        !!doc.querySelector('#helpModal button[onclick*="showTerminalCopyHelp"]'));
      window.showTerminalCopyHelp();
      doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: '-', bubbles: true, cancelable: true }));
      doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: '+', bubbles: true, cancelable: true }));
      check('Commander - and + mask shortcuts do not fire while #terminalHelpModal is open',
        doc.getElementById('terminalHelpModal').classList.contains('open') && cliMaskPrompts.length === 0);
      doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
      check('Escape closes #terminalHelpModal opened from Commander Help',
        !doc.getElementById('terminalHelpModal').classList.contains('open'));
      window.prompt = savedPromptCli;
    }

    // Completed features: string matched preset & rule persistence, CLI lcd local sync & canonical completion,
    // Preferences resume default, and Editor Go-to-line + Search match line jump.
    {
      // 1. Transfer Presets: string `matched` from Rust `/api/presets`, `filename=` query param,
      //    reopening `#transferModal` preserves rule/permission/EOL/preserve_time='all' fields,
      //    and `saveTransferSettings()` forwards octal `permissions` + `preserve_time_dirs` in `transferOptions()`.
      wfState.focusPane = 'local';
      wfState.local.selection.clear();
      wfState.local.selection.add('a.txt');
      responses['/api/presets'] = {
        success: true,
        matched: 'StringMatchedPreset',
        presets: [{
          name: 'StringMatchedPreset',
          description: 'transfer=ascii preservetime=all permissions=0644',
          transfer: 'ascii',
          preserve_time: 'all',
          newer_only: true,
          speed: 384,
          permissions: '0644',
          eol: 'lf',
          filemask: '*.txt',
          host: '127.0.0.1',
          username: 'user',
          remote_dir: '/tmp/*',
          local_dir: '/tmp/*'
        }]
      };
      window.openTransferSettings();
      await window.loadTransferPresets();
      const lastPresetsGet = calls.filter(c => c.path === '/api/presets' && (!c.options.method || c.options.method === 'GET')).pop();
      check('loadTransferPresets passes selected filename and renders string matched preset from backend',
        !!lastPresetsGet &&
        String(lastPresetsGet.url || '').indexOf('filename=a.txt') >= 0 &&
        doc.getElementById('transferPresetMatchedHint').style.display === 'flex' &&
        doc.getElementById('transferPresetMatchedHint').textContent.indexOf('StringMatchedPreset') >= 0);

      window.applyMatchedTransferPreset();
      await window.saveTransferSettings();
      const savedPresetOpts = window.transferOptions();
      check('saving a selected preset forwards octal permissions and preserve_time_dirs in transferOptions()',
        savedPresetOpts.preset === 'StringMatchedPreset' &&
        savedPresetOpts.permissions === '0644' &&
        savedPresetOpts.preserve_time === true &&
        savedPresetOpts.preserve_time_dirs === true);

      // The transfer settings are kept in the preferences document, so the
      // permission mode and the directory timestamps survive a restart.
      const prefsSave = calls.filter(c => c.path === '/api/preferences'
        && String(c.options.method || 'POST').toUpperCase() === 'POST').pop();
      const prefsBody = prefsSave ? JSON.parse(prefsSave.options.body) : {};
      const prefRoundTrip = window.preferencesToSettings({
        permissions: '0644', preserve_time_dirs: true
      });
      check('the transfer dialog keeps its permission mode and directory timestamps in the preferences',
        !!prefsBody.preferences &&
        prefsBody.preferences.permissions === '0644' &&
        prefsBody.preferences.preserve_time_dirs === true &&
        prefRoundTrip.permissions === '0644' &&
        prefRoundTrip.preserveTimeDirs === true);

      window.openTransferSettings();
      await new Promise(resolve => setTimeout(resolve, 25));
      check('reopening #transferModal restores preset permissions, octal mode, EOL, and rule fields',
        doc.getElementById('transferPresetPermissions').value === 'mode' &&
        doc.getElementById('transferPresetModeOctal').value === '0644' &&
        doc.getElementById('transferPresetEol').value === 'lf' &&
        doc.getElementById('transferPresetHost').value === '127.0.0.1');
      await window.resetTransferSettings();
      window.closeModal('transferModal');
      delete responses['/api/presets'];

      // 2. Preferences `#prefResume` defaults to false when `resume` is omitted/false.
      window.fillPreferencesForm({});
      check('fillPreferencesForm defaults #prefResume to unchecked when resume is omitted',
        doc.getElementById('prefResume').checked === false &&
        doc.getElementById('prefPreserveTime').checked === true);
      await window.loadTransferSettings();

      // 3. CLI Console: expanded canonical Tab-completion (`lmkdir`, `find`, `savepreset`, `backup`)
      //    and `lcd` updating `state.local.path` from `result.local_dir` on local/disconnected tabs.
      const cliIn = doc.getElementById('cliInput');
      cliIn.value = 'lmk';
      window.handleCliInputKeydown(new window.KeyboardEvent('keydown', { key: 'Tab', cancelable: true }));
      const completedLmkdir = cliIn.value;
      cliIn.value = 'savep';
      window.handleCliInputKeydown(new window.KeyboardEvent('keydown', { key: 'Tab', cancelable: true }));
      const completedSavepreset = cliIn.value;
      const prevLocalPath = wfState.local.path;
      const prevExecResp = responses['/api/command/exec'];
      const prevLocalListResp = responses['/api/local/list'];
      responses['/api/command/exec'] = {
        success: true,
        exit_code: 0,
        stdout: '/tmp/cli-moved\n',
        stderr: '',
        local_dir: '/tmp/cli-moved'
      };
      responses['/api/local/list'] = { success: true, path: '/tmp/cli-moved', entries: [] };
      cliIn.value = 'lcd /tmp/cli-moved';
      await window.execCliCommand();
      const lastCliExec = calls.filter(c => c.path === '/api/command/exec').pop();
      const lastLocalList = calls.filter(c => c.path === '/api/local/list').pop();
      check('CLI Console completes lmkdir/savepreset, sends local_dir, and updates local pane from result.local_dir',
        completedLmkdir === 'lmkdir ' &&
        completedSavepreset === 'savepreset ' &&
        !!lastCliExec && JSON.parse(lastCliExec.options.body).local_dir === prevLocalPath &&
        wfState.local.path === '/tmp/cli-moved' &&
        !!lastLocalList && decodeURIComponent(String(lastLocalList.url || '')).indexOf('/tmp/cli-moved') >= 0);
      responses['/api/command/exec'] = prevExecResp;
      responses['/api/local/list'] = prevLocalListResp;
      await window.loadLocal(prevLocalPath);

      // 4. Editor Go-to-line button, live cursor indicator, and Search content-match line jump.
      check('Editor toolbar exposes #editorGotoLineBtn and #editorCursorPos',
        !!doc.getElementById('editorGotoLineBtn') && !!doc.getElementById('editorCursorPos'));
      const prevRemoteEdit = responses['/api/remote/edit'];
      const prevRemoteSearch = responses['/api/remote/search'];
      responses['/api/remote/edit'] = {
        success: true,
        content: 'line1\nline2\nline3\nneedle line 4\nline5\n',
        info: { size: 38, mtime: 1700000000, mtime_ns: '1700000000000000000', encoding: 'UTF-8', eol: 'lf', bom: false }
      };
      responses['/api/remote/search'] = {
        success: true,
        scanned: 1,
        skipped: 0,
        bytes_scanned: 38,
        matches: [{
          name: 'keep.txt',
          path: '/tmp/slowremote/keep.txt',
          size: 38,
          is_dir: false,
          line: 4,
          snippet: 'needle line 4'
        }]
      };
      window.openSearch('remote');
      doc.getElementById('searchContents').checked = true;
      window.toggleSearchContents();
      doc.getElementById('searchText').value = 'needle';
      await window.runSearch();
      const matchEditBtn = Array.from(doc.querySelectorAll('#searchResults button'))
        .find(b => b.textContent === 'Edit');
      check('Search content match renders Edit action button', !!matchEditBtn);
      matchEditBtn.click();
      await new Promise(resolve => setTimeout(resolve, 70));
      if (window.LinSCPEditor) {
        check('Search Edit action opens #editorModal jumped directly to match.line and updates #editorCursorPos',
          doc.getElementById('editorModal').classList.contains('open') &&
          doc.getElementById('editorCursorPos').textContent.indexOf('4') >= 0);
        window.openEditorGotoLine();
        check('openEditorGotoLine() opens CodeMirror .cm-goto-line panel inside #editorHost',
          !!doc.querySelector('#editorHost .cm-goto-line'));
      }
      window.closeEditor();
      responses['/api/remote/edit'] = prevRemoteEdit;
      if (prevRemoteSearch) responses['/api/remote/search'] = prevRemoteSearch;
      else delete responses['/api/remote/search'];
    }
  }

  check('no script errors', errors.length === 0, errors.join(' | '));
  window.close();
})();
