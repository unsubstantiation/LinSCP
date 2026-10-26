/* Real-page English/Spanish/French localization workflows, with a fake backend. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM, VirtualConsole } = require(require.resolve('jsdom', {paths: [process.cwd(), __dirname]}));
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const pause = () => new Promise(resolve => setTimeout(resolve, 30));
let checks = 0;
function check(message, value) { assert.ok(value, message); checks++; }

async function page({ saved, server, browsers = ['en-US'], blocked = false } = {}) {
  const calls = [], errors = [], prompts = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', error => errors.push(error));
  const dom = new JSDOM(html, {
    url: 'http://localhost:8080/', runScripts: 'dangerously', virtualConsole,
    beforeParse(window) {
      window.LSCP_TOKEN = 'private-token';
      window.LSCP_LANGUAGE = server;
      Object.defineProperty(window.navigator, 'languages', {value: browsers});
      if (saved) window.localStorage.setItem('lscp-language', saved);
      if (blocked) Object.defineProperty(window, 'localStorage', {get() { throw new Error('disabled'); }});
      window.setInterval = () => 1;
      window.prompt = question => { prompts.push(question); return 'new name {path} %n.txt'; };
      window.confirm = question => { prompts.push(question); return false; };
      window.fetch = async (url, options = {}) => {
        calls.push({ url, options });
        let data = {success: true};
        if (url === '/api/status') data = {tabs: [{id: 1, name: 'Delete', connected: true,
          session: {hostkey: 'SHA256:abc'}, remote_dir: '/Remote', local_dir: '/Local'}], active_tab: 1};
        if (String(url).startsWith('/api/local/list')) data = {success: true, path: '/Local', entries: [
          {name: 'Delete', size: 12, is_dir: false, permissions: '-rw-r--r--'}]};
        if (String(url).startsWith('/api/remote/list')) data = {success: true, path: '/Remote', entries: [
          {name: 'Save', size: 12, is_dir: false, permissions: '-rw-r--r--'}]};
        if (url === '/api/transfers') data = {transfers: [{id: 1, type: 'Upload', status: 'Queued',
          source: '/Local/Delete', destination: '/Remote/Delete'}]};
        if (url === '/api/sessions') data = {sessions: []};
        if (String(url).startsWith('/api/remote/edit')) data = {success: true, content: 'Delete <script> %n {path}',
          info: {mtime: 42, size: 12}};
        if (url === '/api/remote/save') data = {success: true, info: {mtime: 43}};
        if (url === '/api/sync/preview') data = {success: true, plan: {summary: {upload: 1}, items: [
          {action: 'upload', path: '/Remote/Delete', reason: 'the sizes differ'}]}};
        return {status: 200, json: async () => data};
      };
    }
  });
  await pause();
  return {dom, window: dom.window, calls, errors, prompts};
}

async function run() {
  for (const options of [
    {saved: 'es'}, {browsers: ['eo', 'es-MX']}, {server: 'es'},
    {saved: 'es', server: 'en'}, {saved: 'es', blocked: true, server: 'es'}
  ]) {
    const p = await page(options), w = p.window, doc = w.document;
    try {
      check('Spanish selected', doc.documentElement.lang === 'es');
      check('translated title', doc.querySelector('title').textContent.includes('Transferencia segura'));
      check('translated ARIA', doc.querySelector('#localPane').getAttribute('aria-label') === 'Panel local');
      check('translated toolbar', doc.querySelector('[onclick="openSiteManager()"] .tool-label').textContent === 'Nueva sesión');
      check('session names remain literal', doc.querySelector('#statusBadge').textContent === 'Conectado: Delete');
      check('filenames remain literal', doc.querySelector('#localFileList').textContent.includes('Delete'));
      check('filenames not translated', !doc.querySelector('#localFileList').textContent.includes('Eliminar'));
      check('translated transfer type', doc.querySelector('#queueList').textContent.includes('Subida'));
      check('translated task status', doc.querySelector('#queueList').textContent.includes('En cola'));
      check('Spanish display decimals', w.formatBytes(1536) === '1,5 KB');
      check('singular', w.tn('{count} match', '{count} matches', 1) === '1 coincidencia');
      check('zero plural', w.tn('{count} match', '{count} matches', 0) === '0 coincidencias');
      check('plural', w.tn('{count} match', '{count} matches', 2) === '2 coincidencias');
      check('single-pass literal interpolation', w.t('Line {line}: {snippet}', {line: 1, snippet: '{line} $& %n <img>'}) ===
        'Línea 1: {line} $& %n <img>');
      w.showHostKeyChallenge({host: 'host {port}', port: 22, fingerprint: 'SHA256:<img onerror=boom>'});
      check('security warning translated', doc.querySelector('#hostKeyQuestion').textContent.includes('Conéctese solo si la huella'));
      check('fingerprint exact', doc.querySelector('#hostKeyFingerprint').textContent === 'SHA256:<img onerror=boom>');
      check('fingerprint never becomes markup', !doc.querySelector('#hostKeyFingerprint img'));
      await w.openEditor('/Remote/Save', 'remote', false);
      check('translated editor', doc.querySelector('#editorTitle').textContent === 'Editando /Remote/Save');
      check('file content unchanged', doc.querySelector('#editorText').value === 'Delete <script> %n {path}');
      doc.querySelector('#editorText').value = 'New {path}';
      w.markDirty();
      check('dirty editor translated', doc.querySelector('#editorStatus').textContent === 'Modificado - sin guardar');
      await w.saveEditorFile();
      const save = p.calls.find(call => call.url === '/api/remote/save');
      check('save bytes unchanged', JSON.parse(save.options.body).content === 'New {path}');
      w.openSynchronize();
      await w.previewSynchronization();
      check('translated sync summary', doc.querySelector('#syncSummary').textContent.includes('1 por subir'));
      check('sync paths unchanged', doc.querySelector('#syncPreview').textContent.includes('/Remote/Delete'));
      w.eval("state.local.selection.add('Delete')");
      await w.transfer('upload');
      const transfer = p.calls.find(call => call.url === '/api/transfer/upload');
      check('API selections unchanged', JSON.parse(transfer.options.body).names[0] === 'Delete');
      check('API token preserved', transfer.options.headers['X-LSCP-Token'] === 'private-token');
      check(String(p.errors), p.errors.length === 0);
    } finally { await pause(); p.dom.window.close(); }
  }
  for (const options of [{saved: 'fr'}, {browsers: ['fr-CA', 'en']}, {server: 'fr'}]) {
    const p = await page(options), w = p.window, doc = w.document;
    try {
      check('French selected', doc.documentElement.lang === 'fr');
      check('French title', doc.querySelector('title').textContent.includes('Transfert de fichiers sécurisé'));
      check('French ARIA', doc.querySelector('#localPane').getAttribute('aria-label') === 'Panneau local');
      check('French toolbar', doc.querySelector('[onclick="openSiteManager()"] .tool-label').textContent === 'Nouvelle session');
      check('French no-break space before a colon',
        doc.querySelector('#statusBadge').textContent === 'Connecté\u00a0: Delete');
      check('French transfer type and status', doc.querySelector('#queueList').textContent.includes('Envoyer') &&
        doc.querySelector('#queueList').textContent.includes('En attente'));
      check('French display decimals', w.formatBytes(1536) === '1,5 KB');
      check('French zero is singular', w.tn('{count} match', '{count} matches', 0) === '0 résultat');
      check('French singular', w.tn('{count} match', '{count} matches', 1) === '1 résultat');
      check('French plural', w.tn('{count} match', '{count} matches', 2) === '2 résultats');
      check('French interpolation stays literal', w.t('Line {line}: {snippet}', {line: 1, snippet: '{line} $&'}) ===
        'Ligne 1\u00a0: {line} $&');
      await w.openEditor('/Remote/Save', 'remote', false);
      check('French editor title', doc.querySelector('#editorTitle').textContent === 'Édition /Remote/Save');
      w.openSynchronize();
      await w.previewSynchronization();
      check('French sync summary', doc.querySelector('#syncSummary').textContent.includes('1 à envoyer'));
      check(String(p.errors), p.errors.length === 0);
    } finally { await pause(); p.dom.window.close(); }
  }
  for (const options of [{saved: 'en', server: 'es'}, {browsers: ['xx']}, {server: 'en', browsers: ['es']}]) {
    const p = await page(options);
    try { check('English preference/fallback', p.window.document.documentElement.lang === 'en'); }
    finally {p.dom.window.close();}
  }
  const p = await page({saved: 'es'});
  try {
    p.window.eval('state.editor.dirty = true');
    p.window.changeLanguage('en');
    check('unsaved editor prevents language reload', p.window.localStorage.getItem('lscp-language') === 'es');
    check('localized unsaved-change confirmation', p.prompts.some(x => x.includes('sin guardar')));
  } finally {p.dom.window.close();}
  console.log(`${checks} localization checks passed`);
  console.log('evidence: suite=gui-localization platform=linux ran=1 skipped=0 failed=0');
}
run().catch(error => {
  console.error(error);
  console.log('evidence: suite=gui-localization platform=linux ran=1 skipped=0 failed=1');
  process.exitCode = 1;
});
