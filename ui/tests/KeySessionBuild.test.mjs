import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { JSDOM } from 'jsdom';

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceDir = path.resolve(uiRoot, '../source/gui/web');
const source = fs.readFileSync(path.join(sourceDir, 'key-session.js'), 'utf8');

test('the packaged page embeds the exact shared dialog script', () => {
  const page = fs.readFileSync(path.join(uiRoot, 'dist/index.html'), 'utf8');
  assert.ok(page.includes(source));
  assert.ok(!page.includes('<script src="key-session.js"></script>'));
  assert.equal(page.split('window.LinSCPKeySession = {').length - 1, 1);
});

test('controller instances keep import scan state private and expose only dialog actions', () => {
  const dom = new JSDOM('<!doctype html>', { runScripts: 'outside-only' });
  dom.window.eval(source);
  const factory = dom.window.LinSCPKeySession.create;
  const first = factory({});
  const second = factory({});
  assert.deepEqual(Object.keys(first).sort(), [
    'exportKeySession', 'importKeySession', 'keyImportFileChanged',
    'openKeySessionExport', 'openKeySessionImport', 'scanKeySessionBackup',
    'setKeyExportSelection', 'setKeyImportSelection',
  ].sort());
  assert.notEqual(first.scanKeySessionBackup, second.scanKeySessionBackup);
  assert.equal(first.keyImportScanState, undefined);
  dom.window.close();
});
