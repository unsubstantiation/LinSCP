import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const testsDir = path.dirname(fileURLToPath(import.meta.url));
const editorBundlePath = path.resolve(testsDir, '..', 'dist', 'linscp-editor.iife.js');

function createEditorWindow() {
  const dom = new JSDOM('<!doctype html><body><div id="host"></div></body>', {
    url: 'http://127.0.0.1:8080/',
    runScripts: 'outside-only',
    pretendToBeVisual: true,
  });
  dom.window.Range.prototype.getClientRects = () => [];
  dom.window.Range.prototype.getBoundingClientRect = () => ({
    left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0,
  });
  const code = fs.readFileSync(editorBundlePath, 'utf8');
  dom.window.eval(code + '; window.LinSCPEditor = LinSCPEditor;');
  return dom;
}

test('LinSCPEditor mounts, reports initial cursor, jumps to lines, and opens Go-to-line / Search panels', async () => {
  const dom = createEditorWindow();
  const host = dom.window.document.getElementById('host');
  const cursorEvents = [];
  const docChanges = [];

  const editor = dom.window.LinSCPEditor.mount(host, {
    value: 'alpha\nbeta\ngamma\ndelta\nepsilon',
    readOnly: false,
    languagePath: '/srv/app/config.rs',
    onDocChange: text => docChanges.push(text),
    onCursorChange: pos => cursorEvents.push(pos),
  });

  assert.equal(editor.readOnly, false);
  assert.deepEqual({ ...editor.getCursor() }, { line: 1, column: 1 });
  assert.ok(cursorEvents.length >= 1);
  assert.deepEqual({ ...cursorEvents[0] }, { line: 1, column: 1 });

  editor.goToLine(4);
  assert.deepEqual({ ...editor.getCursor() }, { line: 4, column: 1 });
  assert.deepEqual({ ...cursorEvents[cursorEvents.length - 1] }, { line: 4, column: 1 });

  // Out-of-range line numbers clamp cleanly to the last line.
  editor.goToLine(999);
  assert.deepEqual({ ...editor.getCursor() }, { line: 5, column: 1 });

  // Calling goToLine() with no argument opens CodeMirror's Go-to-line panel.
  editor.goToLine();
  const gotoDialog = host.querySelector('.cm-goto-line');
  assert.ok(gotoDialog, 'expected .cm-goto-line panel to open');
  const lineInput = gotoDialog.querySelector('input[name="line"]');
  assert.ok(lineInput, 'expected line input inside .cm-goto-line');
  lineInput.value = '2:2';
  gotoDialog.querySelector('form').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.deepEqual({ ...editor.getCursor() }, { line: 2, column: 3 });

  // openSearch() opens CodeMirror's Find / Replace panel.
  editor.openSearch();
  assert.ok(host.querySelector('.cm-search'), 'expected .cm-search panel to open');

  editor.setValue('one\ntwo');
  assert.equal(editor.getValue(), 'one\ntwo');
  assert.equal(docChanges[docChanges.length - 1], 'one\ntwo');

  editor.destroy();
  dom.window.close();
});
