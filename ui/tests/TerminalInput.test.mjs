import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';

import { TerminalInput, cursorCellRect } from '../dist/linscp-core.mjs';

/**
 * A real textarea in a real document.
 *
 * These tests are about the one thing a phone terminal could not do: put a
 * character into a shell. That path runs through a genuine `HTMLTextAreaElement`
 * - its `value`, its events, its composition flags - so a stub would test the
 * stub. jsdom supplies the element; the events below are dispatched the way a
 * browser dispatches them.
 */
function installDom() {
  const dom = new JSDOM('<!doctype html><div id="host"></div>', { pretendToBeVisual: true });
  const host = dom.window.document.getElementById('host');
  return { dom, host, cleanup: () => dom.window.close() };
}

/** Builds an attachment on `host` and records what it sends. */
function makeInput(host) {
  const sent = [];
  const keys = [];
  const input = new TerminalInput({
    container: host,
    onData: (data) => sent.push(data),
    onKey: (event) => {
      keys.push(event.key);
      // Stand in for the session's encoder: Enter and Backspace are named keys.
      if (event.key === 'Enter') { sent.push('\r'); return true; }
      if (event.key === 'Backspace') { sent.push('\x7f'); return true; }
      return false;
    },
  });
  const element = host.querySelector('textarea');
  return { input, element, sent, keys };
}

test('the terminal gets an input element it can focus', () => {
  const { dom, host, cleanup } = installDom();
  const { input, element } = makeInput(host);
  assert.ok(element, 'a textarea exists for the input method to compose in');
  assert.equal(element.getAttribute('spellcheck'), 'false');
  // Squiggly autocorrect on a shell command is the last thing anyone wants.
  assert.equal(element.getAttribute('autocorrect'), 'off');
  input.focus();
  assert.equal(dom.window.document.activeElement, element, 'focusing it is what raises the keyboard');
  assert.equal(input.focused, true);
  input.blur();
  assert.equal(input.focused, false);
  cleanup();
});

test('a typed character reaches the shell once and leaves the field empty', () => {
  const { dom, host, cleanup } = installDom();
  const { input, element, sent } = makeInput(host);
  input.focus();
  element.value = 'l';
  element.dispatchEvent(new dom.window.Event('input'));
  assert.deepEqual(sent, ['l']);
  // Left behind, the next keystroke would carry it again; the terminal's grid is
  // the only place text may accumulate.
  assert.equal(element.value, '', 'the attachment never becomes a second buffer');
  cleanup();
});

test('Enter is a carriage return, not the newline a textarea would produce', () => {
  const { dom, host, cleanup } = installDom();
  const { input, element, sent } = makeInput(host);
  input.focus();
  // A browser would insert "\n" here; the shell wants "\r".
  const event = new dom.window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true });
  element.dispatchEvent(event);
  assert.deepEqual(sent, ['\r']);
  assert.equal(event.defaultPrevented, true, 'the textarea must not also insert a newline');
  cleanup();
});

test('Backspace on an empty field deletes in the shell, not in the page', () => {
  const { dom, host, cleanup } = installDom();
  const { input, element, sent } = makeInput(host);
  input.focus();
  element.dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Backspace', cancelable: true }));
  assert.deepEqual(sent, ['\x7f']);
  // With text in the field, deleting it is the delete: sending \x7f as well
  // would erase two characters on the far side for one press.
  sent.length = 0;
  element.value = 'x';
  element.dispatchEvent(new dom.window.KeyboardEvent('keydown', { key: 'Backspace', cancelable: true }));
  assert.deepEqual(sent, [], 'the textarea spends the press on its own text');
  cleanup();
});

test('an input method mid-composition is not sent until it commits', () => {
  const { dom, host, cleanup } = installDom();
  const { input, element, sent } = makeInput(host);
  input.focus();
  // Half-typed romaji must not reach the shell on the way to a character.
  element.dispatchEvent(new dom.window.Event('compositionstart'));
  element.value = 'に';
  element.dispatchEvent(new dom.window.Event('input'));
  assert.deepEqual(sent, [], 'interim text stays in the input method');
  element.value = '日本';
  element.dispatchEvent(new dom.window.Event('compositionend'));
  assert.deepEqual(sent, ['日本'], 'the committed text is sent once');
  assert.equal(element.value, '');
  cleanup();
});

test('a paste goes to the same place the keyboard does', () => {
  const { dom, host, cleanup } = installDom();
  const pastes = [];
  const input = new TerminalInput({
    container: host,
    onData: () => {},
    onPaste: (text) => pastes.push(text),
  });
  const element = host.querySelector('textarea');
  const event = new dom.window.Event('paste', { cancelable: true });
  event.clipboardData = { getData: () => 'ls -la\n' };
  element.dispatchEvent(event);
  assert.deepEqual(pastes, ['ls -la\n']);
  assert.equal(event.defaultPrevented, true);
  cleanup();
});

test('the keyboard sits under the cursor so the candidate window does too', () => {
  const { dom, host, cleanup } = installDom();
  const { input, element } = makeInput(host);
  assert.deepEqual(cursorCellRect({ column: 12, line: 3 }, { width: 9, height: 18 }),
    { left: 108, top: 54, width: 9, height: 18 });
  input.moveTo(cursorCellRect({ column: 40, line: 12 }, { width: 10, height: 20 }));
  assert.equal(element.style.left, '400px');
  assert.equal(element.style.top, '240px');
  cleanup();
});

test('destroying the attachment puts the soft keyboard away', () => {
  const { dom, host, cleanup } = installDom();
  const { input, element } = makeInput(host);
  input.focus();
  assert.equal(host.querySelector('textarea'), element);
  input.destroy();
  // An element left focused would hold the keyboard open over whatever the
  // person opened next.
  assert.equal(host.querySelector('textarea'), null);
  assert.equal(input.focused, false);
  // Sending into a destroyed attachment is a no-op rather than a throw: the
  // session may still be finishing its last frame.
  input.moveTo({ left: 0, top: 0, width: 1, height: 1 });
  cleanup();
});
