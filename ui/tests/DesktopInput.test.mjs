import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { DesktopFrameRenderer, DesktopInput } from '../dist/linscp-core.mjs';

function setup() {
  const dom = new JSDOM('<!doctype html><div id="remote"></div><button id="outside">outside</button>');
  const win = dom.window;
  win.HTMLCanvasElement.prototype.getContext = () => ({
    createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }),
    putImageData() {},
  });
  win.HTMLCanvasElement.prototype.getBoundingClientRect = () =>
    ({ left: 10, top: 20, right: 210, bottom: 120, width: 200, height: 100 });
  const renderer = new DesktopFrameRenderer(win.document.getElementById('remote'));
  renderer.render({ sequence: 1, width: 400, height: 200, keyframe: true,
    rectangles: [{ x: 0, y: 0, width: 400, height: 200, pixels: new Uint8Array(400 * 200 * 4) }] });
  const events = [];
  const input = new DesktopInput(renderer, event => events.push(event));
  function key(type, code, key, extra = {}) {
    const event = new win.KeyboardEvent(type, { bubbles: true, cancelable: true, code, key, ...extra });
    renderer.element.dispatchEvent(event);
    return event;
  }
  function mouse(target, type, options = {}) {
    const event = new win.MouseEvent(type, { bubbles: true, cancelable: true, ...options });
    target.dispatchEvent(event);
    return event;
  }
  return { win, renderer, input, events, key, mouse, close() { input.destroy(); renderer.destroy(); win.close(); } };
}

test('keyboard input requires an enabled, focused canvas and preserves physical keys', () => {
  const s = setup();
  const canvas = s.renderer.element;
  canvas.focus();
  assert.equal(s.key('keydown', 'KeyA', 'a').defaultPrevented, false);
  s.input.setEnabled(true);
  s.win.document.getElementById('outside').focus();
  assert.equal(s.key('keydown', 'KeyA', 'a').defaultPrevented, false);
  canvas.focus();
  assert.equal(s.key('keydown', 'ControlLeft', 'Control', { location: 1 }).defaultPrevented, true);
  s.key('keydown', 'KeyA', 'a');
  s.key('keydown', 'KeyA', 'a', { repeat: true });
  s.key('keyup', 'KeyA', 'A'); // release uses the original press, even if modifiers changed
  s.key('keyup', 'ControlLeft', 'Control', { location: 1 });
  assert.deepEqual(s.events, [
    { type: 'key', down: true, code: 'ControlLeft', key: 'Control', location: 1, repeat: false },
    { type: 'key', down: true, code: 'KeyA', key: 'a', location: 0, repeat: false },
    { type: 'key', down: true, code: 'KeyA', key: 'a', location: 0, repeat: true },
    { type: 'key', down: false, code: 'KeyA', key: 'a', location: 0, repeat: false },
    { type: 'key', down: false, code: 'ControlLeft', key: 'Control', location: 1, repeat: false },
  ]);
  assert.equal(s.key('keydown', 'KeyA', 'a', { isComposing: true }).defaultPrevented, false);
  assert.equal(s.key('keydown', 'Quote', 'Dead').defaultPrevented, false);
  assert.equal(s.key('keyup', 'KeyB', 'b').defaultPrevented, false);
  assert.equal(s.events.length, 5);
  s.close();
});

test('focus loss and disable release keys in reverse order, without duplicate releases', () => {
  const s = setup();
  s.input.setEnabled(true);
  s.renderer.element.focus();
  s.key('keydown', 'ControlLeft', 'Control', { location: 1 });
  s.key('keydown', 'KeyA', 'a');
  s.win.document.getElementById('outside').focus();
  assert.deepEqual(s.events.slice(2).map(e => [e.code, e.down]), [['KeyA', false], ['ControlLeft', false]]);
  s.win.dispatchEvent(new s.win.Event('blur'));
  assert.equal(s.events.length, 4);
  s.renderer.element.focus();
  s.key('keydown', 'ShiftLeft', 'Shift', { location: 1 });
  s.input.setEnabled(false);
  assert.equal(s.events.at(-1).code, 'ShiftLeft');
  assert.equal(s.events.at(-1).down, false);
  const count = s.events.length;
  s.input.setEnabled(false);
  s.key('keydown', 'KeyB', 'b');
  assert.equal(s.events.length, count);
  s.close();
});

test('pointer coordinates, multiple buttons, drag outside, and wheel are forwarded in order', () => {
  const s = setup();
  const canvas = s.renderer.element;
  s.input.setEnabled(true);
  assert.equal(s.mouse(canvas, 'mousedown', { button: 0, clientX: 110, clientY: 70 }).defaultPrevented, true);
  assert.equal(s.win.document.activeElement, canvas);
  s.mouse(canvas, 'mousedown', { button: 2, clientX: 110, clientY: 70 });
  s.mouse(s.win.document.body, 'mousemove', { clientX: 500, clientY: -20 });
  s.mouse(s.win.document.body, 'mouseup', { button: 0, clientX: 500, clientY: -20 });
  s.mouse(s.win.document.body, 'mouseup', { button: 2, clientX: 500, clientY: -20 });
  const wheel = new s.win.WheelEvent('wheel', { bubbles: true, cancelable: true, clientX: 110, clientY: 70,
    deltaX: -1, deltaY: 3, deltaMode: 1 });
  canvas.dispatchEvent(wheel);
  assert.equal(wheel.defaultPrevented, true);
  assert.deepEqual(s.events, [
    { type: 'button', down: true, button: 0, x: 200, y: 100 },
    { type: 'button', down: true, button: 2, x: 200, y: 100 },
    { type: 'pointer', x: 399, y: 0 },
    { type: 'button', down: false, button: 0, x: 399, y: 0 },
    { type: 'button', down: false, button: 2, x: 399, y: 0 },
    { type: 'scroll', x: 200, y: 100, deltaX: -1, deltaY: 3, deltaMode: 1 },
  ]);
  assert.equal(s.mouse(canvas, 'contextmenu', { clientX: 110, clientY: 70 }).defaultPrevented, true);
  s.close();
});

test('outside clicks and hover do not reach the remote, and blur releases held mouse buttons', () => {
  const s = setup();
  const canvas = s.renderer.element;
  s.input.setEnabled(true);
  s.mouse(canvas, 'mousedown', { button: 0, clientX: 300, clientY: 70 });
  assert.equal(s.events.length, 0);
  s.mouse(canvas, 'mousedown', { button: 0, clientX: 110, clientY: 70 });
  s.mouse(s.win.document.body, 'mousemove', { clientX: 300, clientY: 70 });
  s.win.dispatchEvent(new s.win.Event('blur'));
  assert.deepEqual(s.events.at(-1), { type: 'button', down: false, button: 0, x: 399, y: 100 });
  const count = s.events.length;
  s.mouse(s.win.document.body, 'mousemove', { clientX: 110, clientY: 70 });
  s.mouse(s.win.document.body, 'mouseup', { button: 0, clientX: 110, clientY: 70 });
  assert.equal(s.events.length, count);
  s.close();
});

test('destroy releases held input and detaches all listeners', () => {
  const s = setup();
  s.input.setEnabled(true);
  s.mouse(s.renderer.element, 'mousedown', { button: 0, clientX: 110, clientY: 70 });
  s.key('keydown', 'KeyA', 'a');
  s.input.destroy();
  assert.deepEqual(s.events.slice(-2), [
    { type: 'key', down: false, code: 'KeyA', key: 'a', location: 0, repeat: false },
    { type: 'button', down: false, button: 0, x: 200, y: 100 },
  ]);
  const count = s.events.length;
  s.input.setEnabled(true);
  s.key('keydown', 'KeyB', 'b');
  s.mouse(s.renderer.element, 'mousedown', { button: 0, clientX: 110, clientY: 70 });
  s.win.dispatchEvent(new s.win.Event('blur'));
  assert.equal(s.events.length, count);
  s.close();
});
