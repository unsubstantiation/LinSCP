import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { KDriveInputTranslator, DesktopFrameRenderer, DesktopInput } from '../dist/linscp-core.mjs';
const create = (options = {}) => new KDriveInputTranslator({capsLock: false, numLock: false, rightAltIsAltGr: false, ...options});
const key = (code, down, repeat = false) => ({type:'key', code, key:'', location:0, down, repeat});
const button = (button, down, x=3, y=4) => ({type:'button', button, down, x, y});
const unpack = a => a.map(item => {
  if (item.type === 'barrier') return 'barrier';
  const view = new DataView(item.bytes.buffer, item.bytes.byteOffset, item.bytes.byteLength);
  return [view.getUint32(0, true), view.getUint32(4, true), view.getUint32(8, true)];
});

test('ordinary keys use physical X keycodes, including repeats and releases', () => {
  const t = create();
  assert.deepEqual(unpack(t.translate(key('KeyA', true))), [[2,0,38]]);
  assert.deepEqual(unpack(t.translate(key('KeyA', true, true))), [[2,0,38]]);
  assert.deepEqual(unpack(t.translate(key('KeyA', false))), [[3,0,38]]);
  assert.deepEqual(t.translate(key('KeyA', false)), []);
  assert.deepEqual(t.translate(key('__proto__', true)), []);
});

test('modifier release inserts a server barrier before subsequent events', () => {
  const t = create();
  assert.deepEqual(t.translate(key('ShiftLeft', true)), []);
  assert.deepEqual(unpack(t.translate(key('KeyA', true))), [[2,1,38]]);
  assert.deepEqual(unpack(t.translate(key('KeyA', false))), [[3,1,38]]);
  assert.deepEqual(unpack(t.translate(key('ShiftLeft', false))), [[3,1,50], 'barrier']);
  assert.deepEqual(t.translate(key('ShiftRight', true)), []);
  assert.deepEqual(unpack(t.translate(key('KeyB', true))), [[2,1,56]]);
});

test('paired modifiers remain active until the last side releases', () => {
  const t = create();
  t.translate(key('ShiftLeft', true)); t.translate(key('ShiftRight', true));
  t.translate(key('KeyA', true));
  assert.deepEqual(t.translate(key('ShiftLeft', false)), []);
  assert.deepEqual(unpack(t.translate(key('ShiftRight', false))), [[3,1,50], 'barrier']);
});

test('lock keys and AltGr update the X modifier mask', () => {
  const t = create({rightAltIsAltGr:true});
  assert.deepEqual(unpack(t.translate(key('CapsLock', true))), [[2,0,66], 'barrier']);
  assert.deepEqual(t.translate(key('CapsLock', true, true)), []);
  t.translate(key('CapsLock', false)); t.translate(key('AltRight', true));
  assert.deepEqual(unpack(t.translate(key('KeyA', true))), [[2,130,38]]);
  assert.deepEqual(unpack(t.translate(key('AltRight', false))), [[3,130,92], 'barrier']);
});

test('buttons follow the pointer; scroll uses bounded X button notches', () => {
  const t = create();
  assert.deepEqual(unpack(t.translate(button(2, true))), [[6,3,4],[4,0,3]]);
  assert.deepEqual(t.translate(button(2, true)), []);
  assert.deepEqual(unpack(t.translate(button(2, false))), [[5,0,3]]);
  const actions = t.translate({type:'scroll', x:3, y:4, deltaX:0, deltaY:-100000, deltaMode:0});
  assert.equal(actions.length, 20);
  assert.deepEqual(unpack(actions).slice(0,2), [[4,0,4],[5,0,4]]);
  assert.throws(() => t.translate(button(0, true, -1, 0)), /pointer/);
});

test('captured canvas input translates and focus loss releases the modifier', () => {
  const dom = new JSDOM('<div id="view"></div>');
  dom.window.HTMLCanvasElement.prototype.getContext = () => ({createImageData: (w,h) => ({data:new Uint8ClampedArray(w*h*4)}), putImageData() {}});
  const renderer = new DesktopFrameRenderer(dom.window.document.getElementById('view'));
  renderer.render({sequence:1, width:1, height:1, keyframe:true, rectangles:[{x:0,y:0,width:1,height:1,pixels:new Uint8Array(4)}]});
  const translator = create(), actions = [];
  const input = new DesktopInput(renderer, event => actions.push(...translator.translate(event)));
  input.setEnabled(true); renderer.element.focus();
  renderer.element.dispatchEvent(new dom.window.KeyboardEvent('keydown', {code:'ControlLeft', key:'Control'}));
  renderer.element.dispatchEvent(new dom.window.KeyboardEvent('keydown', {code:'KeyC', key:'c'}));
  renderer.element.blur();
  assert.deepEqual(unpack(actions), [[2,4,54],[3,4,54],[3,4,37],'barrier']);
  input.destroy(); renderer.destroy(); dom.window.close();
});

test('a lone modifier sends a tap without disturbing another held side', () => {
  const t = create();
  t.translate(key('MetaLeft', true));
  assert.deepEqual(unpack(t.translate(key('MetaLeft', false))), [[2,0,133]]);
  t.translate(key('ShiftLeft', true)); t.translate(key('ShiftRight', true));
  assert.deepEqual(t.translate(key('ShiftRight', false)), []);
  assert.deepEqual(unpack(t.translate(key('KeyA', true))), [[2,1,38]]);
});
