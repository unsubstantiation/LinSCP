import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { DesktopFrameRenderer } from '../dist/linscp-core.mjs';

function setup() {
  const dom = new JSDOM('<!doctype html><div id="desktop"></div>');
  const paints = [];
  let allocations = 0;
  let failPaint = false;
  const ctx = {
    createImageData(width, height) {
      allocations++;
      return { width, height, data: new Uint8ClampedArray(width * height * 4) };
    },
    putImageData(image, x, y) {
      if (failPaint) throw new Error('canvas unavailable');
      paints.push({ width: image.width, height: image.height, data: [...image.data], x, y });
    },
  };
  dom.window.HTMLCanvasElement.prototype.getContext = () => ctx;
  dom.window.HTMLCanvasElement.prototype.getBoundingClientRect = () =>
    ({ left: 10, top: 20, right: 210, bottom: 120, width: 200, height: 100 });
  const container = dom.window.document.getElementById('desktop');
  const renderer = new DesktopFrameRenderer(container);
  return { dom, renderer, container, paints, get allocations() { return allocations; },
    fail(value) { failPaint = value; } };
}

function full(sequence, width = 2, height = 1, value = 42) {
  return { sequence, width, height, keyframe: true,
    rectangles: [{ x: 0, y: 0, width, height, pixels: new Uint8Array(width * height * 4).fill(value) }] };
}

function delta(sequence, rectangles = [{ x: 1, y: 0, width: 1, height: 1, pixels: Uint8Array.of(1, 2, 3, 255) }]) {
  return { sequence, width: 2, height: 1, keyframe: false, rectangles };
}

test('paints full decoded pixels, ordered updates, and independent canvas instances', () => {
  const first = setup();
  const second = setup();
  assert.equal(first.renderer.render(full(10)), 'painted');
  assert.equal(first.renderer.element.width, 2);
  assert.equal(first.renderer.element.height, 1);
  assert.deepEqual(first.paints[0], { width: 2, height: 1, data: Array(8).fill(42), x: 0, y: 0 });
  assert.equal(first.renderer.render(delta(11)), 'painted');
  assert.deepEqual(first.paints[1], { width: 1, height: 1, data: [1, 2, 3, 255], x: 1, y: 0 });
  assert.equal(second.paints.length, 0);
  assert.equal(second.renderer.render(full(0, 1, 1, 17)), 'painted');
  assert.equal(first.paints.length, 2);
  first.renderer.destroy(); second.renderer.destroy(); first.dom.window.close(); second.dom.window.close();
});

test('requires a keyframe after a gap and ignores stale frames', () => {
  const s = setup();
  assert.equal(s.renderer.render(delta(1)), 'needs-keyframe');
  assert.equal(s.renderer.render(full(5)), 'painted');
  assert.equal(s.renderer.render(delta(5)), 'stale');
  assert.equal(s.renderer.render(delta(7)), 'needs-keyframe');
  assert.equal(s.renderer.remotePoint(20, 30), null);
  assert.equal(s.renderer.render(delta(6)), 'needs-keyframe');
  assert.equal(s.paints.length, 1);
  assert.equal(s.renderer.render(full(8, 3, 2)), 'painted');
  assert.equal(s.renderer.element.width, 3);
  assert.equal(s.renderer.element.height, 2);
  assert.equal(s.renderer.render({ sequence: 9, width: 3, height: 2, keyframe: false, rectangles: [] }), 'painted');
  s.renderer.destroy(); s.dom.window.close();
});

test('a size-changing delta requires a new keyframe', () => {
  const s = setup();
  s.renderer.render(full(1));
  assert.equal(s.renderer.render({ sequence: 2, width: 3, height: 1, keyframe: false, rectangles: [] }), 'needs-keyframe');
  assert.equal(s.renderer.element.width, 2);
  assert.equal(s.renderer.render(full(3, 3, 1)), 'painted');
  assert.equal(s.renderer.element.width, 3);
  s.renderer.destroy(); s.dom.window.close();
});

test('rejects malformed or excessive remote frames before modifying the canvas', () => {
  const s = setup();
  s.renderer.render(full(1));
  const invalid = [
    { ...full(2), width: 8193 },
    { ...full(2), width: 8192, height: 8192 },
    { ...full(2), sequence: Number.MAX_SAFE_INTEGER + 1 },
    { ...full(2), rectangles: [] },
    { ...delta(2), rectangles: [{ x: -1, y: 0, width: 1, height: 1, pixels: new Uint8Array(4) }] },
    { ...delta(2), rectangles: [{ x: 2, y: 0, width: 1, height: 1, pixels: new Uint8Array(4) }] },
    { ...delta(2), rectangles: [{ x: 1, y: 0, width: 1, height: 1, pixels: new Uint8Array(3) }] },
    { ...delta(2), rectangles: [{ x: 1, y: 0, width: 1, height: 1, pixels: new Uint16Array(2) }] },
    { ...delta(2), rectangles: Array(257).fill({ x: 0, y: 0, width: 1, height: 1, pixels: new Uint8Array(4) }) },
  ];
  for (const frame of invalid) assert.throws(() => s.renderer.render(frame));
  assert.equal(s.paints.length, 1);
  assert.equal(s.allocations, 1);
  assert.equal(s.renderer.render(delta(2)), 'painted', 'bad frames do not advance sequence');
  s.renderer.destroy(); s.dom.window.close();
});

test('maps scaled pointer coordinates and tears down the surface', () => {
  const s = setup();
  assert.equal(s.renderer.remotePoint(10, 20), null);
  s.renderer.render(full(1, 400, 200));
  assert.deepEqual(s.renderer.remotePoint(10, 20), { x: 0, y: 0 });
  assert.deepEqual(s.renderer.remotePoint(110, 70), { x: 200, y: 100 });
  assert.deepEqual(s.renderer.remotePoint(209.9, 119.9), { x: 399, y: 199 });
  for (const [x, y] of [[9, 20], [210, 20], [10, 120], [NaN, 20]]) assert.equal(s.renderer.remotePoint(x, y), null);
  assert.deepEqual(s.renderer.remotePoint(999, -10, true), { x: 399, y: 0 });
  assert.equal(s.renderer.remotePoint(NaN, 20, true), null);
  s.renderer.reset();
  assert.equal(s.renderer.remotePoint(20, 30), null);
  assert.equal(s.renderer.render(full(0)), 'painted', 'a new connection can restart sequence numbering');
  s.renderer.destroy();
  s.renderer.destroy();
  assert.equal(s.container.childNodes.length, 0);
  assert.equal(s.renderer.remotePoint(20, 30), null);
  assert.throws(() => s.renderer.render(full(1)), /closed/);
  s.dom.window.close();
});

test('requires a keyframe if painting fails partway through an update', () => {
  const s = setup();
  s.renderer.render(full(1));
  s.fail(true);
  assert.throws(() => s.renderer.render(delta(2)), /canvas unavailable/);
  s.fail(false);
  assert.equal(s.renderer.render(delta(2)), 'needs-keyframe');
  assert.equal(s.renderer.render(full(3)), 'painted');
  s.renderer.destroy(); s.dom.window.close();
});
