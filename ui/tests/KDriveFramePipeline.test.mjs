import assert from 'node:assert/strict';
import test from 'node:test';
import { KDriveFramePipeline, KDriveImageDecoder } from '../dist/linscp-core.mjs';

// Synthetic PNG header; a fake WebView decodes it to distinguishable pixels.
const png = Uint8Array.from([137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,2,0,0,0,1]);
function setup() {
  let frames = [], resets = 0, decodeCount = 0;
  const doc = { defaultView: { Blob, async createImageBitmap() { decodeCount++; return { width: 2, height: 1, close() {} }; } },
    createElement() { return { width: 0, height: 0, getContext() { return { drawImage() {}, getImageData() {
      return { data: Uint8ClampedArray.of(1,2,3,255, 4,5,6,255) }; } }; } }; } };
  const surface = { render(frame) { frames.push(frame); return 'painted'; }, reset() { resets++; } };
  const pipeline = new KDriveFramePipeline(new KDriveImageDecoder(doc), surface);
  return { pipeline, get frames() { return frames; }, get resets() { return resets; }, get decodeCount() { return decodeCount; } };
}
const encoded = (x, y) => ({ sourceId: 0, sourceX: 0, sourceY: 0, x, y, width: 2, height: 1, data: png });
const frame = (extra = {}) => ({ width: 2, height: 1, x: -1, y: -1, cacheId: 0, windowId: 0, regions: [encoded(0, 0)], ...extra });

test('main image goes through the real image decoder to the surface', async () => {
  const s = setup();
  await s.pipeline.apply(frame());
  assert.equal(s.decodeCount, 1);
  assert.equal(s.frames[0].keyframe, true);
  assert.deepEqual([...s.frames[0].rectangles[0].pixels], [1,2,3,255,4,5,6,255]);
});

test('cached images and source rectangles are composed in order', async () => {
  const s = setup();
  await s.pipeline.apply(frame());
  await s.pipeline.apply(frame({ x: 0, y: 0, cacheId: 123 }));
  await s.pipeline.apply(frame({ width: 1, x: 1, y: 0, cacheId: 124,
    regions: [{ sourceId: 123, sourceX: 1, sourceY: 0, x: 0, y: 0, width: 1, height: 1, data: new Uint8Array() }] }));
  assert.deepEqual([...s.frames[2].rectangles[0].pixels], [4,5,6,255]);
  await s.pipeline.apply(frame({ width: 1, x: 0, y: 0, cacheId: 124, regions: [] }));
  assert.deepEqual([...s.frames[3].rectangles[0].pixels], [4,5,6,255]);
  assert.equal(s.decodeCount, 2);
});

test('screen updates use absolute region positions and clip to the screen', async () => {
  const s = setup(); await s.pipeline.apply(frame());
  await s.pipeline.apply(frame({ x: -1, y: 0, regions: [encoded(-1, 0)] }));
  const r = s.frames[1].rectangles[0];
  assert.deepEqual([r.x, r.y, r.width, r.height, ...r.pixels], [0,0,1,1,4,5,6,255]);
});

test('cache miss invalidates screen until explicit reset and a fresh main image', async () => {
  const s = setup(); await s.pipeline.apply(frame());
  await assert.rejects(s.pipeline.apply(frame({ x: 0, y: 0, cacheId: 42, regions: [] })), /cache miss/);
  assert.equal(s.resets, 1);
  await assert.rejects(s.pipeline.apply(frame()), /not ready/);
  s.pipeline.reset();
  await s.pipeline.apply(frame());
  assert.equal(s.frames.at(-1).sequence, 1);
});

test('deletions are explicit and unknown frame references fail closed', async () => {
  const s = setup(); await s.pipeline.apply(frame());
  await s.pipeline.apply(frame({ x: 0, y: 0, cacheId: 5 }));
  s.pipeline.deleteFrames([5]);
  await assert.rejects(s.pipeline.apply(frame({ x: 0, y: 0, cacheId: 5, regions: [] })), /cache miss/);
});

test('malformed regions and unsupported windows cannot paint', async () => {
  for (const bad of [frame({windowId: 1}), frame({regions: [encoded(1, 0)]}),
    frame({regions: [{...encoded(0, 0), data: new Uint8Array()}]})]) {
    const s = setup(); await assert.rejects(s.pipeline.apply(bad));
    assert.equal(s.frames.length, 0); assert.equal(s.resets, 1);
  }
});

test('an update cannot overtake an image still being decoded', async () => {
  let finish;
  const decode = () => new Promise(resolve => { finish = resolve; });
  const paints = [];
  const surface = { render(value) { paints.push(value); return 'painted'; }, reset() {} };
  const pipeline = new KDriveFramePipeline({ decode }, surface);
  const original = frame();
  const first = pipeline.apply(original);
  original.width = 999; // A later caller cannot change the submitted frame.
  await assert.rejects(pipeline.apply(frame()), /not ready/);
  assert.throws(() => pipeline.deleteFrames([1]), /not ready/);
  assert.throws(() => pipeline.reset(), /being decoded/);
  finish({width: 2, height: 1, pixels: Uint8ClampedArray.of(1,2,3,255,4,5,6,255)});
  await first;
  assert.equal(paints[0].width, 2);
  assert.equal(paints.length, 1);
});

test('pipeline paints through DesktopFrameRenderer and maps pointer coordinates', async () => {
  const { JSDOM } = await import('jsdom');
  const { DesktopFrameRenderer } = await import('../dist/linscp-core.mjs');
  const dom = new JSDOM('<div id="view"></div>');
  const painted = [];
  dom.window.HTMLCanvasElement.prototype.getContext = () => ({
    createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }),
    putImageData: (image, x, y) => painted.push({ pixels: [...image.data], x, y }),
  });
  dom.window.HTMLCanvasElement.prototype.getBoundingClientRect = () => ({left: 0, top: 0, right: 200, bottom: 100, width: 200, height: 100});
  const renderer = new DesktopFrameRenderer(dom.window.document.getElementById('view'));
  const decoder = { async decode(_data, width, height) { return {width, height, pixels: Uint8ClampedArray.of(1,2,3,255,4,5,6,255)}; } };
  const pipeline = new KDriveFramePipeline(decoder, renderer);
  await pipeline.apply(frame());
  assert.deepEqual(painted[0].pixels, [1,2,3,255,4,5,6,255]);
  assert.deepEqual(renderer.remotePoint(150, 50), {x: 1, y: 0});
  pipeline.reset();
  assert.equal(renderer.remotePoint(150, 50), null);
  renderer.destroy(); dom.window.close();
});
