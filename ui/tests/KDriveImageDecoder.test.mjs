import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { KDriveImageDecoder } from '../dist/linscp-core.mjs';

// Locally generated 2x1 red fixtures, not captured from a KDrive session.
const PNG = Uint8Array.from(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAIAAAABAQMAAADO7O3JAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAABlBMVEX/AAD///9BHTQRAAAAAWJLR0QB/wIt3gAAAAd0SU1FB+oLEwUrBtevwZMAAAAKSURBVAjXY2AAAAACAAHiIbwzAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDI2LTExLTE5VDA1OjQzOjA2KzAwOjAwsyQMWQAAACV0RVh0ZGF0ZTptb2RpZnkAMjAyNi0xMS0xOVQwNTo0MzowNiswMDowMMJ5tOUAAAAASUVORK5CYII=', 'base64'));
const JPEG = Uint8Array.from(Buffer.from('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAABAAIDAREAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACP/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAVAQEBAAAAAAAAAAAAAAAAAAAHCf/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/ADoDFU3/2Q==', 'base64'));

function fake() {
  let opened = 0, closed = 0, lastCanvas;
  const doc = {
    defaultView: {
      Blob,
      async createImageBitmap(blob, options) {
        opened++;
        assert.ok(['image/png', 'image/jpeg'].includes(blob.type));
        assert.equal(options.imageOrientation, 'none');
        return { width: 2, height: 1, close() { closed++; } };
      },
    },
    createElement() {
      lastCanvas = {
        width: 0, height: 0,
        getContext() { return { drawImage() {}, getImageData() { return { data: Uint8ClampedArray.of(255, 0, 0, 255, 255, 0, 0, 255) }; } }; },
      };
      return lastCanvas;
    },
  };
  return { doc, get opened() { return opened; }, get closed() { return closed; }, get canvas() { return lastCanvas; } };
}

test('accepts PNG and JPEG regions and clears temporary image resources', async () => {
  const s = fake();
  const decoder = new KDriveImageDecoder(s.doc);
  for (const bytes of [PNG, JPEG]) {
    const image = await decoder.decode(bytes, 2, 1);
    assert.deepEqual([image.width, image.height], [2, 1]);
    assert.deepEqual([...image.pixels], [255, 0, 0, 255, 255, 0, 0, 255]);
    assert.equal(s.canvas.width, 0);
    assert.equal(s.canvas.height, 0);
  }
  assert.equal(s.opened, 2);
  assert.equal(s.closed, 2);
});

test('rejects malformed, oversized and mismatched images before native decoding', async () => {
  const s = fake();
  const decoder = new KDriveImageDecoder(s.doc);
  const oversized = PNG.slice();
  oversized[16] = 0x7f;
  const broken = PNG.slice(); broken[15] = 0;
  const badSegment = JPEG.slice(); badSegment[4] = 0xff; badSegment[5] = 0xff;
  for (const [image, width, height] of [[new Uint8Array(), 1, 1], [Uint8Array.of(1, 2, 3), 1, 1],
    [oversized, 2, 1], [broken, 2, 1], [badSegment, 2, 1], [PNG, 3, 1],
    [JPEG, 2, 3], [new Uint8Array(16 * 1024 * 1024 + 1), 1, 1], [PNG, 0, 1], [PNG, 8192, 8192]]) {
    await assert.rejects(decoder.decode(image, width, height));
  }
  assert.equal(s.opened, 0);
});

test('rejects concurrent decoding and resets after native failure', async () => {
  const s = fake();
  let done;
  s.doc.defaultView.createImageBitmap = () => new Promise(resolve => { done = resolve; });
  const decoder = new KDriveImageDecoder(s.doc);
  const pending = decoder.decode(PNG, 2, 1);
  await assert.rejects(decoder.decode(PNG, 2, 1), /busy/);
  done({ width: 4, height: 4, close() {} });
  await assert.rejects(pending, /dimensions changed/);
  s.doc.defaultView.createImageBitmap = async () => { throw new Error('decode failed'); };
  await assert.rejects(decoder.decode(PNG, 2, 1), /decode failed/);
  s.doc.defaultView.createImageBitmap = async () => ({ width: 2, height: 1, close() {} });
  assert.equal((await decoder.decode(PNG, 2, 1)).pixels.length, 8);
});

test('real PNG and JPEG decoding via an optional native-canvas test adapter', { skip: !process.env.LINSCP_TEST_CANVAS }, async () => {
  // The adapter exercises the same Blob/image/canvas flow without claiming it
  // substitutes for the WebViews on Linux, Windows, and macOS.
  const require = createRequire(import.meta.url);
  const { createCanvas, loadImage } = require(process.env.LINSCP_TEST_CANVAS);
  const doc = {
    defaultView: {
      Blob,
      async createImageBitmap(blob) {
        const image = await loadImage(Buffer.from(await blob.arrayBuffer()));
        image.close = () => {};
        return image;
      },
    },
    createElement: () => createCanvas(1, 1),
  };
  const decoder = new KDriveImageDecoder(doc);
  const png = await decoder.decode(PNG, 2, 1);
  assert.deepEqual([...png.pixels], [255, 0, 0, 255, 255, 0, 0, 255]);
  const jpeg = await decoder.decode(JPEG, 2, 1);
  for (let i = 0; i < jpeg.pixels.length; i += 4) {
    assert.ok(jpeg.pixels[i] >= 240 && jpeg.pixels[i + 1] < 15 && jpeg.pixels[i + 2] < 15);
    assert.equal(jpeg.pixels[i + 3], 255);
  }
});
