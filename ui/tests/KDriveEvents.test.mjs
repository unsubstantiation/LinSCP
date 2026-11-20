import assert from 'node:assert/strict';
import test from 'node:test';
import { kdriveKeyEvent, kdriveButtonEvent, kdriveMotionEvent, kdriveUpdateEvent, kdriveGeometryEvent, kdriveControlEvent } from '../dist/linscp-core.mjs';

function fields(bytes, count) {
  assert.equal(bytes.length, 41);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const result = Array.from({ length: count }, (_, i) => view.getUint32(i * 4, true));
  assert.ok(bytes.subarray(count * 4).every(b => b === 0));
  return result;
}

test('key and button events encode type, modifier state and X code', () => {
  assert.deepEqual(fields(kdriveKeyEvent(true, 5, 38), 3), [2, 5, 38]);
  assert.deepEqual(fields(kdriveKeyEvent(false, 0, 38), 3), [3, 0, 38]);
  assert.deepEqual(fields(kdriveButtonEvent(true, 4, 1), 3), [4, 4, 1]);
  assert.deepEqual(fields(kdriveButtonEvent(false, 0, 5), 3), [5, 0, 5]);
});

test('motion and update events encode little endian remote geometry', () => {
  assert.deepEqual(fields(kdriveMotionEvent(1234, 567), 3), [6, 1234, 567]);
  assert.deepEqual(fields(kdriveUpdateEvent(20, 30, 1024, 768), 5), [8, 1024, 768, 20, 30]);
});

test('invalid input is rejected rather than silently truncated', () => {
  for (const code of [0, 7, 256, NaN, 8.5]) assert.throws(() => kdriveKeyEvent(true, 0, code));
  for (const state of [-1, 256, Infinity, 1.5]) assert.throws(() => kdriveButtonEvent(true, state, 1));
  for (const button of [0, 256, 1.5]) assert.throws(() => kdriveButtonEvent(true, 0, button));
  for (const x of [-1, 8192, NaN]) assert.throws(() => kdriveMotionEvent(x, 0));
  assert.throws(() => kdriveUpdateEvent(8191, 0, 2, 1));
  assert.throws(() => kdriveUpdateEvent(0, 0, 0, 1));
  assert.throws(() => kdriveUpdateEvent(0, 0, 8192, 8192));
});


test('geometry matches the negotiated single-screen wire layout', () => {
  const bytes = kdriveGeometryEvent(1280, 720);
  assert.equal(bytes.length, 41);
  assert.deepEqual(Array.from(bytes.slice(0, 13)), [7, 0, 0, 0, 0, 5, 208, 2, 0, 0, 5, 208, 2]);
  assert.ok(bytes.subarray(13).every(b => b === 0));
  for (const [w, h] of [[0, 1], [8193, 1], [8192, 8192], [1.5, 1], [NaN, 1]]) {
    assert.throws(() => kdriveGeometryEvent(w, h));
  }
});

test('payload-free controls have fixed types and zeroed payloads', () => {
  for (const [name, type] of [['keepalive', 12], ['cache-rebuild', 13], ['disconnect', 15]]) {
    assert.deepEqual(fields(kdriveControlEvent(name), 3), [type, 0, 0]);
  }
  assert.throws(() => kdriveControlEvent('unknown'));
});
