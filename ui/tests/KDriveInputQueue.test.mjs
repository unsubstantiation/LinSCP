import assert from 'node:assert/strict';
import test from 'node:test';
import { KDriveInputQueue, KDriveInputTranslator } from '../dist/linscp-core.mjs';
const packet = type => { const bytes = new Uint8Array(41); new DataView(bytes.buffer).setUint32(0, type, true); return { type:'packet', bytes }; };
const barrier = { type:'barrier' };
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const typeOf = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, true);

test('writes batches in order and waits for a barrier acknowledgement', async () => {
  const writes = [];
  const queue = new KDriveInputQueue(async bytes => { writes.push(bytes); });
  const first = queue.enqueue([packet(2), barrier, packet(3)]);
  const second = queue.enqueue([packet(4)]);
  await tick();
  assert.deepEqual(writes.map(typeOf), [2,8]);
  assert.equal(queue.acknowledgeBarrier(), true);
  assert.equal(queue.acknowledgeBarrier(), false);
  await Promise.all([first, second]);
  assert.deepEqual(writes.map(typeOf), [2,8,3,4]);
  assert.deepEqual([...writes[1].slice(0,20)], [8,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0]);
});

test('accepts a response received before a barrier write resolves', async () => {
  let finish, queue;
  queue = new KDriveInputQueue(bytes => {
    if (typeOf(bytes) !== 8) return Promise.resolve();
    return new Promise(resolve => { finish = resolve; });
  });
  let done = false;
  const work = queue.enqueue([barrier, packet(3)]).then(() => { done = true; });
  await tick();
  assert.equal(queue.acknowledgeBarrier(), true);
  await tick(); assert.equal(done, false);
  finish(); await work;
  assert.equal(done, true);
});

test('timeout rejects the active and queued batches and permanently stops writes', async () => {
  const writes = [];
  const queue = new KDriveInputQueue(async bytes => { writes.push(typeOf(bytes)); }, 20);
  const a = queue.enqueue([barrier, packet(2)]);
  const b = queue.enqueue([packet(3)]);
  const results = await Promise.allSettled([a,b]);
  assert.deepEqual(results.map(r => r.status), ['rejected','rejected']);
  assert.match(results[0].reason.message, /timed out/);
  assert.deepEqual(writes, [8]);
  await assert.rejects(queue.enqueue([packet(4)]), /timed out/);
  assert.equal(queue.acknowledgeBarrier(), false);
});

test('close interrupts a stuck write and rejects queued work', async () => {
  let written = 0;
  const queue = new KDriveInputQueue(() => { written++; return new Promise(() => {}); }, 1000);
  const a = queue.enqueue([packet(2)]), b = queue.enqueue([packet(3)]);
  await tick(); queue.close();
  const results = await Promise.allSettled([a,b]);
  assert.deepEqual(results.map(r => r.status), ['rejected','rejected']);
  assert.equal(written, 1);
  await assert.rejects(queue.enqueue([packet(4)]), /closed/);
});

test('copies packets before writing', async () => {
  let unblock;
  const writes = [];
  const queue = new KDriveInputQueue(bytes => { writes.push(typeOf(bytes)); return new Promise(resolve => { unblock = resolve; }); }, 1000, 2);
  const input = packet(2);
  const first = queue.enqueue([input]);
  const second = queue.enqueue([packet(3)]);
  input.bytes[0] = 99;
  await tick(); assert.deepEqual(writes, [2]);
  unblock(); await tick(); assert.deepEqual(writes, [2,3]);
  unblock(); await Promise.all([first, second]);
});

test('overflow fails closed rather than silently losing a translated event', async () => {
  const queue = new KDriveInputQueue(() => new Promise(() => {}), 1000, 1);
  const first = queue.enqueue([packet(2)]);
  const overflow = queue.enqueue([packet(3)]);
  const results = await Promise.allSettled([first, overflow]);
  assert.deepEqual(results.map(r => r.status), ['rejected','rejected']);
  await assert.rejects(queue.enqueue([packet(4)]), /limit/);
});

test('invalid action fails closed and closing before the write prevents it', async () => {
  let count = 0;
  const invalid = new KDriveInputQueue(async () => { count++; });
  await assert.rejects(invalid.enqueue([{type:'packet', bytes:new Uint8Array(3)}]), /Invalid/);
  await assert.rejects(invalid.enqueue([packet(2)]), /Invalid/);
  const closed = new KDriveInputQueue(async () => { count++; });
  const first = closed.enqueue([packet(2)]);
  closed.close();
  await assert.rejects(first, /closed/);
  await tick(); assert.equal(count, 0);
});

test('translator actions flow in order and the barrier gates the next key', async () => {
  const translator = new KDriveInputTranslator({ capsLock:false, numLock:false, rightAltIsAltGr:false });
  const key = (code, down) => ({type:'key', code, key:'', down, location:0, repeat:false});
  const actions = [];
  for (const event of [key('ShiftLeft', true),key('KeyA',true),key('KeyA',false),key('ShiftLeft',false),key('KeyB',true)]) {
    actions.push(...translator.translate(event));
  }
  const writes = [];
  const queue = new KDriveInputQueue(async bytes => writes.push(typeOf(bytes)));
  const work = queue.enqueue(actions);
  await tick(); assert.deepEqual(writes, [2,3,3,8]);
  queue.acknowledgeBarrier(); await work;
  assert.deepEqual(writes, [2,3,3,8,2]);
});
