import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { KDriveViewerSession } from '../dist/linscp-core.mjs';
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
const packetType = p => new DataView(p.buffer, p.byteOffset, p.byteLength).getUint32(0, true);
function setup(options = {}) {
  const dom = new JSDOM('<div id="view"></div>');
  const painted = [], writes = [], errors = [];
  let closes = 0, mainRequests = 0;
  dom.window.HTMLCanvasElement.prototype.getContext = () => ({
    createImageData: (w,h) => ({data: new Uint8ClampedArray(w*h*4)}),
    putImageData: (image,x,y) => painted.push({pixels:[...image.data], x, y}),
  });
  const transport = { async write(p) { writes.push(packetType(p)); }, close() { closes++; },
    async requestMainImage() { mainRequests++; } };
  const decoder = { async decode(_b,w,h) { return {width:w,height:h,pixels:new Uint8ClampedArray(w*h*4).fill(42)}; } };
  const viewer = new KDriveViewerSession(dom.window.document.getElementById('view'), transport,
    {capsLock:false,numLock:false,rightAltIsAltGr:false,decoder,onError:e => errors.push(e.message),...options});
  function key(code, down) { viewer.element.dispatchEvent(new dom.window.KeyboardEvent(down ? 'keydown' : 'keyup', {code, key:code, bubbles:true, cancelable:true})); }
  return {dom, viewer, transport, painted, writes, errors, key, get closes() {return closes;}, get mainRequests() {return mainRequests;}};
}
const region = {sourceId:0,sourceX:0,sourceY:0,x:0,y:0,width:2,height:1,data:Uint8Array.of(1)};
const main = () => ({type:'frame',frame:{width:2,height:1,x:-1,y:-1,cacheId:0,windowId:0,regions:[region]}});

test('a main image enables captured input and paints the desktop', async () => {
  const s = setup(); s.viewer.element.focus(); s.key('KeyA', true); await tick();
  assert.deepEqual(s.writes, []);
  await s.viewer.receive(main());
  assert.deepEqual(s.painted[0].pixels, Array(8).fill(42));
  s.viewer.element.focus(); s.key('KeyA', true); s.key('KeyA', false); await tick();
  assert.deepEqual(s.writes, [2,3]);
  s.viewer.close(); s.viewer.close(); assert.equal(s.closes, 1); s.dom.window.close();
});

test('input packets stop at the barrier until the reader acknowledges', async () => {
  const s = setup(); await s.viewer.receive(main()); s.viewer.element.focus();
  s.key('ShiftLeft',true); s.key('KeyA',true); s.key('KeyA',false); s.key('ShiftLeft',false); s.key('KeyB',true);
  await tick(); assert.deepEqual(s.writes, [2,3,3,8]);
  assert.equal(s.viewer.acknowledgeInputBarrier(), true); await tick();
  assert.deepEqual(s.writes, [2,3,3,8,2]);
  s.viewer.close(); s.dom.window.close();
});

test('reinitialize disables input until a fresh main image', async () => {
  const s = setup(); await s.viewer.receive(main());
  await s.viewer.receive({type:'reinitialize'}); assert.equal(s.mainRequests, 1);
  s.viewer.element.focus(); s.key('KeyA',true); await tick(); assert.deepEqual(s.writes, []);
  await s.viewer.receive(main()); s.viewer.element.focus(); s.key('KeyB',true); await tick();
  assert.deepEqual(s.writes, [2]); s.viewer.close(); s.dom.window.close();
});

test('bad or missed frames fail closed and notify once', async () => {
  const s = setup(); await s.viewer.receive(main());
  await assert.rejects(s.viewer.receive({type:'frame', frame:{...main().frame,x:0,y:0,cacheId:99,regions:[]}}));
  assert.equal(s.closes, 1); assert.deepEqual(s.errors, ['The KDrive viewer session ended.']);
  await assert.rejects(s.viewer.receive(main()), /closed/);
  s.viewer.close(); assert.equal(s.closes, 1); s.dom.window.close();
});

test('queued messages retain their original bytes and cannot overtake a decode', async () => {
  let resolve;
  const s = setup({decoder:{decode(bytes,w,h) { return new Promise(r => { resolve=() => r({width:w,height:h,pixels:new Uint8ClampedArray(w*h*4).fill(bytes[0])}); }); }}});
  const msg = main(); msg.frame.regions = [{...region,data:Uint8Array.of(7)}];
  const a = s.viewer.receive(msg);
  const b = s.viewer.receive({type:'deleted-frames',ids:[123]});
  msg.frame.regions[0].data[0] = 9;
  await tick(); resolve(); await Promise.all([a,b]);
  assert.deepEqual(s.painted[0].pixels, Array(8).fill(7));
  s.viewer.close(); s.dom.window.close();
});

test('closing while decoding prevents later painting', async () => {
  let resolve;
  const s = setup({decoder:{decode(_bytes,w,h) { return new Promise(r => { resolve=() => r({width:w,height:h,pixels:new Uint8ClampedArray(w*h*4)}); }); }}});
  const pending = s.viewer.receive(main()); await tick(); s.viewer.close(); resolve();
  await assert.rejects(pending); assert.equal(s.painted.length, 0); assert.equal(s.closes, 1);
  s.dom.window.close();
});

test('resize enqueues geometry event and selection/cursor messages update state', async () => {
  const selections = [];
  const s = setup({ onSelection: (text, sel) => selections.push([text, sel]) });
  s.dom.window.HTMLCanvasElement.prototype.toDataURL = () => 'data:image/png;base64,iVBORw0KGgo=';
  await s.viewer.receive(main());
  await s.viewer.resize(1280, 720);
  assert.deepEqual(s.writes, [7]);
  await s.viewer.receive({
    type: 'cursor',
    cursor: { serial: 11, width: 1, height: 1, hotX: 0, hotY: 0, foreground: [255, 255, 255], background: [0, 0, 0], data: new Uint8Array([0, 0, 255, 255]) }
  });
  assert.match(s.viewer.element.style.cursor, /^url\(data:image\/png;base64,/);
  await s.viewer.receive({ type: 'deleted-cursors', ids: [11] });
  assert.equal(s.viewer.element.style.cursor, 'default');
  await s.viewer.receive({
    type: 'selection',
    selection: { selection: 0, format: 0, chunkSize: 5, first: true, last: false, compressedSize: 0, total: 10, data: new TextEncoder().encode('hello') }
  });
  await s.viewer.receive({
    type: 'selection',
    selection: { selection: 0, format: 0, chunkSize: 6, first: false, last: true, compressedSize: 0, total: 11, data: new TextEncoder().encode(' world') }
  });
  assert.deepEqual(selections, [['hello world', 0]]);
  s.viewer.close();
  s.dom.window.close();
});


test('closing interrupts a pending main-image request', async () => {
  const s = setup(); await s.viewer.receive(main());
  s.transport.requestMainImage = () => new Promise(() => {});
  const work = s.viewer.receive({type:'reinitialize'});
  await tick(); s.viewer.close();
  await assert.rejects(work, /closed/);
  assert.equal(s.closes, 1); s.dom.window.close();
});

test('too many pending messages closes the session instead of dropping a delta', async () => {
  let resolve;
  const s = setup({decoder:{decode(_bytes,w,h) { return new Promise(r => { resolve=() => r({width:w,height:h,pixels:new Uint8ClampedArray(w*h*4)}); }); }}});
  const jobs = [s.viewer.receive(main())];
  await tick();
  for (let i=0;i<63;i++) jobs.push(s.viewer.receive({type:'keepalive'}));
  const overflow = s.viewer.receive({type:'keepalive'});
  // Attach rejection handlers before resolving the outstanding decode.
  const resultsPromise = Promise.allSettled([...jobs, overflow]);
  resolve();
  const results = await resultsPromise;
  assert.equal(results.length, 65);
  assert.ok(results.every(result => result.status === 'rejected'));
  assert.equal(s.closes, 1); assert.equal(s.errors.length, 1);
  s.dom.window.close();
});

test('service JSON reaches the renderer and malformed IPC closes the session', async () => {
  const s = setup();
  const message = main();
  message.frame.regions = [{...region, data:'AQID'}];
  await s.viewer.receiveIpc(message);
  assert.deepEqual(s.painted[0].pixels, Array(8).fill(42));
  message.frame.regions[0].data = '!!!';
  await assert.rejects(s.viewer.receiveIpc(message), /Invalid KDrive viewer message/);
  assert.equal(s.closes,1); assert.equal(s.errors.length,1);
  s.dom.window.close();
});
