import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeKDriveViewerMessage } from '../dist/linscp-core.mjs';
const ipc = () => ({type:'frame',frame:{width:2,height:1,x:-1,y:-1,cacheId:0,windowId:0,regions:[{sourceId:0,sourceX:0,sourceY:0,x:0,y:0,width:2,height:1,data:'AQID'}]}});

test('decodes the backend frame contract and leaves references empty', () => {
  const message = ipc();
  message.frame.regions.push({sourceId:9,sourceX:2,sourceY:3,x:0,y:0,width:1,height:1,data:''});
  const decoded = decodeKDriveViewerMessage(message);
  assert.equal(decoded.type, 'frame');
  assert.deepEqual([...decoded.frame.regions[0].data], [1,2,3]);
  assert.deepEqual([...decoded.frame.regions[1].data], []);
  assert.deepEqual([decoded.frame.x, decoded.frame.cacheId], [-1,0]);
});

test('accepts only bounded known control messages and uint32 cache IDs', () => {
  assert.deepEqual(decodeKDriveViewerMessage({type:'deleted-frames',ids:[0,4294967295]}), {type:'deleted-frames',ids:[0,4294967295]});
  for (const type of ['keepalive','disconnect','reinitialize']) assert.deepEqual(decodeKDriveViewerMessage({type}), {type});
  for (const message of [null, {type:'clipboard'}, {type:'deleted-frames',ids:[-1]}, {type:'deleted-frames',ids:[1.5]}, {type:'deleted-frames',ids:Array(65537).fill(0)}]) {
    assert.throws(() => decodeKDriveViewerMessage(message));
  }
});

test('rejects malformed base64, noncanonical padding, invalid numbers and too many regions', () => {
  for (const data of ['@AAA','AA=A','A','AB==','AAB=','AA==\n']) {
    const value = ipc(); value.frame.regions[0].data = data;
    assert.throws(() => decodeKDriveViewerMessage(value));
  }
  for (const number of [-1, NaN, 4294967296, 0.5]) {
    const value = ipc(); value.frame.regions[0].sourceId = number;
    assert.throws(() => decodeKDriveViewerMessage(value));
  }
  const value = ipc(); value.frame.regions = Array(65).fill(value.frame.regions[0]);
  assert.throws(() => decodeKDriveViewerMessage(value));
});

test('checks aggregate decoded image size before allocating images', () => {
  const value = ipc();
  value.frame.regions = [{...value.frame.regions[0],data:'AAAA'.repeat(5_592_406)}];
  assert.throws(() => decodeKDriveViewerMessage(value), /limit|encoding/);
});

test('decodes cursor, deleted-cursors, selection and demand-selection messages', () => {
  const cur = decodeKDriveViewerMessage({
    type: 'cursor',
    cursor: { serial: 7, width: 2, height: 1, hotX: 1, hotY: 0, foreground: [255, 255, 255], background: [0, 0, 0], data: 'AQIDBAUGBwg=' }
  });
  assert.equal(cur.type, 'cursor');
  assert.equal(cur.cursor.serial, 7);
  assert.equal(cur.cursor.data.byteLength, 8);
  assert.deepEqual(decodeKDriveViewerMessage({ type: 'deleted-cursors', ids: [7, 8] }), { type: 'deleted-cursors', ids: [7, 8] });
  const sel = decodeKDriveViewerMessage({
    type: 'selection',
    selection: { selection: 0, format: 0, chunkSize: 5, first: true, last: true, compressedSize: 0, total: 5, data: 'aGVsbG8=' }
  });
  assert.equal(sel.type, 'selection');
  assert.equal(new TextDecoder().decode(sel.selection.data), 'hello');
  assert.deepEqual(decodeKDriveViewerMessage({ type: 'demand-selection', selection: 0 }), { type: 'demand-selection', selection: 0 });
});

