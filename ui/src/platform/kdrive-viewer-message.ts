import type { KDriveViewerMessage } from './kdrive-viewer-session.js';
import type { KDriveRegion } from './kdrive-frame-pipeline.js';

const MAX_FRAME_BYTES = 16 * 1024 * 1024;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid KDrive viewer message.');
  return value as Record<string, unknown>;
}
function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) throw new Error('Invalid KDrive viewer number.');
  return value;
}
const uint = (v: unknown) => integer(v, 0, 0xffffffff);
const sint = (v: unknown) => integer(v, -0x80000000, 0x7fffffff);
function encodedLength(value: unknown): number {
  if (typeof value !== 'string' || value.length % 4 !== 0 || value.length > Math.ceil(MAX_FRAME_BYTES / 3) * 4) {
    throw new Error('Invalid KDrive image encoding.');
  }
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const length = value.length / 4 * 3 - padding;
  if (length > MAX_FRAME_BYTES) throw new Error('KDrive frame exceeds limit.');
  // Check linearly rather than using a repeated-group regular expression: some
  // JS engines exhaust their stack on a valid multi-megabyte image payload.
  for (let i = 0; i < value.length - padding; i++) {
    const c = value.charCodeAt(i);
    if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47)) {
      throw new Error('Invalid KDrive image encoding.');
    }
  }
  if (padding === 2 && (ALPHABET.indexOf(value[value.length - 3]!) & 15) !== 0) throw new Error('Invalid KDrive image encoding.');
  if (padding === 1 && (ALPHABET.indexOf(value[value.length - 2]!) & 3) !== 0) throw new Error('Invalid KDrive image encoding.');
  return length;
}

/** Decode the bounded JSON contract produced by x2go_transport::viewer_message(_extended).
 * Image and screen contents are sensitive and must not be logged. This does
 * not parse raw wire messages or provide a transport. */
export function decodeKDriveViewerMessage(input: unknown): KDriveViewerMessage {
  const message = object(input);
  if (message.type === 'keepalive' || message.type === 'disconnect' || message.type === 'reinitialize') return { type: message.type };
  if (message.type === 'deleted-frames' || message.type === 'deleted-cursors') {
    if (!Array.isArray(message.ids) || message.ids.length > 65536) throw new Error('Invalid KDrive ID deletion.');
    return { type: message.type, ids: message.ids.map(uint) };
  }
  if (message.type === 'cursor') {
    const cur = object(message.cursor);
    const width = integer(cur.width, 1, 256);
    const height = integer(cur.height, 1, 256);
    const hotX = integer(cur.hotX, 0, width - 1);
    const hotY = integer(cur.hotY, 0, height - 1);
    const serial = uint(cur.serial);
    if (!Array.isArray(cur.foreground) || cur.foreground.length !== 3 || !Array.isArray(cur.background) || cur.background.length !== 3) {
      throw new Error('Invalid KDrive cursor palette.');
    }
    const foreground: [number, number, number] = [integer(cur.foreground[0], 0, 255), integer(cur.foreground[1], 0, 255), integer(cur.foreground[2], 0, 255)];
    const background: [number, number, number] = [integer(cur.background[0], 0, 255), integer(cur.background[1], 0, 255), integer(cur.background[2], 0, 255)];
    const len = encodedLength(cur.data);
    if (len > 256 * 256 * 4) throw new Error('KDrive cursor exceeds limit.');
    const binary = atob(cur.data as string);
    const data = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) data[i] = binary.charCodeAt(i);
    return { type: 'cursor', cursor: { serial, width, height, hotX, hotY, foreground, background, data } };
  }
  if (message.type === 'selection') {
    const sel = object(message.selection);
    const selection = uint(sel.selection);
    const format = uint(sel.format);
    const chunkSize = integer(sel.chunkSize, 0, 2 * 1024 * 1024);
    const compressedSize = integer(sel.compressedSize, 0, 2 * 1024 * 1024);
    const total = integer(sel.total, 0, 2 * 1024 * 1024);
    if (typeof sel.first !== 'boolean' || typeof sel.last !== 'boolean') throw new Error('Invalid KDrive selection flags.');
    const len = encodedLength(sel.data);
    if (len > 2 * 1024 * 1024) throw new Error('KDrive selection exceeds limit.');
    const binary = atob(sel.data as string);
    const data = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) data[i] = binary.charCodeAt(i);
    return { type: 'selection', selection: { selection, format, chunkSize, first: sel.first, last: sel.last, compressedSize, total, data } };
  }
  if (message.type === 'demand-selection') {
    return { type: 'demand-selection', selection: integer(message.selection, 0, 65535) };
  }
  if (message.type !== 'frame') throw new Error('Unsupported KDrive viewer message.');
  const frame = object(message.frame);
  if (!Array.isArray(frame.regions) || frame.regions.length > 64) throw new Error('Invalid KDrive regions.');
  let total = 0;
  const metadata = frame.regions.map(raw => {
    const region = object(raw);
    total += encodedLength(region.data);
    if (total > MAX_FRAME_BYTES) throw new Error('KDrive frame exceeds limit.');
    return { sourceId: uint(region.sourceId), sourceX: sint(region.sourceX), sourceY: sint(region.sourceY),
      x: sint(region.x), y: sint(region.y), width: uint(region.width), height: uint(region.height), encoded: region.data as string };
  });
  // Validate frame metadata and all encoded sizes before allocating decoded data.
  const width = uint(frame.width), height = uint(frame.height), x = sint(frame.x), y = sint(frame.y);
  const cacheId = uint(frame.cacheId), windowId = uint(frame.windowId);
  const regions: KDriveRegion[] = metadata.map(({encoded, ...region}) => {
    const binary = atob(encoded);
    const data = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) data[i] = binary.charCodeAt(i);
    return { ...region, data };
  });
  return { type: 'frame', frame: { width, height, x, y, cacheId, windowId, regions } };
}
