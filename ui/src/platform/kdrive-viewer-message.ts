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

/** Decode the bounded JSON contract produced by x2go_transport::viewer_message.
 * Image and screen contents are sensitive and must not be logged. This does
 * not parse raw wire messages or provide a transport. */
export function decodeKDriveViewerMessage(input: unknown): KDriveViewerMessage {
  const message = object(input);
  if (message.type === 'keepalive' || message.type === 'disconnect' || message.type === 'reinitialize') return { type: message.type };
  if (message.type === 'deleted-frames') {
    if (!Array.isArray(message.ids) || message.ids.length > 65536) throw new Error('Invalid KDrive frame deletion.');
    return { type: 'deleted-frames', ids: message.ids.map(uint) };
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
