/** Low-level KDrive TCP client events. These do not translate browser keys or
 * manage modifier state; sending DOM events directly would be incorrect.
 * Field layouts are documented in docs/x2go-rendering.md. */
const EVENT_SIZE = 41;
const MAX_DIMENSION = 8192;
const MAX_PIXELS = 16_777_216;

/** These control packets have no payload; selection and version negotiation
 * have separate formats and are deliberately not accepted here. */
export type KDriveControlEvent = 'keepalive' | 'cache-rebuild' | 'disconnect';

function uint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function event(type: number, first: number, second: number): Uint8Array {
  if (!uint32(first) || !uint32(second)) throw new Error('Invalid KDrive event field.');
  const result = new Uint8Array(EVENT_SIZE);
  const view = new DataView(result.buffer);
  view.setUint32(0, type, true);
  view.setUint32(4, first, true);
  view.setUint32(8, second, true);
  return result;
}

/** Encode an X keycode and modifier mask. Keyboard state and server batching
 * semantics must be handled by the caller; this is not a DOM key mapping. */
export function kdriveKeyEvent(down: boolean, state: number, keycode: number): Uint8Array {
  if (typeof down !== 'boolean' || !Number.isInteger(keycode) || keycode < 8 || keycode > 255 || !Number.isInteger(state) || state < 0 || state > 255) {
    throw new Error('Invalid KDrive key event.');
  }
  return event(down ? 2 : 3, state, keycode);
}

/** X11 buttons are numbered from one. Wheel notches are button events too. */
export function kdriveButtonEvent(down: boolean, state: number, button: number): Uint8Array {
  if (typeof down !== 'boolean' || !Number.isInteger(button) || button < 1 || button > 255 || !Number.isInteger(state) || state < 0 || state > 255) {
    throw new Error('Invalid KDrive button event.');
  }
  return event(down ? 4 : 5, state, button);
}

/** Encode a pointer position in remote framebuffer coordinates. */
export function kdriveMotionEvent(x: number, y: number): Uint8Array {
  if (!Number.isInteger(x) || !Number.isInteger(y) || x < 0 || y < 0 || x >= MAX_DIMENSION || y >= MAX_DIMENSION) {
    throw new Error('Invalid KDrive pointer position.');
  }
  return event(6, x, y);
}

/** Ask the server to refresh a rectangle. The caller must supply bounds within
 * the current desktop and serialize the result on the authenticated channel. */
export function kdriveUpdateEvent(x: number, y: number, width: number, height: number): Uint8Array {
  if (![x, y, width, height].every(Number.isInteger) || x < 0 || y < 0 || width < 1 || height < 1 ||
      x + width > MAX_DIMENSION || y + height > MAX_DIMENSION || width * height > MAX_PIXELS) {
    throw new Error('Invalid KDrive update rectangle.');
  }
  const result = new Uint8Array(EVENT_SIZE);
  const view = new DataView(result.buffer);
  view.setUint32(0, 8, true);
  view.setUint32(4, width, true);
  view.setUint32(8, height, true);
  view.setUint32(12, x, true);
  view.setUint32(16, y, true);
  return result;
}

/** Request one screen of the given geometry after version negotiation. */
export function kdriveGeometryEvent(width: number, height: number): Uint8Array {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 ||
      width > MAX_DIMENSION || height > MAX_DIMENSION || width * height > MAX_PIXELS) {
    throw new Error('Invalid KDrive geometry.');
  }
  const result = new Uint8Array(EVENT_SIZE);
  const view = new DataView(result.buffer);
  view.setUint32(0, 7, true);
  view.setUint16(4, width, true);
  view.setUint16(6, height, true);
  // Primary screen index is zero; its origin is (0, 0).
  view.setUint16(9, width, true);
  view.setUint16(11, height, true);
  return result;
}

/** Encode a payload-free transport control message. */
export function kdriveControlEvent(kind: KDriveControlEvent): Uint8Array {
  const type = kind === 'keepalive' ? 12 : kind === 'cache-rebuild' ? 13 : kind === 'disconnect' ? 15 : 0;
  if (!type) throw new Error('Invalid KDrive control event.');
  return event(type, 0, 0);
}
