import { DesktopFrameRenderer } from './desktop-frame-renderer.js';
import { DesktopInput } from './desktop-input.js';
import { kdriveGeometryEvent } from './kdrive-events.js';
import { KDriveFramePipeline, type KDriveFrame } from './kdrive-frame-pipeline.js';
import { KDriveImageDecoder, type KDriveDecodedImage } from './kdrive-image-decoder.js';
import { KDriveInputTranslator } from './kdrive-input.js';
import { KDriveInputQueue } from './kdrive-input-queue.js';
import { decodeKDriveViewerMessage } from './kdrive-viewer-message.js';

export interface KDriveCursorPayload {
  serial: number;
  width: number;
  height: number;
  hotX: number;
  hotY: number;
  foreground: [number, number, number];
  background: [number, number, number];
  data: Uint8Array;
}

export interface KDriveSelectionPayload {
  selection: number;
  format: number;
  chunkSize: number;
  first: boolean;
  last: boolean;
  compressedSize: number;
  total: number;
  data: Uint8Array;
}

/** Parsed messages, not raw KDrive bytes. The SSH-side reader must preserve
 * order and deliver frames/deletions without discarding any of them. */
export type KDriveViewerMessage =
  | { type: 'frame'; frame: KDriveFrame }
  | { type: 'deleted-frames'; ids: readonly number[] }
  | { type: 'cursor'; cursor: KDriveCursorPayload }
  | { type: 'deleted-cursors'; ids: readonly number[] }
  | { type: 'selection'; selection: KDriveSelectionPayload }
  | { type: 'demand-selection'; selection: number }
  | { type: 'reinitialize' }
  | { type: 'keepalive' }
  | { type: 'disconnect' };

export interface KDriveViewerTransport {
  /** Write one complete KDrive event on the authenticated graphics channel. */
  write(packet: Uint8Array): Promise<void>;
  /** Close the graphics channel and arrange cleanup of the remote agent. */
  close(): void;
  /** Request a main image after reinitialization; fail if this cannot be done. */
  requestMainImage(): Promise<void>;
}
export interface KDriveViewerOptions {
  capsLock: boolean;
  numLock: boolean;
  rightAltIsAltGr: boolean;
  /** Receives only a generic error, never server content or credentials. */
  onError?: (error: Error) => void;
  /** Invoked when the remote server pushes UTF-8 clipboard/selection text. */
  onSelection?: (text: string, selection: number) => void;
  /** Invoked when the remote server demands client selection data. */
  onSelectionDemand?: (selection: number) => void;
  /** Defaults to the WebView decoder; injectable for isolated tests. */
  decoder?: { decode(data: Uint8Array, width: number, height: number): Promise<KDriveDecodedImage> };
  inputTimeoutMs?: number;
}
const MAX_PENDING_MESSAGES = 64;
const MAX_PENDING_BYTES = 32 * 1024 * 1024;
const MAX_FRAME_BYTES = 16 * 1024 * 1024;
const MAX_CACHED_CURSORS = 256;
const MAX_SELECTION_ACCUM = 2 * 1024 * 1024;

/** Connects rendering and focused input to a supplied KDrive transport. This
 * does not start an agent, negotiate SSH, parse wire bytes, or implement a
 * window: the owner is responsible for those and for remote cleanup. */
export class KDriveViewerSession {
  private readonly renderer: DesktopFrameRenderer;
  private readonly input: DesktopInput;
  private readonly frames: KDriveFramePipeline;
  private readonly queue: KDriveInputQueue;
  private readonly cursorCache = new Map<number, string>();
  private activeCursorSerial: number | null = null;
  private selectionChunks: Uint8Array[] = [];
  private selectionBytes = 0;
  private closed = false;
  private chain: Promise<void> = Promise.resolve();
  private pendingMessages = 0;
  private pendingBytes = 0;
  private cancelMainRequest: ((error: Error) => void) | null = null;

  constructor(container: HTMLElement, private readonly transport: KDriveViewerTransport,
              private readonly options: KDriveViewerOptions) {
    this.renderer = new DesktopFrameRenderer(container);
    this.frames = new KDriveFramePipeline(options.decoder ?? new KDriveImageDecoder(container.ownerDocument), this.renderer);
    const translator = new KDriveInputTranslator(options);
    this.queue = new KDriveInputQueue(packet => transport.write(packet), options.inputTimeoutMs);
    this.input = new DesktopInput(this.renderer, event => {
      if (this.closed) return;
      try {
        const actions = translator.translate(event);
        void this.queue.enqueue(actions).catch(() => this.fail());
      } catch { this.fail(); }
    });
    // Input is enabled only after a valid main image has been painted.
  }

  public get element(): HTMLCanvasElement { return this.renderer.element; }

  /** Request a dynamic remote desktop resize using a KDrive geometry event. */
  public resize(width: number, height: number): Promise<void> {
    if (this.closed) return Promise.reject(new Error('KDrive viewer is closed.'));
    let packet: Uint8Array;
    try {
      packet = kdriveGeometryEvent(width, height);
    } catch (err) {
      return Promise.reject(err);
    }
    return this.queue.enqueue([{ type: 'packet', bytes: packet }]).catch(err => {
      this.fail();
      throw err;
    });
  }

  /** The transport must only acknowledge the response to the current barrier.
   * Since the wire protocol has no request ID, the reader must account for
   * unsolicited updates; misidentification may break keyboard ordering. */
  public acknowledgeInputBarrier(): boolean {
    return !this.closed && this.queue.acknowledgeBarrier();
  }

  /** Accept the service JSON contract. A malformed message closes the viewer
   * instead of dropping a frame or leaving input attached to a stale screen. */
  public receiveIpc(value: unknown): Promise<void> {
    if (this.closed) return Promise.reject(new Error('KDrive viewer is closed.'));
    try { return this.receive(decodeKDriveViewerMessage(value)); }
    catch {
      this.fail();
      return Promise.reject(new Error('Invalid KDrive viewer message.'));
    }
  }

  /** Queue a parsed message, copying its payload before any asynchronous work.
   * Errors and overflow close the whole viewer instead of dropping a delta. */
  public receive(message: KDriveViewerMessage): Promise<void> {
    if (this.closed) return Promise.reject(new Error('KDrive viewer is closed.'));
    let copy: KDriveViewerMessage;
    let bytes = 0;
    try {
      if (!message || typeof message !== 'object') throw new Error('Invalid message.');
      if (message.type === 'frame') {
        const frame = message.frame;
        if (!frame || !Array.isArray(frame.regions) || frame.regions.length > 64) throw new Error('Invalid frame.');
        for (const region of frame.regions) {
          if (!region || !(region.data instanceof Uint8Array)) throw new Error('Invalid region.');
          bytes += region.data.byteLength;
          if (bytes > MAX_FRAME_BYTES) throw new Error('Frame exceeds limit.');
        }
        if (this.pendingBytes + bytes > MAX_PENDING_BYTES) throw new Error('Input exceeds limit.');
        copy = { type: 'frame', frame: { ...frame, regions: frame.regions.map(region => ({ ...region, data: region.data.slice() })) } };
      } else if (message.type === 'deleted-frames' || message.type === 'deleted-cursors') {
        if (!Array.isArray(message.ids) || message.ids.length > 65536) throw new Error('Invalid deletion.');
        bytes = message.ids.length * 4;
        if (this.pendingBytes + bytes > MAX_PENDING_BYTES) throw new Error('Input exceeds limit.');
        copy = { type: message.type, ids: [...message.ids] };
      } else if (message.type === 'cursor') {
        const cur = message.cursor;
        if (!cur || !(cur.data instanceof Uint8Array) || cur.width < 1 || cur.width > 256 || cur.height < 1 || cur.height > 256) {
          throw new Error('Invalid cursor.');
        }
        bytes = cur.data.byteLength;
        if (bytes > 256 * 256 * 4 || this.pendingBytes + bytes > MAX_PENDING_BYTES) throw new Error('Input exceeds limit.');
        copy = { type: 'cursor', cursor: { ...cur, foreground: [...cur.foreground] as [number, number, number], background: [...cur.background] as [number, number, number], data: cur.data.slice() } };
      } else if (message.type === 'selection') {
        const sel = message.selection;
        if (!sel || !(sel.data instanceof Uint8Array) || sel.data.byteLength > MAX_SELECTION_ACCUM) {
          throw new Error('Invalid selection.');
        }
        bytes = sel.data.byteLength;
        if (this.pendingBytes + bytes > MAX_PENDING_BYTES) throw new Error('Input exceeds limit.');
        copy = { type: 'selection', selection: { ...sel, data: sel.data.slice() } };
      } else if (message.type === 'demand-selection') {
        if (!Number.isInteger(message.selection) || message.selection < 0 || message.selection > 65535) throw new Error('Invalid selection demand.');
        copy = { type: 'demand-selection', selection: message.selection };
      } else if (message.type === 'reinitialize' || message.type === 'keepalive' || message.type === 'disconnect') {
        copy = { type: message.type };
      } else throw new Error('Unsupported message.');
      if (this.pendingMessages >= MAX_PENDING_MESSAGES) throw new Error('Input exceeds limit.');
    } catch {
      this.fail();
      return Promise.reject(new Error('Invalid KDrive viewer message.'));
    }
    this.pendingMessages++; this.pendingBytes += bytes;
    const work = this.chain.then(async () => {
      if (this.closed) throw new Error('KDrive viewer is closed.');
      if (copy.type === 'frame') {
        await this.frames.apply(copy.frame);
        if (this.closed) throw new Error('KDrive viewer is closed.');
        if (copy.frame.cacheId === 0 && copy.frame.x === -1 && copy.frame.y === -1) this.input.setEnabled(true);
      } else if (copy.type === 'deleted-frames') {
        this.frames.deleteFrames(copy.ids);
      } else if (copy.type === 'cursor') {
        this.applyCursor(copy.cursor);
      } else if (copy.type === 'deleted-cursors') {
        for (const id of copy.ids) {
          this.cursorCache.delete(id);
          if (this.activeCursorSerial === id) {
            this.activeCursorSerial = null;
            this.element.style.cursor = 'default';
          }
        }
      } else if (copy.type === 'selection') {
        this.applySelection(copy.selection);
      } else if (copy.type === 'demand-selection') {
        try { this.options.onSelectionDemand?.(copy.selection); } catch { /* ignore UI callback error */ }
      } else if (copy.type === 'reinitialize') {
        this.input.setEnabled(false);
        this.frames.reset();
        await this.requestMainImage();
      } else if (copy.type === 'disconnect') {
        throw new Error('KDrive server disconnected.');
      }
    }).catch(error => {
      if (!this.closed) this.fail();
      throw error;
    }).finally(() => { this.pendingMessages--; this.pendingBytes -= bytes; });
    // Keep subsequent deliveries ordered while returning each failure to its caller.
    this.chain = work.catch(() => {});
    return work;
  }

  private applyCursor(cursor: KDriveCursorPayload): void {
    let css = this.cursorCache.get(cursor.serial);
    if (!css && cursor.data.byteLength > 0) {
      const pixels = decodeCursorPixels(cursor);
      if (pixels) {
        try {
          const doc = this.element.ownerDocument;
          const canvas = doc.createElement('canvas');
          canvas.width = cursor.width;
          canvas.height = cursor.height;
          const ctx = canvas.getContext('2d');
          if (ctx && typeof ctx.createImageData === 'function' && typeof ctx.putImageData === 'function' && typeof canvas.toDataURL === 'function') {
            const img = ctx.createImageData(cursor.width, cursor.height);
            img.data.set(pixels);
            ctx.putImageData(img, 0, 0);
            const url = canvas.toDataURL('image/png');
            if (typeof url === 'string' && url.startsWith('data:image/png')) {
              css = `url(${url}) ${cursor.hotX} ${cursor.hotY}, default`;
            }
          }
        } catch {
          css = undefined;
        }
      }
      if (css) {
        if (this.cursorCache.size >= MAX_CACHED_CURSORS) {
          const oldest = this.cursorCache.keys().next().value;
          if (oldest !== undefined) this.cursorCache.delete(oldest);
        }
        this.cursorCache.set(cursor.serial, css);
      }
    }
    if (css) {
      this.activeCursorSerial = cursor.serial;
      this.element.style.cursor = css;
    }
  }

  private applySelection(sel: KDriveSelectionPayload): void {
    if (sel.format !== 0 || sel.compressedSize !== 0) {
      this.selectionChunks = [];
      this.selectionBytes = 0;
      return;
    }
    if (sel.first) {
      this.selectionChunks = [];
      this.selectionBytes = 0;
    }
    if (this.selectionBytes + sel.data.byteLength > MAX_SELECTION_ACCUM) {
      this.selectionChunks = [];
      this.selectionBytes = 0;
      return;
    }
    this.selectionChunks.push(sel.data);
    this.selectionBytes += sel.data.byteLength;
    if (sel.last) {
      const merged = new Uint8Array(this.selectionBytes);
      let offset = 0;
      for (const chunk of this.selectionChunks) {
        merged.set(chunk, offset);
        offset += chunk.byteLength;
      }
      this.selectionChunks = [];
      this.selectionBytes = 0;
      const text = new TextDecoder('utf-8', { fatal: false }).decode(merged);
      try { this.options.onSelection?.(text, sel.selection); } catch { /* ignore UI callback error */ }
    }
  }

  private async requestMainImage(): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const interrupted = new Promise<never>((_resolve, reject) => {
      this.cancelMainRequest = reject;
      timer = setTimeout(() => reject(new Error('KDrive main image request timed out.')), 10000);
    });
    const request = Promise.resolve().then(() => {
      if (this.closed) throw new Error('KDrive viewer is closed.');
      return this.transport.requestMainImage();
    });
    try { await Promise.race([request, interrupted]); }
    finally { if (timer !== undefined) clearTimeout(timer); this.cancelMainRequest = null; }
  }

  public close(): void {
    if (this.closed) return;
    this.closed = true;
    this.cancelMainRequest?.(new Error('KDrive viewer is closed.'));
    this.queue.close();
    this.input.destroy();
    // A decode already in progress will fail against the destroyed renderer
    // and clear its own cache; otherwise discard pixels immediately.
    try { this.frames.reset(); } catch { /* frame is still decoding */ }
    this.renderer.destroy();
    try { this.transport.close(); } catch { /* cleanup is best-effort */ }
  }

  private fail(): void {
    if (this.closed) return;
    this.close();
    try { this.options.onError?.(new Error('The KDrive viewer session ended.')); } catch { /* UI callbacks cannot prevent cleanup */ }
  }
}

function decodeCursorPixels(cursor: KDriveCursorPayload): Uint8ClampedArray | null {
  const { width, height, data, foreground, background } = cursor;
  const rgbaCount = width * height * 4;
  if (data.byteLength === rgbaCount) {
    // KDrive 32-bit ARGB little-endian (B, G, R, A bytes) -> RGBA.
    const out = new Uint8ClampedArray(rgbaCount);
    for (let i = 0; i < rgbaCount; i += 4) {
      out[i] = data[i + 2]!;
      out[i + 1] = data[i + 1]!;
      out[i + 2] = data[i]!;
      out[i + 3] = data[i + 3]!;
    }
    return out;
  }
  const stride = Math.ceil(width / 8);
  const planeBytes = stride * height;
  if (data.byteLength === planeBytes * 2) {
    // X11 1-bit source + mask planes (LSB-first per byte).
    const out = new Uint8ClampedArray(rgbaCount);
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const byteIndex = y * stride + (x >> 3);
        const bit = 1 << (x & 7);
        const srcBit = (data[byteIndex]! & bit) !== 0;
        const maskBit = (data[planeBytes + byteIndex]! & bit) !== 0;
        const dst = (y * width + x) * 4;
        if (maskBit) {
          const rgb = srcBit ? foreground : background;
          out[dst] = rgb[0];
          out[dst + 1] = rgb[1];
          out[dst + 2] = rgb[2];
          out[dst + 3] = 255;
        }
      }
    }
    return out;
  }
  return null;
}

