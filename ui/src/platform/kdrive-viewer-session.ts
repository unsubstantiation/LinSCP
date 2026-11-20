import { DesktopFrameRenderer } from './desktop-frame-renderer.js';
import { DesktopInput } from './desktop-input.js';
import { KDriveFramePipeline, type KDriveFrame } from './kdrive-frame-pipeline.js';
import { KDriveImageDecoder, type KDriveDecodedImage } from './kdrive-image-decoder.js';
import { KDriveInputTranslator } from './kdrive-input.js';
import { KDriveInputQueue } from './kdrive-input-queue.js';
import { decodeKDriveViewerMessage } from './kdrive-viewer-message.js';

/** Parsed messages, not raw KDrive bytes. The SSH-side reader must preserve
 * order and deliver frames/deletions without discarding any of them. */
export type KDriveViewerMessage =
  | { type: 'frame'; frame: KDriveFrame }
  | { type: 'deleted-frames'; ids: readonly number[] }
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
  /** Defaults to the WebView decoder; injectable for isolated tests. */
  decoder?: { decode(data: Uint8Array, width: number, height: number): Promise<KDriveDecodedImage> };
  inputTimeoutMs?: number;
}
const MAX_PENDING_MESSAGES = 64;
const MAX_PENDING_BYTES = 32 * 1024 * 1024;
const MAX_FRAME_BYTES = 16 * 1024 * 1024;

/** Connects rendering and focused input to a supplied KDrive transport. This
 * does not start an agent, negotiate SSH, parse wire bytes, or implement a
 * window: the owner is responsible for those and for remote cleanup. */
export class KDriveViewerSession {
  private readonly renderer: DesktopFrameRenderer;
  private readonly input: DesktopInput;
  private readonly frames: KDriveFramePipeline;
  private readonly queue: KDriveInputQueue;
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
      } else if (message.type === 'deleted-frames') {
        if (!Array.isArray(message.ids) || message.ids.length > 65536) throw new Error('Invalid deletion.');
        bytes = message.ids.length * 4;
        if (this.pendingBytes + bytes > MAX_PENDING_BYTES) throw new Error('Input exceeds limit.');
        copy = { type: 'deleted-frames', ids: [...message.ids] };
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
