/**
 * A display surface for already-decoded remote desktop pixels.
 *
 * This is not a KDrive decoder or transport. A future session pipeline must
 * produce ordered RGBA frames and handle remote input separately. Keeping the
 * surface independent of a particular decoder lets all desktop WebViews paint
 * the same pixels, but exporting it does not make an X2Go connection possible.
 */

/** An uncompressed, tightly packed, row-major RGBA rectangle. */
export interface DesktopPixelRect {
  x: number;
  y: number;
  width: number;
  height: number;
  pixels: Uint8Array | Uint8ClampedArray;
}

export interface DesktopPixelFrame {
  /** Monotonically increasing safe integer within a single connection. */
  sequence: number;
  width: number;
  height: number;
  /** A keyframe is exactly one rectangle covering the whole desktop. */
  keyframe: boolean;
  /** Rectangles are composited in order; an empty delta advances sequence. */
  rectangles: readonly DesktopPixelRect[];
}

export type DesktopFrameResult = 'painted' | 'stale' | 'needs-keyframe';

// Avoid trusting a remote server to allocate an unbounded canvas or rectangle
// list in the UI process. The decoder/transport must enforce limits too.
const MAX_DIMENSION = 8192;
const MAX_PIXELS = 16_777_216;
const MAX_RECTANGLES = 256;
const MAX_FRAME_BYTES = MAX_PIXELS * 4;

function positiveInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function validPixelBytes(value: unknown): value is Uint8Array | Uint8ClampedArray {
  const kind = Object.prototype.toString.call(value);
  return kind === '[object Uint8Array]' || kind === '[object Uint8ClampedArray]';
}

/**
 * Paints decoded frames into a canvas owned by the calling window.
 *
 * A missing delta invalidates the current screen. Until a fresh keyframe
 * arrives, subsequent deltas are rejected instead of rendering a plausible but
 * incorrect desktop. Each connection must use a new renderer or call reset.
 */
export class DesktopFrameRenderer {
  private readonly canvas: HTMLCanvasElement;
  private readonly context: CanvasRenderingContext2D;
  private sequence: number | null = null;
  private width = 0;
  private height = 0;
  private needsKeyframe = true;
  private destroyed = false;

  constructor(container: HTMLElement) {
    const canvas = container.ownerDocument.createElement('canvas');
    const context = canvas.getContext('2d', { alpha: false });
    if (!context) throw new Error('A 2D canvas is required for remote desktop rendering.');
    canvas.className = 'desktop-frame-canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'Remote desktop');
    canvas.style.display = 'block';
    canvas.style.maxWidth = '100%';
    canvas.style.maxHeight = '100%';
    canvas.style.objectFit = 'contain';
    container.appendChild(canvas);
    this.canvas = canvas;
    this.context = context;
  }

  public get element(): HTMLCanvasElement {
    return this.canvas;
  }

  public render(frame: DesktopPixelFrame): DesktopFrameResult {
    if (this.destroyed) throw new Error('The remote desktop renderer is closed.');
    if (!frame || !Number.isSafeInteger(frame.sequence) || frame.sequence < 0) {
      throw new Error('Invalid desktop frame sequence.');
    }
    if (this.sequence !== null && frame.sequence <= this.sequence) return 'stale';
    if (!frame.keyframe && (this.needsKeyframe || this.sequence === null || frame.sequence !== this.sequence + 1)) {
      this.needsKeyframe = true;
      return 'needs-keyframe';
    }
    this.validateFrame(frame);
    if (!frame.keyframe && (frame.width !== this.width || frame.height !== this.height)) {
      this.needsKeyframe = true;
      return 'needs-keyframe';
    }

    // Prepare all rectangles before changing the canvas, so an allocation or
    // validation error cannot leave half a frame painted and advance sequence.
    const images = frame.rectangles.map(rect => {
      const image = this.context.createImageData(rect.width, rect.height);
      image.data.set(rect.pixels);
      return image;
    });
    if (frame.keyframe && (frame.width !== this.width || frame.height !== this.height)) {
      this.canvas.width = frame.width;
      this.canvas.height = frame.height;
      this.width = frame.width;
      this.height = frame.height;
    }
    try {
      for (let i = 0; i < frame.rectangles.length; i++) {
        const rect = frame.rectangles[i]!;
        this.context.putImageData(images[i]!, rect.x, rect.y);
      }
    } catch (error) {
      // A canvas failure may have painted only part of a frame.
      this.needsKeyframe = true;
      throw error;
    }
    this.sequence = frame.sequence;
    this.needsKeyframe = false;
    return 'painted';
  }

  /** Maps browser client coordinates to remote pixels. Drag events can clamp outside positions to an edge. */
  public remotePoint(clientX: number, clientY: number, clamp = false): { x: number; y: number } | null {
    if (this.destroyed || this.needsKeyframe || !Number.isFinite(clientX) || !Number.isFinite(clientY)) return null;
    const box = this.canvas.getBoundingClientRect();
    if (box.width <= 0 || box.height <= 0 || (!clamp && (clientX < box.left || clientY < box.top ||
        clientX >= box.right || clientY >= box.bottom))) return null;
    return {
      x: Math.max(0, Math.min(this.width - 1, Math.floor((clientX - box.left) * this.width / box.width))),
      y: Math.max(0, Math.min(this.height - 1, Math.floor((clientY - box.top) * this.height / box.height))),
    };
  }

  /** Discards the previous connection's state and waits for a new keyframe. */
  public reset(): void {
    if (this.destroyed) return;
    this.sequence = null;
    this.width = 0;
    this.height = 0;
    this.needsKeyframe = true;
    this.canvas.width = 0;
    this.canvas.height = 0;
  }

  public destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.canvas.remove();
  }

  private validateFrame(frame: DesktopPixelFrame): void {
    if (!positiveInteger(frame.width) || !positiveInteger(frame.height) ||
        frame.width > MAX_DIMENSION || frame.height > MAX_DIMENSION || frame.width * frame.height > MAX_PIXELS) {
      throw new Error('Invalid remote desktop dimensions.');
    }
    if (typeof frame.keyframe !== 'boolean' || !Array.isArray(frame.rectangles) || frame.rectangles.length > MAX_RECTANGLES) {
      throw new Error('Invalid desktop frame rectangles.');
    }
    if (frame.keyframe && (frame.rectangles.length !== 1 || frame.rectangles[0]?.x !== 0 ||
        frame.rectangles[0]?.y !== 0 || frame.rectangles[0]?.width !== frame.width || frame.rectangles[0]?.height !== frame.height)) {
      throw new Error('A desktop keyframe must cover the entire desktop.');
    }
    let totalBytes = 0;
    for (const rect of frame.rectangles) {
      if (!rect || !Number.isSafeInteger(rect.x) || !Number.isSafeInteger(rect.y) || rect.x < 0 || rect.y < 0 ||
          !positiveInteger(rect.width) || !positiveInteger(rect.height) ||
          rect.width > frame.width - rect.x || rect.height > frame.height - rect.y ||
          !validPixelBytes(rect.pixels) || rect.pixels.byteLength !== rect.width * rect.height * 4) {
        throw new Error('Invalid desktop pixel rectangle.');
      }
      totalBytes += rect.pixels.byteLength;
      if (totalBytes > MAX_FRAME_BYTES) throw new Error('Desktop frame is too large.');
    }
  }
}
