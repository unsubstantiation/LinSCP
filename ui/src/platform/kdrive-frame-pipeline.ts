import type { DesktopPixelFrame, DesktopFrameResult } from './desktop-frame-renderer.js';
import type { KDriveDecodedImage } from './kdrive-image-decoder.js';

/** Fields from a decoded KDrive wire Frame. Image payloads remain compressed. */
export interface KDriveRegion {
  sourceId: number; sourceX: number; sourceY: number;
  x: number; y: number; width: number; height: number; data: Uint8Array;
}
export interface KDriveFrame {
  width: number; height: number; x: number; y: number; cacheId: number;
  windowId: number; regions: readonly KDriveRegion[];
}
interface Image { width: number; height: number; pixels: Uint8ClampedArray }
interface ImageDecoder { decode(data: Uint8Array, width: number, height: number): Promise<KDriveDecodedImage> }
interface FrameSurface { render(frame: DesktopPixelFrame): DesktopFrameResult; reset(): void }
const MAX_DIMENSION = 8192, MAX_PIXELS = 16_777_216, MAX_REGIONS = 64;
const MAX_CACHE_BYTES = 128 * 1024 * 1024, MAX_CACHE_ENTRIES = 1024;
const MAX_ENCODED_BYTES = 16 * 1024 * 1024, MAX_WORK_BYTES = 128 * 1024 * 1024;

function validSize(w: number, h: number): boolean {
  return Number.isInteger(w) && Number.isInteger(h) && w > 0 && h > 0 &&
    w <= MAX_DIMENSION && h <= MAX_DIMENSION && w * h <= MAX_PIXELS;
}
function uint32(n: number): boolean { return Number.isInteger(n) && n >= 0 && n <= 0xffffffff; }
function int32(n: number): boolean { return Number.isInteger(n) && n >= -0x80000000 && n <= 0x7fffffff; }
function fits(x: number, y: number, w: number, h: number, image: {width: number; height: number}): boolean {
  return x >= 0 && y >= 0 && w <= image.width - x && h <= image.height - y;
}

/** Ordered frame composition for a single KDrive connection. The owner must
 * serialize all protocol messages, including deletes and resets. Errors poison
 * the pipeline and clear both screen and cache: a caller must reconnect or
 * explicitly reset and request a new main image, never silently skip a frame.
 * This does not parse wire bytes or provide a transport. */
export class KDriveFramePipeline {
  private readonly cache = new Map<number, Image>();
  private cacheBytes = 0;
  private width = 0;
  private height = 0;
  private sequence = 0;
  private busy = false;
  private failed = false;

  constructor(private readonly decoder: ImageDecoder, private readonly surface: FrameSurface) {}

  public reset(): void {
    if (this.busy) throw new Error('KDrive frame is being decoded.');
    this.cache.clear(); this.cacheBytes = 0; this.width = 0; this.height = 0;
    this.sequence = 0; this.failed = false; this.surface.reset();
  }

  public deleteFrames(ids: readonly number[]): void {
    if (this.busy || this.failed) throw new Error('KDrive frame pipeline is not ready.');
    if (!Array.isArray(ids) || ids.length > 65536 || !ids.every(uint32)) throw new Error('Invalid KDrive cache deletion.');
    for (const id of ids) {
      const old = this.cache.get(id);
      if (old) { this.cacheBytes -= old.pixels.byteLength; this.cache.delete(id); }
    }
  }

  public async apply(frame: KDriveFrame): Promise<void> {
    if (this.busy || this.failed) throw new Error('KDrive frame pipeline is not ready.');
    this.busy = true;
    try {
      // Freeze metadata before any asynchronous image decode.
      if (frame) frame = { ...frame };
      if (!frame || !validSize(frame.width, frame.height) || !int32(frame.x) || !int32(frame.y) ||
          !uint32(frame.cacheId) || !uint32(frame.windowId) || frame.windowId !== 0 ||
          !Array.isArray(frame.regions) || frame.regions.length > MAX_REGIONS) throw new Error('Invalid or unsupported KDrive frame.');
      const main = frame.cacheId === 0 && frame.x === -1 && frame.y === -1;
      if (!main && (!this.width || !this.height)) throw new Error('KDrive main image required.');
      let encodedBytes = 0;
      const regions = frame.regions.map(r => {
        if (!r || !uint32(r.sourceId) || !int32(r.sourceX) || !int32(r.sourceY) || !int32(r.x) || !int32(r.y) ||
            !validSize(r.width, r.height) || !(r.data instanceof Uint8Array)) throw new Error('Invalid KDrive region.');
        if ((r.sourceId === 0 && !r.data.length) || (r.sourceId !== 0 && r.data.length)) throw new Error('Invalid KDrive region data.');
        encodedBytes += r.data.length;
        if (encodedBytes > MAX_ENCODED_BYTES) throw new Error('KDrive frame data is too large.');
        return { ...r, data: r.data.slice() };
      });
      let image: Image;
      if (!regions.length) {
        if (!frame.cacheId) throw new Error('Empty KDrive frame.');
        const existing = this.cache.get(frame.cacheId);
        if (!existing || existing.width !== frame.width || existing.height !== frame.height) throw new Error('KDrive cache miss.');
        image = existing;
      } else {
        const length = frame.width * frame.height * 4;
        const old = this.cache.get(frame.cacheId);
        if (frame.cacheId && ((!old && this.cache.size >= MAX_CACHE_ENTRIES) ||
            this.cacheBytes - (old?.pixels.byteLength ?? 0) + length > MAX_CACHE_BYTES)) throw new Error('KDrive cache limit exceeded.');
        let work = 0;
        const ox = frame.cacheId === 0 && !main ? frame.x : 0;
        const oy = frame.cacheId === 0 && !main ? frame.y : 0;
        for (const r of regions) {
          if (!fits(r.x - ox, r.y - oy, r.width, r.height, frame)) throw new Error('KDrive region outside frame.');
          work += r.width * r.height * 4;
          if (work > Math.min(length * 4, MAX_WORK_BYTES)) throw new Error('KDrive frame work limit exceeded.');
          if (r.sourceId) {
            const source = this.cache.get(r.sourceId);
            if (!source || !fits(r.sourceX, r.sourceY, r.width, r.height, source)) throw new Error('KDrive cache reference is invalid.');
          }
        }
        image = { width: frame.width, height: frame.height, pixels: new Uint8ClampedArray(length) };
        for (const r of regions) {
          const source = r.sourceId ? this.cache.get(r.sourceId)! : await this.decoder.decode(r.data, r.width, r.height);
          if ((!r.sourceId && (source.width !== r.width || source.height !== r.height)) ||
              source.pixels.byteLength !== source.width * source.height * 4) throw new Error('Invalid decoded KDrive pixels.');
          const sx = r.sourceId ? r.sourceX : 0, sy = r.sourceId ? r.sourceY : 0;
          const dx = r.x - ox, dy = r.y - oy;
          for (let row = 0; row < r.height; row++) {
            const from = ((sy + row) * source.width + sx) * 4;
            image.pixels.set(source.pixels.subarray(from, from + r.width * 4), ((dy + row) * image.width + dx) * 4);
          }
        }
      }
      const screenWidth = main ? frame.width : this.width, screenHeight = main ? frame.height : this.height;
      const x = main ? 0 : frame.x, y = main ? 0 : frame.y;
      const left = Math.max(0, x), top = Math.max(0, y);
      const right = Math.min(screenWidth, x + image.width), bottom = Math.min(screenHeight, y + image.height);
      const rectangles: DesktopPixelFrame['rectangles'] = right > left && bottom > top ? [{
        x: left, y: top, width: right - left, height: bottom - top,
        pixels: (() => {
          if (left === x && top === y && right - left === image.width && bottom - top === image.height) return image.pixels;
          const pixels = new Uint8ClampedArray((right - left) * (bottom - top) * 4);
          for (let row = 0; row < bottom - top; row++) {
            const from = ((top - y + row) * image.width + left - x) * 4;
            pixels.set(image.pixels.subarray(from, from + (right - left) * 4), row * (right - left) * 4);
          }
          return pixels;
        })(),
      }] : [];
      if (this.surface.render({ sequence: this.sequence + 1, width: screenWidth, height: screenHeight, keyframe: main, rectangles }) !== 'painted') throw new Error('KDrive screen requires a new main image.');
      this.sequence++;
      if (main) { this.width = screenWidth; this.height = screenHeight; }
      if (frame.cacheId && regions.length) {
        const old = this.cache.get(frame.cacheId);
        this.cacheBytes += image.pixels.byteLength - (old?.pixels.byteLength ?? 0);
        this.cache.set(frame.cacheId, image);
      }
    } catch (error) {
      this.cache.clear(); this.cacheBytes = 0; this.width = 0; this.height = 0;
      this.failed = true; this.surface.reset();
      throw error;
    } finally { this.busy = false; }
  }
}
