/** Decode a KDrive JPEG/PNG region using the WebView's built-in image decoder.
 * This is not a transport, a KDrive message parser, or a complete viewer.
 */
export interface KDriveDecodedImage {
  width: number;
  height: number;
  pixels: Uint8ClampedArray;
}

const MAX_ENCODED_BYTES = 16 * 1024 * 1024;
const MAX_DIMENSION = 8192;
const MAX_PIXELS = 16_777_216;

function validSize(width: number, height: number): boolean {
  return Number.isSafeInteger(width) && Number.isSafeInteger(height) && width > 0 && height > 0 &&
    width <= MAX_DIMENSION && height <= MAX_DIMENSION && width * height <= MAX_PIXELS;
}

function be16(bytes: Uint8Array, i: number): number {
  return bytes[i]! * 256 + bytes[i + 1]!;
}
function be32(bytes: Uint8Array, i: number): number {
  return bytes[i]! * 0x1000000 + bytes[i + 1]! * 0x10000 + bytes[i + 2]! * 0x100 + bytes[i + 3]!;
}

/** Read only the declared image dimensions before invoking a native decoder. */
function inspect(bytes: Uint8Array): { width: number; height: number; mime: string } {
  if (Object.prototype.toString.call(bytes) !== '[object Uint8Array]' || bytes.byteLength === 0 || bytes.byteLength > MAX_ENCODED_BYTES) {
    throw new Error('Invalid KDrive image size.');
  }
  const png = [137, 80, 78, 71, 13, 10, 26, 10];
  if (bytes.length >= 24 && png.every((b, i) => bytes[i] === b)) {
    if (be32(bytes, 8) !== 13 || bytes[12] !== 73 || bytes[13] !== 72 || bytes[14] !== 68 || bytes[15] !== 82) {
      throw new Error('Invalid KDrive PNG header.');
    }
    const width = be32(bytes, 16);
    const height = be32(bytes, 20);
    if (!validSize(width, height)) throw new Error('Invalid KDrive image dimensions.');
    return { width, height, mime: 'image/png' };
  }
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) throw new Error('Unsupported KDrive image format.');
  // JPEG headers are marker segments. Look for a start-of-frame marker before
  // scan data; metadata segments have a big-endian length including that field.
  let position = 2;
  let dimensions: { width: number; height: number } | null = null;
  while (position < bytes.length) {
    if (bytes[position++] !== 0xff) throw new Error('Invalid KDrive JPEG marker.');
    while (position < bytes.length && bytes[position] === 0xff) position++;
    if (position >= bytes.length) break;
    const marker = bytes[position++]!;
    if (marker === 0xd9 || marker === 0x00) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (position + 2 > bytes.length) break;
    const segmentLength = be16(bytes, position);
    if (segmentLength < 2 || segmentLength > bytes.length - position) throw new Error('Invalid KDrive JPEG segment.');
    if (marker === 0xda) {
      if (!dimensions) break;
      return { ...dimensions, mime: 'image/jpeg' };
    }
    const isFrame = (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker));
    if (isFrame) {
      if (segmentLength < 8 || dimensions) throw new Error('Invalid KDrive JPEG frame.');
      const height = be16(bytes, position + 3);
      const width = be16(bytes, position + 5);
      if (!validSize(width, height)) throw new Error('Invalid KDrive image dimensions.');
      dimensions = { width, height };
    }
    position += segmentLength;
  }
  throw new Error('KDrive JPEG dimensions or scan were not found.');
}

/**
 * One instance serializes decoding to limit in-flight native image allocations.
 * Callers must still bound the number of queued images and handle a decoding
 * failure by invalidating/rebuilding the protocol cache, never by skipping it.
 */
export class KDriveImageDecoder {
  private busy = false;
  constructor(private readonly document: Document) {}

  public async decode(bytes: Uint8Array, width: number, height: number): Promise<KDriveDecodedImage> {
    if (this.busy) throw new Error('KDrive image decoder is busy.');
    if (!validSize(width, height)) throw new Error('Invalid KDrive image dimensions.');
    if (Object.prototype.toString.call(bytes) !== '[object Uint8Array]' || bytes.byteLength === 0 || bytes.byteLength > MAX_ENCODED_BYTES) {
      throw new Error('Invalid KDrive image size.');
    }
    // Inspect the same immutable snapshot that is passed to the WebView, even
    // if the caller's original buffer is shared or changed while decoding.
    const copy = new Uint8Array(bytes.length);
    copy.set(bytes);
    const image = inspect(copy);
    if (image.width !== width || image.height !== height) throw new Error('KDrive image dimensions do not match the region.');
    const view = this.document.defaultView;
    if (!view || typeof view.createImageBitmap !== 'function') throw new Error('The WebView cannot decode KDrive images.');
    this.busy = true;
    let bitmap: ImageBitmap | null = null;
    let canvas: HTMLCanvasElement | null = null;
    try {
      const blob = new view.Blob([copy.buffer], { type: image.mime });
      bitmap = await view.createImageBitmap(blob, { imageOrientation: 'none', premultiplyAlpha: 'none', colorSpaceConversion: 'none' });
      if (bitmap.width !== width || bitmap.height !== height) throw new Error('Decoded KDrive image dimensions changed.');
      canvas = this.document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const context = canvas.getContext('2d', { willReadFrequently: true });
      if (!context) throw new Error('A 2D canvas is required to decode KDrive images.');
      context.drawImage(bitmap, 0, 0);
      const pixels = context.getImageData(0, 0, width, height).data;
      if (pixels.length !== width * height * 4) throw new Error('Invalid decoded KDrive image.');
      // Copy out before clearing the temporary canvas. No canvas/bitmap survives.
      return { width, height, pixels: new Uint8ClampedArray(pixels) };
    } finally {
      try {
        if (bitmap) bitmap.close();
      } finally {
        try {
          if (canvas) { canvas.width = 0; canvas.height = 0; }
        } finally {
          this.busy = false;
        }
      }
    }
  }
}
