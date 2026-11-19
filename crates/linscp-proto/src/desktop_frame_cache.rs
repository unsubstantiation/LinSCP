//! Bounded RGBA image cache and composition primitives for a desktop viewer.
//!
//! This module is protocol-independent: it does not parse KDrive messages or
//! decode JPEG/PNG. A future decoder must translate verified messages into these
//! operations and handle cache misses/resynchronization according to the wire
//! protocol. Cache entries are never evicted implicitly.

use std::collections::HashMap;

const MAX_DIMENSION: u32 = 8192;
const MAX_PIXELS: u64 = 16_777_216;
const MAX_PATCHES: usize = 256;
const MAX_COMPOSITION_BYTES: usize = 128 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// A rectangle in pixel coordinates. Width and height must be nonzero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// One ordered overwrite into a new RGBA image. Pixel data is tightly packed,
/// row-major RGBA; alpha is copied as-is, without blending.
#[derive(Clone, Copy)]
pub enum Patch<'a> {
    Pixels { destination: Rect, rgba: &'a [u8] },
    Copy { source_id: u32, source: Rect, x: u32, y: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    InvalidDimensions,
    InvalidRectangle,
    InvalidPixelLength,
    TooManyPatches,
    WorkLimit,
    MissingSource,
    EntryLimit,
    ByteLimit,
    AllocationFailed,
}

/// An owned tightly packed RGBA image. Access does not allow mutation of the
/// cache, so callers cannot invalidate its byte accounting.
pub struct Image {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl std::fmt::Debug for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Image")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("rgba", &"[redacted]")
            .finish()
    }
}

impl Image {
    pub fn width(&self) -> u32 { self.width }
    pub fn height(&self) -> u32 { self.height }
    pub fn rgba(&self) -> &[u8] { &self.rgba }
}

/// Explicit memory limits count stored RGBA bytes, not object/hash overhead or
/// caller-owned input. Composition temporarily needs up to one additional image;
/// no cache entry is modified until every patch has passed validation and the
/// output has been built successfully.
#[derive(Debug)]
pub struct FrameCache {
    images: HashMap<u32, Image>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

fn image_bytes(width: u32, height: u32) -> Result<usize, CacheError> {
    let pixels = u64::from(width) * u64::from(height);
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION || pixels > MAX_PIXELS {
        return Err(CacheError::InvalidDimensions);
    }
    usize::try_from(pixels * 4).map_err(|_| CacheError::InvalidDimensions)
}

fn fits(rect: Rect, width: u32, height: u32) -> bool {
    rect.width != 0 && rect.height != 0 &&
        rect.x.checked_add(rect.width).is_some_and(|right| right <= width) &&
        rect.y.checked_add(rect.height).is_some_and(|bottom| bottom <= height)
}

impl FrameCache {
    /// Limits are supplied by the caller and should be chosen for the host.
    /// They are capped at 4096 entries and 256 MiB; zero disables storage.
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self { images: HashMap::new(), bytes: 0,
            max_entries: max_entries.min(MAX_CACHE_ENTRIES),
            max_bytes: max_bytes.min(MAX_CACHE_BYTES) }
    }

    pub fn get(&self, id: u32) -> Option<&Image> { self.images.get(&id) }
    pub fn len(&self) -> usize { self.images.len() }
    pub fn is_empty(&self) -> bool { self.images.is_empty() }
    pub fn bytes(&self) -> usize { self.bytes }

    /// Delete an entry explicitly; missing entries are harmless.
    pub fn remove(&mut self, id: u32) -> bool {
        if let Some(image) = self.images.remove(&id) {
            self.bytes -= image.rgba.len();
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.images.clear();
        self.bytes = 0;
    }

    /// Compose a new image, initially transparent black, and store it under id.
    /// Patches are applied in order as overwrites. Copy sources refer to the
    /// cache as it was before this call, including when replacing the same id.
    /// A missing source or any invalid patch rejects the entire composition.
    /// Total copied pixels are limited to four output images and 128 MiB to
    /// prevent a tiny patch list from repeatedly rewriting a huge surface.
    pub fn compose(&mut self, id: u32, width: u32, height: u32, patches: &[Patch<'_>]) -> Result<&Image, CacheError> {
        let size = image_bytes(width, height)?;
        if patches.len() > MAX_PATCHES { return Err(CacheError::TooManyPatches); }
        let old_size = self.images.get(&id).map_or(0, |image| image.rgba.len());
        if old_size == 0 && self.images.len() >= self.max_entries { return Err(CacheError::EntryLimit); }
        let total = self.bytes.checked_sub(old_size).and_then(|n| n.checked_add(size)).ok_or(CacheError::ByteLimit)?;
        if total > self.max_bytes { return Err(CacheError::ByteLimit); }

        let mut copied_bytes = 0usize;
        let work_limit = size.saturating_mul(4).min(MAX_COMPOSITION_BYTES);
        for patch in patches {
            let patch_bytes = match *patch {
                Patch::Pixels { destination, rgba } => {
                    if !fits(destination, width, height) { return Err(CacheError::InvalidRectangle); }
                    let expected = image_bytes(destination.width, destination.height)?;
                    if rgba.len() != expected { return Err(CacheError::InvalidPixelLength); }
                    expected
                }
                Patch::Copy { source_id, source, x, y } => {
                    let image = self.images.get(&source_id).ok_or(CacheError::MissingSource)?;
                    let destination = Rect { x, y, width: source.width, height: source.height };
                    if !fits(source, image.width, image.height) || !fits(destination, width, height) {
                        return Err(CacheError::InvalidRectangle);
                    }
                    image_bytes(source.width, source.height)?
                }
            };
            copied_bytes = copied_bytes.checked_add(patch_bytes).ok_or(CacheError::WorkLimit)?;
            if copied_bytes > work_limit { return Err(CacheError::WorkLimit); }
        }

        // Reserve before changing state. try_reserve also avoids an infallible
        // Vec allocation for untrusted dimensions.
        if old_size == 0 { self.images.try_reserve(1).map_err(|_| CacheError::AllocationFailed)?; }
        let mut output = Vec::new();
        output.try_reserve_exact(size).map_err(|_| CacheError::AllocationFailed)?;
        output.resize(size, 0);
        let output_stride = width as usize * 4;
        for patch in patches {
            let (source_bytes, source_stride, source_x, source_y, destination) = match *patch {
                Patch::Pixels { destination, rgba } => (rgba, destination.width as usize * 4, 0, 0, destination),
                Patch::Copy { source_id, source, x, y } => {
                    // Validation above guarantees this exists; the cache is unchanged.
                    let image = &self.images[&source_id];
                    (image.rgba.as_slice(), image.width as usize * 4, source.x, source.y,
                     Rect { x, y, width: source.width, height: source.height })
                }
            };
            let row_bytes = destination.width as usize * 4;
            for row in 0..destination.height as usize {
                let source_offset = (source_y as usize + row) * source_stride + source_x as usize * 4;
                let dest_offset = (destination.y as usize + row) * output_stride + destination.x as usize * 4;
                output[dest_offset..dest_offset + row_bytes].copy_from_slice(&source_bytes[source_offset..source_offset + row_bytes]);
            }
        }
        self.images.insert(id, Image { width, height, rgba: output });
        self.bytes = total;
        Ok(&self.images[&id])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32, y: u32, width: u32, height: u32) -> Rect { Rect { x, y, width, height } }
    fn pixels<'a>(destination: Rect, rgba: &'a [u8]) -> Patch<'a> { Patch::Pixels { destination, rgba } }

    #[test]
    fn caller_limits_are_capped_and_zero_disables_storage() {
        let maximum = FrameCache::new(usize::MAX, usize::MAX);
        assert_eq!(maximum.max_entries, MAX_CACHE_ENTRIES);
        assert_eq!(maximum.max_bytes, MAX_CACHE_BYTES);
        let mut no_entries = FrameCache::new(0, 32);
        assert_eq!(no_entries.compose(1, 1, 1, &[]).unwrap_err(), CacheError::EntryLimit);
        let mut no_bytes = FrameCache::new(1, 0);
        assert_eq!(no_bytes.compose(1, 1, 1, &[]).unwrap_err(), CacheError::ByteLimit);
    }

    #[test]
    fn composes_ordered_rgba_and_copies_source_subrectangles() {
        let mut cache = FrameCache::new(2, 64);
        let data: Vec<u8> = (0..16).collect();
        cache.compose(1, 2, 2, &[pixels(rect(0, 0, 2, 2), &data)]).unwrap();
        let image = cache.compose(2, 2, 2, &[
            Patch::Copy { source_id: 1, source: rect(1, 0, 1, 2), x: 0, y: 0 },
            pixels(rect(1, 1, 1, 1), &[90, 91, 92, 93]),
        ]).unwrap();
        assert_eq!((image.width(), image.height()), (2, 2));
        assert_eq!(image.rgba(), &[4, 5, 6, 7, 0, 0, 0, 0, 12, 13, 14, 15, 90, 91, 92, 93]);
        assert_eq!((cache.len(), cache.bytes()), (2, 32));
        assert!(!format!("{cache:?}").contains("90, 91, 92, 93"));
        assert!(format!("{cache:?}").contains("[redacted]"));
    }

    #[test]
    fn replacing_an_entry_can_copy_its_previous_value() {
        let mut cache = FrameCache::new(1, 16);
        cache.compose(7, 2, 1, &[pixels(rect(0, 0, 2, 1), &[1, 2, 3, 4, 5, 6, 7, 8])]).unwrap();
        let image = cache.compose(7, 2, 1, &[
            Patch::Copy { source_id: 7, source: rect(1, 0, 1, 1), x: 0, y: 0 },
            Patch::Copy { source_id: 7, source: rect(0, 0, 1, 1), x: 1, y: 0 },
        ]).unwrap();
        assert_eq!(image.rgba(), &[5, 6, 7, 8, 1, 2, 3, 4]);
        assert_eq!(cache.bytes(), 8);
    }

    #[test]
    fn failed_composition_is_atomic_and_never_evicts() {
        let mut cache = FrameCache::new(1, 8);
        cache.compose(1, 1, 1, &[pixels(rect(0, 0, 1, 1), &[1, 2, 3, 4])]).unwrap();
        assert_eq!(cache.compose(2, 1, 1, &[]).unwrap_err(), CacheError::EntryLimit);
        assert_eq!(cache.compose(1, 3, 1, &[]).unwrap_err(), CacheError::ByteLimit);
        assert_eq!(cache.compose(1, 1, 1, &[pixels(rect(0, 0, 1, 1), &[9, 9, 9, 9]),
            Patch::Copy { source_id: 99, source: rect(0, 0, 1, 1), x: 0, y: 0 }]).unwrap_err(), CacheError::MissingSource);
        assert_eq!(cache.get(1).unwrap().rgba(), &[1, 2, 3, 4]);
        assert_eq!((cache.len(), cache.bytes()), (1, 4));
        assert!(cache.remove(1));
        assert!(!cache.remove(1));
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
        cache.compose(2, 2, 1, &[]).unwrap();
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn replacement_accounting_and_overlapping_patches_are_ordered() {
        let mut cache = FrameCache::new(2, 16);
        cache.compose(1, 1, 1, &[]).unwrap();
        cache.compose(2, 1, 1, &[]).unwrap();
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let img = cache.compose(1, 2, 1, &[
            pixels(rect(0, 0, 2, 1), &data),
            pixels(rect(1, 0, 1, 1), &[9, 10, 11, 12]),
        ]).unwrap();
        assert_eq!(img.rgba(), &[1, 2, 3, 4, 9, 10, 11, 12]);
        assert_eq!(cache.bytes(), 12);
        assert_eq!(cache.compose(2, 2, 2, &[]).unwrap_err(), CacheError::ByteLimit);
        assert_eq!(cache.bytes(), 12);
        cache.compose(1, 1, 1, &[]).unwrap();
        assert_eq!(cache.bytes(), 8);
    }

    #[test]
    fn copied_rectangles_match_pixel_by_pixel_reference() {
        let mut cache = FrameCache::new(2, 1024);
        let original: Vec<u8> = (0..4 * 5 * 4).map(|n| n as u8).collect();
        cache.compose(1, 4, 5, &[pixels(rect(0, 0, 4, 5), &original)]).unwrap();
        for width in 1..=4u32 {
            for height in 1..=5u32 {
                for x in 0..=4 - width {
                    for y in 0..=5 - height {
                        let result = cache.compose(2, 4, 5, &[Patch::Copy {
                            source_id: 1, source: rect(x, y, width, height), x: 4 - width, y: 5 - height,
                        }]).unwrap();
                        let mut expected = vec![0; 4 * 5 * 4];
                        for row in 0..height {
                            for col in 0..width {
                                for channel in 0..4usize {
                                    let src = (((y + row) * 4 + x + col) * 4) as usize + channel;
                                    let dst = (((5 - height + row) * 4 + 4 - width + col) * 4) as usize + channel;
                                    expected[dst] = original[src];
                                }
                            }
                        }
                        assert_eq!(result.rgba(), expected, "{x},{y} {width}x{height}");
                    }
                }
            }
        }
    }

    #[test]
    fn bounds_lengths_and_patch_counts_are_validated() {
        let mut cache = FrameCache::new(2, 64);
        assert_eq!(cache.compose(1, 0, 1, &[]).unwrap_err(), CacheError::InvalidDimensions);
        assert_eq!(cache.compose(1, 8193, 1, &[]).unwrap_err(), CacheError::InvalidDimensions);
        assert_eq!(cache.compose(1, 8192, 8192, &[]).unwrap_err(), CacheError::InvalidDimensions);
        assert_eq!(cache.compose(1, 1, 1, &[pixels(rect(u32::MAX, 0, 2, 1), &[])]).unwrap_err(), CacheError::InvalidRectangle);
        assert_eq!(cache.compose(1, 1, 1, &[pixels(rect(0, 0, 0, 1), &[])]).unwrap_err(), CacheError::InvalidRectangle);
        assert_eq!(cache.compose(1, 1, 1, &[pixels(rect(0, 0, 1, 1), &[0; 3])]).unwrap_err(), CacheError::InvalidPixelLength);
        let patches = vec![pixels(rect(0, 0, 1, 1), &[0; 4]); MAX_PATCHES + 1];
        assert_eq!(cache.compose(1, 1, 1, &patches).unwrap_err(), CacheError::TooManyPatches);
        let excessive_work = vec![pixels(rect(0, 0, 1, 1), &[0; 4]); 5];
        assert_eq!(cache.compose(1, 1, 1, &excessive_work).unwrap_err(), CacheError::WorkLimit);
        cache.compose(1, 1, 1, &[]).unwrap();
        assert_eq!(cache.compose(2, 1, 1, &[Patch::Copy { source_id: 1, source: rect(0, 0, 2, 1), x: 0, y: 0 }]).unwrap_err(), CacheError::InvalidRectangle);
        assert_eq!(cache.compose(2, 1, 1, &[Patch::Copy { source_id: 1, source: rect(0, 0, 1, 1), x: u32::MAX, y: 0 }]).unwrap_err(), CacheError::InvalidRectangle);
        assert!(cache.get(2).is_none());
    }
}
