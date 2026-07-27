///! Decoding the images a document carries, for showing them.
///
/// This is not part of reading or checking a document, and nothing in
/// [`crate::session`] calls it. A file written out is always the bytes the chip
/// holds; this only exists so a frontend can put a face on screen.
///
/// It is here rather than in the frontend because the frontend in question is
/// Android, which has no JPEG 2000 decoder and no safe way to get one.
use simplelog::debug;

/// The largest image we will decode, in pixels: 4096 by 4096.
///
/// ICAO 9303 p10 expects a face image a few hundred pixels across, and a whole
/// data group is tens of kilobytes, so nothing genuine comes close.
#[cfg(any(feature = "jpeg2000", test))]
const MAX_PIXELS: u64 = 4096 * 4096;

/// A decoded image as 8-bit RGBA, ready to hand to whatever draws it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rgba8 {
    pub width: u32,
    pub height: u32,
    /// `width * height * 4` bytes, R, G, B then A.
    pub data: Vec<u8>,
}

/// Whether this looks like JPEG 2000, by its leading bytes.
///
/// Both forms a document can carry count: the JP2 container, which opens with
/// a signature box, and the bare codestream, which opens with the SOC and SIZ
/// markers (ISO/IEC 15444-1 Annexes I and A).
pub fn looks_like_jpeg2000(data: &[u8]) -> bool {
    const JP2_SIGNATURE_BOX: [u8; 12] = [
        0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
    ];
    const CODESTREAM_START: [u8; 4] = [0xFF, 0x4F, 0xFF, 0x51];

    return data.starts_with(&JP2_SIGNATURE_BOX) || data.starts_with(&CODESTREAM_START);
}

/// Whether this looks like a JPEG, by its leading bytes.
///
/// The Start of Image marker, then the first byte of whichever marker follows
/// it (ISO/IEC 10918-1). The other thing DG2 is allowed to hold.
pub fn looks_like_jpeg(data: &[u8]) -> bool {
    return data.starts_with(&[0xFF, 0xD8, 0xFF]);
}

/// Decode a JPEG 2000 image, in either the JP2 or bare codestream form.
///
/// Returns None for anything that does not decode, rather than propagating a
/// reason: the caller's only recourse is to show the file as undisplayable
/// either way, and the reason goes to the log.
#[cfg(feature = "jpeg2000")]
pub fn decode_jpeg2000(data: &[u8]) -> Option<Rgba8> {
    use hayro_jpeg2000::{DecodeSettings, DecoderContext, Image};

    // The decoder is memory-safe, but this is still a parser being fed a file
    // off a stranger's document, and a panic here would cross a JNI boundary.
    let decoded = std::panic::catch_unwind(|| {
        let image = Image::new(data, &DecodeSettings::default()).ok()?;
        let width = image.width();
        let height = image.height();

        // A JPEG 2000 header can claim any size it likes, and a few hundred
        // bytes can ask for gigabytes of output. The face image on a document
        // is a few hundred pixels across; this ceiling is far above anything
        // real and well below anything that would take the process down.
        if u64::from(width) * u64::from(height) > MAX_PIXELS {
            debug!(
                "Refusing to decode a {}x{} image, which is larger than anything a document \
                 holds.",
                width, height
            );
            return None;
        }

        let channels = usize::from(image.color_space().num_channels());
        let has_alpha = image.has_alpha();
        let mut context = DecoderContext::default();
        // Always 8-bit interleaved, whatever the original depth was.
        let samples = image.decode(&mut context).ok()?.data_u8();
        return Some((width, height, channels, has_alpha, samples));
    });

    let (width, height, channels, has_alpha, samples) = match decoded {
        Ok(Some(decoded)) => decoded,
        Ok(None) => {
            debug!("The image is not usable JPEG 2000.");
            return None;
        }
        Err(_) => {
            debug!("The JPEG 2000 decoder panicked on this image.");
            return None;
        }
    };

    return to_rgba8(width, height, channels, has_alpha, &samples);
}

#[cfg(not(feature = "jpeg2000"))]
pub fn decode_jpeg2000(_data: &[u8]) -> Option<Rgba8> {
    debug!("This build has no JPEG 2000 support (the `jpeg2000` feature is off).");
    return None;
}

/// Turn interleaved 8-bit samples into RGBA.
///
/// The decoder always hands back 8 bits per sample whatever the original depth,
/// with the alpha channel last when there is one. A face image is greyscale or
/// colour; anything else is a document doing something we would only guess at,
/// so it is refused rather than rendered wrongly.
#[cfg(any(feature = "jpeg2000", test))]
fn to_rgba8(
    width: u32,
    height: u32,
    channels: usize,
    has_alpha: bool,
    samples: &[u8],
) -> Option<Rgba8> {
    let pixels = usize::try_from(width).ok()? * usize::try_from(height).ok()?;
    let stride = channels + usize::from(has_alpha);
    if pixels == 0 || samples.len() < pixels * stride {
        debug!(
            "The decoded image is {}x{} with {} channels, but only {} samples came back.",
            width,
            height,
            stride,
            samples.len()
        );
        return None;
    }

    let mut data = Vec::with_capacity(pixels * 4);
    for pixel in 0..pixels {
        let sample = &samples[pixel * stride..];
        let (red, green, blue) = match channels {
            1 => (sample[0], sample[0], sample[0]),
            3 => (sample[0], sample[1], sample[2]),
            _ => {
                debug!("Cannot show a {}-channel image.", channels);
                return None;
            }
        };
        let alpha = if has_alpha { sample[channels] } else { 0xFF };
        data.extend_from_slice(&[red, green, blue, alpha]);
    }

    return Some(Rgba8 {
        width,
        height,
        data,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 16x16 JPEG 2000, in both the forms a document can carry, generated
    /// with OpenJPEG. See tests/fixtures/README.md.
    const JP2: &[u8] = include_bytes!("../tests/fixtures/gradient.jp2");
    const CODESTREAM: &[u8] = include_bytes!("../tests/fixtures/gradient.j2k");

    #[test]
    fn recognizes_both_forms() {
        assert!(looks_like_jpeg2000(JP2));
        assert!(looks_like_jpeg2000(CODESTREAM));
        // A JPEG, which is the other thing DG2 can hold, must not be claimed.
        assert!(!looks_like_jpeg2000(&[0xFF, 0xD8, 0xFF, 0xE0]));
        assert!(!looks_like_jpeg2000(b""));
        assert!(!looks_like_jpeg2000(b"not an image at all"));
    }

    /// The container and the bare codestream have to give the same picture,
    /// since a document may carry either.
    #[cfg(feature = "jpeg2000")]
    #[test]
    fn decodes_both_forms() {
        for (name, data) in [("JP2", JP2), ("codestream", CODESTREAM)] {
            let image = decode_jpeg2000(data).expect(name);
            assert_eq!((image.width, image.height), (16, 16), "{}", name);
            assert_eq!(image.data.len(), 16 * 16 * 4, "{}", name);

            // The fixture is a red/green gradient: red rises with x, green with
            // y, blue is zero. Lossless, so these are exact.
            let pixel = |x: usize, y: usize| {
                let offset = (y * 16 + x) * 4;
                return &image.data[offset..offset + 4];
            };
            assert_eq!(pixel(0, 0), [0, 0, 0, 0xFF], "{} at 0,0", name);
            assert_eq!(pixel(15, 0), [15 * 17, 0, 0, 0xFF], "{} at 15,0", name);
            assert_eq!(pixel(0, 15), [0, 15 * 17, 0, 0xFF], "{} at 0,15", name);
        }
    }

    /// Anything that is not a picture has to come back as None rather than
    /// taking the read down with it.
    #[cfg(feature = "jpeg2000")]
    #[test]
    fn refuses_rubbish() {
        assert_eq!(decode_jpeg2000(b""), None);
        assert_eq!(decode_jpeg2000(b"certainly not an image"), None);
        // A truncated file is the realistic failure: a read that stopped early.
        assert_eq!(decode_jpeg2000(&JP2[..JP2.len() / 2]), None);
        // Right header, nothing behind it.
        assert_eq!(decode_jpeg2000(&JP2[..16]), None);
    }

    /// Greyscale is common for a face image, and has to widen to RGB rather
    /// than being refused or read as a third of a colour image.
    #[test]
    fn widens_greyscale_to_rgb() {
        let image = to_rgba8(2, 1, 1, false, &[0x00, 0x80]).unwrap();
        assert_eq!(image.data, vec![0, 0, 0, 0xFF, 0x80, 0x80, 0x80, 0xFF]);
    }

    /// An alpha channel sits last, and opaque is the default without one.
    #[test]
    fn carries_alpha_through() {
        let image = to_rgba8(1, 1, 3, true, &[1, 2, 3, 4]).unwrap();
        assert_eq!(image.data, vec![1, 2, 3, 4]);

        let image = to_rgba8(1, 1, 3, false, &[1, 2, 3]).unwrap();
        assert_eq!(image.data, vec![1, 2, 3, 0xFF]);
    }

    /// Samples that do not add up must not be read past the end of.
    #[test]
    fn refuses_a_short_buffer() {
        assert_eq!(to_rgba8(4, 4, 3, false, &[0; 10]), None);
        assert_eq!(to_rgba8(0, 0, 3, false, &[]), None);
        // Four channels is not something a face image is, so it is refused
        // rather than guessed at.
        assert_eq!(to_rgba8(1, 1, 4, false, &[1, 2, 3, 4]), None);
    }
}
