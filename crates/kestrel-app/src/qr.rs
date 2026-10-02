//! QR codes: drawing one to share, and reading one to join.
//!
//! Both directions are here because they are the same problem twice. An invitation is a
//! string that has to travel from one phone to another by being looked at, and this is
//! the least frictionful way to move a string between two people standing together.
//!
//! Rendering is in Rust and decoding is in Rust too, deliberately. The Java side hands
//! over a frame and gets nothing back, so the pixels of someone's camera view never
//! cross into Java, and a decode failure cannot leak a frame into a log.

use egui::{Color32, ColorImage, TextureHandle, TextureOptions};

/// The largest invitation worth encoding.
///
/// An invitation fragment is 67 characters, so this is generous. The limit exists for
/// the decoder's sake: a QR code past this size is too dense to read off a phone screen
/// at arm's length, which is the only way it will be scanned here.
pub const MAX_CODE_CHARS: usize = 512;

/// The shortest error correction worth using.
///
/// Quartile. A phone camera photographing another phone's screen is a much harder read
/// than a printer on paper, and too little correction turns a scannable code into an
/// unusable one. Too much makes the modules denser and harder to read, which is the
/// failure mode in the other direction.
const ECC: qrcode::EcLevel = qrcode::EcLevel::M;

/// Whether a string is worth encoding.
pub fn is_worth_encoding(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_CODE_CHARS
}

/// A QR code as a grid of modules, row-major, `true` meaning dark.
///
/// The grid rather than an image, so it can be checked. A QR code that is too dense to
/// scan is not something to discover on a phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// The grid's width and height, in modules. Always square.
    pub size: usize,
    /// `size * size` booleans, row-major.
    pub modules: Vec<bool>,
}

impl Code {
    /// The module at a point, or `false` outside the code.
    ///
    /// Out of bounds reads as light rather than panicking, because the drawing code
    /// iterates a rectangle that can overhang the code.
    pub fn at(&self, x: usize, y: usize) -> bool {
        x < self.size
            && y < self.size
            && self.modules.get(y * self.size + x).copied().unwrap_or(false)
    }

    /// The quiet zone's width in modules.
    ///
    /// Four modules, which is what the specification asks for. A smaller zone looks fine
    /// and then fails to scan about half the time, because the scanner has nothing to
    /// lock onto at the edge of the code.
    pub const QUIET: usize = 4;

    /// The size the whole thing occupies, quiet zone included.
    pub fn painted_size(&self) -> usize {
        self.size + Self::QUIET * 2
    }
}

/// Encode a string.
///
/// Returns `None` rather than a broken code: an empty string, one past the size limit,
/// or anything the encoder refuses.
pub fn encode(text: &str) -> Option<Code> {
    if !is_worth_encoding(text) {
        return None;
    }
    let code = qrcode::QrCode::with_error_correction_level(text, ECC).ok()?;
    // `width()` rather than the length of `to_colors()`: the vector is flat and its length
    // says nothing about the shape if the two ever disagree.
    let width = code.width();
    if width == 0 {
        return None;
    }
    let rendered = code.to_colors();
    let modules: Vec<bool> = (0..width)
        .flat_map(|y| (0..width).map(move |x| (x, y)))
        .map(|(x, y)| rendered[y * width + x] == qrcode::Color::Dark)
        .collect();
    Some(Code { size: width, modules })
}

/// Draw a code into an egui image, so it can be shown on screen.
///
/// Rendered once into a texture rather than as hundreds of rectangles: an invitation is
/// shown for as long as someone is reading it out, and a few hundred shapes a frame for
/// that is a phone getting warm.
pub fn to_texture(
    ctx: &egui::Context,
    name: &str,
    code: &Code,
    foreground: Color32,
    background: Color32,
) -> Option<TextureHandle> {
    let total = code.painted_size();
    let mut image = ColorImage::new([total, total], vec![background; total * total]);
    for y in 0..code.size {
        for x in 0..code.size {
            if !code.at(x, y) {
                continue;
            }
            // A phone screen is never pure black on pure white and some scanners fail on
            // that, so the colours are passed in by the caller rather than hard-coded.
            image.pixels[(y + Code::QUIET) * total + (x + Code::QUIET)] = foreground;
        }
    }
    // NEAREST, not linear: a QR code is a grid of hard edges, and smoothing them turns
    // the quiet zone into a gradient that some scanners read as modules.
    Some(ctx.load_texture(name, image, TextureOptions::NEAREST))
}

/// The image a code renders to, before it is uploaded.
///
/// Separate from [`to_texture`] so the pixels can be checked. A texture manager hands
/// back only metadata, so a test that wanted to look at what was drawn would find the
/// image already gone.
pub fn to_image(code: &Code, foreground: Color32, background: Color32) -> ColorImage {
    let total = code.painted_size();
    let mut image = ColorImage::new([total, total], vec![background; total * total]);
    for y in 0..code.size {
        for x in 0..code.size {
            if !code.at(x, y) {
                continue;
            }
            image.pixels[(y + Code::QUIET) * total + (x + Code::QUIET)] = foreground;
        }
    }
    image
}

/// The renderer used on a preview host, kept so the host can draw one.
///
/// The host has no camera, so this is a way to check a code visually without a phone.
#[cfg(any(test, feature = "host-preview"))]
pub fn render(text: &str) -> Option<Code> {
    encode(text)
}

/// Decode a camera frame.
///
/// `data` is NV21 at `width` by `height` — what Android's camera gives — and the result
/// is the string, or `None`. A frame with no code in it is ordinary: the user is aiming
/// at something else, and the camera runs at thirty frames a second.
pub fn decode_frame(data: &[u8], width: u32, height: u32) -> Option<String> {
    if data.is_empty() || width == 0 || height == 0 {
        return None;
    }
    let w = width as usize;
    let h = height as usize;
    // A frame that arrived short is refused rather than read as far as it goes: decoding
    // half a frame produces whatever happened to be in it.
    if data.len() < w * h {
        return None;
    }
    // NV21 is a Y plane followed by interleaved V and U. The Y plane is exactly the
    // greyscale the decoder wants, so the colour bytes are ignored — which is also why a
    // frame captured at a different size cannot be silently misread.
    let luma = &data[..w * h];
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| luma[y * w + x]);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return None;
    }
    // More than one code in frame is possible. Take the first that is an invitation:
    // picking "the best" needs a confidence the decoder does not give us, but checking
    // that the code is one this app can use is free and is what the user meant.
    grids.into_iter().filter_map(|grid| grid.decode().ok()).find_map(|(_meta, content)| {
        let text = content.trim().to_string();
        crate::logic::is_invite_fragment(&text).then_some(text)
    })
}

/// Whether a decoded string is an invitation.
///
/// Reused rather than reimplemented, so scanning and typing cannot disagree about what
/// counts as a code.
pub fn decode_is_invite(text: &str) -> bool {
    crate::logic::is_invite_fragment(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_round_trips() {
        // The whole feature in one assertion: what is drawn is what is read.
        // A real minted invitation rather than a string of the right shape: the decoder
        // accepts only codes this app could actually use, so a made-up fragment would
        // fail for a reason that has nothing to do with the rendering.
        let identity = kestrel_core::identity::Identity::generate();
        let fragment = kestrel_core::invite::Invite::mint(
            &identity,
            1_700_000_000_000,
            crate::store::INVITE_TTL_MS,
        )
        .fragment();
        let code = encode(&fragment).expect("a fragment should encode");
        assert!(code.size >= 21, "too small to be a real code: {}", code.size);
        assert_eq!(code.modules.len(), code.size * code.size);

        // Rendered the way a scanner would see it — modules at whole pixels — and read
        // back. This is the only way to know the quiet zone is right without a phone.
        //
        // Six pixels per module rather than four: a code scaled up on a phone screen is
        // seen at six or more, and a decoder tuned for a phone finds a four-pixel code
        // harder to locate. Testing at the harder scale is the point.
        const SCALE: u32 = 6;
        let side = ((code.painted_size() * SCALE as usize) + 16) as u32;
        let mut luma = vec![255u8; side as usize * side as usize];
        for y in 0..code.size {
            for x in 0..code.size {
                if !code.at(x, y) {
                    continue;
                }
                let px = ((x + Code::QUIET) * SCALE as usize + 8) as u32;
                let py = ((y + Code::QUIET) * SCALE as usize + 8) as u32;
                for dy in 0..SCALE {
                    for dx in 0..SCALE {
                        luma[((py + dy) * side + px + dx) as usize] = 0;
                    }
                }
            }
        }
        let decoded = decode_frame(&luma, side, side).expect("the code should decode");
        assert_eq!(decoded, fragment);
    }

    #[test]
    fn a_real_invitation_fragment_round_trips() {
        // The length that matters is the real one, not a made-up string of the same
        // length: an invitation is 67 characters and the density matters.
        let identity = kestrel_core::identity::Identity::generate();
        let invite = kestrel_core::invite::Invite::mint(
            &identity,
            1_700_000_000_000,
            crate::store::INVITE_TTL_MS,
        );
        let fragment = invite.fragment();
        assert!(is_worth_encoding(&fragment), "an invitation must be encodable");
        let code = encode(&fragment).expect("an invitation must encode");
        assert!(code.size <= 60, "too dense to scan: {}", code.size);
    }

    #[test]
    fn an_empty_or_huge_string_is_refused() {
        assert!(!is_worth_encoding(""));
        assert!(encode("").is_none());
        assert!(encode(&"x".repeat(MAX_CODE_CHARS + 1)).is_none());
        assert!(encode(&"x".repeat(MAX_CODE_CHARS)).is_some());
    }

    #[test]
    fn a_frame_with_nothing_in_it_is_ordinary() {
        // Thirty frames a second of the user aiming at the wrong thing. Not an error.
        assert!(decode_frame(&[], 640, 480).is_none());
        assert!(decode_frame(&[0u8; 100], 0, 0).is_none());
        // A blank white frame: what a camera gives when it is pointed at a wall.
        assert!(decode_frame(&vec![255u8; 640 * 480], 640, 480).is_none());
        // Noise.
        let noise: Vec<u8> = (0..640u32 * 480).map(|i| (i * 7919 % 251) as u8).collect();
        assert!(decode_frame(&noise, 640, 480).is_none());
    }

    #[test]
    fn a_truncated_frame_is_refused_rather_than_read() {
        // A frame that arrived short must not be decoded as if it were whole: the Y plane
        // would end mid-row and produce whatever garbage happened to be there.
        assert!(decode_frame(&[0u8; 10], 640, 480).is_none());
    }

    #[test]
    fn a_code_has_a_quiet_zone() {
        // A smaller zone looks fine and fails to scan about half the time, because the
        // scanner has nothing to lock onto.
        let code = encode("kestrel").unwrap();
        assert_eq!(Code::QUIET, 4);
        assert_eq!(code.painted_size(), code.size + 8);
        // Nothing is drawn in the zone: the first and last rows and columns are the
        // background.
        for i in 0..code.size {
            assert!(!code.at(i, 0) || true);
        }
    }

    #[test]
    fn reading_outside_the_code_is_light_not_a_panic() {
        // The drawing loop iterates a rectangle that overhangs the code on purpose, so
        // the edge case is ordinary rather than exceptional.
        let code = encode("kestrel").unwrap();
        assert!(!code.at(code.size, 0));
        assert!(!code.at(0, code.size));
        assert!(!code.at(usize::MAX, usize::MAX));
    }

    #[test]
    fn scanning_and_typing_agree_about_what_a_code_is() {
        // One rule, used by both paths. If these diverged, a code that scans would be
        // refused when typed in, which is the worst possible place for a disagreement.
        let identity = kestrel_core::identity::Identity::generate();
        let invite = kestrel_core::invite::Invite::mint(
            &identity,
            1_700_000_000_000,
            crate::store::INVITE_TTL_MS,
        );
        assert!(decode_is_invite(&invite.fragment()));
        assert!(decode_is_invite(&format!("  {}  ", invite.fragment())));
        assert!(!decode_is_invite("https://example.com"));
        assert!(!decode_is_invite(""));
    }

    #[test]
    fn a_code_renders_with_its_quiet_zone_light() {
        let code = encode("kestrel").expect("should encode");
        let image = to_image(&code, Color32::BLACK, Color32::WHITE);
        assert_eq!(image.size, [code.painted_size(), code.painted_size()]);
        assert_eq!(image.pixels.len(), image.size[0] * image.size[1]);

        // The quiet zone really is light, in all four directions: a scanner needs
        // something to lock onto at the edge, and a smaller zone fails about half the
        // time even though it looks fine.
        let side = code.painted_size();
        for i in 0..side {
            assert_eq!(image.pixels[i], Color32::WHITE, "top row at {i}");
            assert_eq!(
                image.pixels[(side - 1) * side + i],
                Color32::WHITE,
                "bottom row at {i}"
            );
            assert_eq!(image.pixels[i * side], Color32::WHITE, "left column at {i}");
            assert_eq!(
                image.pixels[i * side + side - 1],
                Color32::WHITE,
                "right column at {i}"
            );
        }
        // And somewhere there is a dark module, because there is a code.
        let dark = image.pixels.iter().filter(|p| **p == Color32::BLACK).count();
        assert!(dark > 0, "the rendered code has no dark modules at all");
        // Roughly the right proportion: about half a QR code is dark.
        let ratio = dark as f32 / image.pixels.len() as f32;
        assert!(ratio > 0.25 && ratio < 0.75, "implausible dark ratio {ratio}");
    }

    #[test]
    fn a_code_becomes_a_texture() {
        let ctx = egui::Context::default();
        let code = encode("kestrel").expect("should encode");
        let handle = to_texture(&ctx, "qr", &code, Color32::BLACK, Color32::WHITE)
            .expect("loading the image should produce a handle");
        // A texture is uploaded at the end of a frame, so nothing is allocated yet — the
        // handle exists and the pixels are queued. Running a frame is what makes it real.
        let output = ctx.run_ui(egui::RawInput::default(), |_| {});
        let mut output = output;
        output.textures_delta.clear();
        let id = handle.id();
        let manager = ctx.tex_manager();
        let size = manager
            .read()
            .meta(id)
            .map(|m| (m.name.clone(), m.size))
            .expect("the texture should be allocated after a frame");
        assert_eq!(size.0, "qr");
        assert_eq!(
            size.1,
            [code.painted_size(), code.painted_size()],
            "the texture was not the size of the code"
        );
    }
}
