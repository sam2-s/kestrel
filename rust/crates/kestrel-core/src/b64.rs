//! Unpadded base64url, the only binary encoding on the wire.
//!
//! Two details are load-bearing rather than cosmetic, and both are places a
//! naive decoder disagrees with the reference implementation:
//!
//! * **Trailing bits are ignored.** A 32- or 65-byte key encodes to 43 or 87
//!   characters, and the final character carries two bits that no byte uses.
//!   The reference decoder accepts any spelling of those bits, so the same key
//!   has four valid encodings. We accept them too, and [`canonical`] exists so
//!   stored keys keep exactly one spelling.
//! * **Strictness elsewhere.** Padding characters, whitespace and any character
//!   outside the URL-safe alphabet are rejected rather than skipped.

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_encode_padding(false)
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::RequireNone);

/// Unpadded base64url with lenient trailing bits.
static ENGINE: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::URL_SAFE, CONFIG);

/// Maximum encoded length we will even look at, so a hostile caller cannot
/// make the relay allocate from an attacker-chosen length.
pub const MAX_ENCODED: usize = 4096;

pub fn encode(bytes: &[u8]) -> String {
    ENGINE.encode(bytes)
}

/// Decode, or `None` if the input is not valid unpadded base64url.
///
/// The length check runs first and is deliberately generous: it exists to
/// bound work, not to validate.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    if s.len() > MAX_ENCODED {
        return None;
    }
    ENGINE.decode(s).ok()
}

/// The single spelling we store for a byte string, so two records holding the
/// same key compare equal as text.
///
/// Records are compared as *bytes* wherever it matters; this only keeps storage
/// and display stable.
pub fn canonical(s: &str) -> Option<String> {
    decode(s).map(|b| encode(&b))
}

/// True when `s` is in the alphabet and short enough to be a key. Used on the
/// receive path before any allocation.
pub fn looks_like_key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ENCODED
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub fn decode_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = decode(s)?;
    <[u8; N]>::try_from(v.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_lengths() {
        for n in 0..200usize {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 % 256) as u8).collect();
            let s = encode(&bytes);
            assert!(!s.contains('='), "padding leaked at n={n}");
            assert_eq!(decode(&s).as_deref(), Some(bytes.as_slice()));
        }
    }

    #[test]
    fn accepts_all_four_trailing_bit_spellings() {
        // 32 zero bytes: last char is 'A' (all bits clear). Flipping the two
        // unused low bits must still decode, exactly as the reference does.
        let base = encode(&[0u8; 32]);
        assert_eq!(base, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(decode(&base).unwrap().len(), 32);
        for tail in ['B', 'C', 'D'] {
            let mut s = base.clone();
            s.pop();
            s.push(tail);
            assert_eq!(decode(&s).unwrap(), vec![0u8; 32], "tail {tail}");
        }
    }

    #[test]
    fn canonical_collapses_the_spellings() {
        let base = encode(&[0u8; 32]);
        let mut s = base.clone();
        s.pop();
        s.push('B');
        assert_eq!(canonical(&s).as_deref(), Some(base.as_str()));
    }

    #[test]
    fn rejects_padding_and_foreign_characters() {
        assert!(decode("AAAA=").is_none());
        assert!(decode("AA+/").is_none(), "standard alphabet must not pass");
        assert!(decode("A A").is_none());
    }

    #[test]
    fn the_empty_string_decodes_to_no_bytes() {
        // Legitimate, and callers distinguish it with `looks_like_key`, which
        // rejects an empty field. Decoding an empty string to an empty buffer is
        // correct; silently accepting it as a *key* is not.
        assert_eq!(decode(""), Some(Vec::new()));
        assert!(!looks_like_key(""));
    }

    #[test]
    fn bounds_hostile_lengths() {
        assert!(decode(&"A".repeat(MAX_ENCODED + 1)).is_none());
    }

    #[test]
    fn exact_length_accessor_checks_the_length() {
        assert!(decode_exact::<32>(&encode(&[1u8; 32])).is_some());
        assert!(decode_exact::<33>(&encode(&[1u8; 32])).is_none());
    }
}
