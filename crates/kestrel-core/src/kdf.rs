//! Every key derivation in the protocol, in one place.
//!
//! All of it is HKDF-SHA-256 with a salt of 32 zero bytes, and every info
//! string begins with the protocol prefix. The prefix is what keeps a
//! derivation unique to this protocol, so a key here can never collide with one
//! derived for something else out of the same input.
//!
//! The label strings are byte-exact. A single wrong character produces a
//! different key rather than an error, which is the worst kind of bug to chase
//! later, so `tests/vectors.rs` pins every one of them against the published
//! vectors.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::b64;

/// Protocol tag. Prefixes every info string and appears in both the AEAD
/// associated data and the signature base.
pub const PROTO: &str = "starling/v2";

/// HKDF salt: 32 zero bytes, for every derivation.
const SALT: [u8; 32] = [0u8; 32];

/// Lowercase hex, as the relay names channels and members.
pub fn hex(bytes: &[u8]) -> String {
    const D: [u8; 16] = *b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// HKDF-SHA-256 with the fixed salt. Returns `None` only if the requested
/// length is out of range for HKDF-SHA-256 (over 255 hash-lengths), which no
/// caller here can trigger.
fn hkdf(ikm: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    Hkdf::<Sha256>::new(Some(&SALT), ikm).expand(info, out).is_ok()
}

fn hkdf32(ikm: &[u8], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    // 32 bytes is always a valid HKDF-SHA-256 output length.
    let _ = hkdf(ikm, info.as_bytes(), &mut out);
    out
}

fn hkdf16(ikm: &[u8], info: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let _ = hkdf(ikm, info.as_bytes(), &mut out);
    out
}

// ---------------------------------------------------------------- generation

/// The generation anchor. The channel id is derived from this, so the seed is
/// the one secret that names a generation.
pub fn anchor(seed: &[u8; 32]) -> [u8; 32] {
    hkdf32(seed, "starling/v2/anchor")
}

/// The relay channel id for a generation: 16 bytes rendered as 32 lowercase
/// hex characters.
pub fn channel_id(anchor: &[u8; 32]) -> String {
    hex(&hkdf16(anchor, "starling/v2/channel-id"))
}

/// The generation's first chain key, `CK_0`.
pub fn chain0(seed: &[u8; 32]) -> [u8; 32] {
    hkdf32(seed, "starling/v2/chain")
}

/// One forward step of the epoch chain: `CK_e` to `CK_{e+1}`.
///
/// Each step is one hash, so walking the chain forwards is cheap and walking it
/// backwards is infeasible. That is what makes an old epoch unrecoverable once
/// its key is dropped.
pub fn chain_step(ck: &[u8; 32]) -> [u8; 32] {
    hkdf32(ck, "starling/v2/step")
}

/// The AES-256-GCM content key for one (epoch, sender) pair.
///
/// Note this is per *sender*, not per circle. A content key therefore only ever
/// proves that some holder of circle key material wrote a message; which member
/// it was is settled by the signature, which is checked separately.
pub fn msg_key(ck: &[u8; 32], member: &str) -> [u8; 32] {
    hkdf32(ck, &format!("starling/v2/msg|{member}"))
}

/// The next generation's seed, from the chain key at the mix epoch concatenated
/// with 32 bytes of fresh key-exchange entropy.
///
/// The entropy is mixed in at a specific epoch rather than simply at call time
/// so that everyone derives the same next seed even if their re-key messages
/// arrive in different orders.
pub fn next_seed(ck_at_mix: &[u8; 32], fresh_entropy: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ck_at_mix);
    ikm[32..].copy_from_slice(fresh_entropy);
    let seed = hkdf32(&ikm, "starling/v2/rekey");
    ikm.zeroize();
    seed
}

/// The AES-256-GCM key that wraps a fresh seed to one recipient.
pub fn wrap_key(shared_x: &[u8; 32], channel: &str, member: &str) -> [u8; 32] {
    hkdf32(shared_x, &format!("starling/v2/wrap|{channel}|{member}"))
}

// ---------------------------------------------------------------- rendezvous

/// The invite channel for one invitation: a rendezvous point the inviter and
/// joiner meet on. Separate from the circle channel, so the two are unrelated
/// to anyone watching.
pub fn invite_channel(invite_secret: &[u8; 32]) -> String {
    hex(&hkdf16(invite_secret, "starling/v2/invite-channel"))
}

/// The key that seals the handshake on the invite channel.
pub fn invite_key(invite_secret: &[u8; 32]) -> [u8; 32] {
    hkdf32(invite_secret, "starling/v2/invite-enc")
}

/// The inviter's commitment to their own keys: the first 16 bytes of a hash
/// over both public keys.
///
/// This is what makes a stolen invite link inert. The link carries the
/// commitment, so a device holding one can only ever ask; it cannot present
/// itself as the inviter, and a welcome is only believed when it verifies
/// against this value.
pub fn inviter_commitment(pk: &[u8], epk: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"starling/v2/inviter");
    h.update(pk);
    h.update(epk);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

// ---------------------------------------------------------------- help link

/// The channel a help beacon posts to. One per viewer, so revoking a link
/// removes that viewer's channel and nothing else.
pub fn help_channel(secret: &[u8; 32]) -> String {
    hex(&hkdf16(secret, "starling/v2/help-channel-id"))
}

/// The key a help beacon seals with. Symmetric: the viewer derives the same key
/// and could therefore also write, which the trust model accounts for.
pub fn help_key(secret: &[u8; 32]) -> [u8; 32] {
    hkdf32(secret, "starling/v2/help-enc")
}

// ---------------------------------------------------------------- membership

/// A member id: the first 16 bytes of a hash over *both* public keys, as 32
/// lowercase hex characters.
///
/// Committing to the signing key and the agreement key together is what pins
/// them. A relay cannot swap one for another without breaking the id, and a
/// member cannot present a different signing key under an id they already hold.
pub fn member_id(pk: &[u8], epk: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"starling/v2/member");
    h.update(pk);
    h.update(epk);
    hex(&h.finalize()[..16])
}

/// A member id is well formed when it is 32 lowercase hex characters.
pub fn is_member_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// The first 18 bytes of a hash over both public keys, the raw material for a
/// safety number.
pub fn fingerprint(pk: &[u8], epk: &[u8]) -> [u8; 18] {
    let mut h = Sha256::new();
    h.update(b"starling/v2/fp");
    h.update(pk);
    h.update(epk);
    let d = h.finalize();
    let mut out = [0u8; 18];
    out.copy_from_slice(&d[..18]);
    out
}

/// A hash over a roster's member ids, as unpadded base64url.
///
/// Every member of a generation computes this from the roster they believe is
/// current, and a re-key carries the expected value. Disagreement means a
/// re-key is in flight or a member is being added, so it resolves itself; a
/// persistent disagreement is what a split circle looks like.
pub fn roster_hash(ids: &[String]) -> String {
    let mut sorted: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    // Member ids are lowercase hex, so a byte sort is the same as a numeric one
    // and does not depend on locale.
    sorted.sort_unstable();

    let mut h = Sha256::new();
    h.update(b"starling/v2/roster|");
    for (i, id) in sorted.iter().enumerate() {
        if i > 0 {
            h.update(b",");
        }
        h.update(id.as_bytes());
    }
    b64::encode(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(unhex("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert!(unhex("0f0").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn anchor_matches_the_published_vector() {
        assert_eq!(
            hex(&anchor(&SEED)),
            "d448eeb615b7078dfb1bd9cda7a14f1ff8e85446e8851d19553437e545fade5f"
        );
    }

    #[test]
    fn channel_id_matches_the_published_vector() {
        let a = anchor(&SEED);
        assert_eq!(channel_id(&a), "f1c695a80bae6baf8bb34828bc177bc9");
    }

    #[test]
    fn chain0_matches_the_published_vector() {
        assert_eq!(
            hex(&chain0(&SEED)),
            "3e807d0367f0c50adeb1ab8defe671706808d2f6812345b7e6632e7d56682992"
        );
    }

    #[test]
    fn chain_step_matches_the_published_vector() {
        let mut ck = [0u8; 32];
        ck[0] = 0x03;
        for (i, b) in [
            0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e,
            0x65, 0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9,
            0xc0, 0xc7, 0xce, 0xd5, 0xdc,
        ]
        .iter()
        .enumerate()
        {
            ck[1 + i] = *b;
        }
        assert_eq!(
            hex(&chain_step(&ck)),
            "bde5c17cc1602562b4ddfd6d6133d3824fc0abb69a565751883f6b6222be6f9a"
        );
    }

    #[test]
    fn next_seed_matches_the_published_vector() {
        let mut ck = [0u8; 32];
        for (i, b) in [
            0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57,
            0x5e, 0x65, 0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2,
            0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc,
        ]
        .iter()
        .enumerate()
        {
            ck[i] = *b;
        }
        let mut ns = [0u8; 32];
        for (i, b) in [
            0x05, 0x10, 0x1b, 0x26, 0x31, 0x3c, 0x47, 0x52, 0x5d, 0x68, 0x73, 0x7e, 0x89,
            0x94, 0x9f, 0xaa, 0xb5, 0xc0, 0xcb, 0xd6, 0xe1, 0xec, 0xf7, 0x02, 0x0d, 0x18,
            0x23, 0x2e, 0x39, 0x44, 0x4f, 0x5a,
        ]
        .iter()
        .enumerate()
        {
            ns[i] = *b;
        }
        assert_eq!(
            hex(&next_seed(&ck, &ns)),
            "c7acc26e46d1fc9bfa3af2c68ec68d55e8f06f0840e9dc94b478248eb617b270"
        );
    }

    #[test]
    fn member_id_is_128_bits_of_both_keys() {
        // An all-zero keypair, the degenerate case from the published vectors.
        assert_eq!(member_id(&[0u8; 32], &[0u8; 65]), "f00e016dc606b8e419d5424bf601e1d3");
    }

    #[test]
    fn member_id_changes_when_either_key_changes() {
        let a = member_id(&[1u8; 32], &[2u8; 65]);
        assert_ne!(a, member_id(&[1u8; 32], &[3u8; 65]));
        assert_ne!(a, member_id(&[9u8; 32], &[2u8; 65]));
    }

    #[test]
    fn member_id_validation_is_strict() {
        assert!(is_member_id("dc73c74c3f57c6ff0c2d9016c333507f"));
        assert!(!is_member_id("DC73C74C3F57C6FF0C2D9016C333507F"), "uppercase");
        assert!(!is_member_id("dc73c74c3f57c6ff0c2d9016c33350"), "31 chars");
        assert!(!is_member_id("dc73c74c3f57c6ff0c2d9016c333507ff"), "33 chars");
        assert!(!is_member_id("dc73c74c3f57c6ff0c2d9016c333507g"), "non-hex");
    }

    #[test]
    fn roster_hash_does_not_depend_on_input_order() {
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        assert_eq!(roster_hash(&[a.clone(), b.clone()]), roster_hash(&[b, a]));
    }

    #[test]
    fn roster_hash_separators_are_load_bearing() {
        // Without the commas, ["ab","c"] and ["a","bc"] would collide.
        let mk = |parts: &[&str]| {
            roster_hash(&parts.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
        };
        assert_ne!(mk(&["ab", "c"]), mk(&["a", "bc"]));
    }

    #[test]
    fn msg_key_is_per_sender() {
        let ck = [7u8; 32];
        assert_ne!(msg_key(&ck, "aa"), msg_key(&ck, "bb"));
        // Same sender, same epoch, same key: deterministic.
        assert_eq!(msg_key(&ck, "aa"), msg_key(&ck, "aa"));
    }

    #[test]
    fn chain_steps_are_deterministic_and_distinct() {
        let ck0 = chain0(&SEED);
        let ck1 = chain_step(&ck0);
        let ck2 = chain_step(&ck1);
        assert_ne!(ck0, ck1);
        assert_ne!(ck1, ck2);
        assert_eq!(ck2, chain_step(&ck1));
    }

    #[test]
    fn invite_and_help_channels_are_separate_namespaces() {
        let s = SEED;
        assert_ne!(invite_channel(&s), help_channel(&s));
        assert_ne!(invite_key(&s), help_key(&s));
    }
}
