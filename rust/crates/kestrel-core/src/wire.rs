//! The wire format: what a post looks like on the network, and the checks that
//! decide whether it is worth decrypting.
//!
//! There is no binary framing. A post is a small JSON object whose binary
//! fields are unpadded base64url, and whose plaintext is always exactly
//! [`PAD_LEN`] bytes. Everything a receiver must agree on before it can open a
//! message — the channel, the member, the epoch, the timestamp — is bound into
//! the AEAD associated data, and the same fields plus the ciphertext are bound
//! into what the sender signs. Binding the epoch is what stops a point being
//! replayed into a different epoch, just as binding the channel stops it being
//! replayed into a different circle.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{b64, kdf::PROTO};

/// Plaintext length for every message, in bytes, before encryption.
///
/// Padding every message to one length means the relay cannot tell a location
/// post from a re-key by looking at the request, and cannot tell a short name
/// from a long one.
pub const PAD_LEN: usize = 512;

/// Largest post body the relay will read.
pub const MAX_BODY: usize = 2048;

/// Largest ciphertext the relay will accept, in bytes: the padded plaintext
/// plus the GCM tag.
pub const MAX_CT: usize = 540;

/// Largest nonce the relay will accept, in bytes: a 96-bit GCM nonce.
pub const MAX_NONCE: usize = 18;

/// Members per circle, enforced by the relay.
pub const MEMBER_CAP: usize = 16;

/// Points retained per member per channel, the length of a visible trail.
pub const TRAIL_CAP: usize = 240;

/// How long a row lives on the relay.
pub const TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// How far ahead of the relay's clock a timestamp may be.
pub const FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;

/// Length of an epoch, the interval at which content keys advance.
pub const EPOCH_MS: i64 = 10 * 60 * 1000;

/// How many epochs of drift are tolerated between devices, in either
/// direction. Two, so twenty minutes.
pub const MAX_SKEW_EPOCHS: i64 = 2;

/// How long an invitation stays usable.
pub const INVITE_TTL_MS: i64 = 60 * 60 * 1000;

/// Longest jump forward a device will follow before treating it as a takeover
/// attempt and destroying its keys. Thirty days.
pub const MAX_CATCHUP_EPOCHS: i64 = 4320;

/// Default readable history, in epochs. One hour.
pub const DEFAULT_HISTORY_EPOCHS: i64 = 6;

/// The absolute epoch index for a wall-clock time. Always absolute, never
/// relative to a generation, so any device can check it against its own clock.
pub fn epoch_at(ms: i64) -> i64 {
    ms.div_euclid(EPOCH_MS)
}

/// The associated data for one message: the fields a receiver must agree on
/// before the ciphertext means anything.
///
/// Six fields, joined with a single `|`, no trailing separator.
pub fn aad(channel: &str, member: &str, epoch: i64, ts: i64) -> String {
    format!("{PROTO}|{channel}|{member}|{epoch}|{ts}")
}

/// What the sender signs: the associated-data fields, *including the
/// timestamp*, plus the nonce and the ciphertext exactly as they appear on the
/// wire.
///
/// Seven fields. The timestamp is bound into the signature as well as the
/// associated data, so a signed post cannot have its `ts` altered to dodge a
/// monotonicity check.
///
/// Signing the base64 spellings rather than the raw bytes means a verifier
/// checks the bytes it is about to store, so a re-encoding cannot slip a
/// different message past a signature check.
pub fn sig_base(
    channel: &str,
    member: &str,
    epoch: i64,
    ts: i64,
    nonce_b64: &str,
    ct_b64: &str,
) -> String {
    format!("{PROTO}|{channel}|{member}|{epoch}|{ts}|{nonce_b64}|{ct_b64}")
}

/// The AEAD associated data for a key wrap. The label is `rekey` for a welcome
/// too; what distinguishes the two is the context string.
pub fn wrap_aad(channel: &str, recipient: &str, context: &str) -> String {
    format!("{PROTO}/rekey|{channel}|{recipient}|{context}")
}

/// The 12-byte AEAD nonce for a post: 4 random bytes followed by the timestamp
/// as a big-endian u64.
///
/// The random prefix is the guard that makes a repeated timestamp safe. The low
/// eight bytes alone would repeat if a device sealed two messages in the same
/// millisecond under one key, and a repeated GCM nonce under one key leaks the
/// XOR of the two plaintexts.
pub fn nonce_for(ts: i64, guard: [u8; 4]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&guard);
    nonce[4..].copy_from_slice(&(ts as u64).to_be_bytes());
    nonce
}

/// True when `epoch` is close enough to `now` to be believable.
///
/// Applied by the relay to a claim, and by every receiver to the epoch it
/// carries, so a device with a badly wrong clock cannot shift everybody else's
/// view of the chain.
pub fn epoch_plausible(epoch: i64, now: i64) -> bool {
    let current = epoch_at(now);
    (epoch - current).abs() <= MAX_SKEW_EPOCHS
}

/// The signing algorithm, named on the wire.
///
/// This is *not* trusted on receipt. A relay can flip it, so the algorithm is
/// recovered from the public key's length instead. See [`Alg::from_pk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Alg {
    Ed25519,
    P256,
}

impl Alg {
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Ed25519 => "ed25519",
            Alg::P256 => "p256",
        }
    }

    /// Recover the algorithm from a public key's length.
    ///
    /// The two encodings cannot be confused: an Ed25519 key is 32 bytes and a
    /// P-256 key is 65. Deriving the algorithm this way means the value on the
    /// wire has no effect on how a message is verified.
    pub fn from_pk(pk: &[u8]) -> Option<Alg> {
        match pk.len() {
            32 => Some(Alg::Ed25519),
            65 => Some(Alg::P256),
            _ => None,
        }
    }

    pub fn pk_len(self) -> usize {
        match self {
            Alg::Ed25519 => 32,
            Alg::P256 => 65,
        }
    }
}

/// A post as it appears in a `POST` body or a feed entry.
///
/// Field names are short because the relay stores and serves this verbatim;
/// there is no schema evolution to spend bytes on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Post {
    /// Member id, 32 lowercase hex characters.
    pub m: String,
    /// Declared algorithm. Ignored on receipt; see [`Alg::from_pk`].
    pub alg: String,
    /// Signing public key.
    pub pk: String,
    /// Agreement public key, always P-256.
    pub epk: String,
    /// Epoch this message belongs to.
    pub e: i64,
    /// Sender's timestamp, milliseconds.
    pub ts: i64,
    /// 12-byte nonce, base64url.
    pub n: String,
    /// Ciphertext, base64url.
    pub c: String,
    /// Signature over [`sig_base`], base64url.
    pub sig: String,
}

impl Post {
    /// A human-readable summary of why a post is not usable, or `None` if it
    /// is well formed.
    ///
    /// The order of the checks is the order of increasing cost, and the cheap
    /// structural checks come first: there is no reason to decode a key before
    /// checking that the field is short.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if !kdf_is_member_id(&self.m) {
            return Err("bad member id");
        }
        if self.e < 0 || self.e > i64::MAX / 2 {
            return Err("bad epoch");
        }
        if self.ts <= 0 || self.ts > i64::MAX / 2 {
            return Err("bad timestamp");
        }
        if !b64::looks_like_key(&self.pk) || self.pk.len() > 90 {
            return Err("bad signing key");
        }
        if !b64::looks_like_key(&self.epk) || self.epk.len() > 90 {
            return Err("bad agreement key");
        }
        if !b64::looks_like_key(&self.n) || self.n.len() > MAX_NONCE {
            return Err("bad nonce");
        }
        if !b64::looks_like_key(&self.c) || self.c.len() > 720 {
            return Err("bad ciphertext");
        }
        if !b64::looks_like_key(&self.sig) || self.sig.len() > 90 {
            return Err("bad signature");
        }
        Ok(())
    }

    /// The signing key bytes, or `None` if the field is not decodable.
    pub fn pk_bytes(&self) -> Option<Vec<u8>> {
        b64::decode(&self.pk)
    }

    /// The agreement key bytes, or `None` if the field is not decodable.
    pub fn epk_bytes(&self) -> Option<Vec<u8>> {
        b64::decode(&self.epk)
    }

    /// Recompute the member id from the keys the post presents and require it
    /// to match the id the post claims.
    ///
    /// This is the check that makes pinning work. A member id commits to both
    /// public keys, so a post that presents one id and different keys is asking
    /// to be admitted under an identity it does not hold.
    pub fn keys_match_claimed_id(&self) -> bool {
        match (self.pk_bytes(), self.epk_bytes()) {
            (Some(pk), Some(epk)) => {
                constant_time_eq_str(&kdf_member_id(&pk, &epk), &self.m)
            }
            _ => false,
        }
    }
}

fn kdf_is_member_id(s: &str) -> bool {
    crate::kdf::is_member_id(s)
}
fn kdf_member_id(pk: &[u8], epk: &[u8]) -> String {
    crate::kdf::member_id(pk, epk)
}

/// Compare two member ids without leaking their first differing byte through
/// timing. Cheap to do, and it removes a class of question entirely.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// One member's identity as the relay holds it, returned on every feed read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedMember {
    pub m: String,
    pub alg: String,
    pub pk: String,
    pub epk: String,
    pub points: Vec<FeedPoint>,
}

impl FeedMember {
    pub fn member_id(&self) -> &str {
        &self.m
    }
}

/// One stored point, with the relay's own receive time alongside the sender's.
///
/// The signature and the epoch travel with every point so that each receiver
/// picks its own key and checks the signature itself. The relay is not trusted
/// to have done either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedPoint {
    pub e: i64,
    pub ts: i64,
    /// Relay receive time, and the feed cursor.
    pub srv: i64,
    pub n: String,
    pub c: String,
    pub sig: String,
}

impl FeedPoint {
    /// Reassemble this point into a post under the member it belongs to.
    pub fn to_post(&self, member: &FeedMember) -> Post {
        Post {
            m: member.m.clone(),
            alg: member.alg.clone(),
            pk: member.pk.clone(),
            epk: member.epk.clone(),
            e: self.e,
            ts: self.ts,
            n: self.n.clone(),
            c: self.c.clone(),
            sig: self.sig.clone(),
        }
    }
}

/// A feed read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Feed {
    /// The relay's clock, so a client can correct its own drift.
    pub now: i64,
    pub members: Vec<FeedMember>,
}

impl Feed {
    /// Every point in the feed, paired with the member it came from.
    pub fn posts(&self) -> Vec<Post> {
        self.members
            .iter()
            .flat_map(|mem| mem.points.iter().map(move |p| p.to_post(mem)))
            .collect()
    }
}

/// A relay error, carrying the status code and the exact body text.
///
/// The body text matters: the client maps `400 clock` to "your device clock is
/// wrong", which is a different problem from a malformed request, and the two
/// must not be reported the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayError {
    pub status: u16,
    pub message: String,
    /// The request was rejected specifically because the claimed epoch was not
    /// plausible for the relay's clock.
    pub clock: bool,
}

impl RelayError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        let message = message.into();
        let clock = message == "clock";
        Self { status, message, clock }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.status)
    }
}

impl std::error::Error for RelayError {}

/// Zeroize a buffer that held key material.
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL: &str = "00112233445566778899aabbccddeeff";
    const MEMBER: &str = "ffeeddccbbaa99887766554433221100";

    fn base_post() -> Post {
        Post {
            m: MEMBER.to_string(),
            alg: "ed25519".to_string(),
            pk: b64::encode(&[1u8; 32]),
            epk: b64::encode(&[2u8; 65]),
            e: 2980472,
            ts: 1788282659714,
            n: "AAAAAAAADm7-4zY".to_string(),
            c: "Q2lwaGVydGV4dEJ5dGVz".to_string(),
            sig: b64::encode(&[3u8; 64]),
        }
    }

    #[test]
    fn aad_matches_the_published_vector() {
        let s = aad(CHANNEL, MEMBER, 2980472, 1788282659714);
        assert_eq!(
            s,
            "starling/v2|00112233445566778899aabbccddeeff|ffeeddccbbaa99887766554433221100|2980472|1788282659714"
        );
        assert_eq!(s.len(), 99);
    }

    #[test]
    fn sig_base_matches_the_published_vector() {
        let s = sig_base(
            CHANNEL,
            MEMBER,
            2980472,
            1788282659714,
            "AAAAAAAADm7-4zY",
            "Q2lwaGVydGV4dEJ5dGVz",
        );
        assert_eq!(
            s,
            "starling/v2|00112233445566778899aabbccddeeff|ffeeddccbbaa99887766554433221100|2980472|1788282659714|AAAAAAAADm7-4zY|Q2lwaGVydGV4dEJ5dGVz"
        );
    }

    #[test]
    fn aad_and_sig_base_bind_the_epoch() {
        assert_ne!(
            aad(CHANNEL, MEMBER, 2980472, 1788282659714),
            aad(CHANNEL, MEMBER, 2980473, 1788282659714)
        );
        assert_ne!(
            sig_base(CHANNEL, MEMBER, 1, 1, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVz"),
            sig_base(CHANNEL, MEMBER, 2, 1, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVz")
        );
    }

    #[test]
    fn sig_base_covers_every_header_field() {
        let base =
            sig_base(CHANNEL, MEMBER, 1, 2, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVz");
        // Changing any single field must change what is signed.
        assert_ne!(
            base,
            sig_base(
                "ffffffffffffffffffffffffffffffff",
                MEMBER,
                1,
                2,
                "AAAAAAAADm7-4zY",
                "Q2lwaGVydGV4dEJ5dGVz"
            )
        );
        assert_ne!(
            base,
            sig_base(
                CHANNEL,
                "cccccccccccccccccccccccccccccccc",
                1,
                2,
                "AAAAAAAADm7-4zY",
                "Q2lwaGVydGV4dEJ5dGVz"
            )
        );
        assert_ne!(
            base,
            sig_base(CHANNEL, MEMBER, 9, 2, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVz")
        );
        // The timestamp is bound, so a signed post cannot have its ts altered.
        assert_ne!(
            base,
            sig_base(CHANNEL, MEMBER, 1, 3, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVz")
        );
        assert_ne!(
            base,
            sig_base(CHANNEL, MEMBER, 1, 2, "AAAAAAAADm7-4aY", "Q2lwaGVydGV4dEJ5dGVz")
        );
        assert_ne!(
            base,
            sig_base(CHANNEL, MEMBER, 1, 2, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVa")
        );
    }

    #[test]
    fn nonce_is_four_random_bytes_then_big_endian_ts() {
        let n = nonce_for(1788282659714, [0, 0, 0, 0]);
        assert_eq!(n.len(), 12);
        assert_eq!(&n[..4], &[0, 0, 0, 0], "guard is the first four bytes");
        // The low 8 bytes are exactly the timestamp, big-endian. The published
        // vector spells this nonce `00000000000001a05df3e382`.
        assert_eq!(u64::from_be_bytes(n[4..].try_into().unwrap()), 1788282659714);
        assert_eq!(crate::kdf::hex(&n), "00000000000001a05df3e382");
    }

    #[test]
    fn nonce_guard_varies_with_the_timestamp() {
        let a = nonce_for(1000, [0, 0, 0, 0]);
        let b = nonce_for(1001, [0, 0, 0, 0]);
        assert_ne!(a, b);
    }

    #[test]
    fn epoch_math_is_floor_division() {
        // 1788282659714 / 600000 = 2980471.09...
        assert_eq!(epoch_at(1788282659714), 2980471);
        assert_eq!(epoch_at(2980472 * EPOCH_MS), 2980472);
        assert_eq!(epoch_at(0), 0);
        // Negative times floor downwards rather than truncating towards zero.
        assert_eq!(epoch_at(-1), -1);
    }

    #[test]
    fn epoch_plausibility_allows_two_epochs_of_drift() {
        let now = 2980472 * EPOCH_MS;
        assert!(epoch_plausible(2980472, now));
        assert!(epoch_plausible(2980474, now), "+2 is allowed");
        assert!(epoch_plausible(2980470, now), "-2 is allowed");
        assert!(!epoch_plausible(2980475, now), "+3 is not");
        assert!(!epoch_plausible(2980469, now), "-3 is not");
    }

    #[test]
    fn alg_is_recovered_from_key_length_not_the_wire_field() {
        assert_eq!(Alg::from_pk(&[0u8; 32]), Some(Alg::Ed25519));
        assert_eq!(Alg::from_pk(&[0u8; 65]), Some(Alg::P256));
        assert_eq!(Alg::from_pk(&[0u8; 33]), None);
        assert_eq!(Alg::from_pk(&[0u8; 64]), None);
    }

    #[test]
    fn shape_validation_rejects_malformed_posts() {
        assert!(base_post().validate_shape().is_ok());

        let mut p = base_post();
        p.m = "nope".into();
        assert_eq!(p.validate_shape(), Err("bad member id"));

        let mut p = base_post();
        p.e = -1;
        assert_eq!(p.validate_shape(), Err("bad epoch"));

        let mut p = base_post();
        p.ts = 0;
        assert_eq!(p.validate_shape(), Err("bad timestamp"));

        let mut p = base_post();
        p.c = "A".repeat(721);
        assert_eq!(p.validate_shape(), Err("bad ciphertext"));

        let mut p = base_post();
        p.pk = "has padding=".into();
        assert_eq!(p.validate_shape(), Err("bad signing key"));
    }

    #[test]
    fn keys_must_hash_to_the_claimed_member_id() {
        let mut p = base_post();
        p.m = kdf_member_id(&[1u8; 32], &[2u8; 65]);
        assert!(p.keys_match_claimed_id());

        // Same signing key, different agreement key: a different identity.
        p.epk = b64::encode(&[9u8; 65]);
        assert!(!p.keys_match_claimed_id());
    }

    #[test]
    fn a_flip_in_the_ciphertext_changes_what_is_signed() {
        // The signature covers the base64 spelling, so changing one character
        // of the ciphertext changes the signed string.
        let a = sig_base(CHANNEL, MEMBER, 1, 2, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVz");
        let b = sig_base(CHANNEL, MEMBER, 1, 2, "AAAAAAAADm7-4zY", "Q2lwaGVydGV4dEJ5dGVa");
        assert_ne!(a, b);
    }

    #[test]
    fn relay_error_distinguishes_a_clock_problem() {
        let e = RelayError::new(400, "clock");
        assert!(e.clock);
        let e = RelayError::new(400, "bad request");
        assert!(!e.clock);
    }

    #[test]
    fn feed_reassembles_points_into_posts() {
        let feed = Feed {
            now: 100,
            members: vec![FeedMember {
                m: MEMBER.to_string(),
                alg: "ed25519".to_string(),
                pk: b64::encode(&[1u8; 32]),
                epk: b64::encode(&[2u8; 65]),
                points: vec![FeedPoint {
                    e: 1,
                    ts: 2,
                    srv: 3,
                    n: "AAAAAAAADm7-4zY".to_string(),
                    c: "Q2lwaGVydGV4dEJ5dGVz".to_string(),
                    sig: b64::encode(&[4u8; 64]),
                }],
            }],
        };
        let posts = feed.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].m, MEMBER);
        assert_eq!(posts[0].e, 1);
        assert_eq!(posts[0].ts, 2);
    }
}
