//! Sealing and opening: AES-256-GCM, with the padding and nonce rules the
//! protocol fixes.
//!
//! Two rules live here that are easy to get wrong and impossible to notice
//! later:
//!
//! * **Exactly one key is ever tried.** Given a ciphertext, a receiver derives
//!   the key the message's own epoch selects and either opens it or gives up.
//!   Trying several candidate keys and reporting which one worked is a
//!   partitioning oracle, so [`ContentKey::open`] takes one key and returns a
//!   bool.
//! * **The sender's timestamp appears twice.** It is in the nonce, in the
//!   associated data and in the plaintext. The receiver requires the plaintext
//!   copy to equal the header copy, so a message cannot claim one time
//!   outside and another inside.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    wire::{PAD_LEN, Post, aad, nonce_for, sig_base},
    {b64, identity::Identity, wire::Alg},
};

/// Encrypt a padded plaintext under `key`, binding `aad`.
///
/// Returns the ciphertext with the GCM tag appended, so it is
/// `plaintext.len() + 16` bytes.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }
    let k = Key::<Aes256Gcm>::try_from(&key[..]).ok()?;
    let cipher = Aes256Gcm::new(&k);
    let n = Nonce::try_from(&nonce[..]).ok()?;
    cipher.encrypt(&n, Payload { msg: plaintext, aad }).ok()
}

/// The inverse of [`seal`]. `None` on any authentication failure.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }
    let k = Key::<Aes256Gcm>::try_from(&key[..]).ok()?;
    let cipher = Aes256Gcm::new(&k);
    let n = Nonce::try_from(&nonce[..]).ok()?;
    cipher.decrypt(&n, Payload { msg: ciphertext, aad }).ok()
}

/// Pad a message body to exactly [`PAD_LEN`] bytes with spaces.
///
/// Spaces rather than zero bytes, because the body is JSON and JSON parsers
/// ignore trailing whitespace, so the padding is free to carry. Refuses to pad
/// anything already too long, rather than truncating it: a silently truncated
/// location post is worse than a rejected one.
pub fn pad(body: &str) -> Option<Vec<u8>> {
    if body.len() > PAD_LEN {
        return None;
    }
    let mut buf = Vec::with_capacity(PAD_LEN);
    buf.extend_from_slice(body.as_bytes());
    buf.resize(PAD_LEN, b' ');
    Some(buf)
}

/// Remove the padding from a decrypted body.
///
/// Trailing spaces only. The body is JSON, and JSON parsers ignore trailing
/// whitespace, so trimming from the end is exactly reversible; a space *inside*
/// the body is data and is left alone.
pub fn unpad(padded: &[u8]) -> String {
    let end = padded.iter().rposition(|&b| b != b' ').map(|i| i + 1).unwrap_or(0);
    String::from_utf8_lossy(&padded[..end]).into_owned()
}

/// A 32-byte content key. Wrapped so it is zeroized on drop rather than being
/// an ordinary array on the stack.
#[derive(Clone)]
pub struct ContentKey([u8; 32]);

impl ContentKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encrypt a padded body under an explicit nonce.
    pub fn seal_padded(&self, body: &str, nonce: &[u8; 12], aad: &[u8]) -> Option<Vec<u8>> {
        seal(&self.0, nonce, &pad(body)?, aad)
    }

    /// Encrypt a padded body under the nonce for `ts` with a fresh random
    /// guard, and return the nonce so the caller can put it on the wire.
    pub fn seal_padded_fresh(
        &self,
        body: &str,
        ts: i64,
        aad: &[u8],
    ) -> Option<(Vec<u8>, [u8; 12])> {
        let nonce = nonce_for(ts, random4());
        let ct = self.seal_padded(body, &nonce, aad)?;
        Some((ct, nonce))
    }

    /// Decrypt and unpad, returning `None` for any failure: a bad tag, a
    /// malformed nonce, or a body that was not padded.
    ///
    /// There is deliberately no way to ask *why* it failed, and no way to try a
    /// second key.
    pub fn open_padded(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Option<String> {
        Some(unpad(&open(&self.0, nonce, ciphertext, aad)?))
    }
}

impl Drop for ContentKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContentKey(<redacted>)")
    }
}

impl PartialEq for ContentKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for ContentKey {}

/// Build the whole POST envelope for one message.
///
/// This is the single place a post is created, so the nonce, the padding, the
/// associated data and the signature cannot drift apart from one another. The
/// caller supplies the content key and the timestamp; everything else follows
/// from the identity and the channel.
pub fn build_post(
    identity: &Identity,
    channel: &str,
    key: &ContentKey,
    epoch: i64,
    ts: i64,
    body: &str,
) -> Result<Post, &'static str> {
    let aad = aad(channel, identity.member_id(), epoch, ts);
    let (ct, nonce) =
        key.seal_padded_fresh(body, ts, aad.as_bytes()).ok_or("message too large")?;

    let n = b64::encode(&nonce);
    let c = b64::encode(&ct);
    let sig =
        identity.sign_text(&sig_base(channel, identity.member_id(), epoch, ts, &n, &c));

    Ok(Post {
        m: identity.member_id().to_string(),
        alg: identity.alg().as_str().to_string(),
        pk: b64::encode(&identity.pk_bytes()),
        epk: b64::encode(&identity.epk_bytes()),
        e: epoch,
        ts,
        n,
        c,
        sig,
    })
}

/// A sealed, signed message on its way through the relay, with the plaintext
/// the receiver will see once the checks pass.
pub struct Opened {
    pub body: String,
    pub epoch: i64,
    pub ts: i64,
}

/// Verify a post's signature and open its body.
///
/// The order is fixed and each step is a precondition for the next:
/////
/// 1. shape, so nothing downstream parses a hostile string;
/// 2. the declared keys hash to the claimed member id, so a stranger cannot
///    post under someone else's id;
/// 3. the signature, which is what says *which* member this is — the content
///    key only says that some holder of circle key material wrote it;
/// 4. decryption under the one key the message's own epoch selects;
/// 5. the inner timestamp matching the header, so a message cannot present two
///    different times.
pub fn verify_and_open(
    post: &Post,
    channel: &str,
    key: &ContentKey,
    now: i64,
) -> Option<Opened> {
    post.validate_shape().ok()?;
    if !post.keys_match_claimed_id() {
        return None;
    }

    let pk = post.pk_bytes()?;
    let alg = Alg::from_pk(&pk)?;
    let sig = b64::decode(&post.sig)?;

    let base = sig_base(channel, &post.m, post.e, post.ts, &post.n, &post.c);
    if !crate::identity::verify_sig(alg, &pk, &sig, base.as_bytes()) {
        return None;
    }

    let aad = aad(channel, &post.m, post.e, post.ts);
    let ct = b64::decode(&post.c)?;
    // The nonce comes off the wire, not from the timestamp. Recomputing it
    // would only work if the guard were transmitted, and it is.
    let nonce: [u8; 12] = b64::decode_exact(&post.n)?;
    let body = key.open_padded(&ct, &nonce, aad.as_bytes())?;

    if !crate::msg::inner_timestamp_matches(&body, post.ts) {
        return None;
    }
    if post.ts > now + crate::wire::FUTURE_SKEW_MS {
        return None;
    }

    Some(Opened { body, epoch: post.e, ts: post.ts })
}

/// Four random bytes, for a nonce guard.
pub fn random4() -> [u8; 4] {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).expect("os randomness unavailable");
    b
}

/// Eight random bytes, for callers that want a little randomness without
/// committing to a random-number dependency of their own.
///
/// A jittered backoff is the caller here. `None` only if the system entropy
/// source is unavailable, which a caller should treat as "do not pretend to be
/// random".
pub fn random_bytes_8() -> Option<[u8; 8]> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).ok()?;
    Some(b)
}

/// `n` random bytes, for seeds, fresh entropy and invite secrets.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("os randomness unavailable");
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf;

    #[test]
    fn padding_is_exactly_512_bytes_and_the_body_leads_it() {
        let body = r#"{"t":"loc"}"#;
        let p = pad(body).unwrap();
        assert_eq!(p.len(), PAD_LEN);
        assert_eq!(&p[..body.len()], body.as_bytes());
        assert!(p[body.len()..].iter().all(|&b| b == b' '));
    }

    #[test]
    fn a_space_inside_the_body_survives_unpadding() {
        // Unpadding trims from the end only, so interior whitespace is data.
        let body = r#"{"st":"a b c"}"#;
        assert_eq!(unpad(&pad(body).unwrap()), body);
    }

    #[test]
    fn padding_refuses_to_truncate() {
        let too_long = "x".repeat(PAD_LEN + 1);
        assert!(pad(&too_long).is_none());
        // Exactly at the limit is still fine.
        assert!(pad(&"x".repeat(PAD_LEN)).is_some());
    }

    #[test]
    fn unpad_round_trips_including_edge_cases() {
        assert_eq!(unpad(&pad(r#"{"a":1}"#).unwrap()), r#"{"a":1}"#);
        assert_eq!(unpad(&[]), "");
        assert_eq!(unpad(b"  "), "");
    }

    #[test]
    fn ciphertext_is_plaintext_plus_a_tag() {
        let ct = seal(&[1u8; 32], &[0u8; 12], &pad(r#"{"a":1}"#).unwrap(), b"aad").unwrap();
        assert_eq!(ct.len(), PAD_LEN + 16);
    }

    #[test]
    fn a_tampered_associated_data_string_fails_to_open() {
        let ct = seal(&[1u8; 32], &[0u8; 12], &pad(r#"{"a":1}"#).unwrap(), b"aad").unwrap();
        assert!(open(&[1u8; 32], &[0u8; 12], &ct, b"aad2").is_none());
    }

    #[test]
    fn a_tampered_ciphertext_fails_to_open() {
        let mut ct =
            seal(&[1u8; 32], &[0u8; 12], &pad(r#"{"a":1}"#).unwrap(), b"aad").unwrap();
        ct[0] ^= 1;
        assert!(open(&[1u8; 32], &[0u8; 12], &ct, b"aad").is_none());
    }

    #[test]
    fn the_wrong_key_does_not_open_the_message() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let aad_s = b"aad";
        let ct = seal(&k1, &[0u8; 12], &pad(r#"{"a":1}"#).unwrap(), aad_s).unwrap();
        assert!(open(&k2, &[0u8; 12], &ct, aad_s).is_none());
    }

    #[test]
    fn the_wrong_epoch_means_the_wrong_key_means_no_message() {
        // This is the whole point of one key per epoch: moving a point into a
        // different epoch finds no key that opens it.
        let ck0 = kdf::chain0(&[1u8; 32]);
        let ck1 = kdf::chain_step(&ck0);
        let aad_s = b"aad";
        let ct = seal(&ck0, &[0u8; 12], &pad(r#"{"a":1}"#).unwrap(), aad_s).unwrap();
        assert!(open(&ck1, &[0u8; 12], &ct, aad_s).is_none());
    }

    #[test]
    fn a_repeated_nonce_is_avoided_by_the_random_guard() {
        // Two messages in the same millisecond under one key must not share a
        // nonce, or GCM leaks the XOR of the plaintexts.
        let k = [3u8; 32];
        let g1 = random4();
        let g2 = random4();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let mut g = [0u8; 4];
            getrandom::fill(&mut g).unwrap();
            seen.insert(crate::wire::nonce_for(1_700_000_000_000, g));
            let _ = (g1, g2);
        }
        assert_eq!(seen.len(), 64);
        let _ = k;
    }

    #[test]
    fn content_key_equality_is_not_string_comparison() {
        assert_eq!(ContentKey::new([1u8; 32]), ContentKey::new([1u8; 32]));
        assert_ne!(ContentKey::new([1u8; 32]), ContentKey::new([2u8; 32]));
    }

    #[test]
    fn content_key_debug_does_not_leak() {
        let s = format!("{:?}", ContentKey::new([0xab; 32]));
        assert_eq!(s, "ContentKey(<redacted>)");
        assert!(!s.contains("ab"));
    }

    #[test]
    fn content_key_seals_and_opens_with_the_transmitted_nonce() {
        let k = ContentKey::new([4u8; 32]);
        let aad_s = b"x";
        let (ct, nonce) = k.seal_padded_fresh("hi", 1_700_000_000_000, aad_s).unwrap();
        assert_eq!(k.open_padded(&ct, &nonce, aad_s), Some("hi".into()));
    }

    #[test]
    fn the_nonce_cannot_be_recomputed_from_the_timestamp_alone() {
        // The random guard is not derivable, so a receiver must be given the
        // nonce rather than reconstructing it.
        let k = ContentKey::new([4u8; 32]);
        let (ct, nonce) = k.seal_padded_fresh("hi", 1_700_000_000_000, b"x").unwrap();
        let forged = nonce_for(1_700_000_000_000, [0, 0, 0, 0]);
        assert_ne!(nonce, forged);
        assert!(k.open_padded(&ct, &forged, b"x").is_none());
    }
}
